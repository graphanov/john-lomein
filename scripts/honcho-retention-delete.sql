\set ON_ERROR_STOP on
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='5min';
SELECT pg_advisory_xact_lock(hashtextextended(:'workspace' || ':' || :'cutoff', 0));
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_stat_activity
    WHERE datname=current_database() AND pid<>pg_backend_pid()
  ) THEN
    RAISE EXCEPTION 'retention requires exclusive database quiescence';
  END IF;
END $$;
LOCK TABLE messages, message_embeddings, documents, queue, active_queue_sessions
  IN SHARE ROW EXCLUSIVE MODE;

CREATE TEMP TABLE jl_message_ids(id bigint PRIMARY KEY) ON COMMIT DROP;
INSERT INTO jl_message_ids SELECT value::bigint FROM jsonb_array_elements_text(:'message_ids'::jsonb);
CREATE TEMP TABLE jl_message_public_ids(id text PRIMARY KEY) ON COMMIT DROP;
INSERT INTO jl_message_public_ids SELECT value FROM jsonb_array_elements_text(:'message_public_ids'::jsonb);
CREATE TEMP TABLE jl_message_identities(
  id bigint PRIMARY KEY, public_id text NOT NULL UNIQUE, fingerprint text NOT NULL
) ON COMMIT DROP;
INSERT INTO jl_message_identities
SELECT id, public_id, fingerprint
FROM jsonb_to_recordset(:'message_identities'::jsonb)
  AS value(id bigint, public_id text, fingerprint text);

CREATE TEMP TABLE jl_embedding_ids(id bigint PRIMARY KEY) ON COMMIT DROP;
INSERT INTO jl_embedding_ids SELECT value::bigint FROM jsonb_array_elements_text(:'embedding_ids'::jsonb);
CREATE TEMP TABLE jl_embedding_identities(
  id bigint PRIMARY KEY, message_id text NOT NULL, fingerprint text NOT NULL
) ON COMMIT DROP;
INSERT INTO jl_embedding_identities
SELECT id, message_id, fingerprint
FROM jsonb_to_recordset(:'embedding_identities'::jsonb)
  AS value(id bigint, message_id text, fingerprint text);

CREATE TEMP TABLE jl_document_ids(id text PRIMARY KEY) ON COMMIT DROP;
INSERT INTO jl_document_ids SELECT value FROM jsonb_array_elements_text(:'document_ids'::jsonb);
CREATE TEMP TABLE jl_queue_ids(id bigint PRIMARY KEY) ON COMMIT DROP;
INSERT INTO jl_queue_ids SELECT value::bigint FROM jsonb_array_elements_text(:'queue_ids'::jsonb);
CREATE TEMP TABLE jl_queue_identities(
  id bigint PRIMARY KEY, work_unit_key text NOT NULL, fingerprint text NOT NULL
) ON COMMIT DROP;
INSERT INTO jl_queue_identities
SELECT id, work_unit_key, fingerprint
FROM jsonb_to_recordset(:'queue_identities'::jsonb)
  AS value(id bigint, work_unit_key text, fingerprint text);

CREATE TEMP TABLE jl_active_queue_session_ids(id text PRIMARY KEY) ON COMMIT DROP;
INSERT INTO jl_active_queue_session_ids SELECT value FROM jsonb_array_elements_text(:'active_queue_session_ids'::jsonb);
CREATE TEMP TABLE jl_sequence_high_waters(
  table_name text NOT NULL,
  column_name text NOT NULL,
  sequence_name text NOT NULL,
  high_water bigint NOT NULL CHECK (high_water>=0),
  PRIMARY KEY(table_name,column_name)
) ON COMMIT DROP;
INSERT INTO jl_sequence_high_waters
SELECT value->>'table', value->>'column', value->>'sequence', (value->>'high_water')::bigint
FROM jsonb_array_elements(:'sequence_high_waters'::jsonb) value;

SELECT set_config('john_lomein.expected_message_count', :'expected_message_count', true);
SELECT set_config('john_lomein.expected_document_count', :'expected_document_count', true);
SELECT set_config('john_lomein.expected_embedding_count', :'expected_embedding_count', true);
SELECT set_config('john_lomein.expected_queue_count', :'expected_queue_count', true);
SELECT set_config('john_lomein.expected_active_count', :'expected_active_count', true);
SELECT set_config('john_lomein.workspace', :'workspace', true);
SELECT set_config('john_lomein.cutoff', :'cutoff', true);

DO $$
DECLARE
  actual_count bigint;
  actual_document_count bigint;
  actual_embedding_count bigint;
  actual_queue_count bigint;
  actual_active_count bigint;
  collision_count bigint;
BEGIN
  IF EXISTS (SELECT id FROM jl_message_ids EXCEPT SELECT id FROM jl_message_identities)
     OR EXISTS (SELECT id FROM jl_message_identities EXCEPT SELECT id FROM jl_message_ids)
     OR EXISTS (SELECT id FROM jl_message_public_ids EXCEPT SELECT public_id FROM jl_message_identities)
     OR EXISTS (SELECT public_id FROM jl_message_identities EXCEPT SELECT id FROM jl_message_public_ids)
     OR EXISTS (SELECT id FROM jl_embedding_ids EXCEPT SELECT id FROM jl_embedding_identities)
     OR EXISTS (SELECT id FROM jl_embedding_identities EXCEPT SELECT id FROM jl_embedding_ids)
     OR EXISTS (SELECT id FROM jl_queue_ids EXCEPT SELECT id FROM jl_queue_identities)
     OR EXISTS (SELECT id FROM jl_queue_identities EXCEPT SELECT id FROM jl_queue_ids) THEN
    RAISE EXCEPTION 'retention identity bindings do not exactly cover bigint candidates';
  END IF;
  IF EXISTS (
    SELECT 1 FROM jl_message_identities
    WHERE fingerprint !~ '^sha256:[0-9a-f]{64}$'
    UNION ALL
    SELECT 1 FROM jl_embedding_identities
    WHERE fingerprint !~ '^sha256:[0-9a-f]{64}$'
    UNION ALL
    SELECT 1 FROM jl_queue_identities
    WHERE fingerprint !~ '^sha256:[0-9a-f]{64}$'
  ) THEN
    RAISE EXCEPTION 'retention identity fingerprint is invalid';
  END IF;
  IF (SELECT count(*) FROM jl_sequence_high_waters)<>
       ((CASE WHEN pg_get_serial_sequence('messages','id') IS NOT NULL THEN 1 ELSE 0 END)
        +(CASE WHEN pg_get_serial_sequence('message_embeddings','id') IS NOT NULL THEN 1 ELSE 0 END)
        +(CASE WHEN pg_get_serial_sequence('queue','id') IS NOT NULL THEN 1 ELSE 0 END))
     OR (pg_get_serial_sequence('messages','id') IS NOT NULL AND NOT EXISTS (
       SELECT 1 FROM jl_sequence_high_waters
       WHERE table_name='messages' AND column_name='id'
         AND sequence_name=pg_get_serial_sequence('messages','id')
     ))
     OR (pg_get_serial_sequence('message_embeddings','id') IS NOT NULL AND NOT EXISTS (
       SELECT 1 FROM jl_sequence_high_waters
       WHERE table_name='message_embeddings' AND column_name='id'
         AND sequence_name=pg_get_serial_sequence('message_embeddings','id')
     ))
     OR (pg_get_serial_sequence('queue','id') IS NOT NULL AND NOT EXISTS (
       SELECT 1 FROM jl_sequence_high_waters
       WHERE table_name='queue' AND column_name='id'
         AND sequence_name=pg_get_serial_sequence('queue','id')
     )) THEN
    RAISE EXCEPTION 'retention sequence high-water bindings are incomplete or stale';
  END IF;

  SELECT count(*) INTO collision_count
  FROM messages m JOIN jl_message_identities j ON j.id=m.id
  WHERE m.workspace_name=current_setting('john_lomein.workspace')
    AND (
      m.public_id IS DISTINCT FROM j.public_id
      OR 'sha256:' || encode(sha256(convert_to(to_jsonb(m)::text,'UTF8')),'hex') IS DISTINCT FROM j.fingerprint
    );
  IF collision_count<>0 THEN
    RAISE EXCEPTION 'retention message identity collision: % reusable ids no longer match', collision_count;
  END IF;
  SELECT count(*) INTO collision_count
  FROM message_embeddings e JOIN jl_embedding_identities j ON j.id=e.id
  WHERE e.workspace_name=current_setting('john_lomein.workspace')
    AND (
      e.message_id IS DISTINCT FROM j.message_id
      OR 'sha256:' || encode(sha256(convert_to(to_jsonb(e)::text,'UTF8')),'hex') IS DISTINCT FROM j.fingerprint
    );
  IF collision_count<>0 THEN
    RAISE EXCEPTION 'retention embedding identity collision: % reusable ids no longer match', collision_count;
  END IF;
  SELECT count(*) INTO collision_count
  FROM queue q JOIN jl_queue_identities j ON j.id=q.id
  WHERE q.workspace_name=current_setting('john_lomein.workspace')
    AND (
      q.work_unit_key IS DISTINCT FROM j.work_unit_key
      OR 'sha256:' || encode(sha256(convert_to(to_jsonb(q)::text,'UTF8')),'hex') IS DISTINCT FROM j.fingerprint
    );
  IF collision_count<>0 THEN
    RAISE EXCEPTION 'retention queue identity collision: % reusable ids no longer match', collision_count;
  END IF;

  SELECT count(*) INTO actual_count
  FROM messages m JOIN jl_message_identities j
    ON j.id=m.id AND j.public_id=m.public_id
      AND j.fingerprint='sha256:' || encode(sha256(convert_to(to_jsonb(m)::text,'UTF8')),'hex')
  WHERE m.workspace_name=current_setting('john_lomein.workspace')
    AND m.created_at<current_setting('john_lomein.cutoff')::timestamptz;
  SELECT count(*) INTO actual_document_count
  FROM documents d JOIN jl_document_ids j ON j.id=d.id
  WHERE d.workspace_name=current_setting('john_lomein.workspace') AND d.deleted_at IS NULL;
  SELECT count(*) INTO actual_embedding_count
  FROM message_embeddings e JOIN jl_embedding_identities j
    ON j.id=e.id AND j.message_id=e.message_id
      AND j.fingerprint='sha256:' || encode(sha256(convert_to(to_jsonb(e)::text,'UTF8')),'hex')
  WHERE e.workspace_name=current_setting('john_lomein.workspace');
  SELECT count(*) INTO actual_queue_count
  FROM queue q JOIN jl_queue_identities j
    ON j.id=q.id AND j.work_unit_key=q.work_unit_key
      AND j.fingerprint='sha256:' || encode(sha256(convert_to(to_jsonb(q)::text,'UTF8')),'hex')
  WHERE q.workspace_name=current_setting('john_lomein.workspace');
  SELECT count(*) INTO actual_active_count
  FROM active_queue_sessions a JOIN jl_active_queue_session_ids j ON j.id=a.id
  WHERE EXISTS (
    SELECT 1 FROM queue q JOIN jl_queue_identities jq ON jq.id=q.id
    WHERE q.workspace_name=current_setting('john_lomein.workspace')
      AND q.work_unit_key=a.work_unit_key
      AND jq.work_unit_key=q.work_unit_key
      AND jq.fingerprint='sha256:' || encode(sha256(convert_to(to_jsonb(q)::text,'UTF8')),'hex')
  );
  IF actual_count<>current_setting('john_lomein.expected_message_count')::bigint THEN
    RAISE EXCEPTION 'retention plan is stale: expected %, observed %',
      current_setting('john_lomein.expected_message_count'), actual_count;
  END IF;
  IF actual_document_count<>current_setting('john_lomein.expected_document_count')::bigint THEN
    RAISE EXCEPTION 'retention document plan is stale: expected %, observed %',
      current_setting('john_lomein.expected_document_count'), actual_document_count;
  END IF;
  IF actual_embedding_count<>current_setting('john_lomein.expected_embedding_count')::bigint THEN
    RAISE EXCEPTION 'retention embedding plan is stale';
  END IF;
  IF actual_queue_count<>current_setting('john_lomein.expected_queue_count')::bigint THEN
    RAISE EXCEPTION 'retention queue plan is stale';
  END IF;
  IF actual_active_count<>current_setting('john_lomein.expected_active_count')::bigint THEN
    RAISE EXCEPTION 'retention active queue plan is stale';
  END IF;
END $$;

-- Advancing is deliberately after all identity and stale-plan checks. setval is
-- non-transactional, but advancing a sequence is safe even if a later delete fails.
SELECT setval(
  to_regclass(s.sequence_name),
  GREATEST(s.high_water,COALESCE(pg_sequence_last_value(to_regclass(s.sequence_name)),0),COALESCE((SELECT max(id) FROM messages),0)),
  true
)
FROM jl_sequence_high_waters s
WHERE s.table_name='messages' AND s.column_name='id'
  AND GREATEST(s.high_water,COALESCE(pg_sequence_last_value(to_regclass(s.sequence_name)),0),COALESCE((SELECT max(id) FROM messages),0))>0;
SELECT setval(
  to_regclass(s.sequence_name),
  GREATEST(s.high_water,COALESCE(pg_sequence_last_value(to_regclass(s.sequence_name)),0),COALESCE((SELECT max(id) FROM message_embeddings),0)),
  true
)
FROM jl_sequence_high_waters s
WHERE s.table_name='message_embeddings' AND s.column_name='id'
  AND GREATEST(s.high_water,COALESCE(pg_sequence_last_value(to_regclass(s.sequence_name)),0),COALESCE((SELECT max(id) FROM message_embeddings),0))>0;
SELECT setval(
  to_regclass(s.sequence_name),
  GREATEST(s.high_water,COALESCE(pg_sequence_last_value(to_regclass(s.sequence_name)),0),COALESCE((SELECT max(id) FROM queue),0)),
  true
)
FROM jl_sequence_high_waters s
WHERE s.table_name='queue' AND s.column_name='id'
  AND GREATEST(s.high_water,COALESCE(pg_sequence_last_value(to_regclass(s.sequence_name)),0),COALESCE((SELECT max(id) FROM queue),0))>0;
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM jl_sequence_high_waters s
    WHERE COALESCE(pg_sequence_last_value(to_regclass(s.sequence_name)),0)<s.high_water
  ) THEN
    RAISE EXCEPTION 'retention sequence high-water restoration failed';
  END IF;
END $$;

DELETE FROM active_queue_sessions a
WHERE a.id IN (SELECT id FROM jl_active_queue_session_ids)
  AND EXISTS (
    SELECT 1 FROM queue q JOIN jl_queue_identities jq ON jq.id=q.id
    WHERE q.workspace_name=:'workspace' AND q.work_unit_key=a.work_unit_key
      AND jq.work_unit_key=q.work_unit_key
      AND jq.fingerprint='sha256:' || encode(sha256(convert_to(to_jsonb(q)::text,'UTF8')),'hex')
  );
DELETE FROM queue
USING jl_queue_identities j
WHERE queue.workspace_name=:'workspace' AND queue.id=j.id
  AND queue.work_unit_key=j.work_unit_key
  AND j.fingerprint='sha256:' || encode(sha256(convert_to(to_jsonb(queue)::text,'UTF8')),'hex');
DELETE FROM message_embeddings
USING jl_embedding_identities j
WHERE message_embeddings.workspace_name=:'workspace' AND message_embeddings.id=j.id
  AND message_embeddings.message_id=j.message_id
  AND j.fingerprint='sha256:' || encode(sha256(convert_to(to_jsonb(message_embeddings)::text,'UTF8')),'hex');
DELETE FROM documents
WHERE workspace_name=:'workspace' AND id IN (SELECT id FROM jl_document_ids);
DELETE FROM messages
USING jl_message_identities j
WHERE messages.workspace_name=:'workspace' AND messages.id=j.id
  AND messages.public_id=j.public_id
  AND j.fingerprint='sha256:' || encode(sha256(convert_to(to_jsonb(messages)::text,'UTF8')),'hex');
DO $$
DECLARE remaining bigint;
BEGIN
  SELECT
    (SELECT count(*) FROM messages WHERE workspace_name=current_setting('john_lomein.workspace') AND id IN (SELECT id FROM jl_message_ids))+
    (SELECT count(*) FROM message_embeddings WHERE workspace_name=current_setting('john_lomein.workspace') AND id IN (SELECT id FROM jl_embedding_ids))+
    (SELECT count(*) FROM queue WHERE workspace_name=current_setting('john_lomein.workspace') AND id IN (SELECT id FROM jl_queue_ids))+
    (SELECT count(*) FROM documents WHERE workspace_name=current_setting('john_lomein.workspace') AND id IN (SELECT id FROM jl_document_ids))+
    (SELECT count(*) FROM active_queue_sessions WHERE id IN (SELECT id FROM jl_active_queue_session_ids))
  INTO remaining;
  IF remaining<>0 THEN
    RAISE EXCEPTION 'retention verification failed: % rows remain', remaining;
  END IF;
END $$;
COMMIT;
