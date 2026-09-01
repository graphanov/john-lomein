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
CREATE TEMP TABLE jl_embedding_ids(id bigint PRIMARY KEY) ON COMMIT DROP;
INSERT INTO jl_embedding_ids SELECT value::bigint FROM jsonb_array_elements_text(:'embedding_ids'::jsonb);
CREATE TEMP TABLE jl_document_ids(id text PRIMARY KEY) ON COMMIT DROP;
INSERT INTO jl_document_ids SELECT value FROM jsonb_array_elements_text(:'document_ids'::jsonb);
CREATE TEMP TABLE jl_queue_ids(id bigint PRIMARY KEY) ON COMMIT DROP;
INSERT INTO jl_queue_ids SELECT value::bigint FROM jsonb_array_elements_text(:'queue_ids'::jsonb);
CREATE TEMP TABLE jl_active_queue_session_ids(id text PRIMARY KEY) ON COMMIT DROP;
INSERT INTO jl_active_queue_session_ids SELECT value FROM jsonb_array_elements_text(:'active_queue_session_ids'::jsonb);
SELECT set_config('john_lomein.expected_message_count', :'expected_message_count', true);
SELECT set_config('john_lomein.expected_document_count', :'expected_document_count', true);
SELECT set_config('john_lomein.expected_embedding_count', :'expected_embedding_count', true);
SELECT set_config('john_lomein.expected_queue_count', :'expected_queue_count', true);
SELECT set_config('john_lomein.expected_active_count', :'expected_active_count', true);
SELECT set_config('john_lomein.workspace', :'workspace', true);
SELECT set_config('john_lomein.cutoff', :'cutoff', true);
DO $$
DECLARE actual_count bigint; actual_document_count bigint; actual_embedding_count bigint; actual_queue_count bigint; actual_active_count bigint;
BEGIN
  SELECT count(*) INTO actual_count
  FROM messages m JOIN jl_message_ids j ON j.id=m.id
  WHERE m.workspace_name=current_setting('john_lomein.workspace')
    AND m.created_at<current_setting('john_lomein.cutoff')::timestamptz;
  SELECT count(*) INTO actual_document_count
  FROM documents d JOIN jl_document_ids j ON j.id=d.id
  WHERE d.workspace_name=current_setting('john_lomein.workspace') AND d.deleted_at IS NULL;
  SELECT count(*) INTO actual_embedding_count
  FROM message_embeddings e JOIN jl_embedding_ids j ON j.id=e.id
  WHERE e.workspace_name=current_setting('john_lomein.workspace');
  SELECT count(*) INTO actual_queue_count
  FROM queue q JOIN jl_queue_ids j ON j.id=q.id
  WHERE q.workspace_name=current_setting('john_lomein.workspace');
  SELECT count(*) INTO actual_active_count
  FROM active_queue_sessions a JOIN jl_active_queue_session_ids j ON j.id=a.id
  WHERE EXISTS (
    SELECT 1 FROM queue q JOIN jl_queue_ids jq ON jq.id=q.id
    WHERE q.workspace_name=current_setting('john_lomein.workspace')
      AND q.work_unit_key=a.work_unit_key
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
DELETE FROM active_queue_sessions a
WHERE a.id IN (SELECT id FROM jl_active_queue_session_ids)
  AND EXISTS (
    SELECT 1 FROM queue q JOIN jl_queue_ids jq ON jq.id=q.id
    WHERE q.workspace_name=:'workspace' AND q.work_unit_key=a.work_unit_key
  );
DELETE FROM queue
WHERE workspace_name=:'workspace' AND id IN (SELECT id FROM jl_queue_ids);
DELETE FROM message_embeddings
WHERE workspace_name=:'workspace' AND id IN (SELECT id FROM jl_embedding_ids);
DELETE FROM documents
WHERE workspace_name=:'workspace' AND id IN (SELECT id FROM jl_document_ids);
DELETE FROM messages
WHERE workspace_name=:'workspace' AND id IN (SELECT id FROM jl_message_ids);
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
