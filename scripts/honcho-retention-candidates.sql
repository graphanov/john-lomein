WITH RECURSIVE
candidate_messages AS (
  SELECT m.id, m.public_id,
         'sha256:' || encode(sha256(convert_to(to_jsonb(m)::text,'UTF8')),'hex') AS fingerprint
  FROM messages m
  WHERE m.workspace_name=:'workspace' AND m.created_at < :'cutoff'::timestamptz
),
candidate_queue_seed AS (
  SELECT q.id, q.work_unit_key
  FROM queue q
  WHERE q.workspace_name=:'workspace'
    AND (
      q.message_id IN (SELECT id FROM candidate_messages)
      OR EXISTS (
        SELECT 1 FROM candidate_messages m
        WHERE jsonb_path_exists(
          q.payload,
          '$.** ? (@ == $target)',
          jsonb_build_object('target',to_jsonb(m.id::text))
        ) OR jsonb_path_exists(
          q.payload,
          '$.** ? (@ == $target)',
          jsonb_build_object('target',to_jsonb(m.public_id))
        )
      )
    )
),
candidate_queue AS (
  SELECT DISTINCT q.id, q.work_unit_key,
         'sha256:' || encode(sha256(convert_to(to_jsonb(q)::text,'UTF8')),'hex') AS fingerprint
  FROM queue q
  WHERE q.workspace_name=:'workspace'
    AND (
      q.id IN (SELECT id FROM candidate_queue_seed)
      OR q.work_unit_key IN (SELECT work_unit_key FROM candidate_queue_seed)
    )
),
mixed_work_units AS (
  SELECT work_unit_key FROM candidate_queue WHERE false
),
unknown_touching_queue AS (
  SELECT DISTINCT q.id
  FROM queue q
  WHERE q.workspace_name=:'workspace'
    AND q.id NOT IN (SELECT id FROM candidate_queue)
    AND EXISTS (
      SELECT 1 FROM candidate_messages m
      WHERE jsonb_path_exists(
        q.payload,
        '$.** ? (@ == $target)',
        jsonb_build_object('target',to_jsonb(m.id::text))
      ) OR jsonb_path_exists(
        q.payload,
        '$.** ? (@ == $target)',
        jsonb_build_object('target',to_jsonb(m.public_id))
      )
    )
),
seed_documents AS (
  SELECT DISTINCT d.id
  FROM documents d
  WHERE d.workspace_name=:'workspace' AND d.deleted_at IS NULL
    AND EXISTS (
      SELECT 1
      FROM jsonb_array_elements_text(
        CASE WHEN jsonb_typeof(d.internal_metadata->'message_ids')='array'
          THEN d.internal_metadata->'message_ids' ELSE '[]'::jsonb END
      ) mid
      JOIN candidate_messages m ON mid IN (m.id::text,m.public_id)
    )
),
candidate_documents(id) AS (
  SELECT id FROM seed_documents
  UNION
  SELECT d.id
  FROM documents d JOIN candidate_documents parent ON (
    EXISTS (
      SELECT 1 FROM jsonb_array_elements_text(
        CASE WHEN jsonb_typeof(d.source_ids)='array'
          THEN d.source_ids ELSE '[]'::jsonb END
      ) sid WHERE sid=parent.id
    )
    OR d.internal_metadata->>'copied_from'=parent.id
    OR d.internal_metadata->>'copy_of'=parent.id
    OR EXISTS (
      SELECT 1 FROM jsonb_array_elements_text(
        CASE WHEN jsonb_typeof(d.internal_metadata->'premise_ids')='array'
          THEN d.internal_metadata->'premise_ids' ELSE '[]'::jsonb END
      ) sid WHERE sid=parent.id
    )
    OR EXISTS (
      SELECT 1 FROM jsonb_array_elements_text(
        CASE WHEN jsonb_typeof(d.internal_metadata->'source_ids')='array'
          THEN d.internal_metadata->'source_ids' ELSE '[]'::jsonb END
      ) sid WHERE sid=parent.id
    )
  )
  WHERE d.workspace_name=:'workspace' AND d.deleted_at IS NULL
),
malformed_lineage AS (
  SELECT d.id
  FROM documents d
  WHERE d.workspace_name=:'workspace' AND d.deleted_at IS NULL AND (
    (d.source_ids IS NOT NULL AND jsonb_typeof(d.source_ids) NOT IN ('array','null'))
    OR (
      d.internal_metadata ? 'message_ids'
      AND jsonb_typeof(d.internal_metadata->'message_ids') NOT IN ('array','null')
    )
    OR (
      d.internal_metadata ? 'premise_ids'
      AND jsonb_typeof(d.internal_metadata->'premise_ids') NOT IN ('array','null')
    )
    OR (
      d.internal_metadata ? 'source_ids'
      AND jsonb_typeof(d.internal_metadata->'source_ids') NOT IN ('array','null')
    )
    OR EXISTS (
      SELECT 1 FROM jsonb_array_elements(
        CASE WHEN jsonb_typeof(d.internal_metadata->'message_ids')='array'
          THEN d.internal_metadata->'message_ids' ELSE '[]'::jsonb END
      ) value
      WHERE jsonb_typeof(value)<>'string' OR btrim(value #>> '{}')=''
    )
    OR EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(d.internal_metadata->'premise_ids')='array' THEN d.internal_metadata->'premise_ids' ELSE '[]'::jsonb END) value WHERE jsonb_typeof(value)<>'string' OR btrim(value #>> '{}')='')
    OR EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(d.internal_metadata->'source_ids')='array' THEN d.internal_metadata->'source_ids' ELSE '[]'::jsonb END) value WHERE jsonb_typeof(value)<>'string' OR btrim(value #>> '{}')='')
    OR (d.internal_metadata ? 'copy_of' AND (jsonb_typeof(d.internal_metadata->'copy_of')<>'string' OR btrim(d.internal_metadata->>'copy_of')=''))
    OR (d.internal_metadata ? 'copied_from' AND (jsonb_typeof(d.internal_metadata->'copied_from')<>'string' OR btrim(d.internal_metadata->>'copied_from')=''))
    OR EXISTS (
      SELECT 1 FROM jsonb_array_elements(
        CASE WHEN jsonb_typeof(d.source_ids)='array'
          THEN d.source_ids ELSE '[]'::jsonb END
      ) value
      WHERE jsonb_typeof(value)<>'string' OR btrim(value #>> '{}')=''
    )
  )
),
candidate_embeddings AS (
  SELECT e.id, e.message_id,
         'sha256:' || encode(sha256(convert_to(to_jsonb(e)::text,'UTF8')),'hex') AS fingerprint
  FROM message_embeddings e
  WHERE e.workspace_name=:'workspace'
    AND e.message_id IN (SELECT public_id FROM candidate_messages)
),
candidate_active_units AS (
  SELECT a.id, a.work_unit_key
  FROM active_queue_sessions a
  WHERE a.work_unit_key IN (SELECT work_unit_key FROM candidate_queue)
),
sequence_sources(table_name,column_name,sequence_name,max_id) AS (
  SELECT 'messages','id',pg_get_serial_sequence('messages','id'),COALESCE((SELECT max(id) FROM messages),0)::bigint
  UNION ALL
  SELECT 'message_embeddings','id',pg_get_serial_sequence('message_embeddings','id'),COALESCE((SELECT max(id) FROM message_embeddings),0)::bigint
  UNION ALL
  SELECT 'queue','id',pg_get_serial_sequence('queue','id'),COALESCE((SELECT max(id) FROM queue),0)::bigint
),
sequence_high_waters AS (
  SELECT table_name, column_name, sequence_name,
         GREATEST(max_id,COALESCE(pg_sequence_last_value(to_regclass(sequence_name)),0))::bigint AS high_water
  FROM sequence_sources
  WHERE sequence_name IS NOT NULL
)
SELECT json_build_object(
  'message_ids', COALESCE((SELECT json_agg(id ORDER BY id) FROM candidate_messages),'[]'::json),
  'message_public_ids', COALESCE((SELECT json_agg(public_id ORDER BY public_id) FROM candidate_messages),'[]'::json),
  'message_identities', COALESCE((SELECT json_agg(json_build_object('id',id,'public_id',public_id,'fingerprint',fingerprint) ORDER BY id) FROM candidate_messages),'[]'::json),
  'embedding_ids', COALESCE((SELECT json_agg(id ORDER BY id) FROM candidate_embeddings),'[]'::json),
  'embedding_identities', COALESCE((SELECT json_agg(json_build_object('id',id,'message_id',message_id,'fingerprint',fingerprint) ORDER BY id) FROM candidate_embeddings),'[]'::json),
  'document_ids', COALESCE((SELECT json_agg(id ORDER BY id) FROM candidate_documents),'[]'::json),
  'queue_ids', COALESCE((SELECT json_agg(id ORDER BY id) FROM candidate_queue),'[]'::json),
  'queue_identities', COALESCE((SELECT json_agg(json_build_object('id',id,'work_unit_key',work_unit_key,'fingerprint',fingerprint) ORDER BY id) FROM candidate_queue),'[]'::json),
  'work_unit_keys', COALESCE((SELECT json_agg(DISTINCT work_unit_key ORDER BY work_unit_key) FROM candidate_queue),'[]'::json),
  'active_queue_session_ids', COALESCE((SELECT json_agg(id ORDER BY id) FROM candidate_active_units),'[]'::json),
  'active_work_unit_keys', COALESCE((SELECT json_agg(work_unit_key ORDER BY work_unit_key) FROM candidate_active_units),'[]'::json),
  'mixed_work_unit_keys', COALESCE((SELECT json_agg(work_unit_key ORDER BY work_unit_key) FROM mixed_work_units),'[]'::json),
  'unknown_touching_queue_ids', COALESCE((SELECT json_agg(id ORDER BY id) FROM unknown_touching_queue),'[]'::json),
  'malformed_lineage_ids', COALESCE((SELECT json_agg(id ORDER BY id) FROM malformed_lineage),'[]'::json),
  'sequence_high_waters', COALESCE((SELECT json_agg(json_build_object('table',table_name,'column',column_name,'sequence',sequence_name,'high_water',high_water) ORDER BY table_name) FROM sequence_high_waters),'[]'::json)
)::text;
