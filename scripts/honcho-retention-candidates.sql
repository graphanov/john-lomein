WITH RECURSIVE
candidate_messages AS (
  SELECT id, public_id
  FROM messages
  WHERE workspace_name=:'workspace' AND created_at < :'cutoff'::timestamptz
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
  SELECT DISTINCT q.id, q.work_unit_key
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
  SELECT e.id
  FROM message_embeddings e
  WHERE e.workspace_name=:'workspace'
    AND e.message_id IN (SELECT public_id FROM candidate_messages)
),
candidate_active_units AS (
  SELECT a.id, a.work_unit_key
  FROM active_queue_sessions a
  WHERE a.work_unit_key IN (SELECT work_unit_key FROM candidate_queue)
)
SELECT json_build_object(
  'message_ids', COALESCE((SELECT json_agg(id ORDER BY id) FROM candidate_messages),'[]'::json),
  'message_public_ids', COALESCE((SELECT json_agg(public_id ORDER BY public_id) FROM candidate_messages),'[]'::json),
  'embedding_ids', COALESCE((SELECT json_agg(id ORDER BY id) FROM candidate_embeddings),'[]'::json),
  'document_ids', COALESCE((SELECT json_agg(id ORDER BY id) FROM candidate_documents),'[]'::json),
  'queue_ids', COALESCE((SELECT json_agg(id ORDER BY id) FROM candidate_queue),'[]'::json),
  'work_unit_keys', COALESCE((SELECT json_agg(DISTINCT work_unit_key ORDER BY work_unit_key) FROM candidate_queue),'[]'::json),
  'active_queue_session_ids', COALESCE((SELECT json_agg(id ORDER BY id) FROM candidate_active_units),'[]'::json),
  'active_work_unit_keys', COALESCE((SELECT json_agg(work_unit_key ORDER BY work_unit_key) FROM candidate_active_units),'[]'::json),
  'mixed_work_unit_keys', COALESCE((SELECT json_agg(work_unit_key ORDER BY work_unit_key) FROM mixed_work_units),'[]'::json),
  'unknown_touching_queue_ids', COALESCE((SELECT json_agg(id ORDER BY id) FROM unknown_touching_queue),'[]'::json),
  'malformed_lineage_ids', COALESCE((SELECT json_agg(id ORDER BY id) FROM malformed_lineage),'[]'::json)
)::text;
