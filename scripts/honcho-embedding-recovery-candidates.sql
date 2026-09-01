WITH per_message AS (
  SELECT m.public_id, m.token_count, count(e.id)::int AS embedding_rows,
         bool_or(e.sync_state='failed') AS has_failed
  FROM messages m
  LEFT JOIN message_embeddings e
    ON e.workspace_name=m.workspace_name AND e.message_id=m.public_id
  WHERE m.workspace_name=:'workspace'
  GROUP BY m.public_id,m.token_count
)
SELECT json_build_object(
  'missing', COALESCE(json_agg(public_id ORDER BY public_id) FILTER (WHERE embedding_rows=0), '[]'::json),
  'failed', COALESCE(json_agg(public_id ORDER BY public_id) FILTER (WHERE has_failed), '[]'::json),
  'legacy_long_single', COALESCE(json_agg(public_id ORDER BY public_id) FILTER (WHERE token_count>:'cap'::int AND embedding_rows=1), '[]'::json)
)::text
FROM per_message;
