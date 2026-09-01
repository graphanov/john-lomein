\set ON_ERROR_STOP on
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='5min';
SELECT pg_advisory_xact_lock(hashtextextended(:'workspace' || ':' || :'peer', 0));
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_stat_activity
    WHERE datname=current_database() AND pid<>pg_backend_pid()
  ) THEN
    RAISE EXCEPTION 'participant deletion requires exclusive database quiescence';
  END IF;
END $$;
LOCK TABLE peers, sessions, session_peers, messages, message_embeddings,
  documents, collections, queue, active_queue_sessions
  IN SHARE ROW EXCLUSIVE MODE;
CREATE TEMP TABLE jl_peer_ids(id text PRIMARY KEY) ON COMMIT DROP;
INSERT INTO jl_peer_ids SELECT value FROM jsonb_array_elements_text(:'peer_ids'::jsonb);
CREATE TEMP TABLE jl_session_ids(id text PRIMARY KEY) ON COMMIT DROP;
INSERT INTO jl_session_ids SELECT value FROM jsonb_array_elements_text(:'session_ids'::jsonb);
CREATE TEMP TABLE jl_session_names(name text PRIMARY KEY) ON COMMIT DROP;
INSERT INTO jl_session_names SELECT value FROM jsonb_array_elements_text(:'session_names'::jsonb);
CREATE TEMP TABLE jl_message_ids(id bigint PRIMARY KEY) ON COMMIT DROP;
INSERT INTO jl_message_ids SELECT value::bigint FROM jsonb_array_elements_text(:'message_ids'::jsonb);
CREATE TEMP TABLE jl_embedding_ids(id bigint PRIMARY KEY) ON COMMIT DROP;
INSERT INTO jl_embedding_ids SELECT value::bigint FROM jsonb_array_elements_text(:'embedding_ids'::jsonb);
CREATE TEMP TABLE jl_document_ids(id text PRIMARY KEY) ON COMMIT DROP;
INSERT INTO jl_document_ids SELECT value FROM jsonb_array_elements_text(:'document_ids'::jsonb);
CREATE TEMP TABLE jl_collection_ids(id text PRIMARY KEY) ON COMMIT DROP;
INSERT INTO jl_collection_ids SELECT value FROM jsonb_array_elements_text(:'collection_ids'::jsonb);
CREATE TEMP TABLE jl_queue_ids(id bigint PRIMARY KEY) ON COMMIT DROP;
INSERT INTO jl_queue_ids SELECT value::bigint FROM jsonb_array_elements_text(:'queue_ids'::jsonb);
CREATE TEMP TABLE jl_work_units(id text PRIMARY KEY) ON COMMIT DROP;
INSERT INTO jl_work_units SELECT value FROM jsonb_array_elements_text(:'work_unit_keys'::jsonb);
DELETE FROM active_queue_sessions WHERE work_unit_key IN (SELECT id FROM jl_work_units);
DELETE FROM queue WHERE id IN (SELECT id FROM jl_queue_ids);
DELETE FROM message_embeddings WHERE id IN (SELECT id FROM jl_embedding_ids);
DELETE FROM documents WHERE id IN (SELECT id FROM jl_document_ids);
DELETE FROM collections WHERE workspace_name=:'workspace' AND id IN (SELECT id FROM jl_collection_ids);
DELETE FROM messages WHERE id IN (SELECT id FROM jl_message_ids);
DELETE FROM session_peers WHERE workspace_name=:'workspace' AND (session_name IN (SELECT name FROM jl_session_names) OR peer_name=:'peer');
DELETE FROM sessions WHERE workspace_name=:'workspace' AND id IN (SELECT id FROM jl_session_ids);
DELETE FROM peers WHERE workspace_name=:'workspace' AND id IN (SELECT id FROM jl_peer_ids);
DO $$
DECLARE remaining bigint;
BEGIN
 SELECT
  (SELECT count(*) FROM peers WHERE id IN (SELECT id FROM jl_peer_ids)) +
  (SELECT count(*) FROM sessions WHERE id IN (SELECT id FROM jl_session_ids)) +
  (SELECT count(*) FROM messages WHERE id IN (SELECT id FROM jl_message_ids)) +
  (SELECT count(*) FROM message_embeddings WHERE id IN (SELECT id FROM jl_embedding_ids)) +
  (SELECT count(*) FROM documents WHERE id IN (SELECT id FROM jl_document_ids)) +
  (SELECT count(*) FROM collections WHERE id IN (SELECT id FROM jl_collection_ids)) +
  (SELECT count(*) FROM queue WHERE id IN (SELECT id FROM jl_queue_ids)) +
  (SELECT count(*) FROM active_queue_sessions WHERE work_unit_key IN (SELECT id FROM jl_work_units))
 INTO remaining;
 IF remaining <> 0 THEN RAISE EXCEPTION 'participant deletion verification failed: % rows remain', remaining; END IF;
END $$;
COMMIT;
