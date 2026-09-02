from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


REQUIRED = ("initdb", "pg_ctl", "createdb", "psql", "redis-server", "redis-cli")
pytestmark = pytest.mark.skipif(
    any(shutil.which(command) is None for command in REQUIRED),
    reason="disposable PostgreSQL/Redis integration binaries are unavailable",
)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run(command: list[str], **kwargs):
    env = dict(os.environ)
    env.update({"LC_ALL": "C", "LANG": "C"})
    env.update(kwargs.pop("env", {}) or {})
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=True,
        timeout=60,
        env=env,
        **kwargs,
    )


@pytest.fixture()
def disposable_stores(tmp_path):
    pg_data = tmp_path / "postgres"
    pg_port = free_port()
    run(["initdb", "-D", str(pg_data), "--auth=trust", "--no-locale", "--encoding=UTF8"])
    run(
        [
            "pg_ctl",
            "-D",
            str(pg_data),
            "-o",
            f"-h 127.0.0.1 -p {pg_port}",
            "-l",
            str(tmp_path / "postgres.log"),
            "-w",
            "start",
        ]
    )
    admin = f"postgresql://127.0.0.1:{pg_port}/postgres"
    run(["createdb", "--maintenance-db", admin, "public_memory"])
    run(["createdb", "--maintenance-db", admin, "personal_sentinel"])

    redis_processes = []
    redis_urls = []
    for name in ("personal", "public"):
        redis_dir = tmp_path / f"redis-{name}"
        redis_dir.mkdir()
        port = free_port()
        process = subprocess.Popen(
            [
                "redis-server",
                "--bind",
                "127.0.0.1",
                "--port",
                str(port),
                "--protected-mode",
                "yes",
                "--save",
                "",
                "--appendonly",
                "no",
                "--dir",
                str(redis_dir),
            ],
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        url = f"redis://127.0.0.1:{port}/0"
        for _ in range(100):
            ping = subprocess.run(
                ["redis-cli", "-u", url, "PING"],
                text=True,
                capture_output=True,
                check=False,
            )
            if ping.returncode == 0 and ping.stdout.strip() == "PONG":
                break
            time.sleep(0.05)
        else:
            process.terminate()
            raise RuntimeError(f"disposable {name} Redis did not start")
        redis_processes.append(process)
        redis_urls.append(url)

    try:
        yield {
            "public_db": f"postgresql://127.0.0.1:{pg_port}/public_memory",
            "personal_db": f"postgresql://127.0.0.1:{pg_port}/personal_sentinel",
            "personal_redis": redis_urls[0],
            "public_redis": redis_urls[1],
        }
    finally:
        for process in redis_processes:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        subprocess.run(
            ["pg_ctl", "-D", str(pg_data), "-m", "fast", "-w", "stop"],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )


SCHEMA = r"""
CREATE TABLE workspaces(name text PRIMARY KEY);
CREATE TABLE peers(id text PRIMARY KEY,name text,workspace_name text,internal_metadata jsonb DEFAULT '{}'::jsonb);
CREATE TABLE sessions(id text PRIMARY KEY,name text,workspace_name text);
CREATE TABLE session_peers(workspace_name text,session_name text,peer_name text);
CREATE TABLE messages(id bigint PRIMARY KEY,public_id text,session_name text,peer_name text,workspace_name text,created_at timestamptz);
CREATE TABLE message_embeddings(id bigint PRIMARY KEY,message_id text,workspace_name text);
CREATE TABLE collections(id text PRIMARY KEY,observer text,observed text,workspace_name text);
CREATE TABLE documents(id text PRIMARY KEY,workspace_name text,session_name text,observer text,observed text,source_ids jsonb,internal_metadata jsonb,deleted_at timestamptz,sync_state text);
CREATE TABLE queue(id bigint PRIMARY KEY,session_id text,work_unit_key text,task_type text,payload jsonb,processed boolean DEFAULT false,error text,created_at timestamptz DEFAULT now(),workspace_name text,message_id bigint);
CREATE TABLE active_queue_sessions(id text PRIMARY KEY,work_unit_key text UNIQUE,last_updated timestamptz DEFAULT now());
"""


def psql(database: str, sql: str, variables: dict[str, object] | None = None) -> str:
    command = ["psql", "-X", "--dbname", database, "-At", "-v", "ON_ERROR_STOP=1"]
    for key, value in sorted((variables or {}).items()):
        command.extend(["-v", f"{key}={value}"])
    result = subprocess.run(
        command,
        input=sql,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    return result.stdout.strip()


def test_retention_removes_all_public_dependents_and_leaves_personal_sentinels_untouched(
    disposable_stores,
):
    from john_lomein_honcho_pilot import (
        flush_dedicated_honcho_cache,
        retention_apply_sql,
        retention_candidate_sets,
    )

    public_db = disposable_stores["public_db"]
    personal_db = disposable_stores["personal_db"]
    psql(public_db, SCHEMA)
    psql(personal_db, "CREATE TABLE sentinel(value text); INSERT INTO sentinel VALUES ('PERSONAL_DB_UNTOUCHED');")
    psql(
        public_db,
        r"""
INSERT INTO workspaces VALUES ('public-workspace');
INSERT INTO messages VALUES
 (1,'old-public','old-session','participant','public-workspace',now()-interval '31 days'),
 (2,'new-public','new-session','participant','public-workspace',now()-interval '1 day');
INSERT INTO message_embeddings VALUES (20,'old-public','public-workspace'),(21,'new-public','public-workspace');
INSERT INTO documents VALUES
 ('doc-old','public-workspace','old-session','guide','participant','[]','{"message_ids":["1"]}',NULL,'synced'),
 ('doc-child','public-workspace','old-session','guide','participant','["doc-old"]','{}',NULL,'synced'),
 ('doc-new','public-workspace','new-session','guide','participant','[]','{"message_ids":["2"]}',NULL,'synced');
INSERT INTO queue VALUES
 (30,NULL,'work-old','representation','{}',false,NULL,now(),'public-workspace',1),
 (31,NULL,'work-old','representation','{"sibling":"old work unit"}',false,NULL,now(),'public-workspace',NULL),
 (32,NULL,'payload-only','representation','{"legacy":{"message":"old-public"}}',false,NULL,now(),'public-workspace',NULL),
 (33,NULL,'work-new','representation','{}',false,NULL,now(),'public-workspace',2);
INSERT INTO active_queue_sessions VALUES
 ('active-old','work-old',now()),('active-payload','payload-only',now()),('active-new','work-new',now());
""",
    )
    run(["redis-cli", "-u", disposable_stores["personal_redis"], "SET", "sentinel", "PERSONAL_REDIS_UNTOUCHED"])
    run(["redis-cli", "-u", disposable_stores["public_redis"], "SET", "public-cache", "delete-me"])

    cutoff = psql(public_db, "SELECT (now()-interval '30 days')::text;")
    candidates = retention_candidate_sets(public_db, "public-workspace", cutoff)
    assert candidates["message_ids"] == [1]
    assert candidates["queue_ids"] == [30, 31, 32]
    assert candidates["active_queue_session_ids"] == ["active-old", "active-payload"]
    assert candidates["document_ids"] == ["doc-child", "doc-old"]
    assert candidates["unknown_touching_queue_ids"] == []

    variables = {
        "workspace": "public-workspace",
        "cutoff": cutoff,
        "expected_message_count": 1,
        "expected_embedding_count": 1,
        "expected_document_count": 2,
        "expected_queue_count": 3,
        "expected_active_count": 2,
    }
    for key in (
        "message_ids",
        "message_public_ids",
        "message_identities",
        "embedding_ids",
        "embedding_identities",
        "document_ids",
        "queue_ids",
        "queue_identities",
        "sequence_high_waters",
        "work_unit_keys",
        "active_queue_session_ids",
        "active_work_unit_keys",
    ):
        variables[key] = json.dumps(candidates[key], separators=(",", ":"))
    psql(public_db, retention_apply_sql(), variables)
    flush_dedicated_honcho_cache(disposable_stores["public_redis"])

    public_counts = json.loads(
        psql(
            public_db,
            "SELECT json_build_object('messages',(SELECT json_agg(id ORDER BY id) FROM messages),'embeddings',(SELECT json_agg(id ORDER BY id) FROM message_embeddings),'documents',(SELECT json_agg(id ORDER BY id) FROM documents),'queue',(SELECT json_agg(id ORDER BY id) FROM queue),'active',(SELECT json_agg(id ORDER BY id) FROM active_queue_sessions))::text;",
        )
    )
    assert public_counts == {
        "messages": [2],
        "embeddings": [21],
        "documents": ["doc-new"],
        "queue": [33],
        "active": ["active-new"],
    }
    assert psql(personal_db, "SELECT value FROM sentinel;") == "PERSONAL_DB_UNTOUCHED"
    assert run(
        ["redis-cli", "-u", disposable_stores["personal_redis"], "GET", "sentinel"]
    ).stdout.strip() == "PERSONAL_REDIS_UNTOUCHED"


def test_participant_restore_replay_deletes_only_recorded_ids_and_preserves_new_rows(
    disposable_stores,
):
    from john_lomein_honcho_pilot import (
        participant_deletion_apply_sql,
        participant_deletion_candidate_sets,
    )

    public_db = disposable_stores["public_db"]
    psql(public_db, SCHEMA)
    psql(
        public_db,
        r"""
INSERT INTO workspaces VALUES ('public-workspace');
INSERT INTO peers VALUES
 ('peer-target','participant','public-workspace','{}'),
 ('peer-guide','guide','public-workspace','{}');
INSERT INTO sessions VALUES ('session-old','old-session','public-workspace');
INSERT INTO session_peers VALUES
 ('public-workspace','old-session','participant'),
 ('public-workspace','old-session','guide');
INSERT INTO messages VALUES
 (100,'message-old','old-session','participant','public-workspace','2026-08-01T00:00:00Z');
INSERT INTO message_embeddings VALUES (120,'message-old','public-workspace');
INSERT INTO collections VALUES ('collection-old','guide','participant','public-workspace');
INSERT INTO documents VALUES
 ('document-old','public-workspace','old-session','guide','participant','[]','{"message_ids":["100"]}',NULL,'synced');
INSERT INTO queue VALUES
 (130,'session-old','delete-work','representation','{}',false,NULL,'2026-08-01T00:00:00Z','public-workspace',100),
 (131,NULL,'delete-work','representation','{"sibling":true}',false,NULL,'2026-08-01T00:00:00Z','public-workspace',NULL);
INSERT INTO active_queue_sessions VALUES ('active-old','delete-work',now());
""",
    )
    exact = participant_deletion_candidate_sets(
        public_db,
        "public-workspace",
        "participant",
        ["guide"],
    )
    assert exact["message_ids"] == [100]
    assert exact["queue_ids"] == [130, 131]
    assert exact["active_queue_session_ids"] == ["active-old"]

    def apply_exact(expected: dict[str, list[object]] | None = None) -> None:
        variables = {
            "workspace": "public-workspace",
            "peer": "participant",
        }
        for key in (
            "peer_ids",
            "session_ids",
            "session_names",
            "session_peer_link_keys",
            "message_ids",
            "message_public_ids",
            "message_identities",
            "embedding_ids",
            "embedding_identities",
            "document_ids",
            "collection_ids",
            "queue_ids",
            "queue_identities",
            "sequence_high_waters",
            "work_unit_keys",
            "active_queue_session_ids",
            "active_work_unit_keys",
        ):
            variables[key] = json.dumps(exact[key], separators=(",", ":"))
        expected_sets = expected or exact
        for name, key in {
            "peer": "peer_ids",
            "session": "session_ids",
            "session_link": "session_peer_link_keys",
            "message": "message_ids",
            "embedding": "embedding_ids",
            "document": "document_ids",
            "collection": "collection_ids",
            "queue": "queue_ids",
            "active": "active_queue_session_ids",
        }.items():
            variables[f"expected_{name}_count"] = len(expected_sets.get(key) or [])
        psql(public_db, participant_deletion_apply_sql(), variables)

    apply_exact()
    assert psql(public_db, "SELECT count(*) FROM messages;") == "0"

    # Simulate an old-backup restore followed by a new enrollment before replay.
    # The new rows use new IDs but the same participant name and even reuse the
    # old work-unit key, so a name/work-unit recomputation would over-delete.
    psql(
        public_db,
        r"""
INSERT INTO peers VALUES ('peer-target','participant','public-workspace','{}');
INSERT INTO sessions VALUES
 ('session-old','old-session','public-workspace'),
 ('session-new','new-session','public-workspace');
INSERT INTO session_peers VALUES
 ('public-workspace','old-session','participant'),
 ('public-workspace','old-session','guide'),
 ('public-workspace','new-session','participant');
INSERT INTO messages VALUES
 (100,'message-old','old-session','participant','public-workspace','2026-08-01T00:00:00Z'),
 (200,'message-new','new-session','participant','public-workspace',now());
INSERT INTO message_embeddings VALUES
 (120,'message-old','public-workspace'),(220,'message-new','public-workspace');
INSERT INTO collections VALUES ('collection-old','guide','participant','public-workspace');
INSERT INTO documents VALUES
 ('document-old','public-workspace','old-session','guide','participant','[]','{"message_ids":["100"]}',NULL,'synced');
INSERT INTO queue VALUES
 (130,'session-old','delete-work','representation','{}',false,NULL,'2026-08-01T00:00:00Z','public-workspace',100),
 (131,NULL,'delete-work','representation','{"sibling":true}',false,NULL,'2026-08-01T00:00:00Z','public-workspace',NULL),
 (132,'session-new','delete-work','representation','{"post_request":true}',false,NULL,now(),'public-workspace',200);
INSERT INTO active_queue_sessions VALUES
 ('active-old','delete-work',now()),('active-new','new-work',now());
""",
    )
    from john_lomein_honcho_pilot import exact_tombstone_residue

    restored_residue = exact_tombstone_residue(
        public_db, "public-workspace", exact
    )
    apply_exact(restored_residue)
    survivors = json.loads(
        psql(
            public_db,
            "SELECT json_build_object('messages',(SELECT json_agg(id ORDER BY id) FROM messages),'embeddings',(SELECT json_agg(id ORDER BY id) FROM message_embeddings),'queue',(SELECT json_agg(id ORDER BY id) FROM queue),'active',(SELECT json_agg(id ORDER BY id) FROM active_queue_sessions))::text;",
        )
    )
    assert survivors == {
        "messages": [200],
        "embeddings": [220],
        "queue": [132],
        "active": ["active-new"],
    }
    assert psql(
        public_db,
        "SELECT count(*) FROM session_peers WHERE session_name='new-session' AND peer_name='participant';",
    ) == "1"
