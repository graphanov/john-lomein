from __future__ import annotations

import json
import plistlib
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def dedicated_manifest(runtime: Path) -> dict:
    return {
        "instance": {"slug": "public-pilot"},
        "runtime": {"hermes_home": str(runtime)},
        "memory": {
            "provider": "honcho",
            "honcho": {
                "workspace": "public-pilot-memory",
            },
        },
    }


def test_contract_derives_a_dedicated_nonpersonal_service_boundary(tmp_path):
    from john_lomein_honcho_contract import honcho_settings

    first = honcho_settings(dedicated_manifest(tmp_path), instance_slug="public-pilot")
    second = honcho_settings(dedicated_manifest(tmp_path), instance_slug="public-pilot")

    assert first == second
    assert first["service_mode"] == "dedicated_public"
    assert first["database"].startswith("john_lomein_public_pilot_public_")
    assert first["database"] != "honcho_local"
    assert first["base_url"] != "http://127.0.0.1:8000"
    assert first["redis_url"] != "redis://127.0.0.1:6379/0"
    assert first["redis_url"].endswith("/0")
    assert first["server_root"] == str(
        (tmp_path / "services" / "public-honcho" / "server").resolve()
    )
    assert first["checkout_commit"] == "9379c634ed240d0225b63443606e5304a4e261c5"
    assert first["retention_interval_seconds"] == 300
    assert first["backup_max_age_days"] == 30
    assert first["supervisor_label"] == "ai.john-lomein.public-pilot.public-honcho"


@pytest.mark.parametrize(
    "override, message",
    [
        ({"database": "honcho_local"}, "dedicated PostgreSQL"),
        ({"base_url": "http://127.0.0.1:8000"}, "dedicated API port"),
        ({"redis_url": "redis://127.0.0.1:6379/0"}, "dedicated Redis"),
        (
            {"server_root": "PERSONAL_CHECKOUT"},
            "personal Honcho checkout",
        ),
        ({"checkout_commit": "main"}, "40-character commit"),
        ({"retention_interval_seconds": 301}, "exactly 300"),
        ({"backup_max_age_days": 31}, "at most 30"),
    ],
)
def test_contract_rejects_shared_or_unpinned_public_memory_targets(
    tmp_path, override, message
):
    from john_lomein_honcho_contract import honcho_settings

    manifest = dedicated_manifest(tmp_path)
    if override.get("server_root") == "PERSONAL_CHECKOUT":
        override = {
            **override,
            "server_root": str(Path.home() / ".hermes" / "honcho-local" / "server"),
        }
    manifest["memory"]["honcho"].update(override)
    with pytest.raises(ValueError, match=message):
        honcho_settings(manifest, instance_slug="public-pilot")


def test_launchagent_can_only_execute_the_product_supervisor(tmp_path):
    from john_lomein_public_honcho_service import build_supervisor_plist

    runtime = tmp_path / "runtime"
    manifest = tmp_path / "instance.yaml"
    script = runtime / "scripts" / "john_lomein_public_honcho_service.py"
    payload = build_supervisor_plist(
        manifest_path=manifest,
        runtime_home=runtime,
        instance_slug="public-pilot",
        python="/usr/bin/python3",
        supervisor_script=script,
    )
    encoded = plistlib.dumps(payload)
    decoded = plistlib.loads(encoded)

    assert decoded["Label"] == "ai.john-lomein.public-pilot.public-honcho"
    assert decoded["ProgramArguments"] == [
        "/usr/bin/python3",
        str(script),
        "supervise",
        "--manifest",
        str(manifest),
    ]
    assert decoded["KeepAlive"] is True
    serialized = json.dumps(decoded, sort_keys=True)
    assert "ai.hermes.honcho" not in serialized
    assert "fastapi" not in serialized
    assert "src.deriver" not in serialized


def test_runtime_configuration_is_dedicated_local_and_redis_is_nonpersistent(tmp_path):
    import john_lomein_public_honcho_service as service

    server = tmp_path / "runtime" / "services" / "public-honcho" / "server"
    server.mkdir(parents=True)
    redis_config = service._write_runtime_configuration(
        {
            "server_root": str(server),
            "database": "john_lomein_public_test",
            "redis_url": "redis://127.0.0.1:19042/0",
            "expected_memory_model": "honcho-memory:test",
        }
    )
    env = (server / ".env").read_text(encoding="utf-8")
    redis = redis_config.read_text(encoding="utf-8")
    assert "DB_CONNECTION_URI=postgresql+psycopg:///john_lomein_public_test" in env
    assert "CACHE_URL=redis://127.0.0.1:19042/0?suppress=true" in env
    assert "DERIVER_MODEL_CONFIG__MODEL=honcho-memory:test" in env
    assert "DIALECTIC_LEVELS__LOW__MODEL_CONFIG__MODEL=honcho-memory:test" in env
    assert 'save ""' in redis
    assert "appendonly no" in redis
    assert "databases 1" in redis
    assert stat.S_IMODE((server / ".env").stat().st_mode) == 0o600
    assert stat.S_IMODE(redis_config.stat().st_mode) == 0o600


def test_checkout_must_be_clean_exactly_pinned_and_on_the_approved_remote(tmp_path):
    from john_lomein_public_honcho_service import validate_pinned_checkout

    root = tmp_path / "server"
    root.mkdir()

    def runner(command, **_kwargs):
        if command[-2:] == ["rev-parse", "HEAD"]:
            return SimpleNamespace(stdout="a" * 40 + "\n")
        if command[-3:] == ["remote", "get-url", "origin"]:
            return SimpleNamespace(stdout="https://github.com/plastic-labs/honcho.git\n")
        if "status" in command:
            return SimpleNamespace(stdout="")
        raise AssertionError(command)

    receipt = validate_pinned_checkout(
        root,
        expected_url="https://github.com/plastic-labs/honcho.git",
        expected_commit="a" * 40,
        runner=runner,
    )
    assert receipt["clean"] is True
    assert receipt["head"] == "a" * 40

    def dirty_runner(command, **kwargs):
        result = runner(command, **kwargs)
        if "status" in command:
            result.stdout = "?? local.py\n"
        return result

    with pytest.raises(ValueError, match="dirty"):
        validate_pinned_checkout(
            root,
            expected_url="https://github.com/plastic-labs/honcho.git",
            expected_commit="a" * 40,
            runner=dirty_runner,
        )
    with pytest.raises(ValueError, match="pinned commit"):
        validate_pinned_checkout(
            root,
            expected_url="https://github.com/plastic-labs/honcho.git",
            expected_commit="b" * 40,
            runner=runner,
        )


def test_database_isolation_rejects_any_other_workspace(monkeypatch):
    import john_lomein_public_honcho_service as service

    monkeypatch.setattr(
        service,
        "psql_json",
        lambda *_args, **_kwargs: {
            "database": "john_lomein_public",
            "database_oid": 44,
            "system_identifier": "777",
            "workspace_names": ["public-pilot-memory"],
        },
    )
    isolated = service.assert_dedicated_database(
        "john_lomein_public", "public-pilot-memory"
    )
    assert isolated["workspace_names"] == ["public-pilot-memory"]

    monkeypatch.setattr(
        service,
        "psql_json",
        lambda *_args, **_kwargs: {
            "database": "john_lomein_public",
            "database_oid": 44,
            "system_identifier": "777",
            "workspace_names": ["personal", "public-pilot-memory"],
        },
    )
    with pytest.raises(ValueError, match="shared or multi-workspace"):
        service.assert_dedicated_database(
            "john_lomein_public", "public-pilot-memory"
        )


def test_retention_receipt_is_required_fresh_and_exactly_five_minute_policy(tmp_path):
    from john_lomein_public_honcho_service import (
        build_retention_receipt,
        validate_retention_receipt,
    )

    now = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
    receipt = build_retention_receipt(
        database_identity_digest="a" * 64,
        workspace="public-pilot-memory",
        cutoff="2026-08-02T11:59:59Z",
        completed_at="2026-09-01T11:59:59Z",
        deleted_counts={"messages": 0, "queue": 0},
    )
    assert validate_retention_receipt(
        receipt,
        expected_database_identity_digest="a" * 64,
        expected_workspace="public-pilot-memory",
        now=now,
    )
    assert not validate_retention_receipt(
        receipt,
        expected_database_identity_digest="a" * 64,
        expected_workspace="public-pilot-memory",
        now=now + timedelta(minutes=5, seconds=1),
    )
    assert receipt["retention_days"] == 30
    assert receipt["maximum_active_store_lag_seconds"] == 300


def _exact_tombstone(state: str) -> dict:
    from john_lomein_honcho_pilot import sha256_json

    exact_ids = {
        "peer_ids": ["peer-id"],
        "session_ids": ["session-id"],
        "session_names": ["session"],
        "session_peer_link_keys": ["session|participant"],
        "message_ids": [1],
        "message_public_ids": ["message-public"],
        "embedding_ids": [2],
        "document_ids": ["document-id"],
        "collection_ids": ["collection-id"],
        "queue_ids": [3],
        "work_unit_keys": ["work-unit"],
        "active_queue_session_ids": ["active-id"],
        "active_work_unit_keys": ["work-unit"],
        "conflicting_peers": [],
        "unknown_touching_queue_ids": [],
        "malformed_lineage_ids": [],
    }
    body = {
        "schema_version": "john-lomein.honcho-deletion-tombstone.v2",
        "operation": "participant_deletion",
        "state": state,
        "plan_digest": "a" * 64,
        "workspace": "public-pilot-memory",
        "request_cutoff": "2026-09-01T00:00:00Z",
        "database_identity": {
            "database": "john_lomein_public",
            "database_oid": 44,
            "system_identifier": "777",
            "schema_fingerprint": "sha256:" + "c" * 64,
        },
        "schema_fingerprint": "sha256:" + "c" * 64,
        "server_identity": {
            "remote": "https://github.com/plastic-labs/honcho.git",
            "head": "f" * 40,
            "clean": True,
        },
        "manifest_digest": "sha256:" + "9" * 64,
        "exact_candidate_ids": exact_ids,
        "candidate_sets_digest": sha256_json(exact_ids),
        "id_set_digests": {
            key: sha256_json(value) for key, value in exact_ids.items()
        },
        "participant_peer": "participant",
        "allowed_service_peers": ["guide"],
        "backup": {
            "sha256": "sha256:" + "b" * 64,
            "verified": True,
            "created_at": "2026-09-01T00:00:00Z",
            "expires_at": "2026-10-01T00:00:00Z",
        },
        "created_at": "2026-09-01T00:00:00Z",
    }
    body["tombstone_digest"] = sha256_json(body)
    return body


def _write_tombstone(root: Path, name: str, payload: dict) -> None:
    target = root / name
    target.write_text(json.dumps(payload), encoding="utf-8")
    target.chmod(0o600)


def test_pending_blocks_applied_clean_passes_and_resurrected_exact_ids_block(
    tmp_path, monkeypatch
):
    import john_lomein_honcho_pilot as pilot

    root = tmp_path / "tombstones"
    root.mkdir(mode=0o700)
    _write_tombstone(root, "one.json", _exact_tombstone("pending"))
    monkeypatch.setattr(pilot, "exact_tombstone_residue", lambda *_a, **_k: {})
    blockers = pilot.honcho_startup_blockers(
        root,
        database="john_lomein_public",
        workspace="public-pilot-memory",
    )
    assert [item["reason"] for item in blockers] == ["pending_tombstone"]

    (root / "one.json").unlink()
    _write_tombstone(root, "two.json", _exact_tombstone("applied"))
    assert pilot.honcho_startup_blockers(
        root,
        database="john_lomein_public",
        workspace="public-pilot-memory",
    ) == []

    monkeypatch.setattr(
        pilot,
        "exact_tombstone_residue",
        lambda *_a, **_k: {"message_ids": [1]},
    )
    blockers = pilot.honcho_startup_blockers(
        root,
        database="john_lomein_public",
        workspace="public-pilot-memory",
    )
    assert blockers[0]["reason"] == "deletion_replay_required"


def test_malformed_tombstone_fails_closed(tmp_path):
    from john_lomein_honcho_pilot import honcho_startup_blockers

    root = tmp_path / "tombstones"
    root.mkdir(mode=0o700)
    target = root / "bad.json"
    target.write_text('{"state":"applied"}\n', encoding="utf-8")
    target.chmod(0o600)
    with pytest.raises(ValueError, match="tombstone"):
        honcho_startup_blockers(
            root,
            database="john_lomein_public",
            workspace="public-pilot-memory",
        )


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: payload.update(candidate_sets_digest="0" * 64),
        lambda payload: payload["server_identity"].update(clean=False),
        lambda payload: payload["backup"].update(expires_at="2026-10-02T00:00:00Z"),
        lambda payload: payload.update(manifest_digest="not-a-digest"),
    ),
)
def test_tombstone_evidence_mismatch_is_malformed_and_blocks(tmp_path, mutate):
    from john_lomein_honcho_pilot import honcho_startup_blockers, sha256_json

    root = tmp_path / "tombstones"
    root.mkdir(mode=0o700)
    payload = _exact_tombstone("applied")
    mutate(payload)
    payload.pop("tombstone_digest", None)
    payload["tombstone_digest"] = sha256_json(payload)
    _write_tombstone(root, "malformed.json", payload)
    with pytest.raises(ValueError, match="tombstone"):
        honcho_startup_blockers(
            root,
            database="john_lomein_public",
            workspace="public-pilot-memory",
        )


def test_dedicated_redis_flush_is_database_wide_but_never_scans_or_touches_personal(
    monkeypatch,
):
    import john_lomein_honcho_pilot as pilot

    commands = []

    def run(command, **_kwargs):
        commands.append(command)
        if command[-1] == "DBSIZE":
            return SimpleNamespace(stdout="0\n")
        return SimpleNamespace(stdout="OK\n")

    monkeypatch.setattr(pilot, "run_checked", run)
    result = pilot.flush_dedicated_honcho_cache("redis://127.0.0.1:17321/0")
    assert result["remaining"] == 0
    assert any(command[-2:] == ["FLUSHDB", "SYNC"] for command in commands)
    assert all("--scan" not in command for command in commands)
    assert all("6379" not in " ".join(command) for command in commands)


def test_retention_and_deletion_sql_bind_active_ids_and_every_scoped_table():
    from john_lomein_honcho_pilot import (
        participant_deletion_apply_sql,
        retention_apply_sql,
    )

    for sql in (retention_apply_sql(), participant_deletion_apply_sql()):
        assert "jl_active_queue_session_ids" in sql
        assert "DELETE FROM active_queue_sessions" in sql
        for table in (
            "queue",
            "message_embeddings",
            "documents",
            "messages",
        ):
            statement = next(
                line for line in sql.splitlines() if line.startswith(f"DELETE FROM {table}")
            )
            tail = sql[sql.index(statement) : sql.index(statement) + 220]
            assert "workspace_name=:'workspace'" in tail

    candidate_sql = (SCRIPTS / "honcho-retention-candidates.sql").read_text(
        encoding="utf-8"
    )
    assert "jsonb_path_exists" in candidate_sql
    assert "active_queue_session_ids" in candidate_sql


def test_deploy_and_doctor_reference_only_the_public_supervisor_boundary():
    deploy = (SCRIPTS / "deploy-instance.sh").read_text(encoding="utf-8")
    doctor = (SCRIPTS / "doctor-instance.py").read_text(encoding="utf-8")

    assert "public-service-install" in deploy
    assert "every 24h" not in deploy
    assert "install-startup-gates" not in deploy
    assert "ai.hermes.honcho.api" not in deploy
    assert "ai.hermes.honcho.deriver" not in deploy
    assert "Public Honcho supervisor" in doctor
    assert "Honcho API/deriver startup gate" not in doctor


def test_public_service_assets_never_name_or_control_personal_launchagents():
    forbidden = ("ai.hermes.honcho.api", "ai.hermes.honcho.deriver")
    service_assets = [
        SCRIPTS / "john_lomein_public_honcho_service.py",
        SCRIPTS / "john_lomein_honcho_pilot.py",
        SCRIPTS / "john-lomein-honcho-retention.sh",
    ]
    for asset in service_assets:
        text = asset.read_text(encoding="utf-8")
        for label in forbidden:
            assert label not in text


def test_tombstone_files_are_private(tmp_path):
    root = tmp_path / "tombstones"
    root.mkdir(mode=0o700)
    _write_tombstone(root, "one.json", _exact_tombstone("pending"))
    assert stat.S_IMODE((root / "one.json").stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "crash_stage",
    ("during_sql", "after_commit", "cache_flush", "before_applied_fsync"),
)
def test_crash_injection_never_advances_pending_before_database_and_cache_verify(
    tmp_path, monkeypatch, crash_stage
):
    import john_lomein_honcho_pilot as pilot

    candidates = {key: [] for key in pilot.DELETION_CANDIDATE_KEYS}
    candidates.update(
        {
            "peer_ids": ["peer-id"],
            "session_ids": ["session-id"],
            "session_names": ["session"],
            "session_peer_link_keys": ["session|participant"],
            "message_ids": [1],
            "message_public_ids": ["message-public"],
            "embedding_ids": [2],
            "document_ids": ["document-id"],
            "collection_ids": ["collection-id"],
            "queue_ids": [3],
            "work_unit_keys": ["work-unit"],
            "active_queue_session_ids": ["active-id"],
            "active_work_unit_keys": ["work-unit"],
        }
    )
    plan = pilot.make_participant_deletion_plan(
        database_oid=44,
        workspace="public-workspace",
        peer="participant",
        candidate_sets=candidates,
        allowed_service_peers=["guide"],
        schema_fingerprint="sha256:" + "c" * 64,
        generated_at="2026-09-01T00:00:00Z",
    )
    receipt = pilot.build_honcho_quiescence_receipt(
        database_oid_value=44,
        schema_fingerprint_value="sha256:" + "c" * 64,
        service_labels=[
            "ai.john-lomein.pilot.public-honcho.child.api",
            "ai.john-lomein.pilot.public-honcho.child.deriver",
        ],
        observed_at=(datetime.now(timezone.utc) - timedelta(seconds=1))
        .isoformat()
        .replace("+00:00", "Z"),
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=4))
        .isoformat()
        .replace("+00:00", "Z"),
        nonce="d" * 64,
        vector_store_config_digest="e" * 64,
    )
    tombstone_path = tmp_path / "private" / "tombstone.json"
    tombstone_path.parent.mkdir(mode=0o700)
    monkeypatch.setattr(pilot, "database_oid", lambda _database: 44)
    monkeypatch.setattr(pilot, "schema_fingerprint", lambda _database: "c" * 64)
    monkeypatch.setattr(pilot, "assert_honcho_quiescent", lambda *_a, **_k: None)
    monkeypatch.setattr(
        pilot,
        "verify_honcho_runtime_targets",
        lambda *_a, **_k: {"head": "f" * 40, "clean": True},
    )
    monkeypatch.setattr(
        pilot,
        "inspect_honcho_vector_store",
        lambda *_a, **_k: {"type": "pgvector", "migrated": False, "config_digest": "e" * 64},
    )
    monkeypatch.setattr(
        pilot, "participant_deletion_candidate_sets", lambda *_a, **_k: candidates
    )
    monkeypatch.setattr(
        pilot,
        "verified_backup_metadata",
        lambda *_a, **_k: {
            "path": "/private/public.dump",
            "sha256": "sha256:" + "b" * 64,
            "size_bytes": 1,
            "database": "public_database",
            "created_at": "2026-09-01T00:00:00Z",
            "manifest_digest": "a" * 64,
            "verified": True,
        },
    )
    monkeypatch.setattr(
        pilot,
        "honcho_database_identity",
        lambda *_a, **_k: {
            "database": "public_database",
            "database_oid": 44,
            "schema_fingerprint": "sha256:" + "c" * 64,
            "identity_digest": "f" * 64,
        },
    )
    if crash_stage == "during_sql":
        monkeypatch.setattr(
            pilot, "run_checked", mock.Mock(side_effect=RuntimeError("sql crash"))
        )
    else:
        monkeypatch.setattr(pilot, "run_checked", mock.Mock())
    if crash_stage == "after_commit":
        monkeypatch.setattr(
            pilot,
            "exact_tombstone_residue",
            mock.Mock(side_effect=RuntimeError("post-commit crash")),
        )
    else:
        monkeypatch.setattr(pilot, "exact_tombstone_residue", mock.Mock(return_value={}))
    if crash_stage == "cache_flush":
        monkeypatch.setattr(
            pilot,
            "flush_dedicated_honcho_cache",
            mock.Mock(side_effect=RuntimeError("cache crash")),
        )
    else:
        monkeypatch.setattr(
            pilot,
            "flush_dedicated_honcho_cache",
            mock.Mock(return_value={"remaining": 0}),
        )
    if crash_stage == "before_applied_fsync":
        monkeypatch.setattr(
            pilot,
            "write_private_json",
            mock.Mock(side_effect=RuntimeError("applied fsync crash")),
        )

    with pytest.raises(RuntimeError):
        pilot.apply_participant_deletion(
            database="public_database",
            plan=plan,
            confirm_digest=plan["plan_digest"],
            backup_path=tmp_path / "public.dump",
            quiescence_receipt=receipt,
            base_url="http://127.0.0.1:18001",
            redis_url="redis://127.0.0.1:19001/0",
            server_root=tmp_path / "server",
            tombstone_path=tombstone_path,
            manifest_digest="sha256:" + "9" * 64,
        )
    persisted = json.loads(tombstone_path.read_text(encoding="utf-8"))
    assert persisted["state"] == "pending"
    assert persisted["exact_candidate_ids"]["message_ids"] == [1]


def test_success_marks_applied_only_after_cache_and_exact_postcondition(tmp_path, monkeypatch):
    import john_lomein_honcho_pilot as pilot

    pending = _exact_tombstone("pending")
    path = tmp_path / "applied.json"
    tmp_path.chmod(0o700)
    pilot.reserve_private_json(path, pending)
    cache = {"scope": "dedicated_redis_database", "remaining": 0}
    applied = pilot._mark_exact_tombstone_applied(
        pending, tombstone_path=path, cache=cache
    )
    assert applied["state"] == "applied"
    assert json.loads(path.read_text(encoding="utf-8"))["cache"] == cache
