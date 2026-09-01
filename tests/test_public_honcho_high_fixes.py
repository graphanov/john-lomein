from __future__ import annotations

import inspect
import json
import os
import subprocess
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


class FakeProcess:
    def __init__(self, pid: int = 4242) -> None:
        self.pid = pid
        self.terminated = False

    def poll(self):
        return None

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout=None):
        return 0

    def kill(self) -> None:
        self.terminated = True


def test_redis_collision_is_refused_before_spawn_ping_or_flush(tmp_path):
    import john_lomein_public_honcho_service as service

    popen = mock.Mock()
    runner = mock.Mock()
    with pytest.raises(RuntimeError, match="pre-existing Redis listener"):
        service._start_verified_dedicated_redis(
            tmp_path / "redis.conf",
            "redis://127.0.0.1:19042/0",
            cwd=tmp_path,
            listener_probe=lambda _url: True,
            popen_factory=popen,
            runner=runner,
            sleeper=lambda _seconds: None,
        )

    popen.assert_not_called()
    runner.assert_not_called()


def test_redis_spawned_pid_is_verified_before_ping_and_wrong_owner_never_pings(
    tmp_path,
):
    import john_lomein_public_honcho_service as service

    process = FakeProcess()
    commands = []

    def runner(command, **_kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "process_id:9999\n", "")

    with pytest.raises(RuntimeError, match="listener ownership"):
        service._start_verified_dedicated_redis(
            tmp_path / "redis.conf",
            "redis://127.0.0.1:19042/0",
            cwd=tmp_path,
            listener_probe=lambda _url: False,
            popen_factory=lambda *_args, **_kwargs: process,
            runner=runner,
            sleeper=lambda _seconds: None,
        )

    assert commands
    assert commands[0][-2:] == ["INFO", "server"]
    assert not any(command[-1] == "PING" for command in commands)
    assert not any("FLUSHDB" in command for command in commands)
    assert process.terminated is True


def test_redis_ping_occurs_only_after_spawned_pid_matches(tmp_path):
    import john_lomein_public_honcho_service as service

    process = FakeProcess()
    commands = []

    def runner(command, **_kwargs):
        commands.append(command)
        stdout = f"process_id:{process.pid}\n" if command[-1] == "server" else "PONG\n"
        return subprocess.CompletedProcess(command, 0, stdout, "")

    started = service._start_verified_dedicated_redis(
        tmp_path / "redis.conf",
        "redis://127.0.0.1:19042/0",
        cwd=tmp_path,
        listener_probe=lambda _url: False,
        popen_factory=lambda *_args, **_kwargs: process,
        runner=runner,
        sleeper=lambda _seconds: None,
    )

    assert started is process
    assert [command[-2:] for command in commands] == [
        ["INFO", "server"],
        ["redis://127.0.0.1:19042/0", "PING"],
    ]


def test_resident_supervisor_observes_watchdog_pause_while_children_run():
    import john_lomein_public_honcho_service as service

    source = inspect.getsource(service.supervise_public_service)
    child_loop = source[source.index("while not stopping and time.monotonic() < deadline") :]
    assert "pause_path.exists() or pause_path.is_symlink()" in child_loop
    assert "public Honcho pause requested" in child_loop


def test_expiry_removes_old_partial_and_manifestless_dumps_only(tmp_path):
    import john_lomein_honcho_pilot as pilot

    now = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
    old = now - timedelta(days=31)
    old_partial = tmp_path / "old.dump.partial"
    old_orphan = tmp_path / "orphan.dump"
    fresh_partial = tmp_path / "fresh.dump.partial"
    unrelated = tmp_path / "operator-note.txt"
    for path, payload in (
        (old_partial, b"partial"),
        (old_orphan, b"orphan"),
        (fresh_partial, b"fresh"),
        (unrelated, b"keep"),
    ):
        path.write_bytes(payload)
        path.chmod(0o600)
    old_epoch = old.timestamp()
    os.utime(old_partial, (old_epoch, old_epoch))
    os.utime(old_orphan, (old_epoch, old_epoch))
    fresh_epoch = now.timestamp()
    os.utime(fresh_partial, (fresh_epoch, fresh_epoch))

    removed = pilot.expire_public_backups(tmp_path, now=now)

    assert removed == 2
    assert not old_partial.exists()
    assert not old_orphan.exists()
    assert fresh_partial.read_bytes() == b"fresh"
    assert unrelated.read_bytes() == b"keep"


def test_expiry_never_follows_or_unlinks_a_backup_symlink(tmp_path):
    import john_lomein_honcho_pilot as pilot

    outside = tmp_path.parent / f"{tmp_path.name}-outside.dump"
    outside.write_bytes(b"personal-or-external")
    outside.chmod(0o600)
    link = tmp_path / "unsafe.dump"
    link.symlink_to(outside)

    with pytest.raises(ValueError, match="unsafe"):
        pilot.expire_public_backups(
            tmp_path,
            now=datetime(2026, 9, 1, tzinfo=timezone.utc),
        )
    assert outside.read_bytes() == b"personal-or-external"


def _retention_receipt(*, cutoff: str, completed_at: str) -> dict:
    from john_lomein_honcho_pilot import sha256_json

    receipt = {
        "schema_version": "john-lomein.honcho-retention-receipt.v2",
        "database_identity_digest": "a" * 64,
        "workspace": "public-pilot-memory",
        "cutoff": cutoff,
        "completed_at": completed_at,
        "retention_days": 30,
        "maximum_active_store_lag_seconds": 300,
        "deleted_counts": {"messages": 0},
    }
    receipt["receipt_digest"] = sha256_json(receipt)
    return receipt


def test_retention_receipt_cutoff_is_bound_to_completion_and_current_lag():
    import john_lomein_honcho_pilot as pilot
    from john_lomein_public_honcho_service import validate_retention_receipt

    now = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
    valid = _retention_receipt(
        cutoff="2026-08-02T11:55:00Z",
        completed_at="2026-09-01T12:00:00Z",
    )
    stale_cutoff = _retention_receipt(
        cutoff="2020-01-01T00:00:00Z",
        completed_at="2026-09-01T12:00:00Z",
    )

    assert validate_retention_receipt(
        valid,
        expected_database_identity_digest="a" * 64,
        expected_workspace="public-pilot-memory",
        now=now,
    )
    assert pilot.validate_public_retention_receipt(
        valid,
        database_identity_digest="a" * 64,
        workspace="public-pilot-memory",
        now=now,
    )
    assert not validate_retention_receipt(
        stale_cutoff,
        expected_database_identity_digest="a" * 64,
        expected_workspace="public-pilot-memory",
        now=now,
    )
    assert not pilot.validate_public_retention_receipt(
        stale_cutoff,
        database_identity_digest="a" * 64,
        workspace="public-pilot-memory",
        now=now,
    )
    assert not validate_retention_receipt(
        valid,
        expected_database_identity_digest="a" * 64,
        expected_workspace="public-pilot-memory",
        now=now + timedelta(seconds=1),
    )


def test_backup_hashes_stream_and_oversize_archive_fails_closed(tmp_path, monkeypatch):
    import john_lomein_honcho_pilot as pilot

    def run_checked(command, *, capture=False, input_text=None):
        if command[0] == "pg_dump":
            Path(command[-1]).write_bytes(b"archive")
            return SimpleNamespace(stdout="")
        return SimpleNamespace(stdout="archive listing")

    monkeypatch.setattr(pilot, "run_checked", run_checked)
    source = inspect.getsource(pilot.create_backup) + inspect.getsource(pilot.restore_verify)
    assert ".read_bytes(" not in source

    destination = tmp_path / "bounded.dump"
    with pytest.raises(RuntimeError, match="byte quota"):
        pilot.create_backup("public_database", destination, maximum_bytes=3)
    assert not destination.exists()
    assert not destination.with_name(destination.name + ".partial").exists()


def test_backup_quota_counts_complete_manifestless_and_partial_archives(tmp_path):
    import john_lomein_honcho_pilot as pilot

    complete = tmp_path / "one.dump"
    partial = tmp_path / "two.dump.partial"
    complete.write_bytes(b"1234")
    partial.write_bytes(b"56")
    complete.chmod(0o600)
    partial.chmod(0o600)

    usage = pilot.enforce_public_backup_quota(
        tmp_path,
        maximum_count=2,
        maximum_bytes=6,
    )
    assert usage == {"count": 2, "bytes": 6}
    with pytest.raises(RuntimeError, match="count quota"):
        pilot.enforce_public_backup_quota(
            tmp_path,
            additional_count=1,
            maximum_count=2,
            maximum_bytes=100,
        )
    with pytest.raises(RuntimeError, match="byte quota"):
        pilot.enforce_public_backup_quota(
            tmp_path,
            additional_bytes=1,
            maximum_count=10,
            maximum_bytes=6,
        )


def _candidate_sets(pilot, *, message_ids=(1,)):
    candidates = {key: [] for key in pilot.RETENTION_CANDIDATE_KEYS}
    candidates.update(
        {
            "message_ids": list(message_ids),
            "message_public_ids": [f"message-{value}" for value in message_ids],
        }
    )
    return candidates


def test_reusable_backup_requires_exact_public_scope_and_candidate_coverage():
    import john_lomein_honcho_pilot as pilot

    now = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
    covered = _candidate_sets(pilot, message_ids=(1, 2))
    current = _candidate_sets(pilot, message_ids=(1,))
    metadata = {
        "verified": True,
        "database": "public_database",
        "created_at": "2026-09-01T11:00:00Z",
        "retention_coverage": {
            "schema_version": "john-lomein.honcho-retention-backup-coverage.v1",
            "database_identity_digest": "a" * 64,
            "workspace": "public-pilot-memory",
            "coverage_cutoff": "2026-08-03T12:00:00Z",
            "candidate_sets": covered,
            "candidate_sets_digest": pilot.sha256_json(covered),
        },
    }

    assert pilot.retention_backup_covers(
        metadata,
        expected_database="public_database",
        database_identity_digest="a" * 64,
        workspace="public-pilot-memory",
        cutoff="2026-08-02T12:00:00Z",
        candidate_sets=current,
        now=now,
    )
    assert not pilot.retention_backup_covers(
        metadata,
        expected_database="public_database",
        database_identity_digest="a" * 64,
        workspace="public-pilot-memory",
        cutoff="2026-08-02T12:00:00Z",
        candidate_sets=_candidate_sets(pilot, message_ids=(1, 3)),
        now=now,
    )
    assert not pilot.retention_backup_covers(
        metadata,
        expected_database="public_database",
        database_identity_digest="a" * 64,
        workspace="personal",
        cutoff="2026-08-02T12:00:00Z",
        candidate_sets=current,
        now=now,
    )


def test_retention_cycle_reuses_safe_backup_and_samples_final_cutoff_after_selection(
    tmp_path, monkeypatch
):
    import john_lomein_honcho_pilot as pilot

    manifest_path = tmp_path / "instance.yaml"
    manifest_path.write_text("instance: {slug: public-pilot}\n", encoding="utf-8")
    runtime = tmp_path / "runtime"
    targets = {
        "runtime_home": str(runtime),
        "database": "public_database",
        "workspace": "public-pilot-memory",
        "tombstone_dir": str(runtime / "private" / "honcho-deletion-tombstones"),
        "server_root": str(tmp_path / "server"),
        "base_url": "http://127.0.0.1:18042",
        "redis_url": "redis://127.0.0.1:19042/0",
    }
    boundaries = iter(
        [
            {"database_now": "2026-09-01T11:50:00Z", "cutoff": "2026-08-02T11:50:00Z"},
            {"database_now": "2026-09-01T12:00:00Z", "cutoff": "2026-08-02T12:00:00Z"},
            {"database_now": "2026-09-01T12:00:10Z", "cutoff": "2026-08-02T12:00:10Z"},
        ]
    )
    candidate_calls = []

    monkeypatch.setattr(pilot, "manifest_payload", lambda _path: {"instance": {"slug": "public-pilot"}})
    monkeypatch.setattr(pilot, "manifest_honcho_targets", lambda _path: targets)
    monkeypatch.setattr(pilot, "honcho_startup_blockers", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(pilot, "verify_honcho_runtime_targets", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(pilot, "_database_retention_boundary", lambda _database: next(boundaries))

    def candidates(_database, _workspace, cutoff):
        candidate_calls.append(cutoff)
        return _candidate_sets(pilot)

    monkeypatch.setattr(pilot, "retention_candidate_sets", candidates)
    monkeypatch.setattr(pilot, "database_oid", lambda _database: 44)
    monkeypatch.setattr(pilot, "schema_fingerprint", lambda _database: "c" * 64)
    monkeypatch.setattr(pilot, "expire_public_backups", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(
        pilot,
        "enforce_public_backup_quota",
        lambda *_args, **_kwargs: {"count": 1, "bytes": 7},
    )
    reused = {"path": str(runtime / "private" / "honcho-backups" / "safe.dump")}
    monkeypatch.setattr(pilot, "find_reusable_public_backup", lambda *_args, **_kwargs: reused)
    monkeypatch.setattr(pilot, "retention_backup_covers", lambda *_args, **_kwargs: True)
    create = mock.Mock(side_effect=AssertionError("must reuse verified coverage"))
    monkeypatch.setattr(pilot, "create_backup", create)
    monkeypatch.setattr(pilot, "create_honcho_quiescence_receipt", lambda *_args, **_kwargs: {"receipt_digest": "q"})
    applied = mock.Mock(return_value={"tombstone_digest": "t" * 64})
    monkeypatch.setattr(pilot, "apply_retention", applied)
    monkeypatch.setattr(pilot, "file_sha256", lambda _path: "sha256:" + "9" * 64)
    monkeypatch.setattr(
        pilot,
        "_write_retention_receipt",
        lambda **kwargs: {"receipt_digest": "r" * 64, **kwargs},
    )

    result = pilot.run_public_retention_cycle(
        manifest_path,
        database_identity={"database_identity_digest": "a" * 64},
    )

    create.assert_not_called()
    assert result["backup_reused"] is True
    assert candidate_calls == ["2026-08-02T11:50:00Z", "2026-08-02T12:00:00Z"]
    plan = applied.call_args.kwargs["plan"]
    assert plan["cutoff"] == "2026-08-02T12:00:00Z"
    assert applied.call_args.kwargs["backup_path"] == Path(reused["path"])
