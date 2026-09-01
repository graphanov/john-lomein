#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import john_lomein_autonomy as autonomy


def at(minute: int = 0, second: int = 0) -> datetime:
    return datetime(2026, 1, 2, 12, minute, second, tzinfo=timezone.utc)


class AutonomyControlsTest(unittest.TestCase):
    def runtime(self, root: str) -> Path:
        runtime = Path(root) / "runtime"
        runtime.mkdir()
        return runtime

    def policy(self, **overrides):
        raw = {
            "circuit_breaker": {
                "failure_threshold": 3,
                "cooldown_seconds": 60,
            },
            "budgets": {
                "max_daily_runtime_seconds": 3600,
                "max_daily_runs": {
                    "maintainer": 10,
                    "forge": 10,
                    "portfolio": 10,
                    "triage": 10,
                    "release": 10,
                },
                "max_run_seconds": {
                    "maintainer": 120,
                    "forge": 120,
                    "portfolio": 120,
                    "triage": 120,
                    "release": 120,
                },
                "max_daily_effects": {
                    "public_comments": 2,
                    "branches": 2,
                    "pull_requests": 2,
                    "merges": 2,
                    "workflow_dispatches": 1,
                    "publishes": 0,
                },
            },
        }
        for section, values in overrides.items():
            if isinstance(values, dict) and isinstance(raw.get(section), dict):
                raw[section].update(values)
            else:
                raw[section] = values
        return autonomy.normalize_policy(raw)

    def test_policy_rejects_strings_booleans_unknowns_and_unsafe_ranges(self):
        invalid = [
            {"circuit_breaker": {"failure_threshold": "3"}},
            {"circuit_breaker": {"failure_threshold": True}},
            {"circuit_breaker": {"cooldown_seconds": 59}},
            {"budgets": {"max_daily_runtime_seconds": 0}},
            {"budgets": {"max_daily_runs": {"attacker": 1}}},
            {"budgets": {"max_run_seconds": {"forge": 29}}},
            {"budgets": {"max_daily_effects": {"publishes": -1}}},
            {"unknown": {}},
        ]
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    autonomy.normalize_policy(value)

    def test_triage_lane_has_bounded_hourly_defaults(self):
        policy = autonomy.normalize_policy({})
        self.assertIn("triage", autonomy.LANES)
        self.assertEqual(
            policy["budgets"]["max_daily_runs"]["triage"],
            24,
        )
        self.assertEqual(
            policy["budgets"]["max_run_seconds"]["triage"],
            300,
        )

    def test_journal_is_hash_chained_and_detects_modification(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            start = autonomy.begin_run(
                runtime,
                policy,
                "maintainer",
                idempotency_key="queue:one",
                now=at(),
            )
            autonomy.finish_run(
                runtime,
                start["run_id"],
                status="ok",
                exit_code=0,
                duration_seconds=7,
                now=at(second=7),
            )
            events = autonomy.read_events(runtime)
            self.assertEqual([e["sequence"] for e in events], [1, 2])
            self.assertEqual(events[1]["previous_hash"], events[0]["event_hash"])
            self.assertEqual(
                autonomy.autonomy_status(runtime, policy)["chain_head"],
                events[-1]["event_hash"],
            )

            journal = next(
                (runtime / "state" / "autonomy" / "journal").glob("*.jsonl")
            )
            lines = journal.read_text(encoding="utf-8").splitlines()
            event = json.loads(lines[1])
            event["duration_seconds"] = 8
            lines[1] = json.dumps(event, sort_keys=True, separators=(",", ":"))
            journal.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                autonomy.AutonomyError,
                "modified",
            ):
                autonomy.read_events(runtime)

    def test_partial_final_record_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            autonomy.begin_run(
                runtime,
                self.policy(),
                "forge",
                idempotency_key="queue:partial",
                now=at(),
            )
            journal = next(
                (runtime / "state" / "autonomy" / "journal").glob("*.jsonl")
            )
            with journal.open("ab") as handle:
                handle.write(b'{"partial":')
            with self.assertRaisesRegex(
                autonomy.AutonomyError,
                "partial final record",
            ):
                autonomy.read_events(runtime)

    def test_short_append_is_rolled_back_to_last_valid_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            autonomy.begin_run(
                runtime,
                policy,
                "forge",
                idempotency_key="queue:existing",
                now=at(),
            )
            journal = next(
                (runtime / "state" / "autonomy" / "journal").glob("*.jsonl")
            )
            original = journal.read_bytes()
            real_write = os.write

            def short_write(fd: int, raw: bytes) -> int:
                written = max(1, len(raw) // 2)
                self.assertEqual(real_write(fd, raw[:written]), written)
                return written

            with mock.patch.object(autonomy.os, "write", side_effect=short_write):
                with self.assertRaisesRegex(
                    autonomy.AutonomyError,
                    "short write",
                ):
                    autonomy.begin_run(
                        runtime,
                        policy,
                        "forge",
                        idempotency_key="queue:interrupted",
                        now=at(second=1),
                    )

            self.assertEqual(journal.read_bytes(), original)
            events = autonomy.read_events(runtime)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event_type"], "run_started")
            self.assertEqual(events[0]["lane"], "forge")

    def test_interrupted_append_is_rolled_back_to_last_valid_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            autonomy.begin_run(
                runtime,
                policy,
                "maintainer",
                idempotency_key="queue:existing",
                now=at(),
            )
            journal = next(
                (runtime / "state" / "autonomy" / "journal").glob("*.jsonl")
            )
            original = journal.read_bytes()
            real_write = os.write

            def interrupted_write(fd: int, raw: bytes) -> int:
                written = max(1, len(raw) // 2)
                self.assertEqual(real_write(fd, raw[:written]), written)
                raise InterruptedError("simulated interrupted journal append")

            with mock.patch.object(
                autonomy.os,
                "write",
                side_effect=interrupted_write,
            ):
                with self.assertRaisesRegex(InterruptedError, "simulated"):
                    autonomy.begin_run(
                        runtime,
                        policy,
                        "maintainer",
                        idempotency_key="queue:interrupted",
                        now=at(second=1),
                    )

            self.assertEqual(journal.read_bytes(), original)
            events = autonomy.read_events(runtime)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event_type"], "run_started")
            self.assertEqual(events[0]["lane"], "maintainer")

    def test_active_event_limit_rotates_without_stopping_the_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            old_limit = autonomy.MAX_EVENTS
            autonomy.MAX_EVENTS = 1
            try:
                run = autonomy.begin_run(
                    runtime,
                    self.policy(),
                    "forge",
                    idempotency_key="forge:event-limit",
                    now=at(),
                )
                finished = autonomy.finish_run(
                    runtime,
                    run["run_id"],
                    status="ok",
                    exit_code=0,
                    duration_seconds=1,
                    now=at(second=1),
                )
                self.assertEqual(finished["sequence"], 2)
                self.assertEqual(
                    [event["sequence"] for event in autonomy.read_events(runtime)],
                    [1, 2],
                )
                checkpoint = json.loads(
                    (
                        runtime
                        / "state"
                        / "autonomy"
                        / "checkpoint.json"
                    ).read_text(encoding="utf-8")
                )
                self.assertEqual(
                    checkpoint["archived_through_sequence"],
                    1,
                )
            finally:
                autonomy.MAX_EVENTS = old_limit

    def test_active_byte_target_rotates_without_a_size_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            old_event_target = autonomy.CHECKPOINT_EVENT_TARGET
            old_byte_target = autonomy.CHECKPOINT_BYTE_TARGET
            autonomy.CHECKPOINT_EVENT_TARGET = autonomy.MAX_EVENTS
            autonomy.CHECKPOINT_BYTE_TARGET = 1
            try:
                run = autonomy.begin_run(
                    runtime,
                    self.policy(),
                    "forge",
                    idempotency_key="forge:byte-rotation",
                    now=at(),
                )
                finished = autonomy.finish_run(
                    runtime,
                    run["run_id"],
                    status="ok",
                    exit_code=0,
                    duration_seconds=1,
                    now=at(second=1),
                )
                self.assertEqual(finished["sequence"], 2)
                self.assertEqual(len(autonomy.read_events(runtime)), 2)
                self.assertTrue(
                    (
                        runtime
                        / "state"
                        / "autonomy"
                        / "checkpoint.json"
                    ).exists()
                )
            finally:
                autonomy.CHECKPOINT_EVENT_TARGET = old_event_target
                autonomy.CHECKPOINT_BYTE_TARGET = old_byte_target

    def test_rotation_preserves_active_effect_receipts_and_online_indexes(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            old_target = autonomy.CHECKPOINT_EVENT_TARGET
            autonomy.CHECKPOINT_EVENT_TARGET = 1
            try:
                run = autonomy.begin_run(
                    runtime,
                    policy,
                    "maintainer",
                    idempotency_key="maintainer:rotating",
                    now=at(),
                )
                first = autonomy.begin_effect(
                    runtime,
                    policy,
                    "maintainer",
                    run["run_id"],
                    "public_comments",
                    idempotency_key="comment:first",
                    now=at(second=1),
                )
                autonomy.finish_effect(
                    runtime,
                    first["effect_id"],
                    receipt={
                        "number": 17,
                        "url": "https://github.com/owner/repo/issues/17",
                    },
                    now=at(second=2),
                )
                second = autonomy.begin_effect(
                    runtime,
                    policy,
                    "maintainer",
                    run["run_id"],
                    "public_comments",
                    idempotency_key="comment:second",
                    now=at(second=3),
                )
                with mock.patch.object(
                    autonomy,
                    "_read_archived_events_unlocked",
                    side_effect=AssertionError(
                        "online control path reread archived history"
                    ),
                ):
                    duplicate = autonomy.begin_effect(
                        runtime,
                        policy,
                        "maintainer",
                        run["run_id"],
                        "public_comments",
                        idempotency_key="comment:first",
                        now=at(second=4),
                    )
                    status = autonomy.autonomy_status(
                        runtime,
                        policy,
                        now=at(second=4),
                    )
                self.assertEqual(
                    duplicate["reason"],
                    "effect_idempotency_completed",
                )
                self.assertEqual(duplicate["receipt"]["number"], 17)
                self.assertEqual(status["event_count"], 4)
                self.assertEqual(len(status["active_runs"]), 1)
                self.assertEqual(status["pending_effects"], 1)
                autonomy.finish_effect(
                    runtime,
                    second["effect_id"],
                    success=False,
                    now=at(second=5),
                )
                autonomy.finish_run(
                    runtime,
                    run["run_id"],
                    status="ok",
                    exit_code=0,
                    duration_seconds=6,
                    now=at(second=6),
                )
                events = autonomy.read_events(runtime)
                self.assertEqual(
                    [event["sequence"] for event in events],
                    list(range(1, len(events) + 1)),
                )
            finally:
                autonomy.CHECKPOINT_EVENT_TARGET = old_target

    def test_rotation_preserves_daily_budgets_circuits_and_run_idempotency(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            policy["circuit_breaker"]["failure_threshold"] = 2
            policy["budgets"]["max_daily_runs"]["portfolio"] = 2
            old_target = autonomy.CHECKPOINT_EVENT_TARGET
            autonomy.CHECKPOINT_EVENT_TARGET = 1
            try:
                for attempt in range(2):
                    started = at(minute=attempt)
                    run = autonomy.begin_run(
                        runtime,
                        policy,
                        "portfolio",
                        idempotency_key=f"portfolio:rotated:{attempt}",
                        now=started,
                    )
                    autonomy.finish_run(
                        runtime,
                        run["run_id"],
                        status="failed",
                        exit_code=1,
                        duration_seconds=5,
                        now=started + timedelta(seconds=5),
                    )
                status = autonomy.autonomy_status(
                    runtime,
                    policy,
                    now=at(minute=1, second=6),
                )
                lane = status["lanes"]["portfolio"]
                self.assertEqual(lane["daily"]["lane_runs"], 2)
                self.assertEqual(lane["daily"]["runtime_seconds"], 10)
                self.assertEqual(
                    lane["circuit"]["consecutive_failures"],
                    2,
                )
                blocked = autonomy.begin_run(
                    runtime,
                    policy,
                    "portfolio",
                    idempotency_key="portfolio:blocked-after-rotation",
                    now=at(minute=1, second=6),
                )
                self.assertEqual(blocked["reason"], "circuit_open")

                success = autonomy.begin_run(
                    runtime,
                    policy,
                    "forge",
                    idempotency_key="forge:successful-across-rotation",
                    now=at(minute=2),
                )
                autonomy.finish_run(
                    runtime,
                    success["run_id"],
                    status="ok",
                    exit_code=0,
                    duration_seconds=1,
                    now=at(minute=2, second=1),
                )
                autonomy.begin_run(
                    runtime,
                    policy,
                    "maintainer",
                    idempotency_key="maintainer:forces-next-rotation",
                    now=at(minute=2, second=2),
                )
                duplicate = autonomy.begin_run(
                    runtime,
                    policy,
                    "forge",
                    idempotency_key="forge:successful-across-rotation",
                    now=at(minute=2, second=3),
                )
                self.assertEqual(
                    duplicate["reason"],
                    "idempotency_completed",
                )
            finally:
                autonomy.CHECKPOINT_EVENT_TARGET = old_target

    def test_archived_history_tampering_is_detected_by_full_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            old_target = autonomy.CHECKPOINT_EVENT_TARGET
            autonomy.CHECKPOINT_EVENT_TARGET = 1
            try:
                run = autonomy.begin_run(
                    runtime,
                    self.policy(),
                    "forge",
                    idempotency_key="forge:archive-tamper",
                    now=at(),
                )
                autonomy.finish_run(
                    runtime,
                    run["run_id"],
                    status="ok",
                    exit_code=0,
                    duration_seconds=1,
                    now=at(second=1),
                )
                archived = next(
                    (
                        runtime / "state" / "autonomy" / "archive"
                    ).glob("*/2026-*.jsonl")
                )
                raw = bytearray(archived.read_bytes())
                raw[len(raw) // 2] ^= 1
                archived.chmod(0o600)
                archived.write_bytes(raw)
                with self.assertRaisesRegex(
                    autonomy.AutonomyError,
                    "archived journal was modified",
                ):
                    autonomy.read_events(runtime)
            finally:
                autonomy.CHECKPOINT_EVENT_TARGET = old_target

    def test_checkpoint_tampering_blocks_online_control_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            old_target = autonomy.CHECKPOINT_EVENT_TARGET
            autonomy.CHECKPOINT_EVENT_TARGET = 1
            try:
                run = autonomy.begin_run(
                    runtime,
                    policy,
                    "forge",
                    idempotency_key="forge:checkpoint-tamper",
                    now=at(),
                )
                autonomy.finish_run(
                    runtime,
                    run["run_id"],
                    status="ok",
                    exit_code=0,
                    duration_seconds=1,
                    now=at(second=1),
                )
                checkpoint_path = (
                    runtime
                    / "state"
                    / "autonomy"
                    / "checkpoint.json"
                )
                checkpoint = json.loads(
                    checkpoint_path.read_text(encoding="utf-8")
                )
                checkpoint["created_at"] = "2026-01-02T12:00:59Z"
                checkpoint_path.write_text(
                    json.dumps(
                        checkpoint,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    autonomy.AutonomyError,
                    "checkpoint was modified",
                ):
                    autonomy.autonomy_status(runtime, policy, now=at(second=2))
            finally:
                autonomy.CHECKPOINT_EVENT_TARGET = old_target

    def test_full_verification_rebuilds_modified_control_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            old_target = autonomy.CHECKPOINT_EVENT_TARGET
            autonomy.CHECKPOINT_EVENT_TARGET = 1
            try:
                for attempt in range(2):
                    started = at(minute=attempt)
                    run = autonomy.begin_run(
                        runtime,
                        policy,
                        "portfolio",
                        idempotency_key=f"portfolio:retained:{attempt}",
                        now=started,
                    )
                    autonomy.finish_run(
                        runtime,
                        run["run_id"],
                        status="failed",
                        exit_code=1,
                        duration_seconds=1,
                        now=started + timedelta(seconds=1),
                    )
                autonomy.begin_run(
                    runtime,
                    policy,
                    "maintainer",
                    idempotency_key="maintainer:force-retention-checkpoint",
                    now=at(minute=3),
                )
                index_path = (
                    runtime
                    / "state"
                    / "autonomy"
                    / autonomy.CONTROL_INDEX_FILENAME
                )
                connection = sqlite3.connect(index_path)
                try:
                    connection.execute(
                        """
                        UPDATE terminal_runs
                        SET status = 'ok'
                        WHERE lane = 'portfolio'
                        """
                    )
                    connection.commit()
                finally:
                    connection.close()
                events = autonomy.read_events(runtime)
                self.assertEqual(len(events), 5)
                connection = sqlite3.connect(index_path)
                try:
                    statuses = [
                        row[0]
                        for row in connection.execute(
                            """
                            SELECT status
                            FROM terminal_runs
                            WHERE lane = 'portfolio'
                            ORDER BY terminal_sequence
                            """
                        )
                    ]
                finally:
                    connection.close()
                self.assertEqual(statuses, ["failed", "failed"])
            finally:
                autonomy.CHECKPOINT_EVENT_TARGET = old_target

    def test_checkpoint_is_bounded_with_large_success_cardinality(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            policy["budgets"]["max_daily_runs"]["forge"] = 500
            policy["budgets"]["max_daily_runtime_seconds"] = 86400
            policy["budgets"]["max_run_seconds"]["forge"] = 30
            old_target = autonomy.CHECKPOINT_EVENT_TARGET
            autonomy.CHECKPOINT_EVENT_TARGET = 12
            first_key = "forge:historical:0"
            try:
                for attempt in range(160):
                    started = at() + timedelta(seconds=attempt * 2)
                    run = autonomy.begin_run(
                        runtime,
                        policy,
                        "forge",
                        idempotency_key=f"forge:historical:{attempt}",
                        now=started,
                    )
                    autonomy.finish_run(
                        runtime,
                        run["run_id"],
                        status="ok",
                        exit_code=0,
                        duration_seconds=0,
                        now=started + timedelta(seconds=1),
                    )
                checkpoint_path = (
                    runtime
                    / "state"
                    / "autonomy"
                    / "checkpoint.json"
                )
                checkpoint = json.loads(
                    checkpoint_path.read_text(encoding="utf-8")
                )
                self.assertEqual(
                    checkpoint["schema_version"],
                    autonomy.CHECKPOINT_SCHEMA,
                )
                self.assertNotIn("retained_events", checkpoint)
                self.assertLess(checkpoint_path.stat().st_size, 1024)
                index_path = (
                    runtime
                    / "state"
                    / "autonomy"
                    / autonomy.CONTROL_INDEX_FILENAME
                )
                connection = sqlite3.connect(index_path)
                try:
                    count = connection.execute(
                        "SELECT count(*) FROM successful_runs"
                    ).fetchone()[0]
                finally:
                    connection.close()
                self.assertEqual(count, 160)
                with mock.patch.object(
                    autonomy,
                    "_read_archived_events_unlocked",
                    side_effect=AssertionError(
                        "online idempotency reread archived history"
                    ),
                ):
                    duplicate = autonomy.begin_run(
                        runtime,
                        policy,
                        "forge",
                        idempotency_key=first_key,
                        now=at() + timedelta(minutes=10),
                    )
                self.assertEqual(
                    duplicate["reason"],
                    "idempotency_completed",
                )
            finally:
                autonomy.CHECKPOINT_EVENT_TARGET = old_target

    def test_missing_corrupt_schema_and_anchor_indexes_rebuild(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            old_target = autonomy.CHECKPOINT_EVENT_TARGET
            autonomy.CHECKPOINT_EVENT_TARGET = 1
            try:
                run = autonomy.begin_run(
                    runtime,
                    policy,
                    "forge",
                    idempotency_key="forge:index-rebuild",
                    now=at(),
                )
                autonomy.finish_run(
                    runtime,
                    run["run_id"],
                    status="ok",
                    exit_code=0,
                    duration_seconds=1,
                    now=at(second=1),
                )
                root = runtime / "state" / "autonomy"
                index_path = root / autonomy.CONTROL_INDEX_FILENAME

                index_path.unlink()
                self.assertEqual(
                    autonomy.autonomy_status(
                        runtime,
                        policy,
                        now=at(second=2),
                    )["event_count"],
                    2,
                )

                index_path.write_bytes(b"not a sqlite database")
                os.chmod(index_path, 0o600)
                self.assertEqual(
                    autonomy.autonomy_status(
                        runtime,
                        policy,
                        now=at(second=3),
                    )["event_count"],
                    2,
                )

                connection = sqlite3.connect(index_path)
                try:
                    connection.execute("PRAGMA user_version = 99")
                finally:
                    connection.close()
                self.assertEqual(
                    autonomy.autonomy_status(
                        runtime,
                        policy,
                        now=at(second=4),
                    )["event_count"],
                    2,
                )

                connection = sqlite3.connect(index_path)
                try:
                    connection.execute(
                        """
                        UPDATE control_meta
                        SET archive_manifest_hash = ?
                        WHERE singleton = 1
                        """,
                        ("0" * 64,),
                    )
                    connection.commit()
                finally:
                    connection.close()
                self.assertEqual(
                    autonomy.autonomy_status(
                        runtime,
                        policy,
                        now=at(second=5),
                    )["event_count"],
                    2,
                )
                checkpoint = json.loads(
                    (root / "checkpoint.json").read_text(encoding="utf-8")
                )
                connection = sqlite3.connect(index_path)
                try:
                    anchored = connection.execute(
                        """
                        SELECT archive_manifest_hash
                        FROM control_meta
                        WHERE singleton = 1
                        """
                    ).fetchone()[0]
                finally:
                    connection.close()
                self.assertEqual(
                    anchored,
                    checkpoint["archive_manifest_hash"],
                )
            finally:
                autonomy.CHECKPOINT_EVENT_TARGET = old_target

    def test_legacy_checkpoint_migrates_without_losing_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            old_target = autonomy.CHECKPOINT_EVENT_TARGET
            autonomy.CHECKPOINT_EVENT_TARGET = 1
            try:
                run = autonomy.begin_run(
                    runtime,
                    policy,
                    "forge",
                    idempotency_key="forge:legacy-checkpoint",
                    now=at(),
                )
                autonomy.finish_run(
                    runtime,
                    run["run_id"],
                    status="ok",
                    exit_code=0,
                    duration_seconds=1,
                    now=at(second=1),
                )
                root = runtime / "state" / "autonomy"
                checkpoint_path = root / "checkpoint.json"
                checkpoint = json.loads(
                    checkpoint_path.read_text(encoding="utf-8")
                )
                archived_events = [
                    event
                    for event in autonomy.read_events(runtime)
                    if event["sequence"]
                    <= checkpoint["archived_through_sequence"]
                ]
                checkpoint["schema_version"] = (
                    autonomy.LEGACY_CHECKPOINT_SCHEMA
                )
                checkpoint["retained_events"] = (
                    autonomy._compact_control_events(
                        archived_events,
                        now=autonomy.parse_utc(
                            checkpoint["created_at"]
                        ),
                    )
                )
                checkpoint.pop(autonomy.CONTROL_INDEX_FIELD)
                checkpoint["checkpoint_hash"] = autonomy._object_digest(
                    checkpoint,
                    "checkpoint_hash",
                )
                checkpoint_path.write_bytes(
                    autonomy.canonical_json(checkpoint) + b"\n"
                )
                (root / autonomy.CONTROL_INDEX_FILENAME).unlink()
                duplicate = autonomy.begin_run(
                    runtime,
                    policy,
                    "forge",
                    idempotency_key="forge:legacy-checkpoint",
                    now=at(second=2),
                )
                self.assertEqual(
                    duplicate["reason"],
                    "idempotency_completed",
                )
                migrated = json.loads(
                    checkpoint_path.read_text(encoding="utf-8")
                )
                self.assertEqual(
                    migrated["schema_version"],
                    autonomy.CHECKPOINT_SCHEMA,
                )
                self.assertNotIn("retained_events", migrated)
            finally:
                autonomy.CHECKPOINT_EVENT_TARGET = old_target

    def test_modified_daily_index_cannot_grant_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            policy["budgets"]["max_daily_runs"]["maintainer"] = 1
            first = autonomy.begin_run(
                runtime,
                policy,
                "maintainer",
                idempotency_key="maintainer:index-budget:first",
                now=at(),
            )
            autonomy.finish_run(
                runtime,
                first["run_id"],
                status="ok",
                exit_code=0,
                duration_seconds=1,
                now=at(second=1),
            )
            index_path = (
                runtime
                / "state"
                / "autonomy"
                / autonomy.CONTROL_INDEX_FILENAME
            )
            connection = sqlite3.connect(index_path)
            try:
                connection.execute(
                    """
                    UPDATE daily_lane_runs
                    SET run_count = 0
                    WHERE lane = 'maintainer'
                    """
                )
                connection.commit()
            finally:
                connection.close()
            blocked = autonomy.begin_run(
                runtime,
                policy,
                "maintainer",
                idempotency_key="maintainer:index-budget:second",
                now=at(second=2),
            )
            self.assertEqual(
                blocked["reason"],
                "daily_run_budget_exhausted",
            )

    def test_deleted_success_index_row_cannot_grant_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            run = autonomy.begin_run(
                runtime,
                policy,
                "forge",
                idempotency_key="forge:index-success",
                now=at(),
            )
            autonomy.finish_run(
                runtime,
                run["run_id"],
                status="ok",
                exit_code=0,
                duration_seconds=1,
                now=at(second=1),
            )
            index_path = (
                runtime
                / "state"
                / "autonomy"
                / autonomy.CONTROL_INDEX_FILENAME
            )
            connection = sqlite3.connect(index_path)
            try:
                connection.execute(
                    "DELETE FROM successful_runs WHERE lane = 'forge'"
                )
                connection.commit()
            finally:
                connection.close()
            duplicate = autonomy.begin_run(
                runtime,
                policy,
                "forge",
                idempotency_key="forge:index-success",
                now=at(second=2),
            )
            self.assertEqual(
                duplicate["reason"],
                "idempotency_completed",
            )

    def test_crash_after_journal_append_recovers_index_before_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            with mock.patch.object(
                autonomy,
                "_apply_control_event",
                side_effect=OSError("simulated index update crash"),
            ):
                with self.assertRaisesRegex(
                    OSError,
                    "index update crash",
                ):
                    autonomy.begin_run(
                        runtime,
                        policy,
                        "forge",
                        idempotency_key="forge:append-before-index",
                        now=at(),
                    )
            retry = autonomy.begin_run(
                runtime,
                policy,
                "forge",
                idempotency_key="forge:append-before-index",
                now=at(second=1),
            )
            self.assertEqual(retry["reason"], "idempotency_in_progress")
            self.assertEqual(len(autonomy.read_events(runtime)), 1)

    def test_tampered_archive_cannot_rebuild_missing_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            old_target = autonomy.CHECKPOINT_EVENT_TARGET
            autonomy.CHECKPOINT_EVENT_TARGET = 1
            try:
                run = autonomy.begin_run(
                    runtime,
                    policy,
                    "forge",
                    idempotency_key="forge:tampered-rebuild",
                    now=at(),
                )
                autonomy.finish_run(
                    runtime,
                    run["run_id"],
                    status="ok",
                    exit_code=0,
                    duration_seconds=1,
                    now=at(second=1),
                )
                root = runtime / "state" / "autonomy"
                archived = next(
                    (root / "archive").glob("*/2026-*.jsonl")
                )
                raw = bytearray(archived.read_bytes())
                raw[len(raw) // 2] ^= 1
                archived.chmod(0o600)
                archived.write_bytes(raw)
                (root / autonomy.CONTROL_INDEX_FILENAME).unlink()
                with self.assertRaisesRegex(
                    autonomy.AutonomyError,
                    "archived journal was modified",
                ):
                    autonomy.autonomy_status(
                        runtime,
                        policy,
                        now=at(second=2),
                    )
            finally:
                autonomy.CHECKPOINT_EVENT_TARGET = old_target

    def test_unsafe_control_index_path_and_mode_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            autonomy.begin_run(
                runtime,
                policy,
                "forge",
                idempotency_key="forge:index-safety",
                now=at(),
            )
            index_path = (
                runtime
                / "state"
                / "autonomy"
                / autonomy.CONTROL_INDEX_FILENAME
            )
            index_path.chmod(0o660)
            with self.assertRaisesRegex(
                autonomy.AutonomyError,
                "group/world permissions",
            ):
                autonomy.autonomy_status(runtime, policy, now=at(second=1))
            index_path.chmod(0o600)
            index_path.unlink()
            outside = Path(tmp) / "outside.sqlite3"
            outside.write_bytes(b"outside")
            index_path.symlink_to(outside)
            with self.assertRaisesRegex(
                autonomy.AutonomyError,
                "control index is a symlink",
            ):
                autonomy.autonomy_status(runtime, policy, now=at(second=2))

    def test_control_index_uses_full_durability_and_normalized_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            autonomy.begin_run(
                runtime,
                self.policy(),
                "forge",
                idempotency_key="forge:index-contract",
                now=at(),
            )
            with autonomy.autonomy_lock(runtime):
                handle = autonomy._open_current_control_index_unlocked(
                    runtime
                )
                try:
                    connection = handle.connection
                    self.assertIsNotNone(connection)
                    self.assertEqual(
                        connection.execute(
                            "PRAGMA journal_mode"
                        ).fetchone()[0],
                        "delete",
                    )
                    self.assertEqual(
                        connection.execute(
                            "PRAGMA synchronous"
                        ).fetchone()[0],
                        2,
                    )
                    self.assertEqual(
                        connection.execute(
                            "PRAGMA fullfsync"
                        ).fetchone()[0],
                        1,
                    )
                    self.assertEqual(
                        connection.execute(
                            "PRAGMA user_version"
                        ).fetchone()[0],
                        autonomy.CONTROL_INDEX_SCHEMA_VERSION,
                    )
                    tables = {
                        row[0]
                        for row in connection.execute(
                            """
                            SELECT name
                            FROM sqlite_master
                            WHERE type = 'table'
                            """
                        )
                    }
                finally:
                    handle.close()
            self.assertTrue(
                {
                    "successful_runs",
                    "active_runs",
                    "daily_runtime",
                    "daily_lane_runs",
                    "daily_effects",
                    "lane_circuits",
                    "latest_effects",
                    "pending_effects",
                    "control_meta",
                }.issubset(tables)
            )

    def test_multi_day_active_journal_rotates_before_manifest_fanout(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            old_event_target = autonomy.CHECKPOINT_EVENT_TARGET
            old_byte_target = autonomy.CHECKPOINT_BYTE_TARGET
            old_file_target = autonomy.CHECKPOINT_FILE_TARGET
            autonomy.CHECKPOINT_EVENT_TARGET = autonomy.MAX_EVENTS
            autonomy.CHECKPOINT_BYTE_TARGET = autonomy.MAX_JOURNAL_BYTES
            autonomy.CHECKPOINT_FILE_TARGET = 2
            try:
                for day in range(3):
                    started = at() + timedelta(days=day)
                    run = autonomy.begin_run(
                        runtime,
                        policy,
                        "forge",
                        idempotency_key=f"forge:multi-day:{day}",
                        now=started,
                    )
                    autonomy.finish_run(
                        runtime,
                        run["run_id"],
                        status="ok",
                        exit_code=0,
                        duration_seconds=1,
                        now=started + timedelta(seconds=1),
                    )
                checkpoint = json.loads(
                    (
                        runtime
                        / "state"
                        / "autonomy"
                        / "checkpoint.json"
                    ).read_text(encoding="utf-8")
                )
                manifest = json.loads(
                    (
                        runtime
                        / "state"
                        / "autonomy"
                        / "archive"
                        / f"{checkpoint['generation']:08d}"
                        / "manifest.json"
                    ).read_text(encoding="utf-8")
                )
                self.assertLessEqual(
                    len(manifest["files"]),
                    autonomy.CHECKPOINT_FILE_TARGET,
                )
                self.assertEqual(len(autonomy.read_events(runtime)), 6)
            finally:
                autonomy.CHECKPOINT_EVENT_TARGET = old_event_target
                autonomy.CHECKPOINT_BYTE_TARGET = old_byte_target
                autonomy.CHECKPOINT_FILE_TARGET = old_file_target

    def test_rotation_recovers_archive_committed_before_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            old_target = autonomy.CHECKPOINT_EVENT_TARGET
            autonomy.CHECKPOINT_EVENT_TARGET = 1
            real_atomic_write = autonomy._atomic_write_json
            failed = False

            def fail_first_checkpoint(path, value):
                nonlocal failed
                if path.name == "checkpoint.json" and not failed:
                    failed = True
                    raise OSError("simulated checkpoint interruption")
                return real_atomic_write(path, value)

            try:
                run = autonomy.begin_run(
                    runtime,
                    policy,
                    "forge",
                    idempotency_key="forge:checkpoint-recovery",
                    now=at(),
                )
                with mock.patch.object(
                    autonomy,
                    "_atomic_write_json",
                    side_effect=fail_first_checkpoint,
                ):
                    with self.assertRaisesRegex(
                        OSError,
                        "checkpoint interruption",
                    ):
                        autonomy.finish_run(
                            runtime,
                            run["run_id"],
                            status="ok",
                            exit_code=0,
                            duration_seconds=1,
                            now=at(second=1),
                        )
                self.assertEqual(
                    [event["sequence"] for event in autonomy.read_events(runtime)],
                    [1],
                )
                recovered = autonomy.finish_run(
                    runtime,
                    run["run_id"],
                    status="ok",
                    exit_code=0,
                    duration_seconds=2,
                    now=at(second=2),
                )
                self.assertEqual(recovered["sequence"], 2)
                self.assertEqual(len(autonomy.read_events(runtime)), 2)
            finally:
                autonomy.CHECKPOINT_EVENT_TARGET = old_target

    def test_successful_idempotency_key_is_not_replayed_but_failure_retries(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            first = autonomy.begin_run(
                runtime,
                policy,
                "forge",
                idempotency_key="issue:12:head:abc",
                now=at(),
            )
            autonomy.finish_run(
                runtime,
                first["run_id"],
                status="failed",
                exit_code=1,
                duration_seconds=5,
                now=at(second=5),
            )
            retry = autonomy.begin_run(
                runtime,
                policy,
                "forge",
                idempotency_key="issue:12:head:abc",
                now=at(second=10),
            )
            self.assertTrue(retry["allowed"])
            autonomy.finish_run(
                runtime,
                retry["run_id"],
                status="ok",
                exit_code=0,
                duration_seconds=5,
                now=at(second=15),
            )
            duplicate = autonomy.begin_run(
                runtime,
                policy,
                "forge",
                idempotency_key="issue:12:head:abc",
                now=at(second=20),
            )
            self.assertFalse(duplicate["allowed"])
            self.assertEqual(duplicate["reason"], "idempotency_completed")

    def test_daily_run_and_runtime_budgets_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            policy["budgets"]["max_daily_runs"]["maintainer"] = 1
            first = autonomy.begin_run(
                runtime,
                policy,
                "maintainer",
                idempotency_key="queue:a",
                now=at(),
            )
            autonomy.finish_run(
                runtime,
                first["run_id"],
                status="ok",
                exit_code=0,
                duration_seconds=10,
                now=at(second=10),
            )
            blocked = autonomy.begin_run(
                runtime,
                policy,
                "maintainer",
                idempotency_key="queue:b",
                now=at(second=20),
            )
            self.assertFalse(blocked["allowed"])
            self.assertEqual(blocked["reason"], "daily_run_budget_exhausted")

            runtime_two = Path(tmp) / "runtime-two"
            runtime_two.mkdir()
            policy = self.policy()
            policy["budgets"]["max_daily_runtime_seconds"] = 60
            run = autonomy.begin_run(
                runtime_two,
                policy,
                "forge",
                idempotency_key="queue:c",
                now=at(),
            )
            autonomy.finish_run(
                runtime_two,
                run["run_id"],
                status="failed",
                exit_code=1,
                duration_seconds=60,
                now=at(minute=1),
            )
            blocked = autonomy.begin_run(
                runtime_two,
                policy,
                "forge",
                idempotency_key="queue:d",
                now=at(minute=2),
            )
            self.assertFalse(blocked["allowed"])
            self.assertEqual(
                blocked["reason"],
                "daily_runtime_budget_exhausted",
            )

    def test_runtime_reservation_never_exceeds_remaining_daily_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            policy["budgets"]["max_daily_runtime_seconds"] = 60
            first = autonomy.begin_run(
                runtime,
                policy,
                "forge",
                idempotency_key="forge:first",
                now=at(),
            )
            autonomy.finish_run(
                runtime,
                first["run_id"],
                status="ok",
                exit_code=0,
                duration_seconds=30,
                now=at(second=30),
            )
            second = autonomy.begin_run(
                runtime,
                policy,
                "forge",
                idempotency_key="forge:second",
                now=at(second=31),
            )
            self.assertTrue(second["allowed"])
            self.assertEqual(second["allowed_run_seconds"], 30)

            other_runtime = Path(tmp) / "other-runtime"
            other_runtime.mkdir()
            first = autonomy.begin_run(
                other_runtime,
                policy,
                "forge",
                idempotency_key="forge:almost-all",
                now=at(),
            )
            autonomy.finish_run(
                other_runtime,
                first["run_id"],
                status="ok",
                exit_code=0,
                duration_seconds=59,
                now=at(second=59),
            )
            blocked = autonomy.begin_run(
                other_runtime,
                policy,
                "forge",
                idempotency_key="forge:no-useful-budget",
                now=at(minute=1),
            )
            self.assertFalse(blocked["allowed"])
            self.assertEqual(
                blocked["reason"],
                "daily_runtime_budget_exhausted",
            )

    def test_zero_reported_duration_keeps_fail_closed_reservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            policy["budgets"]["max_daily_runtime_seconds"] = 60
            policy["budgets"]["max_run_seconds"]["forge"] = 60
            run = autonomy.begin_run(
                runtime,
                policy,
                "forge",
                idempotency_key="forge:zero-duration",
                now=at(),
            )
            autonomy.finish_run(
                runtime,
                run["run_id"],
                status="ok",
                exit_code=0,
                duration_seconds=0,
                now=at(second=1),
            )
            blocked = autonomy.begin_run(
                runtime,
                policy,
                "forge",
                idempotency_key="forge:after-zero-duration",
                now=at(second=2),
            )
            self.assertEqual(
                blocked["reason"],
                "daily_runtime_budget_exhausted",
            )

    def test_daily_runtime_budget_includes_active_runs_from_other_lanes(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            policy["budgets"]["max_daily_runtime_seconds"] = 60
            active = autonomy.begin_run(
                runtime,
                policy,
                "forge",
                idempotency_key="forge:active",
                now=at(),
            )
            self.assertTrue(active["allowed"])
            blocked = autonomy.begin_run(
                runtime,
                policy,
                "release",
                idempotency_key="release:next",
                now=at(minute=1),
            )
            self.assertFalse(blocked["allowed"])
            self.assertEqual(
                blocked["reason"],
                "daily_runtime_budget_exhausted",
            )

    def test_active_reservation_carries_across_utc_midnight(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            policy["budgets"]["max_daily_runtime_seconds"] = 60
            before_midnight = datetime(
                2026,
                1,
                2,
                23,
                59,
                30,
                tzinfo=timezone.utc,
            )
            active = autonomy.begin_run(
                runtime,
                policy,
                "forge",
                idempotency_key="forge:midnight",
                now=before_midnight,
            )
            self.assertEqual(active["allowed_run_seconds"], 60)
            after_midnight = datetime(
                2026,
                1,
                3,
                0,
                0,
                0,
                tzinfo=timezone.utc,
            )
            (
                runtime
                / "state"
                / "autonomy"
                / autonomy.CONTROL_INDEX_FILENAME
            ).unlink()
            next_run = autonomy.begin_run(
                runtime,
                policy,
                "release",
                idempotency_key="release:midnight",
                now=after_midnight,
            )
            self.assertTrue(next_run["allowed"])
            self.assertEqual(next_run["allowed_run_seconds"], 30)

    def test_circuit_opens_after_failure_streak_and_allows_cooldown_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            for attempt in range(3):
                started = at(minute=attempt)
                run = autonomy.begin_run(
                    runtime,
                    policy,
                    "portfolio",
                    idempotency_key=f"portfolio:{attempt}",
                    now=started,
                )
                self.assertTrue(run["allowed"])
                autonomy.finish_run(
                    runtime,
                    run["run_id"],
                    status="blocked_external",
                    exit_code=1,
                    duration_seconds=5,
                    now=started + timedelta(seconds=5),
                )
            (
                runtime
                / "state"
                / "autonomy"
                / autonomy.CONTROL_INDEX_FILENAME
            ).unlink()
            blocked = autonomy.begin_run(
                runtime,
                policy,
                "portfolio",
                idempotency_key="portfolio:blocked",
                now=at(minute=2, second=30),
            )
            self.assertFalse(blocked["allowed"])
            self.assertEqual(blocked["reason"], "circuit_open")
            probe = autonomy.begin_run(
                runtime,
                policy,
                "portfolio",
                idempotency_key="portfolio:probe",
                now=at(minute=4),
            )
            self.assertTrue(probe["allowed"])

    def test_stale_started_run_is_recovered_as_abandoned(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            first = autonomy.begin_run(
                runtime,
                policy,
                "maintainer",
                idempotency_key="queue:stale",
                now=at(),
            )
            self.assertTrue(first["allowed"])
            retry = autonomy.begin_run(
                runtime,
                policy,
                "maintainer",
                idempotency_key="queue:stale",
                now=at(minute=8),
            )
            self.assertTrue(retry["allowed"])
            events = autonomy.read_events(runtime)
            abandoned = [
                event
                for event in events
                if event["event_type"] == "run_abandoned"
            ]
            self.assertEqual(len(abandoned), 1)
            self.assertEqual(abandoned[0]["run_id"], first["run_id"])
            self.assertEqual(
                abandoned[0]["duration_seconds"],
                first["allowed_run_seconds"],
            )
            self.assertTrue(abandoned[0]["duration_clamped"])

    def test_finished_duration_is_clamped_to_reserved_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            run = autonomy.begin_run(
                runtime,
                policy,
                "forge",
                idempotency_key="forge:duration-clamp",
                now=at(),
            )
            finished = autonomy.finish_run(
                runtime,
                run["run_id"],
                status="ok",
                exit_code=0,
                duration_seconds=999,
                now=at(minute=20),
            )
            self.assertEqual(
                finished["duration_seconds"],
                run["allowed_run_seconds"],
            )
            self.assertEqual(
                finished["reported_duration_seconds"],
                999,
            )
            self.assertTrue(finished["duration_clamped"])

    def test_stale_run_is_recovered_when_the_next_fingerprint_differs(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            first = autonomy.begin_run(
                runtime,
                policy,
                "maintainer",
                idempotency_key="queue:old",
                now=at(),
            )
            retry = autonomy.begin_run(
                runtime,
                policy,
                "maintainer",
                idempotency_key="queue:new",
                now=at(minute=8),
            )
            self.assertTrue(retry["allowed"])
            abandoned = [
                event
                for event in autonomy.read_events(runtime)
                if event["event_type"] == "run_abandoned"
            ]
            self.assertEqual(
                [event["run_id"] for event in abandoned],
                [first["run_id"]],
            )

    def test_effect_budget_and_effect_idempotency_are_transactional(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            policy["budgets"]["max_daily_effects"]["public_comments"] = 1
            run = autonomy.begin_run(
                runtime,
                policy,
                "maintainer",
                idempotency_key="queue:effects",
                now=at(),
            )
            before = "1" * 64
            after = "2" * 64
            effect = autonomy.begin_effect(
                runtime,
                policy,
                "maintainer",
                run["run_id"],
                "public_comments",
                idempotency_key="pr:7:comment:status",
                before_sha256=before,
                now=at(second=1),
            )
            self.assertTrue(effect["allowed"])
            autonomy.finish_effect(
                runtime,
                effect["effect_id"],
                after_sha256=after,
                receipt={
                    "url": "https://github.com/owner/repo/issues/7",
                    "number": 7,
                    "stdout": (
                        "https://github.com/owner/repo/issues/7\n"
                    ),
                    "verified": True,
                },
                now=at(second=2),
            )
            (
                runtime
                / "state"
                / "autonomy"
                / autonomy.CONTROL_INDEX_FILENAME
            ).unlink()
            duplicate = autonomy.begin_effect(
                runtime,
                policy,
                "maintainer",
                run["run_id"],
                "public_comments",
                idempotency_key="pr:7:comment:status",
                before_sha256=before,
                now=at(second=3),
            )
            self.assertFalse(duplicate["allowed"])
            self.assertEqual(
                duplicate["reason"],
                "effect_idempotency_completed",
            )
            self.assertEqual(
                duplicate["receipt"]["number"],
                7,
            )
            exhausted = autonomy.begin_effect(
                runtime,
                policy,
                "maintainer",
                run["run_id"],
                "public_comments",
                idempotency_key="pr:8:comment:status",
                now=at(second=4),
            )
            self.assertFalse(exhausted["allowed"])
            self.assertEqual(
                exhausted["reason"],
                "daily_effect_budget_exhausted",
            )

    def test_pending_and_failed_effects_reserve_budget_and_block_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            policy["budgets"]["max_daily_effects"]["branches"] = 1
            run = autonomy.begin_run(
                runtime,
                policy,
                "forge",
                idempotency_key="forge:effects",
                now=at(),
            )
            pending = autonomy.begin_effect(
                runtime,
                policy,
                "forge",
                run["run_id"],
                "branches",
                idempotency_key="repo:branch:one",
                now=at(second=1),
            )
            duplicate = autonomy.begin_effect(
                runtime,
                policy,
                "forge",
                run["run_id"],
                "branches",
                idempotency_key="repo:branch:one",
                now=at(second=2),
            )
            self.assertEqual(
                duplicate["reason"],
                "effect_idempotency_pending",
            )
            exhausted = autonomy.begin_effect(
                runtime,
                policy,
                "forge",
                run["run_id"],
                "branches",
                idempotency_key="repo:branch:two",
                now=at(second=3),
            )
            self.assertEqual(
                exhausted["reason"],
                "daily_effect_budget_exhausted",
            )
            autonomy.finish_effect(
                runtime,
                pending["effect_id"],
                success=False,
                now=at(second=4),
            )
            failed_replay = autonomy.begin_effect(
                runtime,
                policy,
                "forge",
                run["run_id"],
                "branches",
                idempotency_key="repo:branch:one",
                now=at(second=5),
            )
            self.assertEqual(
                failed_replay["reason"],
                "effect_idempotency_failed",
            )

    def test_failed_effect_can_be_reconciled_to_completed(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            run = autonomy.begin_run(
                runtime,
                policy,
                "forge",
                idempotency_key="forge:reconcile-failed",
                now=at(),
            )
            effect = autonomy.begin_effect(
                runtime,
                policy,
                "forge",
                run["run_id"],
                "branches",
                idempotency_key="repo:branch:reconcile-failed",
                now=at(second=1),
            )
            autonomy.finish_effect(
                runtime,
                effect["effect_id"],
                success=False,
                now=at(second=2),
            )
            reconciled = autonomy.reconcile_effect(
                runtime,
                effect["effect_id"],
                observed="completed",
                receipt={
                    "branch": "automation/reconciled",
                    "verified": True,
                },
                now=at(second=3),
            )
            self.assertEqual(
                reconciled["event_type"],
                "effect_reconciled_completed",
            )
            duplicate = autonomy.begin_effect(
                runtime,
                policy,
                "forge",
                run["run_id"],
                "branches",
                idempotency_key="repo:branch:reconcile-failed",
                now=at(second=4),
            )
            self.assertEqual(
                duplicate["reason"],
                "effect_idempotency_completed",
            )
            self.assertEqual(
                duplicate["receipt"]["branch"],
                "automation/reconciled",
            )

    def test_effect_requires_matching_active_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            policy = self.policy()
            run = autonomy.begin_run(
                runtime,
                policy,
                "maintainer",
                idempotency_key="maintainer:done",
                now=at(),
            )
            with self.assertRaisesRegex(
                autonomy.AutonomyError,
                "lane does not match",
            ):
                autonomy.begin_effect(
                    runtime,
                    policy,
                    "forge",
                    run["run_id"],
                    "branches",
                    idempotency_key="repo:branch:mismatch",
                    now=at(second=1),
                )
            autonomy.finish_run(
                runtime,
                run["run_id"],
                status="ok",
                exit_code=0,
                duration_seconds=2,
                now=at(second=2),
            )
            with self.assertRaisesRegex(
                autonomy.AutonomyError,
                "after its run finished",
            ):
                autonomy.begin_effect(
                    runtime,
                    policy,
                    "maintainer",
                    run["run_id"],
                    "public_comments",
                    idempotency_key="pr:1:late-comment",
                    now=at(second=3),
                )

    def test_symlinked_autonomy_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            outside = Path(tmp) / "outside"
            outside.mkdir()
            state = runtime / "state"
            state.mkdir()
            (state / "autonomy").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(
                autonomy.AutonomyError,
                "root is a symlink",
            ):
                autonomy.begin_run(
                    runtime,
                    self.policy(),
                    "release",
                    idempotency_key="release:one",
                )

    def test_mutation_lease_is_process_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.runtime(tmp)
            helper = f"""
import pathlib
import sys
import time

sys.path.insert(0, {str(SCRIPTS)!r})
from john_lomein_autonomy import mutation_lease

runtime = pathlib.Path(sys.argv[1])
marker = pathlib.Path(sys.argv[2])
with mutation_lease(runtime, "maintainer"):
    marker.write_text("held", encoding="utf-8")
    time.sleep(2)
"""
            marker = Path(tmp) / "held"
            first = subprocess.Popen(
                [sys.executable, "-c", helper, str(runtime), str(marker)]
            )
            for _ in range(40):
                if marker.exists():
                    break
                time.sleep(0.05)
            self.assertTrue(marker.exists())
            with self.assertRaisesRegex(
                autonomy.AutonomyError,
                "already held",
            ):
                with autonomy.mutation_lease(runtime, "forge"):
                    pass
            self.assertEqual(first.wait(timeout=5), 0)


if __name__ == "__main__":
    unittest.main()
