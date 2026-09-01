#!/usr/bin/env python3
from __future__ import annotations

import json
import hashlib
import os
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))


class HonchoPilotTest(unittest.TestCase):
    def test_health_thresholds_fail_closed_on_stale_embedding_and_queue(self):
        from john_lomein_honcho_pilot import evaluate_health

        result = evaluate_health(
            {
                "api_healthy": True,
                "queue_pending": 3,
                "queue_oldest_seconds": 1200,
                "queue_error_rows": 2,
                "embedding_pending": 4,
                "embedding_oldest_pending_seconds": 15000,
                "embedding_recent_failed": 0,
                "database_size_bytes": 18 * 1024 * 1024,
            },
            {
                "queue_pending_max": 25,
                "queue_oldest_seconds_max": 900,
                "embedding_pending_max": 10,
                "embedding_oldest_seconds_max": 900,
                "embedding_recent_failed_max": 0,
                "database_size_bytes_max": 1024 * 1024 * 1024,
            },
        )
        self.assertFalse(result["healthy"])
        self.assertIn("queue_oldest_seconds_exceeded", result["reasons"])
        self.assertIn("queue_errors_present", result["reasons"])
        self.assertIn("embedding_oldest_seconds_exceeded", result["reasons"])
        self.assertNotIn("embedding_pending_exceeded", result["reasons"])

    def test_health_thresholds_report_healthy_only_when_all_signals_pass(self):
        from john_lomein_honcho_pilot import evaluate_health

        result = evaluate_health(
            {
                "api_healthy": True,
                "queue_pending": 0,
                "queue_oldest_seconds": 0,
                "queue_error_rows": 0,
                "embedding_pending": 0,
                "embedding_oldest_pending_seconds": 0,
                "embedding_recent_failed": 0,
                "database_size_bytes": 1,
            },
            {
                "queue_pending_max": 0,
                "queue_oldest_seconds_max": 1,
                "embedding_pending_max": 0,
                "embedding_oldest_seconds_max": 1,
                "embedding_recent_failed_max": 0,
                "database_size_bytes_max": 2,
            },
        )
        self.assertEqual(result, {"healthy": True, "reasons": []})

    def test_collect_metrics_scopes_embedding_backlog_to_selected_workspace(self):
        import john_lomein_honcho_pilot as pilot

        captured = {}

        def fake_psql_json(database, sql, *, variables=None):
            captured["database"] = database
            captured["sql"] = sql
            captured["variables"] = variables
            return {}

        original_psql_json = pilot.psql_json
        original_api_health = pilot.api_health
        pilot.psql_json = fake_psql_json
        pilot.api_health = lambda _url: True
        try:
            pilot.collect_metrics("honcho_local", "http://127.0.0.1:8000", "pilot-public")
        finally:
            pilot.psql_json = original_psql_json
            pilot.api_health = original_api_health

        sql = captured["sql"]
        self.assertEqual(captured["variables"], {"workspace": "pilot-public"})
        self.assertIn(
            "FROM message_embeddings WHERE workspace_name=:'workspace' AND sync_state='pending'",
            sql,
        )
        self.assertIn(
            "FROM message_embeddings WHERE workspace_name=:'workspace' AND sync_state='failed'",
            sql,
        )

    def test_retention_plan_digest_is_stable_and_tamper_evident(self):
        from john_lomein_honcho_pilot import make_retention_plan, validate_retention_plan

        values = {
            "database_oid": 123,
            "workspace": "public-pilot",
            "cutoff": "2026-08-01T00:00:00Z",
            "retention_days": 30,
            "message_count": 14,
            "queue_count": 2,
            "embedding_count": 14,
            "document_count": 6,
            "schema_fingerprint": "a" * 64,
        }
        first = make_retention_plan(values)
        second = make_retention_plan(dict(reversed(list(values.items()))))
        self.assertEqual(first, second)
        self.assertTrue(validate_retention_plan(first))
        altered = json.loads(json.dumps(first))
        altered["message_count"] = 15
        self.assertFalse(validate_retention_plan(altered))

    def test_retention_sql_uses_psql_variables_and_deletes_dependencies_first(self):
        from john_lomein_honcho_pilot import retention_apply_sql

        sql = retention_apply_sql()
        self.assertIn(":'workspace'", sql)
        self.assertIn(":'cutoff'", sql)
        self.assertNotIn("public-pilot", sql)
        self.assertLess(sql.index("DELETE FROM queue"), sql.index("DELETE FROM messages"))
        self.assertIn("WITH RECURSIVE impacted", sql)
        self.assertIn("UPDATE documents", sql)
        self.assertLess(sql.index("UPDATE documents"), sql.index("DELETE FROM messages"))
        self.assertIn("expected_document_count", sql)
        self.assertIn("expected_message_count", sql)
        self.assertIn("ON_ERROR_STOP", sql)

    def test_pause_receipt_is_private_and_does_not_auto_clear(self):
        from john_lomein_honcho_pilot import write_pause_receipt

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "state" / "INGESTION_PAUSED.json"
            receipt = write_pause_receipt(
                target,
                {
                    "healthy": False,
                    "reasons": ["embedding_oldest_seconds_exceeded"],
                },
                observed_at="2026-08-31T13:00:00Z",
            )
            self.assertEqual(receipt["schema_version"], "john-lomein.honcho-pause.v1")
            self.assertTrue(target.is_file())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            before = target.read_text(encoding="utf-8")
            write_pause_receipt(
                target,
                {"healthy": True, "reasons": []},
                observed_at="2026-08-31T13:01:00Z",
            )
            self.assertEqual(target.read_text(encoding="utf-8"), before)

    def test_workspace_migration_plan_is_empty_target_only_and_reversible(self):
        from john_lomein_honcho_pilot import (
            build_workspace_migration_plan,
            validate_workspace_migration_plan,
        )

        plan = build_workspace_migration_plan(
            source_workspace="personal",
            target_workspace="public-pilot",
            source_counts={"workspaces": 1, "peers": 8, "sessions": 60, "messages": 481},
            target_counts={"workspaces": 0, "peers": 0, "sessions": 0, "messages": 0},
            profiles=["guide", "forge"],
            schema_fingerprint="sha256:" + "a" * 64,
            generated_at="2026-09-01T00:00:00Z",
        )
        self.assertTrue(validate_workspace_migration_plan(plan))
        self.assertFalse(plan["applied"])
        self.assertEqual(plan["continuity"], "fresh_empty_target")
        self.assertEqual(plan["rollback"]["workspace"], "personal")

    def test_workspace_migration_refuses_nonempty_target(self):
        from john_lomein_honcho_pilot import build_workspace_migration_plan

        with self.assertRaisesRegex(ValueError, "target workspace"):
            build_workspace_migration_plan(
                source_workspace="personal",
                target_workspace="public-pilot",
                source_counts={"workspaces": 1, "messages": 10},
                target_counts={"workspaces": 1, "messages": 1},
                profiles=["guide"],
                schema_fingerprint="sha256:" + "a" * 64,
                generated_at="2026-09-01T00:00:00Z",
            )

    def test_participant_deletion_plan_and_sql_are_exhaustive_and_digest_bound(self):
        from john_lomein_honcho_pilot import (
            DELETION_CANDIDATE_KEYS,
            make_participant_deletion_plan,
            participant_deletion_apply_sql,
            validate_participant_deletion_plan,
        )

        candidate_sets = {key: [] for key in DELETION_CANDIDATE_KEYS}
        candidate_sets.update({
            "peer_ids": [9],
            "session_ids": [10],
            "session_names": ["session-1"],
            "session_peer_link_keys": ["session-1|participant-42", "session-1|guide"],
            "message_ids": [11, 12, 13, 14],
            "message_public_ids": ["m11", "m12", "m13", "m14"],
        })
        candidate_sets.update({
            "embedding_ids": [21, 22, 23, 24],
            "document_ids": [31, 32, 33],
            "collection_ids": ["c1", "c2"],
            "queue_ids": [41, 42],
            "work_unit_keys": ["w1"],
        })
        plan = make_participant_deletion_plan(
            database_oid=123,
            workspace="public-pilot",
            peer="participant-42",
            candidate_sets=candidate_sets,
            allowed_service_peers=["guide"],
            schema_fingerprint="sha256:" + "b" * 64,
            generated_at="2026-09-01T00:00:00Z",
        )
        self.assertTrue(validate_participant_deletion_plan(plan))
        blocked = {key: list(value) for key, value in candidate_sets.items()}
        blocked["conflicting_peers"] = ["another-human"]
        with self.assertRaisesRegex(ValueError, "conflicting_peers"):
            make_participant_deletion_plan(
                database_oid=123,
                workspace="public-pilot",
                peer="participant-42",
                candidate_sets=blocked,
                allowed_service_peers=["guide"],
                schema_fingerprint="sha256:" + "b" * 64,
                generated_at="2026-09-01T00:00:00Z",
            )
        sql = participant_deletion_apply_sql()
        self.assertIn("DELETE FROM active_queue_sessions", sql)
        self.assertIn("DELETE FROM documents", sql)
        self.assertIn("DELETE FROM collections", sql)
        self.assertIn("DELETE FROM session_peers", sql)
        self.assertIn("DELETE FROM peers", sql)
        self.assertIn("DELETE FROM sessions", sql)
        self.assertIn("pg_stat_activity", sql)
        self.assertIn("LOCK TABLE peers, sessions", sql)
        self.assertIn("jl_message_ids", sql)

    def test_deletion_quiescence_receipt_expires_and_is_tamper_evident(self):
        from john_lomein_honcho_pilot import (
            build_honcho_quiescence_receipt,
            validate_honcho_quiescence_receipt,
        )

        receipt = build_honcho_quiescence_receipt(
            database_oid_value=123,
            schema_fingerprint_value="sha256:" + "c" * 64,
            service_labels=["ai.hermes.honcho.api", "ai.hermes.honcho.deriver"],
            observed_at="2026-09-01T00:00:00Z",
            expires_at="2026-09-01T00:05:00Z",
            nonce="d" * 64,
            vector_store_config_digest="e" * 64,
        )
        self.assertTrue(
            validate_honcho_quiescence_receipt(
                receipt,
                now=datetime(2026, 9, 1, 0, 1, tzinfo=timezone.utc),
            )
        )
        altered = dict(receipt)
        altered["services_absent"] = False
        self.assertFalse(
            validate_honcho_quiescence_receipt(
                altered,
                now=datetime(2026, 9, 1, 0, 1, tzinfo=timezone.utc),
            )
        )

    def test_chunking_preflight_requires_private_cap_and_persisted_chunk_wiring(self):
        from john_lomein_honcho_pilot import inspect_chunking_capability

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = root / "src"
            crud = source / "crud"
            crud.mkdir(parents=True)
            (source / "embedding_client.py").write_text(
                "def prepare_chunks(items):\n    return items\n",
                encoding="utf-8",
            )
            (crud / "message.py").write_text(
                "def persist(client, items):\n    return client.prepare_chunks(items)\n",
                encoding="utf-8",
            )
            env_path = root / ".env"
            env_path.write_text("EMBEDDING_MAX_INPUT_TOKENS=1000\n", encoding="utf-8")
            env_path.chmod(0o600)
            result = inspect_chunking_capability(root, env_path, expected_cap=1000)
            self.assertTrue(result["capability_verified"])

    def test_embedding_recovery_plan_is_digest_only_and_non_executing(self):
        from john_lomein_honcho_pilot import make_embedding_recovery_plan

        plan = make_embedding_recovery_plan(
            workspace="public-pilot", expected_cap=1000,
            candidates={"missing": ["m1"], "failed": ["m2"], "legacy_long_single": ["m2", "m3"]},
            capability_digest="sha256:" + "c" * 64,
            schema_fingerprint_value="sha256:" + "s" * 64,
            generated_at="2026-09-01T00:00:00Z",
        )
        self.assertFalse(plan["apply_supported"])
        self.assertFalse(plan["authority"]["can_requeue"])
        self.assertNotIn("m1", json.dumps(plan))
        self.assertEqual(plan["candidate_counts"]["legacy_long_single"], 2)

    def test_verified_backup_requires_private_matching_manifest(self):
        import john_lomein_honcho_pilot as pilot
        with tempfile.TemporaryDirectory() as tmp:
            backup = Path(tmp) / "honcho.dump"
            backup.write_bytes(b"archive")
            backup.chmod(0o600)
            manifest = {
                "schema_version": pilot.BACKUP_SCHEMA,
                "database": "honcho_local",
                "path": str(backup),
                "size_bytes": backup.stat().st_size,
                "sha256": hashlib.sha256(b"archive").hexdigest(),
                "created_at": "2026-09-01T00:00:00Z",
            }
            manifest["manifest_digest"] = pilot.sha256_json(manifest)
            sidecar = backup.with_suffix(".dump.json")
            sidecar.write_text(json.dumps(manifest), encoding="utf-8")
            sidecar.chmod(0o600)
            with mock.patch.object(pilot, "run_checked", return_value=SimpleNamespace(stdout="entry")):
                result = pilot.verified_backup_metadata(backup, expected_database="honcho_local")
                self.assertEqual(result["sha256"], "sha256:" + manifest["sha256"])
                with self.assertRaisesRegex(ValueError, "database"):
                    pilot.verified_backup_metadata(backup, expected_database="other")

    def test_tombstone_directory_rejects_nested_or_non_json_entries(self):
        from john_lomein_honcho_pilot import applied_deletion_tombstones, reserve_private_json
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "nested").mkdir()
            with self.assertRaisesRegex(ValueError, "unsupported entry"):
                applied_deletion_tombstones(root)
            (root / "nested").rmdir()
            target = root / "reserved.json"
            reserve_private_json(target, {"state": "pending"})
            with self.assertRaises(FileExistsError):
                reserve_private_json(target, {"state": "applied"})

    def test_applied_tombstones_block_service_restore_until_replayed(self):
        from john_lomein_honcho_pilot import applied_deletion_tombstones, sha256_json
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            payload = {
                "schema_version": "john-lomein.honcho-deletion-tombstone.v1",
                "state": "applied", "plan_digest": "p",
                "replay_descriptor": {"workspace": "public-pilot", "peer": "participant-1", "allowed_service_peers": ["guide"]},
            }
            payload["tombstone_digest"] = sha256_json(payload)
            target = root / "one.json"
            target.write_text(json.dumps(payload), encoding="utf-8")
            target.chmod(0o600)
            pending = dict(payload)
            pending["state"] = "pending"
            pending.pop("tombstone_digest")
            pending["tombstone_digest"] = sha256_json(pending)
            pending_path = root / "two.json"
            pending_path.write_text(json.dumps(pending), encoding="utf-8")
            pending_path.chmod(0o600)
            found = applied_deletion_tombstones(root)
            self.assertEqual(len(found), 2)
            self.assertEqual({item["state"] for item in found}, {"applied", "pending"})
            self.assertEqual(found[0]["tombstone_digest"], payload["tombstone_digest"])

    def test_restore_verify_does_not_require_source_database_name(self):
        from john_lomein_honcho_pilot import parser

        args = parser().parse_args(["restore-verify", "--backup", "/private/backup.dump"])
        self.assertEqual(args.command, "restore-verify")
        self.assertEqual(args.backup, "/private/backup.dump")

    def test_backup_command_is_custom_format_and_private_destination(self):
        from john_lomein_honcho_pilot import backup_commands

        with tempfile.TemporaryDirectory() as tmp:
            commands = backup_commands("honcho_local", Path(tmp) / "honcho.dump")
        self.assertEqual(commands[0][0], "pg_dump")
        self.assertIn("--format=custom", commands[0])
        self.assertIn("--no-owner", commands[0])
        self.assertEqual(commands[1][:2], ["pg_restore", "--list"])


if __name__ == "__main__":
    unittest.main()
