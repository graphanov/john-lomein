#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "john_lomein_protected_actions.py"
spec = importlib.util.spec_from_file_location(
    "john_lomein_protected_actions", SCRIPT
)
assert spec and spec.loader
protected = importlib.util.module_from_spec(spec)
spec.loader.exec_module(protected)


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)


def input_packet(action: str = "mark_pr_ready") -> dict:
    thread_targets = action == "resolve_review_thread"
    return {
        "schema_version": protected.INPUT_SCHEMA,
        "instance_slug": "widget-production",
        "action": action,
        "observed_at": "2026-07-16T11:59:00Z",
        "repo": "acme/widget",
        "pr": {
            "number": 17,
            "url": "https://github.com/acme/widget/pull/17",
            "base_branch": "main",
            "head_sha": "a" * 40,
            "author_login": "john-lomein[bot]",
            "is_draft": action == "mark_pr_ready",
        },
        "preconditions": {
            "checks_state": "success",
            "unresolved_thread_count": 1 if thread_targets else 0,
            "forbidden_paths_clear": True,
            "bot_authorship_verified": True,
            "verification": {
                "passed": True,
                "commands_sha256": "b" * 64,
                "result_sha256": "c" * 64,
            },
            "evidence_comment_url": (
                "https://github.com/acme/widget/pull/17"
                "#issuecomment-123"
            ),
        },
        "targets": {
            "thread_node_ids": ["PRRT_example"] if thread_targets else [],
            "thread_urls": [
                "https://github.com/acme/widget/pull/17"
                "#discussion_r123"
            ]
            if thread_targets
            else [],
        },
    }


class ProtectedActionPacketTest(unittest.TestCase):
    def test_mark_ready_packet_is_request_only_digest_bound_and_persisted(self):
        raw = input_packet()
        packet = protected.prepare_packet(
            raw,
            now=NOW,
            ttl_seconds=900,
        )
        verified = protected.verify_packet(packet, now=NOW)

        self.assertEqual(verified, packet)
        self.assertEqual(packet["authority"], protected.AUTHORITY)
        self.assertEqual(packet["request"]["action"], "mark_pr_ready")
        self.assertTrue(
            packet["packet_id"].startswith("jlpa-")
        )
        self.assertNotIn(
            "verification output",
            json.dumps(packet, sort_keys=True),
        )

        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            path = protected.persist_packet(runtime, packet, now=NOW)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")),
                packet,
            )
            self.assertEqual(
                protected.persist_packet(runtime, packet, now=NOW),
                path,
            )

    def test_packet_is_bound_to_instance(self):
        first = protected.prepare_packet(input_packet(), now=NOW)
        second_input = input_packet()
        second_input["instance_slug"] = "widget-staging"
        second = protected.prepare_packet(second_input, now=NOW)
        self.assertNotEqual(first["packet_id"], second["packet_id"])
        self.assertNotEqual(
            first["request_digest"],
            second["request_digest"],
        )

    def test_thread_resolution_requires_exact_targets_and_binds_them(self):
        packet = protected.prepare_packet(
            input_packet("resolve_review_thread"),
            now=NOW,
        )
        self.assertEqual(
            packet["request"]["targets"]["thread_node_ids"],
            ["PRRT_example"],
        )
        self.assertEqual(
            protected.verify_packet(packet, now=NOW)["request_digest"],
            packet["request_digest"],
        )

        missing = input_packet("resolve_review_thread")
        missing["targets"] = {
            "thread_node_ids": [],
            "thread_urls": [],
        }
        with self.assertRaisesRegex(
            protected.ProtectedActionError,
            "requires exact thread targets",
        ):
            protected.prepare_packet(missing, now=NOW)

    def test_tampering_expiry_and_unsafe_preconditions_fail_closed(self):
        packet = protected.prepare_packet(
            input_packet(),
            now=NOW,
        )
        tampered = json.loads(json.dumps(packet))
        tampered["request"]["pr"]["head_sha"] = "d" * 40
        with self.assertRaisesRegex(
            protected.ProtectedActionError,
            "digest does not match",
        ):
            protected.verify_packet(tampered, now=NOW)

        with self.assertRaisesRegex(
            protected.ProtectedActionError,
            "expired",
        ):
            protected.verify_packet(
                packet,
                now=NOW + timedelta(hours=1),
            )

        unsafe = input_packet()
        unsafe["preconditions"]["forbidden_paths_clear"] = False
        with self.assertRaisesRegex(
            protected.ProtectedActionError,
            "forbidden-path proof",
        ):
            protected.prepare_packet(unsafe, now=NOW)

        stale = input_packet()
        stale["observed_at"] = "2026-07-16T09:00:00Z"
        with self.assertRaisesRegex(
            protected.ProtectedActionError,
            "evidence is stale",
        ):
            protected.prepare_packet(stale, now=NOW)

    def test_packet_output_refuses_symlinked_outbox(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            state = runtime / "state"
            state.mkdir(parents=True)
            outside = Path(tmp) / "outside"
            outside.mkdir()
            os.symlink(
                outside,
                state / "protected-actions",
                target_is_directory=True,
            )
            packet = protected.prepare_packet(
                input_packet(),
                now=NOW,
            )
            with self.assertRaisesRegex(
                protected.ProtectedActionError,
                "directory is unsafe",
            ):
                protected.persist_packet(runtime, packet, now=NOW)

    def test_urls_reject_queries_suffixes_and_unbound_fragments(self):
        cases = [
            (
                "pr",
                "https://github.com/acme/widget/pull/17/files",
            ),
            (
                "pr",
                "https://github.com/acme/widget/pull/17?token=secret",
            ),
            (
                "evidence",
                "https://github.com/acme/widget/pull/17#discussion_r123",
            ),
        ]
        for field, bad_url in cases:
            raw = input_packet()
            if field == "pr":
                raw["pr"]["url"] = bad_url
            else:
                raw["preconditions"]["evidence_comment_url"] = bad_url
            with self.assertRaisesRegex(
                protected.ProtectedActionError,
                "must target the bound PR",
            ):
                protected.prepare_packet(raw, now=NOW)

        raw = input_packet("resolve_review_thread")
        raw["targets"]["thread_urls"] = [
            "https://github.com/acme/widget/pull/17"
            "#discussion_r123?token=secret"
        ]
        with self.assertRaisesRegex(
            protected.ProtectedActionError,
            "must target the bound PR",
        ):
            protected.prepare_packet(raw, now=NOW)

    def test_persist_verifies_packet_before_using_packet_id(self):
        packet = protected.prepare_packet(input_packet(), now=NOW)
        packet["packet_id"] = "../../escape"
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            with self.assertRaisesRegex(
                protected.ProtectedActionError,
                "packet id does not match",
            ):
                protected.persist_packet(runtime, packet, now=NOW)
            self.assertFalse((Path(tmp) / "escape.json").exists())

    def test_cli_emits_only_relative_packet_locator(self):
        import contextlib
        import io

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "input.json"
            runtime = root / "runtime"
            live_input = input_packet()
            live_input["observed_at"] = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            source.write_text(json.dumps(live_input), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = protected.main(
                    [
                        "prepare",
                        "--input",
                        str(source),
                        "--runtime-home",
                        str(runtime),
                    ]
                )
            self.assertEqual(result, 0)
            data = json.loads(output.getvalue())
            self.assertNotIn("packet_path", data)
            self.assertFalse(Path(data["packet_locator"]).is_absolute())
            self.assertEqual(
                data["packet_locator"],
                "state/protected-actions/outbox/"
                f"{data['packet_id']}.json",
            )


if __name__ == "__main__":
    unittest.main()
