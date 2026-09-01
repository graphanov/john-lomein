from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from broker.john_lomein_broker_actions import (
    BrokerActionError,
    MutationIndeterminate,
    evaluate_snapshot,
    evidence_marker,
    execute_evaluated_action,
)


PACKET_SCRIPT = ROOT / "scripts" / "john_lomein_protected_actions.py"
spec = importlib.util.spec_from_file_location(
    "protected_actions_for_broker_test", PACKET_SCRIPT
)
assert spec and spec.loader
protected = importlib.util.module_from_spec(spec)
spec.loader.exec_module(protected)

NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
REPO = "acme/widget"
REPO_ID = 123456
PR_URL = "https://github.com/acme/widget/pull/17"
COMMENT_URL = PR_URL + "#issuecomment-123"


def packet_input(action: str = "mark_pr_ready") -> dict[str, Any]:
    thread = action == "resolve_review_thread"
    return {
        "schema_version": protected.INPUT_SCHEMA,
        "instance_slug": "widget-production",
        "action": action,
        "observed_at": "2026-07-16T11:59:00Z",
        "repo": REPO,
        "pr": {
            "number": 17,
            "url": PR_URL,
            "base_branch": "main",
            "head_sha": "a" * 40,
            "author_login": "john-lomein[bot]",
            "is_draft": not thread,
        },
        "preconditions": {
            "checks_state": "success",
            "unresolved_thread_count": 1 if thread else 0,
            "forbidden_paths_clear": True,
            "bot_authorship_verified": True,
            "verification": {
                "passed": True,
                "commands_sha256": "b" * 64,
                "result_sha256": "c" * 64,
            },
            "evidence_comment_url": COMMENT_URL,
        },
        "targets": {
            "thread_node_ids": ["PRRT_old"] if thread else [],
            "thread_urls": [
                PR_URL + "#discussion_r321"
            ]
            if thread
            else [],
        },
    }


def make_packet(action: str = "mark_pr_ready") -> dict[str, Any]:
    return protected.prepare_packet(
        packet_input(action), now=NOW, ttl_seconds=900
    )


def config() -> dict[str, Any]:
    return {
        "instance": {
            "repository": {
                "full_name": REPO,
                "id": REPO_ID,
                "default_branch": "main",
            },
            "policy": {
                "allowed_pr_authors": ["john-lomein[bot]"],
                "required_check_contexts": ["test"],
                "allow_no_checks": False,
                "accepted_check_conclusions": [
                    "SUCCESS",
                    "NEUTRAL",
                    "SKIPPED",
                ],
                "maximum_changed_files": 1000,
                "forbidden_paths": [],
                "resolve_outdated_threads_only": True,
                "maximum_clock_skew_seconds": 300,
            },
        }
    }


def snapshot(
    packet: Mapping[str, Any],
    *,
    files: list[str] | None = None,
    checks: list[dict[str, Any]] | None = None,
    marker: str | None = None,
    thread_outdated: bool = True,
) -> dict[str, Any]:
    request = packet["request"]
    is_thread = request["action"] == "resolve_review_thread"
    changed_files = files if files is not None else ["src/widget.py"]
    contexts = checks if checks is not None else [
        {
            "kind": "check_run",
            "name": "test",
            "status": "COMPLETED",
            "conclusion": "SUCCESS",
            "producer": "actions",
        }
    ]
    threads = (
        [
            {
                "id": "PRRT_old",
                "is_resolved": False,
                "is_outdated": thread_outdated,
                "urls": [PR_URL + "#discussion_r321"],
            }
        ]
        if is_thread
        else []
    )
    return {
        "repository": REPO,
        "repository_id": REPO_ID,
        "pr": {
            "id": "PR_node",
            "number": 17,
            "url": PR_URL,
            "state": "OPEN",
            "is_draft": request["pr"]["is_draft"],
            "head_sha": "a" * 40,
            "base_branch": "main",
            "author_login": "john-lomein[bot]",
            "same_repository_head": True,
            "changed_files": len(changed_files),
        },
        "files": changed_files,
        "checks": contexts,
        "evidence_comment": {
            "id": 123,
            "url": COMMENT_URL,
            "author_login": "john-lomein[bot]",
            "body": (
                marker if marker is not None else evidence_marker(packet)
            )
            + "\nStatus: verified.",
            "created_at": "2026-07-16T11:59:30Z",
        },
        "threads": threads,
        "unresolved_thread_count": len(threads),
        "minimum_rate_limit_remaining": 5000,
    }


class FakeLive:
    def __init__(
        self,
        *,
        readback: Mapping[str, Any],
    ) -> None:
        self.readback = json.loads(json.dumps(readback))
        self.calls: list[tuple[str, Mapping[str, Any]]] = []

    def mark_pr_ready(
        self,
        *,
        pr_node_id: str,
        client_mutation_id: str,
    ) -> Mapping[str, Any]:
        self.calls.append(
            (
                "ready",
                {
                    "pr_node_id": pr_node_id,
                    "client_mutation_id": client_mutation_id,
                },
            )
        )
        return {
            "id": "PR_node",
            "number": 17,
            "is_draft": False,
            "head_sha": "a" * 40,
            "state": "OPEN",
            "updated_at": "2026-07-16T12:00:01Z",
        }

    def resolve_review_thread(
        self,
        *,
        thread_id: str,
        client_mutation_id: str,
    ) -> Mapping[str, Any]:
        self.calls.append(
            (
                "resolve",
                {
                    "thread_id": thread_id,
                    "client_mutation_id": client_mutation_id,
                },
            )
        )
        return {"id": thread_id, "is_resolved": True}

    def fetch_snapshot(
        self,
        *,
        pr_number: int,
        evidence_comment_url: str,
    ) -> Mapping[str, Any]:
        self.calls.append(
            (
                "readback",
                {
                    "pr_number": pr_number,
                    "evidence_comment_url": evidence_comment_url,
                },
            )
        )
        return self.readback


class BrokerActionStateMachineTest(unittest.TestCase):
    def test_mark_ready_revalidates_all_authority_from_live_state(self):
        packet = make_packet()
        evaluated = evaluate_snapshot(
            config=config(),
            packet=packet,
            snapshot=snapshot(packet),
        )
        self.assertEqual(evaluated.action, "mark_pr_ready")
        self.assertEqual(evaluated.head_sha, "a" * 40)
        self.assertIsNone(evaluated.target_thread_id)
        self.assertEqual(len(evaluated.before_digest), 64)

    def test_packet_green_boolean_cannot_override_failed_live_check(self):
        packet = make_packet()
        live = snapshot(
            packet,
            checks=[
                {
                    "kind": "check_run",
                    "name": "test",
                    "status": "COMPLETED",
                    "conclusion": "FAILURE",
                    "producer": "actions",
                }
            ],
        )
        with self.assertRaisesRegex(
            BrokerActionError, "pending or unsuccessful"
        ) as caught:
            evaluate_snapshot(
                config=config(), packet=packet, snapshot=live
            )
        self.assertEqual(caught.exception.reason_code, "check_not_successful")

    def test_hard_forbidden_paths_cannot_be_relaxed_by_config(self):
        packet = make_packet()
        with self.assertRaisesRegex(
            BrokerActionError, "broker-forbidden"
        ) as caught:
            evaluate_snapshot(
                config=config(),
                packet=packet,
                snapshot=snapshot(
                    packet, files=[".github/workflows/release.yml"]
                ),
            )
        self.assertEqual(caught.exception.reason_code, "forbidden_path_changed")

    def test_evidence_comment_requires_exact_first_line_marker(self):
        packet = make_packet()
        forged = evidence_marker(packet).replace(
            "head=" + "a" * 40, "head=" + "d" * 40
        )
        with self.assertRaisesRegex(
            BrokerActionError, "exact broker marker"
        ):
            evaluate_snapshot(
                config=config(),
                packet=packet,
                snapshot=snapshot(packet, marker=forged),
            )

    def test_current_thread_remains_blocked_without_verifier_attestation(self):
        packet = make_packet("resolve_review_thread")
        with self.assertRaisesRegex(
            BrokerActionError, "independent verifier"
        ) as caught:
            evaluate_snapshot(
                config=config(),
                packet=packet,
                snapshot=snapshot(packet, thread_outdated=False),
            )
        self.assertEqual(
            caught.exception.reason_code,
            "current_thread_requires_verifier",
        )

    def test_mark_ready_mutation_requires_same_head_readback(self):
        packet = make_packet()
        before = snapshot(packet)
        evaluated = evaluate_snapshot(
            config=config(), packet=packet, snapshot=before
        )
        after = snapshot(packet)
        after["pr"]["is_draft"] = False
        live = FakeLive(readback=after)
        result = execute_evaluated_action(
            live=live,
            config=config(),
            packet=packet,
            evaluated=evaluated,
            attempt_id="attempt-1",
        )
        self.assertTrue(result["readback_verified"])
        self.assertFalse(result["after"]["pr"]["is_draft"])

        raced = snapshot(packet)
        raced["pr"]["is_draft"] = False
        raced["pr"]["head_sha"] = "d" * 40
        with self.assertRaisesRegex(
            MutationIndeterminate, "changed during mutation"
        ) as caught:
            execute_evaluated_action(
                live=FakeLive(readback=raced),
                config=config(),
                packet=packet,
                evaluated=evaluated,
                attempt_id="attempt-2",
            )
        self.assertEqual(
            caught.exception.reason_code, "head_changed_during_mutation"
        )

    def test_already_satisfied_state_is_live_revalidated_without_remutation(self):
        ready_packet = make_packet()
        ready_live = snapshot(ready_packet)
        ready_live["pr"]["is_draft"] = False
        ready = evaluate_snapshot(
            config=config(),
            packet=ready_packet,
            snapshot=ready_live,
            allow_already_satisfied=True,
        )
        self.assertTrue(ready.already_satisfied)

        thread_packet = make_packet("resolve_review_thread")
        thread_live = snapshot(thread_packet)
        thread_live["threads"][0]["is_resolved"] = True
        thread_live["unresolved_thread_count"] = 0
        thread = evaluate_snapshot(
            config=config(),
            packet=thread_packet,
            snapshot=thread_live,
            allow_already_satisfied=True,
        )
        self.assertTrue(thread.already_satisfied)
        self.assertEqual(thread.target_thread_id, "PRRT_old")

    def test_outdated_thread_resolution_is_exactly_targeted_and_read_back(self):
        packet = make_packet("resolve_review_thread")
        before = snapshot(packet)
        evaluated = evaluate_snapshot(
            config=config(), packet=packet, snapshot=before
        )
        self.assertEqual(evaluated.target_thread_id, "PRRT_old")
        after = snapshot(packet)
        after["threads"][0]["is_resolved"] = True
        after["unresolved_thread_count"] = 0
        live = FakeLive(readback=after)
        result = execute_evaluated_action(
            live=live,
            config=config(),
            packet=packet,
            evaluated=evaluated,
            attempt_id="attempt-thread",
        )
        self.assertTrue(result["after"]["target_thread"]["is_resolved"])
        self.assertEqual(live.calls[0][1]["thread_id"], "PRRT_old")


if __name__ == "__main__":
    unittest.main()
