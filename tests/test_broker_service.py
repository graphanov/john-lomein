from __future__ import annotations

import copy
import importlib.util
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from broker.john_lomein_broker_actions import evidence_marker, evaluate_snapshot
from broker.john_lomein_broker_protocol import (
    CONFIG_SCHEMA,
    GITHUB_API_BASE_URL,
    PEER_CREDENTIAL_PROTOCOL,
    SUBMISSION_SCHEMA,
    TRANSPORT_KIND,
)
from broker.john_lomein_broker_service import (
    BrokerServiceError,
    ProtectedBrokerService,
)
from broker.john_lomein_broker_store import (
    BrokerStore,
    MutationReservation,
)


SCRIPT = ROOT / "scripts" / "john_lomein_protected_actions.py"
spec = importlib.util.spec_from_file_location(
    "protected_actions_for_service_test", SCRIPT
)
assert spec and spec.loader
protected = importlib.util.module_from_spec(spec)
spec.loader.exec_module(protected)

NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
REPO = "acme/widget"
REPO_ID = 987654
PR_URL = "https://github.com/acme/widget/pull/17"
COMMENT_URL = PR_URL + "#issuecomment-123"


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def packet(
    *,
    now: datetime = NOW,
    observed_at: str = "2026-07-16T11:59:00Z",
    head_sha: str = "a" * 40,
) -> dict[str, Any]:
    return protected.prepare_packet(
        {
            "schema_version": protected.INPUT_SCHEMA,
            "instance_slug": "widget-production",
            "action": "mark_pr_ready",
            "observed_at": observed_at,
            "repo": REPO,
            "pr": {
                "number": 17,
                "url": PR_URL,
                "base_branch": "main",
                "head_sha": head_sha,
                "author_login": "john-lomein[bot]",
                "is_draft": True,
            },
            "preconditions": {
                "checks_state": "success",
                "unresolved_thread_count": 0,
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
                "thread_node_ids": [],
                "thread_urls": [],
            },
        },
        now=now,
        ttl_seconds=300,
    )


def submission(packet_value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SUBMISSION_SCHEMA,
        "packet": dict(packet_value),
    }


def config(root: Path) -> dict[str, Any]:
    uid = os.getuid()
    return {
        "schema_version": CONFIG_SCHEMA,
        "enabled": True,
        "broker_id": "test-broker",
        "broker_uid": uid,
        "transport": {
            "kind": TRANSPORT_KIND,
            "peer_credentials": PEER_CREDENTIAL_PROTOCOL,
            "socket_path": str(root / "broker.sock"),
            "requester_uid": uid + 1,
            "submit_gid": os.getgid(),
            "max_request_bytes": 262144,
            "request_timeout_seconds": 10,
        },
        "github_app": {
            "app_id": 1234,
            "app_slug": "john-lomein-protected",
            "installation_id": 5678,
            "private_key_path": str(root / "github.pem"),
            "api_base_url": GITHUB_API_BASE_URL,
        },
        "receipt_signing": {
            "key_id": "test-ed25519-1",
            "private_key_path": str(root / "receipt.pem"),
            "public_key_path": str(root / "receipt.pub.pem"),
            "public_key_sha256": "d" * 64,
        },
        "state": {"database_path": str(root / "broker.sqlite")},
        "instance": {
            "slug": "widget-production",
            "repository": {
                "full_name": REPO,
                "id": REPO_ID,
                "default_branch": "main",
            },
            "policy": {
                "allowed_actions": [
                    "mark_pr_ready",
                    "resolve_review_thread",
                ],
                "expected_pr_author_login": "john-lomein[bot]",
                "required_checks": ["test"],
                "allow_no_required_checks": False,
                "forbidden_path_prefixes": [".github/workflows"],
                "require_same_repository_head": True,
                "resolve_outdated_threads_only": True,
                "require_evidence_marker": True,
                "maximum_packet_ttl_seconds": 600,
                "maximum_clock_skew_seconds": 30,
                "accepted_check_conclusions": [
                    "NEUTRAL",
                    "SKIPPED",
                    "SUCCESS",
                ],
                "maximum_changed_files": 500,
                "minimum_rate_limit_remaining": 100,
            },
            "budgets": {
                "requests_per_hour": 30,
                "mutation_attempts_per_day": 20,
                "daily_mark_pr_ready": 10,
                "daily_resolve_review_thread": 20,
                "max_threads_per_submission": 1,
                "consecutive_indeterminate_limit": 3,
            },
        },
    }


def live_snapshot(
    packet_value: Mapping[str, Any],
    *,
    draft: bool,
    head_sha: str = "a" * 40,
    check_conclusion: str = "SUCCESS",
) -> dict[str, Any]:
    return {
        "repository": REPO,
        "repository_id": REPO_ID,
        "pr": {
            "id": "PR_node",
            "number": 17,
            "url": PR_URL,
            "state": "OPEN",
            "is_draft": draft,
            "head_sha": head_sha,
            "base_branch": "main",
            "author_login": "john-lomein[bot]",
            "same_repository_head": True,
            "changed_files": 1,
        },
        "files": ["src/widget.py"],
        "checks": [
            {
                "kind": "check_run",
                "name": "test",
                "status": "COMPLETED",
                "conclusion": check_conclusion,
                "producer": "actions",
            }
        ],
        "evidence_comment": {
            "id": 123,
            "url": COMMENT_URL,
            "author_login": "john-lomein[bot]",
            "body": evidence_marker(packet_value) + "\nStatus: verified.",
            "created_at": "2026-07-16T12:00:00Z",
        },
        "threads": [],
        "unresolved_thread_count": 0,
        "minimum_rate_limit_remaining": 5000,
    }


class FakeLive:
    def __init__(self, packet_value: Mapping[str, Any]) -> None:
        self.packet = packet_value
        self.draft = True
        self.after_head = "a" * 40
        self.check_conclusion = "SUCCESS"
        self.mutations = 0

    def fetch_snapshot(
        self,
        *,
        pr_number: int,
        evidence_comment_url: str,
    ) -> Mapping[str, Any]:
        return live_snapshot(
            self.packet,
            draft=self.draft,
            head_sha=self.after_head,
            check_conclusion=self.check_conclusion,
        )

    def mark_pr_ready(
        self,
        *,
        pr_node_id: str,
        client_mutation_id: str,
    ) -> Mapping[str, Any]:
        self.mutations += 1
        self.draft = False
        return {
            "id": "PR_node",
            "number": 17,
            "is_draft": False,
            "head_sha": self.after_head,
            "state": "OPEN",
            "updated_at": "2026-07-16T12:00:00Z",
        }

    def resolve_review_thread(
        self,
        *,
        thread_id: str,
        client_mutation_id: str,
    ) -> Mapping[str, Any]:
        raise AssertionError("unexpected thread mutation")


def fake_signer(
    payload: Mapping[str, Any],
    _config: Mapping[str, Any],
    _submission: Mapping[str, Any],
) -> Mapping[str, Any]:
    return {
        "schema_version": "test-signed-receipt",
        "payload": dict(payload),
        "signature": "test-only",
    }


class ProtectedBrokerServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.clock = MutableClock(NOW)
        self.packet = packet()
        self.live = FakeLive(self.packet)
        self.store = BrokerStore(self.root / "broker.sqlite")
        self.service = ProtectedBrokerService(
            config(self.root),
            store=self.store,
            live_factory=lambda _now: self.live,
            signer=fake_signer,
            clock=self.clock,
        )

    def tearDown(self) -> None:
        self.service.close()
        self.temporary.cleanup()

    def test_success_is_mutated_once_read_back_and_exactly_replayed(self):
        request = submission(self.packet)
        first = self.service.handle(request)
        second = self.service.handle(request)
        self.assertEqual(first, second)
        self.assertEqual(self.live.mutations, 1)
        self.assertEqual(first["payload"]["outcome"], "succeeded")
        self.assertEqual(
            first["payload"]["reason_code"], "readback_verified"
        )
        self.assertEqual(
            first["payload"]["readback"]["status"], "confirmed"
        )

    def test_exact_receipt_replays_after_packet_expiry(self):
        request = submission(self.packet)
        first = self.service.handle(request)
        self.clock.value = NOW + timedelta(minutes=10)
        self.assertEqual(self.service.handle(request), first)
        self.assertEqual(self.live.mutations, 1)

    def test_failed_live_precondition_is_signed_and_not_mutated(self):
        self.live.check_conclusion = "FAILURE"
        receipt = self.service.handle(submission(self.packet))
        self.assertEqual(receipt["payload"]["outcome"], "rejected")
        self.assertTrue(
            receipt["payload"]["reason_code"].startswith(
                "precondition_check_not_successful"
            )
        )
        self.assertEqual(self.live.mutations, 0)
        self.assertEqual(
            self.service.handle(submission(self.packet)), receipt
        )

    def test_new_packet_for_completed_semantic_effect_gets_own_receipt(self):
        first = self.service.handle(submission(self.packet))
        self.assertEqual(first["payload"]["outcome"], "succeeded")
        self.clock.value = NOW + timedelta(minutes=1)
        second_packet = packet(
            now=self.clock.value,
            observed_at="2026-07-16T12:00:00Z",
        )
        self.live.packet = second_packet
        second = self.service.handle(submission(second_packet))
        self.assertEqual(self.live.mutations, 1)
        self.assertEqual(second["payload"]["outcome"], "succeeded")
        self.assertEqual(
            second["payload"]["reason_code"], "already_satisfied"
        )
        self.assertNotEqual(
            first["payload"]["packet"]["packet_id"],
            second["payload"]["packet"]["packet_id"],
        )

    def test_changed_head_after_mutation_is_indeterminate(self):
        original_mark = self.live.mark_pr_ready

        def raced_mark(**kwargs: Any) -> Mapping[str, Any]:
            result = original_mark(**kwargs)
            self.live.after_head = "d" * 40
            return result

        self.live.mark_pr_ready = raced_mark  # type: ignore[method-assign]
        receipt = self.service.handle(submission(self.packet))
        self.assertEqual(receipt["payload"]["outcome"], "indeterminate")
        self.assertTrue(
            receipt["payload"]["reason_code"].startswith(
                "indeterminate_head_changed_during_mutation"
            )
        )
        self.assertEqual(self.live.mutations, 1)

    def test_failed_check_during_mutation_is_not_attested_as_success(self):
        original_mark = self.live.mark_pr_ready

        def raced_mark(**kwargs: Any) -> Mapping[str, Any]:
            result = original_mark(**kwargs)
            self.live.check_conclusion = "FAILURE"
            return result

        self.live.mark_pr_ready = raced_mark  # type: ignore[method-assign]
        receipt = self.service.handle(submission(self.packet))
        self.assertEqual(receipt["payload"]["outcome"], "indeterminate")
        self.assertEqual(
            receipt["payload"]["reason_code"],
            "indeterminate_readback_preconditions_changed",
        )
        self.assertEqual(self.live.mutations, 1)

    def test_pending_attempt_is_reconciled_from_live_state(self):
        request = submission(self.packet)
        reservation = self.store.reserve(
            self.packet,
            self.service.limits,
            now=NOW,
        )
        evaluated = evaluate_snapshot(
            config=self.service.config,
            packet=self.packet,
            snapshot=self.live.fetch_snapshot(
                pr_number=17,
                evidence_comment_url=COMMENT_URL,
            ),
        )
        self.store.begin_mutation(
            reservation.effect_key,
            self.packet["packet_id"],
            "crashed-attempt",
            self.service.limits,
            precondition_digest=evaluated.before_digest,
            now=NOW,
        )
        self.live.draft = False
        self.service.recover_pending()
        receipt = self.store.receipt_for_packet(self.packet["packet_id"])
        assert receipt is not None
        self.assertEqual(receipt["payload"]["outcome"], "succeeded")
        self.assertEqual(
            receipt["payload"]["reason_code"],
            "reconciled_readback_verified",
        )
        self.assertEqual(self.service.handle(request), receipt)

    def test_expired_pending_packet_can_replay_recovered_receipt(self):
        request = submission(self.packet)
        reservation = self.store.reserve(
            self.packet,
            self.service.limits,
            now=NOW,
        )
        evaluated = evaluate_snapshot(
            config=self.service.config,
            packet=self.packet,
            snapshot=self.live.fetch_snapshot(
                pr_number=17,
                evidence_comment_url=COMMENT_URL,
            ),
        )
        self.store.begin_mutation(
            reservation.effect_key,
            self.packet["packet_id"],
            "crashed-attempt-expired",
            self.service.limits,
            precondition_digest=evaluated.before_digest,
            now=NOW,
        )
        self.live.draft = False
        self.clock.value = NOW + timedelta(minutes=10)
        receipt = self.service.handle(request)
        self.assertEqual(receipt["payload"]["outcome"], "succeeded")
        self.assertEqual(
            receipt["payload"]["reason_code"],
            "reconciled_readback_verified",
        )
        self.assertEqual(self.live.mutations, 0)

    def test_expired_absent_pending_attempt_gets_signed_indeterminate(self):
        request = submission(self.packet)
        reservation = self.store.reserve(
            self.packet,
            self.service.limits,
            now=NOW,
        )
        evaluated = evaluate_snapshot(
            config=self.service.config,
            packet=self.packet,
            snapshot=self.live.fetch_snapshot(
                pr_number=17,
                evidence_comment_url=COMMENT_URL,
            ),
        )
        self.store.begin_mutation(
            reservation.effect_key,
            self.packet["packet_id"],
            "crashed-attempt-expired-absent",
            self.service.limits,
            precondition_digest=evaluated.before_digest,
            now=NOW,
        )
        self.clock.value = NOW + timedelta(minutes=10)
        receipt = self.service.handle(request)
        self.assertEqual(receipt["payload"]["outcome"], "indeterminate")
        self.assertEqual(
            receipt["payload"]["reason_code"],
            "indeterminate_packet_expired_before_retry",
        )
        self.assertEqual(self.live.mutations, 0)

    def test_absent_pending_attempt_is_retried_once_and_read_back(self):
        request = submission(self.packet)
        reservation = self.store.reserve(
            self.packet,
            self.service.limits,
            now=NOW,
        )
        evaluated = evaluate_snapshot(
            config=self.service.config,
            packet=self.packet,
            snapshot=self.live.fetch_snapshot(
                pr_number=17,
                evidence_comment_url=COMMENT_URL,
            ),
        )
        self.store.begin_mutation(
            reservation.effect_key,
            self.packet["packet_id"],
            "crashed-before-send",
            self.service.limits,
            precondition_digest=evaluated.before_digest,
            now=NOW,
        )
        receipt = self.service.handle(request)
        self.assertEqual(receipt["payload"]["outcome"], "succeeded")
        self.assertEqual(
            receipt["payload"]["reason_code"], "readback_verified"
        )
        self.assertEqual(self.live.mutations, 1)

    def test_unrelated_packet_does_not_orphan_absent_recovery(self):
        reservation = self.store.reserve(
            self.packet,
            self.service.limits,
            now=NOW,
        )
        evaluated = evaluate_snapshot(
            config=self.service.config,
            packet=self.packet,
            snapshot=self.live.fetch_snapshot(
                pr_number=17,
                evidence_comment_url=COMMENT_URL,
            ),
        )
        self.store.begin_mutation(
            reservation.effect_key,
            self.packet["packet_id"],
            "crashed-attempt-awaiting-owner",
            self.service.limits,
            precondition_digest=evaluated.before_digest,
            now=NOW,
        )
        self.clock.value = NOW + timedelta(minutes=1)
        unrelated = packet(
            now=self.clock.value,
            observed_at="2026-07-16T12:00:00Z",
            head_sha="d" * 40,
        )
        receipt = self.service.handle(submission(unrelated))
        self.assertEqual(receipt["payload"]["outcome"], "rejected")
        pending = self.store.pending_recovery()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].packet_id, self.packet["packet_id"])

    def test_pending_attempt_with_changed_head_is_indeterminate(self):
        reservation = self.store.reserve(
            self.packet,
            self.service.limits,
            now=NOW,
        )
        evaluated = evaluate_snapshot(
            config=self.service.config,
            packet=self.packet,
            snapshot=self.live.fetch_snapshot(
                pr_number=17,
                evidence_comment_url=COMMENT_URL,
            ),
        )
        self.store.begin_mutation(
            reservation.effect_key,
            self.packet["packet_id"],
            "crashed-unknown-send",
            self.service.limits,
            precondition_digest=evaluated.before_digest,
            now=NOW,
        )
        self.live.after_head = "d" * 40
        receipt = self.service.handle(submission(self.packet))
        self.assertEqual(receipt["payload"]["outcome"], "indeterminate")
        self.assertEqual(
            receipt["payload"]["reason_code"],
            "indeterminate_recovery_head_or_state_changed",
        )
        self.assertEqual(self.live.mutations, 0)

    def test_accepted_packet_gets_signed_mutation_budget_rejection(self):
        budget_root = self.root / "budget"
        budget_root.mkdir(mode=0o700)
        budget_config = config(budget_root)
        budget_config["instance"]["budgets"][
            "mutation_attempts_per_day"
        ] = 1
        budget_config["instance"]["budgets"]["daily_mark_pr_ready"] = 1
        budget_config["instance"]["budgets"][
            "daily_resolve_review_thread"
        ] = 1
        budget_clock = MutableClock(NOW)
        first_packet = packet()
        live = FakeLive(first_packet)
        with BrokerStore(budget_root / "broker.sqlite") as budget_store:
            service = ProtectedBrokerService(
                budget_config,
                store=budget_store,
                live_factory=lambda _now: live,
                signer=fake_signer,
                clock=budget_clock,
            )
            first = service.handle(submission(first_packet))
            self.assertEqual(first["payload"]["outcome"], "succeeded")

            budget_clock.value = NOW + timedelta(minutes=1)
            second_packet = packet(
                now=budget_clock.value,
                observed_at="2026-07-16T12:00:00Z",
                head_sha="d" * 40,
            )
            live.packet = second_packet
            live.draft = True
            live.after_head = "d" * 40
            second = service.handle(submission(second_packet))
            self.assertEqual(second["payload"]["outcome"], "rejected")
            self.assertEqual(
                second["payload"]["reason_code"],
                "budget_daily_mutations",
            )
            self.assertEqual(live.mutations, 1)
            self.assertEqual(
                service.handle(submission(second_packet)), second
            )

    def test_database_binding_refuses_replay_under_changed_config(self):
        receipt = self.service.handle(submission(self.packet))
        self.assertEqual(receipt["payload"]["outcome"], "succeeded")
        self.service.close()
        changed = copy.deepcopy(config(self.root))
        changed["broker_id"] = "different-test-broker"
        with BrokerStore(self.root / "broker.sqlite") as reopened:
            with self.assertRaisesRegex(
                BrokerServiceError, "active config"
            ):
                ProtectedBrokerService(
                    changed,
                    store=reopened,
                    live_factory=lambda _now: self.live,
                    signer=fake_signer,
                    clock=self.clock,
                )

    def test_terminal_race_never_returns_another_packets_receipt(self):
        def raced_begin(
            effect_key: str,
            packet_id: str,
            attempt_key: str,
            *_args: Any,
            **_kwargs: Any,
        ) -> MutationReservation:
            return MutationReservation(
                disposition="indeterminate",
                packet_id=packet_id,
                effect_key=effect_key,
                action="mark_pr_ready",
                attempt_key=None,
                charged_at=None,
                receipt={"foreign_packet_receipt": True},
                receipt_packet_id="jlpa-" + "f" * 24,
            )

        self.store.begin_mutation = raced_begin  # type: ignore[method-assign]
        receipt = self.service.handle(submission(self.packet))
        self.assertNotIn("foreign_packet_receipt", receipt)
        self.assertEqual(receipt["payload"]["outcome"], "rejected")
        self.assertEqual(
            receipt["payload"]["reason_code"],
            "circuit_semantic_indeterminate",
        )
        self.assertEqual(
            receipt["payload"]["packet"]["packet_id"],
            self.packet["packet_id"],
        )


if __name__ == "__main__":
    unittest.main()
