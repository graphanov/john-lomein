#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "broker" / "john_lomein_broker_store.py"
spec = importlib.util.spec_from_file_location(
    "john_lomein_broker_store",
    MODULE,
)
assert spec and spec.loader
store = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = store
spec.loader.exec_module(store)


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
LIMITS = store.BudgetLimits(
    requests_per_hour=20,
    daily_mutations=20,
    mark_pr_ready_per_day=10,
    review_threads_per_day=10,
    consecutive_indeterminate_limit=2,
)
PRECONDITION = "d" * 64


def protected_packet(
    *,
    nonce: int = 1,
    action: str = "mark_pr_ready",
    repo: str = "acme/widget",
    pr_number: int = 17,
    head_sha: str = "a" * 40,
    thread_ids: list[str] | None = None,
    instance_slug: str = "widget-production",
) -> dict[str, Any]:
    thread_ids = (
        list(thread_ids)
        if thread_ids is not None
        else (["PRRT_example"] if action == "resolve_review_thread" else [])
    )
    created = NOW + timedelta(seconds=nonce)
    request = {
        "schema_version": "john-lomein.protected-action-input.v1",
        "instance_slug": instance_slug,
        "action": action,
        "observed_at": store.utc_text(created - timedelta(seconds=30)),
        "repo": repo,
        "pr": {
            "number": pr_number,
            "url": f"https://github.com/{repo}/pull/{pr_number}",
            "base_branch": "main",
            "head_sha": head_sha,
            "author_login": "john-lomein[bot]",
            "is_draft": action == "mark_pr_ready",
        },
        "preconditions": {
            "checks_state": "success",
            "unresolved_thread_count": len(thread_ids),
            "forbidden_paths_clear": True,
            "bot_authorship_verified": True,
            "verification": {
                "passed": True,
                "commands_sha256": f"{nonce:064x}",
                "result_sha256": f"{nonce + 1:064x}",
            },
            "evidence_comment_url": (
                f"https://github.com/{repo}/pull/{pr_number}"
                f"#issuecomment-{100 + nonce}"
            ),
        },
        "targets": {
            "thread_node_ids": thread_ids,
            "thread_urls": [
                f"https://github.com/{repo}/pull/{pr_number}"
                f"#discussion_r{100 + index}"
                for index, _ in enumerate(thread_ids)
            ],
        },
    }
    body = {
        "schema_version": store.PACKET_SCHEMA,
        "authority": store.PACKET_AUTHORITY,
        "requested_by": "john-lomein-maintainer",
        "created_at": store.utc_text(created),
        "expires_at": store.utc_text(created + timedelta(minutes=15)),
        "request": request,
    }
    digest = store.sha256_json(body)
    return {
        **body,
        "packet_id": f"jlpa-{digest[:24]}",
        "request_digest": digest,
    }


class BrokerStoreTest(unittest.TestCase):
    def state_path(self, root: Path) -> Path:
        state = root / "state"
        state.mkdir(mode=0o700)
        return state / "broker.sqlite3"

    def test_secure_sqlite_pragmas_and_required_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            with store.BrokerStore(path) as broker:
                self.assertEqual(
                    broker.pragma_state(),
                    {
                        "journal_mode": "wal",
                        "synchronous": 2,
                        "foreign_keys": 1,
                        "trusted_schema": 0,
                    },
                )
                self.assertEqual(
                    broker.counts(),
                    {
                        "packets": 0,
                        "effects": 0,
                        "budget_events": 0,
                        "receipts": 0,
                        "circuit_breakers": 0,
                    },
                )
                tables = {
                    row[0]
                    for row in broker._db.execute(
                        """
                        SELECT name FROM sqlite_schema
                        WHERE type = 'table'
                        """
                    )
                }
                self.assertTrue(
                    {
                        "packets",
                        "effects",
                        "budget_events",
                        "receipts",
                        "circuit_breakers",
                    }.issubset(tables)
                )

    def test_packet_conflicts_fail_without_spending_an_extra_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            packet = protected_packet()
            with store.BrokerStore(path) as broker:
                first = broker.reserve(packet, LIMITS, now=NOW + timedelta(seconds=2))
                self.assertEqual(first.disposition, "reserved")

                broker._db.execute(
                    """
                    UPDATE packets
                    SET request_digest = ?
                    WHERE packet_id = ?
                    """,
                    ("e" * 64, packet["packet_id"]),
                )
                with self.assertRaisesRegex(
                    store.PacketConflictError,
                    "packet id conflicts",
                ):
                    broker.reserve(
                        packet,
                        LIMITS,
                        now=NOW + timedelta(seconds=2),
                    )

                # Simulate a digest collision/reuse independently of the
                # packet's public verifier.  The store must reject it before
                # any durable budget event can be added.
                broker._db.execute(
                    """
                    INSERT INTO packets(
                        packet_id, request_digest, instance_slug, action,
                        repo, pr_number, head_sha, packet_json, accepted_at,
                        expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "jlpa-" + "f" * 24,
                        "f" * 64,
                        "widget-production",
                        "mark_pr_ready",
                        "acme/widget",
                        99,
                        "f" * 40,
                        store.canonical_json({"synthetic": True}),
                        int(NOW.timestamp()),
                        int((NOW + timedelta(minutes=10)).timestamp()),
                    ),
                )
                with self.assertRaises(sqlite3.IntegrityError):
                    broker._db.execute(
                        """
                        INSERT INTO packets(
                            packet_id, request_digest, instance_slug, action,
                            repo, pr_number, head_sha, packet_json, accepted_at,
                            expires_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "jlpa-" + "e" * 24,
                            "f" * 64,
                            "widget-production",
                            "mark_pr_ready",
                            "acme/widget",
                            100,
                            "e" * 40,
                            store.canonical_json({"synthetic": False}),
                            int(NOW.timestamp()),
                            int((NOW + timedelta(minutes=10)).timestamp()),
                        ),
                    )
                self.assertEqual(broker.counts()["budget_events"], 1)

    def test_semantic_duplicate_and_completed_receipt_are_replayed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            first_packet = protected_packet(nonce=1)
            duplicate_packet = protected_packet(nonce=2)
            with store.BrokerStore(path) as broker:
                first = broker.reserve(
                    first_packet,
                    LIMITS,
                    now=NOW + timedelta(seconds=3),
                )
                duplicate = broker.reserve(
                    duplicate_packet,
                    LIMITS,
                    now=NOW + timedelta(seconds=3),
                )
                self.assertEqual(duplicate.disposition, "duplicate_pending")
                self.assertEqual(duplicate.effect_key, first.effect_key)

                mutation = broker.begin_mutation(
                    first.effect_key,
                    first.packet_id,
                    "attempt-1",
                    LIMITS,
                    precondition_digest=PRECONDITION,
                    now=NOW + timedelta(seconds=4),
                )
                self.assertEqual(mutation.disposition, "charged")
                receipt = {
                    "schema_version": "john-lomein.broker-receipt.v1",
                    "effect_key": first.effect_key,
                    "packet_id": first.packet_id,
                    "outcome": "completed",
                }
                terminal = broker.terminalize(
                    first.effect_key,
                    first.packet_id,
                    "attempt-1",
                    "completed",
                    receipt,
                    LIMITS,
                    now=NOW + timedelta(seconds=5),
                )
                self.assertEqual(terminal.disposition, "terminalized")

                replay = broker.reserve(
                    protected_packet(nonce=3),
                    LIMITS,
                    now=NOW + timedelta(seconds=4),
                )
                self.assertEqual(replay.disposition, "semantic_completed")
                self.assertEqual(replay.receipt, receipt)
                self.assertEqual(
                    replay.receipt_packet_id,
                    first.packet_id,
                )
                reconciled_receipt = {
                    "schema_version": "john-lomein.broker-receipt.v1",
                    "effect_key": first.effect_key,
                    "packet_id": replay.packet_id,
                    "outcome": "reconciled",
                }
                broker.record_packet_receipt(
                    replay.packet_id,
                    "reconciled",
                    reconciled_receipt,
                    effect_key=first.effect_key,
                    now=NOW + timedelta(seconds=5),
                )
                exact_replay = broker.reserve(
                    protected_packet(nonce=3),
                    LIMITS,
                    now=NOW + timedelta(seconds=6),
                )
                self.assertEqual(
                    exact_replay.disposition,
                    "receipt_replay",
                )
                self.assertEqual(
                    exact_replay.receipt,
                    reconciled_receipt,
                )
                no_second_mutation = broker.begin_mutation(
                    first.effect_key,
                    replay.packet_id,
                    "attempt-never-charged",
                    LIMITS,
                    precondition_digest=PRECONDITION,
                    now=NOW + timedelta(seconds=6),
                )
                self.assertEqual(
                    no_second_mutation.disposition,
                    "receipt_replay",
                )
                counts = broker.counts()
                self.assertEqual(counts["effects"], 1)
                self.assertEqual(counts["receipts"], 2)
                # Three distinct packets plus one mutation attempt.
                self.assertEqual(counts["budget_events"], 4)
                self.assertEqual(
                    broker.load_packet(replay.packet_id),
                    protected_packet(nonce=3),
                )
                self.assertEqual(
                    broker.latest_receipt_digest(),
                    store.sha256_json(reconciled_receipt),
                )

    def test_semantic_effect_cannot_cross_broker_instances(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            with store.BrokerStore(path) as broker:
                broker.reserve(
                    protected_packet(nonce=1),
                    LIMITS,
                    now=NOW + timedelta(seconds=2),
                )
                with self.assertRaisesRegex(
                    store.EffectStateError,
                    "another broker instance",
                ):
                    broker.reserve(
                        protected_packet(
                            nonce=2,
                            instance_slug="widget-shadow",
                        ),
                        LIMITS,
                        now=NOW + timedelta(seconds=3),
                    )
                self.assertEqual(broker.counts()["packets"], 1)
                self.assertEqual(broker.counts()["budget_events"], 1)

    def test_request_global_and_per_action_budgets_fail_closed(self):
        request_limits = store.BudgetLimits(
            requests_per_hour=1,
            daily_mutations=10,
            mark_pr_ready_per_day=10,
            review_threads_per_day=10,
            consecutive_indeterminate_limit=2,
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            with store.BrokerStore(path) as broker:
                broker.reserve(
                    protected_packet(nonce=1),
                    request_limits,
                    now=NOW + timedelta(seconds=2),
                )
                with self.assertRaisesRegex(
                    store.BudgetExceeded,
                    "requests_per_hour",
                ):
                    broker.reserve(
                        protected_packet(
                            nonce=2,
                            pr_number=18,
                            head_sha="b" * 40,
                        ),
                        request_limits,
                        now=NOW + timedelta(seconds=3),
                    )
                self.assertEqual(broker.counts()["packets"], 1)

        global_limits = store.BudgetLimits(
            requests_per_hour=10,
            daily_mutations=1,
            mark_pr_ready_per_day=10,
            review_threads_per_day=10,
            consecutive_indeterminate_limit=2,
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            with store.BrokerStore(path) as broker:
                one = broker.reserve(
                    protected_packet(nonce=1),
                    global_limits,
                    now=NOW + timedelta(seconds=2),
                )
                two = broker.reserve(
                    protected_packet(
                        nonce=2,
                        pr_number=18,
                        head_sha="b" * 40,
                    ),
                    global_limits,
                    now=NOW + timedelta(seconds=3),
                )
                broker.begin_mutation(
                    one.effect_key,
                    one.packet_id,
                    "global-1",
                    global_limits,
                    precondition_digest=PRECONDITION,
                    now=NOW + timedelta(seconds=4),
                )
                with self.assertRaisesRegex(
                    store.BudgetExceeded,
                    "daily_mutations",
                ):
                    broker.begin_mutation(
                        two.effect_key,
                        two.packet_id,
                        "global-2",
                        global_limits,
                        precondition_digest=PRECONDITION,
                        now=NOW + timedelta(seconds=5),
                    )

        action_limits = store.BudgetLimits(
            requests_per_hour=10,
            daily_mutations=10,
            mark_pr_ready_per_day=0,
            review_threads_per_day=1,
            consecutive_indeterminate_limit=2,
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            with store.BrokerStore(path) as broker:
                mark = broker.reserve(
                    protected_packet(nonce=1),
                    action_limits,
                    now=NOW + timedelta(seconds=2),
                )
                with self.assertRaisesRegex(
                    store.BudgetExceeded,
                    "mark_pr_ready_per_day",
                ):
                    broker.begin_mutation(
                        mark.effect_key,
                        mark.packet_id,
                        "mark-blocked",
                        action_limits,
                        precondition_digest=PRECONDITION,
                        now=NOW + timedelta(seconds=3),
                    )

                first_thread = protected_packet(
                    nonce=2,
                    action="resolve_review_thread",
                    thread_ids=["PRRT_one"],
                )
                one = broker.reserve(
                    first_thread,
                    action_limits,
                    now=NOW + timedelta(seconds=3),
                )
                second_thread = protected_packet(
                    nonce=3,
                    action="resolve_review_thread",
                    thread_ids=["PRRT_two"],
                )
                two = broker.reserve(
                    second_thread,
                    action_limits,
                    now=NOW + timedelta(seconds=4),
                )
                broker.begin_mutation(
                    one.effect_key,
                    one.packet_id,
                    "thread-1",
                    action_limits,
                    precondition_digest=PRECONDITION,
                    now=NOW + timedelta(seconds=4),
                )
                with self.assertRaisesRegex(
                    store.BudgetExceeded,
                    "review_threads_per_day",
                ):
                    broker.begin_mutation(
                        two.effect_key,
                        two.packet_id,
                        "thread-2",
                        action_limits,
                        precondition_digest=PRECONDITION,
                        now=NOW + timedelta(seconds=5),
                    )

    def test_pending_attempt_survives_restart_and_is_never_double_charged(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            packet = protected_packet()
            with store.BrokerStore(path) as broker:
                reservation = broker.reserve(
                    packet,
                    LIMITS,
                    now=NOW + timedelta(seconds=2),
                )
                broker.begin_mutation(
                    reservation.effect_key,
                    reservation.packet_id,
                    "attempt-1",
                    LIMITS,
                    precondition_digest=PRECONDITION,
                    now=NOW + timedelta(seconds=3),
                )

            with store.BrokerStore(path) as broker:
                recovery = broker.pending_recovery()
                self.assertEqual(len(recovery), 1)
                self.assertEqual(recovery[0].attempt_key, "attempt-1")
                self.assertEqual(
                    recovery[0].precondition_digest,
                    PRECONDITION,
                )
                self.assertEqual(recovery[0].mutation_attempts, 1)
                replay = broker.begin_mutation(
                    reservation.effect_key,
                    reservation.packet_id,
                    "attempt-1",
                    LIMITS,
                    precondition_digest=PRECONDITION,
                    now=NOW + timedelta(seconds=4),
                )
                self.assertEqual(replay.disposition, "already_charged")
                with self.assertRaises(store.PendingRecoveryError):
                    broker.begin_mutation(
                        reservation.effect_key,
                        reservation.packet_id,
                        "attempt-2",
                        LIMITS,
                        precondition_digest=PRECONDITION,
                        now=NOW + timedelta(seconds=4),
                    )
                self.assertEqual(broker.counts()["budget_events"], 2)

                result = broker.reconcile_absent(
                    reservation.effect_key,
                    reservation.packet_id,
                    "attempt-1",
                    {"live_effect_present": False},
                    now=NOW + timedelta(seconds=5),
                )
                self.assertEqual(result, "reconciled_absent")
                self.assertEqual(
                    broker.reconcile_absent(
                        reservation.effect_key,
                        reservation.packet_id,
                        "attempt-1",
                        {"live_effect_present": False},
                        now=NOW + timedelta(seconds=6),
                    ),
                    "already_reconciled_absent",
                )
                self.assertEqual(broker.pending_recovery(), [])
                with self.assertRaisesRegex(
                    store.EffectStateError,
                    "already consumed",
                ):
                    broker.begin_mutation(
                        reservation.effect_key,
                        reservation.packet_id,
                        "attempt-1",
                        LIMITS,
                        precondition_digest=PRECONDITION,
                        now=NOW + timedelta(seconds=6),
                    )
                second = broker.begin_mutation(
                    reservation.effect_key,
                    reservation.packet_id,
                    "attempt-2",
                    LIMITS,
                    precondition_digest="e" * 64,
                    now=NOW + timedelta(seconds=6),
                )
                self.assertEqual(second.disposition, "charged")
                self.assertEqual(broker.counts()["budget_events"], 3)
                self.assertEqual(
                    broker.pending_recovery()[0].mutation_attempts,
                    2,
                )
                with self.assertRaisesRegex(
                    store.EffectStateError,
                    "terminalize",
                ):
                    broker.reconcile_absent(
                        reservation.effect_key,
                        reservation.packet_id,
                        "attempt-2",
                        {"live_effect_present": False},
                        now=NOW + timedelta(seconds=7),
                    )

    def test_expired_packet_cannot_start_but_can_finish_charged_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            with store.BrokerStore(path) as broker:
                expired = broker.reserve(
                    protected_packet(nonce=1),
                    LIMITS,
                    now=NOW + timedelta(seconds=2),
                )
                with self.assertRaisesRegex(
                    store.BrokerStoreError,
                    "expired",
                ):
                    broker.begin_mutation(
                        expired.effect_key,
                        expired.packet_id,
                        "late-attempt",
                        LIMITS,
                        precondition_digest=PRECONDITION,
                        now=NOW + timedelta(minutes=20),
                    )

                charged = broker.reserve(
                    protected_packet(
                        nonce=2,
                        pr_number=18,
                        head_sha="b" * 40,
                    ),
                    LIMITS,
                    now=NOW + timedelta(seconds=3),
                )
                broker.begin_mutation(
                    charged.effect_key,
                    charged.packet_id,
                    "charged-before-expiry",
                    LIMITS,
                    precondition_digest=PRECONDITION,
                    now=NOW + timedelta(seconds=4),
                )
                terminal = broker.terminalize(
                    charged.effect_key,
                    charged.packet_id,
                    "charged-before-expiry",
                    "reconciled",
                    {
                        "packet_id": charged.packet_id,
                        "outcome": "reconciled_after_restart",
                    },
                    LIMITS,
                    now=NOW + timedelta(minutes=20),
                )
                self.assertEqual(terminal.disposition, "terminalized")

    def test_indeterminate_threshold_opens_circuit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            with store.BrokerStore(path) as broker:
                for index in (1, 2):
                    packet = protected_packet(
                        nonce=index,
                        pr_number=16 + index,
                        head_sha=f"{index:x}" * 40,
                    )
                    reservation = broker.reserve(
                        packet,
                        LIMITS,
                        now=NOW + timedelta(seconds=index + 2),
                    )
                    broker.begin_mutation(
                        reservation.effect_key,
                        reservation.packet_id,
                        f"attempt-{index}",
                        LIMITS,
                        precondition_digest=PRECONDITION,
                        now=NOW + timedelta(seconds=index + 3),
                    )
                    broker.terminalize(
                        reservation.effect_key,
                        reservation.packet_id,
                        f"attempt-{index}",
                        "indeterminate",
                        {
                            "effect_key": reservation.effect_key,
                            "outcome": "indeterminate",
                        },
                        LIMITS,
                        now=NOW + timedelta(seconds=index + 4),
                    )

                status = broker.circuit_status(
                    "widget-production",
                    "mark_pr_ready",
                )
                self.assertEqual(status["state"], "open")
                self.assertEqual(status["consecutive_indeterminate"], 2)
                with self.assertRaises(store.CircuitOpenError):
                    broker.reserve(
                        protected_packet(
                            nonce=4,
                            pr_number=20,
                            head_sha="4" * 40,
                        ),
                        LIMITS,
                        now=NOW + timedelta(seconds=6),
                    )
                broker.close_circuit(
                    "widget-production",
                    "mark_pr_ready",
                    now=NOW + timedelta(seconds=7),
                )
                self.assertEqual(
                    broker.circuit_status(
                        "widget-production",
                        "mark_pr_ready",
                    )["state"],
                    "closed",
                )

    def test_packet_receipts_cover_rejection_and_external_satisfaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            with store.BrokerStore(path) as broker:
                first = broker.reserve(
                    protected_packet(nonce=1),
                    LIMITS,
                    now=NOW + timedelta(seconds=2),
                )
                rejected = {
                    "packet_id": first.packet_id,
                    "outcome": "rejected",
                }
                broker.record_packet_receipt(
                    first.packet_id,
                    "rejected",
                    rejected,
                    effect_key=first.effect_key,
                    now=NOW + timedelta(seconds=3),
                )
                exact = broker.reserve(
                    protected_packet(nonce=1),
                    LIMITS,
                    now=NOW + timedelta(seconds=4),
                )
                self.assertEqual(exact.disposition, "receipt_replay")
                self.assertEqual(exact.state, "rejected")
                self.assertEqual(exact.receipt, rejected)
                with self.assertRaisesRegex(
                    store.EffectStateError,
                    "conflicts",
                ):
                    broker.record_packet_receipt(
                        first.packet_id,
                        "failed",
                        {"packet_id": first.packet_id, "outcome": "failed"},
                        effect_key=first.effect_key,
                        now=NOW + timedelta(seconds=4),
                    )

                second = broker.reserve(
                    protected_packet(nonce=2),
                    LIMITS,
                    now=NOW + timedelta(seconds=4),
                )
                self.assertEqual(second.disposition, "duplicate_pending")
                reconciled = {
                    "packet_id": second.packet_id,
                    "outcome": "already_satisfied",
                }
                broker.record_packet_receipt(
                    second.packet_id,
                    "reconciled",
                    reconciled,
                    effect_key=second.effect_key,
                    now=NOW + timedelta(seconds=5),
                )
                exact_second = broker.reserve(
                    protected_packet(nonce=2),
                    LIMITS,
                    now=NOW + timedelta(seconds=6),
                )
                self.assertEqual(
                    exact_second.disposition,
                    "receipt_replay",
                )
                self.assertEqual(exact_second.state, "reconciled")
                third = broker.reserve(
                    protected_packet(nonce=3),
                    LIMITS,
                    now=NOW + timedelta(seconds=6),
                )
                self.assertEqual(
                    third.disposition,
                    "semantic_completed",
                )
                self.assertEqual(third.receipt, reconciled)
                self.assertEqual(broker.counts()["budget_events"], 3)

    def test_terminalization_is_atomic_and_receipt_json_is_strict(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            with store.BrokerStore(path) as broker:
                reservation = broker.reserve(
                    protected_packet(),
                    LIMITS,
                    now=NOW + timedelta(seconds=2),
                )
                broker.begin_mutation(
                    reservation.effect_key,
                    reservation.packet_id,
                    "attempt-1",
                    LIMITS,
                    precondition_digest=PRECONDITION,
                    now=NOW + timedelta(seconds=3),
                )
                with self.assertRaisesRegex(
                    ValueError,
                    "floating-point",
                ):
                    broker.terminalize(
                        reservation.effect_key,
                        reservation.packet_id,
                        "attempt-1",
                        "completed",
                        {"unsafe": float("nan")},
                        LIMITS,
                        now=NOW + timedelta(seconds=4),
                    )
                self.assertEqual(broker.counts()["receipts"], 0)
                self.assertEqual(len(broker.pending_recovery()), 1)

                receipt = {"z": 1, "a": {"value": True}}
                broker._db.execute(
                    """
                    CREATE TRIGGER abort_terminal_effect
                    BEFORE UPDATE OF state ON effects
                    WHEN NEW.state != OLD.state
                    BEGIN
                        SELECT RAISE(ABORT, 'simulated crash boundary');
                    END
                    """
                )
                with self.assertRaises(sqlite3.DatabaseError):
                    broker.terminalize(
                        reservation.effect_key,
                        reservation.packet_id,
                        "attempt-1",
                        "reconciled",
                        receipt,
                        LIMITS,
                        now=NOW + timedelta(seconds=5),
                    )
                self.assertEqual(broker.counts()["receipts"], 0)
                self.assertEqual(len(broker.pending_recovery()), 1)
                broker._db.execute(
                    "DROP TRIGGER abort_terminal_effect"
                )
                broker.terminalize(
                    reservation.effect_key,
                    reservation.packet_id,
                    "attempt-1",
                    "reconciled",
                    receipt,
                    LIMITS,
                    now=NOW + timedelta(seconds=5),
                )
                raw = broker._db.execute(
                    "SELECT receipt_json FROM receipts"
                ).fetchone()[0]
                self.assertEqual(raw, '{"a":{"value":true},"z":1}')

                # Whitespace or alternate encodings are corruption, even if
                # a permissive JSON parser would accept them.
                broker._db.execute(
                    "UPDATE receipts SET receipt_json = ?",
                    ('{ "a": {"value": true}, "z": 1 }',),
                )
                with self.assertRaisesRegex(
                    store.StoreCorruptionError,
                    "not canonical",
                ):
                    broker.reserve(
                        protected_packet(nonce=2),
                        LIMITS,
                        now=NOW + timedelta(seconds=6),
                    )

    def test_symlinked_or_permission_unsafe_database_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            state.mkdir(mode=0o700)
            outside = root / "outside.sqlite3"
            outside.write_bytes(b"")
            os.chmod(outside, 0o600)
            os.symlink(outside, state / "broker.sqlite3")
            with self.assertRaisesRegex(
                store.UnsafeStoreError,
                "database file is unsafe",
            ):
                store.BrokerStore(state / "broker.sqlite3")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            state.mkdir(mode=0o770)
            try:
                with self.assertRaisesRegex(
                    store.UnsafeStoreError,
                    "group or world permissions",
                ):
                    store.BrokerStore(state / "broker.sqlite3")
            finally:
                os.chmod(state, 0o700)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            actual = root / "actual"
            actual.mkdir(mode=0o700)
            os.symlink(actual, root / "state", target_is_directory=True)
            with self.assertRaisesRegex(
                store.UnsafeStoreError,
                "must not be a symlink",
            ):
                store.BrokerStore(root / "state" / "broker.sqlite3")

    def test_concurrent_duplicate_reservations_create_one_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            first_packet = protected_packet(nonce=1)
            second_packet = protected_packet(nonce=2)
            barrier = threading.Barrier(2)
            with store.BrokerStore(path):
                pass

            def reserve(packet: dict[str, Any]) -> store.Reservation:
                with store.BrokerStore(path, timeout=10) as broker:
                    barrier.wait()
                    return broker.reserve(
                        packet,
                        LIMITS,
                        now=NOW + timedelta(seconds=3),
                    )

            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(
                    pool.map(reserve, (first_packet, second_packet))
                )
            self.assertEqual(
                sorted(item.disposition for item in outcomes),
                ["duplicate_pending", "reserved"],
            )
            self.assertEqual(
                len({item.effect_key for item in outcomes}),
                1,
            )
            with store.BrokerStore(path) as broker:
                counts = broker.counts()
                self.assertEqual(counts["packets"], 2)
                self.assertEqual(counts["effects"], 1)
                self.assertEqual(counts["budget_events"], 2)


if __name__ == "__main__":
    unittest.main()
