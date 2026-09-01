#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
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
MODULE = (
    ROOT
    / "release_broker"
    / "john_lomein_release_broker_store.py"
)
spec = importlib.util.spec_from_file_location(
    "john_lomein_release_broker_store",
    MODULE,
)
assert spec and spec.loader
store = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = store
spec.loader.exec_module(store)


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
PRECONDITION = "sha256:" + ("d" * 64)
LIMITS = store.BudgetLimits(
    unique_requests_per_hour=20,
    owner_assertions_per_hour=20,
    bundles_per_day=20,
    mutation_attempts_per_day=20,
    confirmed_merges_per_day=20,
    consecutive_indeterminate_limit=2,
)
BINDING = {
    "schema_version": "john-lomein.protected-release-broker-binding.v1",
    "broker_id": "release-production",
    "config_digest": "sha256:" + ("1" * 64),
    "instance_slug": "widget-production",
    "repository_id": 987654,
    "receipt_key_id": "release-receipts-2026-01",
}


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def release_bundle(
    *,
    bundle_nonce: int = 1,
    repository_id: int = 987654,
    repository_full_name: str = "acme/widget",
    initial_base_sha: str = "a" * 40,
    step_count: int = 1,
) -> dict[str, Any]:
    ordered_prs: list[dict[str, Any]] = []
    for position in range(step_count):
        pr_number = bundle_nonce * 100 + position + 1
        paths = [
            f"src/change_{bundle_nonce}_{position}.py",
            f"tests/test_change_{bundle_nonce}_{position}.py",
        ]
        ordered_prs.append(
            {
                "position": position,
                "number": pr_number,
                "url": (
                    f"https://github.com/{repository_full_name}/pull/"
                    f"{pr_number}"
                ),
                "head_sha": f"{bundle_nonce + position + 1:x}" * 40,
                "expected_merge_tree_sha": (
                    f"{bundle_nonce + position + 10:x}"[-1] * 40
                ),
                "base_branch": "main",
                "author_login": "john-lomein[bot]",
                "changed_paths": paths,
                "changed_paths_digest": store.sha256_json(paths),
                "changed_path_count": len(paths),
                "risk_class": "low",
            }
        )
    bundle = {
        "schema_version": store.BUNDLE_SCHEMA,
        "bundle_id": "",
        "instance_slug": "widget-production",
        "repository": {
            "id": repository_id,
            "full_name": repository_full_name,
            "default_branch": "main",
        },
        "created_at": "2026-07-16T11:55:00Z",
        "expires_at": "2026-07-16T13:00:00Z",
        "initial_base_sha": initial_base_sha,
        "merge_method": "squash",
        "publish": False,
        "ordered_prs": ordered_prs,
        "train_attestation_digest": None,
        "actions": {"merge": True, "publish": False},
        "bundle_digest": "",
    }
    payload = {
        key: value
        for key, value in bundle.items()
        if key not in {"bundle_id", "bundle_digest"}
    }
    bundle["bundle_digest"] = store.sha256_json(payload)
    bundle["bundle_id"] = (
        "jlb-"
        + bundle["bundle_digest"].removeprefix("sha256:")[:24]
    )
    return bundle


def release_packet(
    *,
    packet_nonce: int = 1,
    bundle: dict[str, Any] | None = None,
    owner_nonce: str | None = None,
    signature_nonce: int | None = None,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    bundle = copy.deepcopy(bundle or release_bundle())
    created = created_at or NOW + timedelta(seconds=packet_nonce)
    nonce = owner_nonce or f"{packet_nonce:064x}"
    approval = (
        "APPROVE JOHN-LOMEIN RELEASE BUNDLE: squash-merge the exact "
        "listed PR; DO NOT publish."
    )
    payload = {
        "schema_version": store.OWNER_ASSERTION_SCHEMA,
        "purpose": "release_merge",
        "issuer": "trusted-owner-gateway",
        "actor_id": "owner-123",
        "actor_login": "maintainer",
        "tier": "owner",
        "issued_at": _utc(created - timedelta(seconds=1)),
        "expires_at": _utc(created + timedelta(minutes=10)),
        "nonce": nonce,
        "instance_slug": bundle["instance_slug"],
        "repository_id": bundle["repository"]["id"],
        "repository_full_name": bundle["repository"]["full_name"],
        "bundle_id": bundle["bundle_id"],
        "bundle_digest": bundle["bundle_digest"],
        "approval_text_sha256": store.sha256_text(approval),
        "action": store.RELEASE_ACTION,
        "merge_method": "squash",
        "publish": False,
        "ordered_prs_digest": store.sha256_json(bundle["ordered_prs"]),
        "changed_paths_digest": store.sha256_json(
            [
                {
                    "position": item["position"],
                    "number": item["number"],
                    "changed_paths": item["changed_paths"],
                }
                for item in bundle["ordered_prs"]
            ]
        ),
        "risk_class": "low",
    }
    signature_value = (
        packet_nonce if signature_nonce is None else signature_nonce
    )
    assertion = {
        "schema_version": "john-lomein.signed-envelope.v1",
        "algorithm": "ed25519",
        "key_id": "owner-2026-01",
        "payload": payload,
        # The protocol/crypto layer owns signature verification.  The store
        # treats the already-verified envelope as canonical opaque data.
        "signature": f"test-signature-{signature_value:04d}",
    }
    request = {
        "action": store.RELEASE_ACTION,
        "bundle": bundle,
        "approval": {
            "text": approval,
            "text_sha256": store.sha256_text(approval),
        },
        "owner_assertion": assertion,
        "train_attestation": None,
    }
    body = {
        "schema_version": store.PACKET_SCHEMA,
        "created_at": _utc(created),
        "expires_at": _utc(created + timedelta(minutes=5)),
        "authority": store.PACKET_AUTHORITY,
        "requested_by": {
            "component": "john-lomein-release-executor",
            "instance_slug": bundle["instance_slug"],
        },
        "request": request,
    }
    return {
        **body,
        "packet_id": (
            "jlrp-"
            + store.sha256_json(body).removeprefix("sha256:")[:24]
        ),
        "request_digest": store.sha256_json(request),
    }


def terminal_receipt(
    packet: dict[str, Any],
    bundle_key: str,
    outcome: str,
) -> dict[str, Any]:
    return {
        "schema_version": "john-lomein.protected-release-broker-receipt.v1",
        "packet_id": packet["packet_id"],
        "bundle_key": bundle_key,
        "bundle_digest": packet["request"]["bundle"]["bundle_digest"],
        "outcome": outcome,
    }


class ReleaseBrokerStoreTest(unittest.TestCase):
    def state_path(self, root: Path) -> Path:
        state = root / "state"
        state.mkdir(mode=0o700)
        return state / "release.sqlite3"

    def open_bound(
        self,
        path: Path,
        *,
        limits: store.BudgetLimits = LIMITS,
    ) -> store.ReleaseBrokerStore:
        del limits
        broker = store.ReleaseBrokerStore(path)
        broker.bind_runtime(BINDING, now=NOW)
        return broker

    def reserve_and_charge(
        self,
        broker: store.ReleaseBrokerStore,
        packet: dict[str, Any],
        *,
        now: datetime = NOW + timedelta(seconds=10),
        attempt_id: str = "jlra-attempt-1",
        limits: store.BudgetLimits = LIMITS,
    ) -> tuple[store.Reservation, store.MutationReservation]:
        reservation = broker.reserve(packet, limits, now=now)
        mutation = broker.begin_mutation(
            reservation.bundle_key,
            0,
            packet["packet_id"],
            attempt_id,
            limits,
            expected_base_sha=packet["request"]["bundle"][
                "initial_base_sha"
            ],
            precondition_digest=PRECONDITION,
            now=now + timedelta(seconds=1),
        )
        return reservation, mutation

    def confirm(
        self,
        broker: store.ReleaseBrokerStore,
        reservation: store.Reservation,
        packet: dict[str, Any],
        *,
        attempt_id: str = "jlra-attempt-1",
        merge_sha: str = "e" * 40,
        parent_sha: str | None = None,
        tree_sha: str = "f" * 40,
    ) -> store.StepConfirmation:
        return broker.confirm_step(
            reservation.bundle_key,
            0,
            packet["packet_id"],
            attempt_id,
            merge_sha=merge_sha,
            parent_sha=(
                parent_sha
                or packet["request"]["bundle"]["initial_base_sha"]
            ),
            tree_sha=tree_sha,
            merged_by="john-lomein-release[bot]",
            now=NOW + timedelta(seconds=20),
        )

    def test_secure_pragmas_strict_schema_and_binding_are_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            with store.ReleaseBrokerStore(path) as broker:
                self.assertEqual(
                    broker.pragma_state(),
                    {
                        "journal_mode": "wal",
                        "synchronous": 2,
                        "foreign_keys": 1,
                        "trusted_schema": 0,
                    },
                )
                tables = {
                    row[0]
                    for row in broker._db.execute(
                        """
                        SELECT name
                        FROM sqlite_schema
                        WHERE type = 'table'
                        """
                    )
                }
                self.assertTrue(
                    {
                        "runtime_binding",
                        "packets",
                        "owner_nonces",
                        "bundles",
                        "bundle_steps",
                        "mutation_attempts",
                        "recovery_records",
                        "budget_events",
                        "receipts",
                        "circuits",
                    }.issubset(tables)
                )
                with self.assertRaises(store.StoreBindingError):
                    broker.reserve(release_packet(), LIMITS, now=NOW)
                digest = broker.bind_runtime(BINDING, now=NOW)
                self.assertEqual(digest, store.sha256_json(BINDING))
                self.assertEqual(broker.counts()["runtime_binding"], 1)

            with store.ReleaseBrokerStore(path) as reopened:
                with self.assertRaisesRegex(
                    store.StoreBindingError, "another config"
                ):
                    reopened.bind_runtime(
                        {**BINDING, "broker_id": "other-release-broker"},
                        now=NOW,
                    )
                reopened.bind_runtime(BINDING, now=NOW)

    def test_runtime_binding_tamper_is_detected_before_durable_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            with self.open_bound(path) as broker:
                broker._db.execute(
                    """
                    UPDATE runtime_binding
                    SET binding_json = ?
                    WHERE singleton = 1
                    """,
                    (store.canonical_json({"tampered": True}),),
                )
                with self.assertRaisesRegex(
                    store.StoreCorruptionError, "binding"
                ):
                    broker.reserve(release_packet(), LIMITS, now=NOW)
                self.assertEqual(broker.counts()["packets"], 0)

    def test_database_directory_permissions_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unsafe = root / "unsafe"
            unsafe.mkdir(mode=0o755)
            with self.assertRaisesRegex(
                store.UnsafeStoreError, "group or world permissions"
            ):
                store.ReleaseBrokerStore(unsafe / "release.sqlite3")

            secure = root / "secure"
            secure.mkdir(mode=0o700)
            target = root / "target.sqlite3"
            target.write_bytes(b"not sqlite")
            target.chmod(0o600)
            (secure / "release.sqlite3").symlink_to(target)
            with self.assertRaisesRegex(
                store.UnsafeStoreError, "file is unsafe"
            ):
                store.ReleaseBrokerStore(secure / "release.sqlite3")

    def test_only_exact_packet_replay_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            bundle = release_bundle()
            first_packet = release_packet(packet_nonce=1, bundle=bundle)
            semantic_packet = release_packet(packet_nonce=2, bundle=bundle)
            with self.open_bound(path) as broker:
                first = broker.reserve(
                    first_packet,
                    LIMITS,
                    now=NOW + timedelta(seconds=3),
                )
                self.assertEqual(first.disposition, "new_bundle")
                exact = broker.reserve(
                    first_packet,
                    LIMITS,
                    now=NOW + timedelta(hours=2),
                )
                self.assertEqual(exact.disposition, "exact_pending")
                before_alias = broker.counts()
                with self.assertRaisesRegex(
                    store.SemanticTerminalReplayError,
                    "fresh packet",
                ):
                    broker.reserve(
                        semantic_packet,
                        LIMITS,
                        now=NOW + timedelta(seconds=3),
                    )
                self.assertEqual(broker.counts(), before_alias)
                self.assertIsNone(
                    broker.receipt_for_packet(
                        semantic_packet["packet_id"]
                    )
                )
                counts = broker.counts()
                self.assertEqual(counts["packets"], 1)
                self.assertEqual(counts["owner_nonces"], 1)
                self.assertEqual(counts["bundles"], 1)
                self.assertEqual(counts["bundle_steps"], 1)
                # One request + one assertion + one semantic bundle.
                self.assertEqual(counts["budget_events"], 3)
                self.assertEqual(
                    broker.load_packet(first_packet["packet_id"]),
                    first_packet,
                )

    def test_packet_content_tamper_and_digest_reuse_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            packet = release_packet()
            with self.open_bound(path) as broker:
                broker.reserve(
                    packet, LIMITS, now=NOW + timedelta(seconds=2)
                )
                broker._db.execute(
                    """
                    UPDATE packets
                    SET packet_json = ?
                    WHERE packet_id = ?
                    """,
                    (
                        store.canonical_json({"tampered": True}),
                        packet["packet_id"],
                    ),
                )
                with self.assertRaisesRegex(
                    store.PacketConflictError, "conflicts"
                ):
                    broker.reserve(
                        packet, LIMITS, now=NOW + timedelta(seconds=2)
                    )

    def test_owner_nonce_replay_rolls_back_packet_and_budget_reservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            bundle = release_bundle()
            nonce = "c" * 64
            first = release_packet(
                packet_nonce=1,
                bundle=bundle,
                owner_nonce=nonce,
                signature_nonce=1,
            )
            replay = release_packet(
                packet_nonce=2,
                bundle=release_bundle(bundle_nonce=2),
                owner_nonce=nonce,
                signature_nonce=2,
            )
            with self.open_bound(path) as broker:
                broker.reserve(
                    first, LIMITS, now=NOW + timedelta(seconds=3)
                )
                before = broker.counts()
                with self.assertRaises(store.NonceReplayError):
                    broker.reserve(
                        replay, LIMITS, now=NOW + timedelta(seconds=3)
                    )
                after = broker.counts()
                self.assertEqual(after["packets"], before["packets"])
                self.assertEqual(
                    after["owner_nonces"], before["owner_nonces"]
                )
                self.assertEqual(
                    after["budget_events"], before["budget_events"]
                )

    def test_only_one_active_bundle_wins_a_concurrent_repository_race(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            with self.open_bound(path):
                pass
            barrier = threading.Barrier(2)
            packets = [
                release_packet(
                    packet_nonce=index,
                    bundle=release_bundle(bundle_nonce=index),
                )
                for index in (1, 2)
            ]

            def reserve(packet: dict[str, Any]) -> str:
                barrier.wait()
                try:
                    with store.ReleaseBrokerStore(path, timeout=10) as broker:
                        broker.bind_runtime(BINDING, now=NOW)
                        return broker.reserve(
                            packet,
                            LIMITS,
                            now=NOW + timedelta(seconds=5),
                        ).disposition
                except store.ActiveBundleError:
                    return "active_bundle"

            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(reserve, packets))
            self.assertCountEqual(
                outcomes, ["new_bundle", "active_bundle"]
            )
            with self.open_bound(path) as broker:
                self.assertEqual(broker.counts()["bundles"], 1)
                self.assertEqual(broker.counts()["owner_nonces"], 1)

    def test_schema_supports_ordered_steps_but_live_policy_defaults_to_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            packet = release_packet(
                bundle=release_bundle(step_count=2)
            )
            with self.open_bound(path) as broker:
                with self.assertRaisesRegex(
                    store.BudgetExceeded, "max_prs_per_bundle"
                ):
                    broker.reserve(packet, LIMITS, now=NOW + timedelta(seconds=2))
                multi_limits = store.BudgetLimits(
                    unique_requests_per_hour=20,
                    owner_assertions_per_hour=20,
                    bundles_per_day=20,
                    mutation_attempts_per_day=20,
                    confirmed_merges_per_day=20,
                    consecutive_indeterminate_limit=2,
                    max_prs_per_bundle=2,
                )
                reserved = broker.reserve(
                    packet,
                    multi_limits,
                    now=NOW + timedelta(seconds=2),
                )
                with self.assertRaisesRegex(
                    store.StateTransitionError, "prior release step"
                ):
                    broker.begin_mutation(
                        reserved.bundle_key,
                        1,
                        packet["packet_id"],
                        "jlra-second-too-early",
                        multi_limits,
                        expected_base_sha="e" * 40,
                        precondition_digest=PRECONDITION,
                        now=NOW + timedelta(seconds=3),
                    )
                broker.begin_mutation(
                    reserved.bundle_key,
                    0,
                    packet["packet_id"],
                    "jlra-first",
                    multi_limits,
                    expected_base_sha="a" * 40,
                    precondition_digest=PRECONDITION,
                    now=NOW + timedelta(seconds=3),
                )
                broker.confirm_step(
                    reserved.bundle_key,
                    0,
                    packet["packet_id"],
                    "jlra-first",
                    merge_sha="e" * 40,
                    parent_sha="a" * 40,
                    tree_sha="f" * 40,
                    merged_by="release-bot",
                    now=NOW + timedelta(seconds=4),
                )
                second = broker.begin_mutation(
                    reserved.bundle_key,
                    1,
                    packet["packet_id"],
                    "jlra-second",
                    multi_limits,
                    expected_base_sha="e" * 40,
                    precondition_digest=PRECONDITION,
                    now=NOW + timedelta(seconds=5),
                )
                self.assertEqual(second.disposition, "charged")
                self.assertEqual(
                    broker.bundle_snapshot(reserved.bundle_key)["steps"][1][
                        "expected_base_sha"
                    ],
                    "e" * 40,
                )

    def test_charged_attempt_is_durable_and_absent_retry_requires_exact_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            bundle = release_bundle()
            packet = release_packet(packet_nonce=1, bundle=bundle)
            alias = release_packet(packet_nonce=2, bundle=bundle)
            with self.open_bound(path) as broker:
                reserved, mutation = self.reserve_and_charge(
                    broker, packet
                )
                self.assertEqual(mutation.disposition, "charged")
                exact = broker.begin_mutation(
                    reserved.bundle_key,
                    0,
                    packet["packet_id"],
                    "jlra-attempt-1",
                    LIMITS,
                    expected_base_sha="a" * 40,
                    precondition_digest=PRECONDITION,
                    now=NOW + timedelta(seconds=12),
                )
                self.assertEqual(exact.disposition, "already_charged")
                pending = broker.pending_recovery()
                self.assertEqual(len(pending), 1)
                self.assertEqual(pending[0].attempt_id, "jlra-attempt-1")
                before_alias = broker.counts()
                with self.assertRaisesRegex(
                    store.SemanticTerminalReplayError,
                    "fresh packet",
                ):
                    broker.reserve(
                        alias,
                        LIMITS,
                        now=NOW + timedelta(seconds=12),
                    )
                self.assertEqual(broker.counts(), before_alias)
                self.assertIsNone(
                    broker.receipt_for_packet(alias["packet_id"])
                )
                recovered = broker.record_recovery(
                    reserved.bundle_key,
                    0,
                    packet["packet_id"],
                    "jlra-attempt-1",
                    "jlrr-absent-1",
                    "absent",
                    {"branch_sha": "a" * 40, "pr_merged": False},
                    LIMITS,
                    now=NOW + timedelta(seconds=13),
                )
                self.assertEqual(recovered.disposition, "recorded")
                self.assertEqual(broker.pending_recovery(), [])
                retry = broker.begin_mutation(
                    reserved.bundle_key,
                    0,
                    packet["packet_id"],
                    "jlra-attempt-2",
                    LIMITS,
                    expected_base_sha="a" * 40,
                    precondition_digest=PRECONDITION,
                    now=NOW + timedelta(seconds=14),
                )
                self.assertEqual(retry.disposition, "charged")
                retry_snapshot = broker.bundle_snapshot(
                    reserved.bundle_key
                )
                retry_step = retry_snapshot["steps"][0]
                self.assertEqual(
                    retry_step["latest_attempt"],
                    {
                        "attempt_id": "jlra-attempt-2",
                        "packet_id": packet["packet_id"],
                        "attempt_number": 2,
                        "precondition_digest": PRECONDITION,
                        "expected_base_sha": "a" * 40,
                        "state": "pending",
                        "started_at": "2026-07-16T12:00:14Z",
                        "terminal_at": None,
                        "merge_sha": None,
                        "parent_sha": None,
                        "tree_sha": None,
                        "merged_by": None,
                        "terminal_detail": None,
                    },
                )
                self.assertEqual(
                    retry_step["latest_recovery"],
                    {
                        "recovery_id": "jlrr-absent-1",
                        "attempt_id": "jlra-attempt-1",
                        "classification": "absent",
                        "evidence_digest": store.sha256_json(
                            {
                                "branch_sha": "a" * 40,
                                "pr_merged": False,
                            }
                        ),
                        "evidence": {
                            "branch_sha": "a" * 40,
                            "pr_merged": False,
                        },
                        "recorded_at": "2026-07-16T12:00:13Z",
                    },
                )
                self.assertEqual(
                    retry_step["terminal_detail"],
                    {
                        "branch_sha": "a" * 40,
                        "pr_merged": False,
                    },
                )

            with self.open_bound(path) as reopened:
                pending = reopened.pending_recovery()
                self.assertEqual(len(pending), 1)
                self.assertEqual(pending[0].attempt_number, 2)
                self.assertEqual(pending[0].packet_id, packet["packet_id"])
                reopened.record_recovery(
                    reserved.bundle_key,
                    0,
                    packet["packet_id"],
                    "jlra-attempt-2",
                    "jlrr-absent-2",
                    "absent",
                    {"branch_sha": "a" * 40, "pr_merged": False},
                    LIMITS,
                    now=NOW + timedelta(seconds=15),
                )
                self.assertEqual(
                    reopened.bundles_awaiting_terminal_receipt(),
                    [reserved.bundle_key],
                )
                exhausted_snapshot = reopened.bundle_snapshot(
                    reserved.bundle_key
                )
                exhausted_step = exhausted_snapshot["steps"][0]
                self.assertEqual(
                    exhausted_step["latest_attempt"]["attempt_id"],
                    "jlra-attempt-2",
                )
                self.assertEqual(
                    exhausted_step["latest_attempt"]["state"], "absent"
                )
                self.assertEqual(
                    exhausted_step["latest_attempt"]["terminal_at"],
                    "2026-07-16T12:00:15Z",
                )
                self.assertEqual(
                    exhausted_step["latest_recovery"]["attempt_id"],
                    "jlra-attempt-2",
                )
                self.assertEqual(
                    exhausted_step["latest_recovery"]["classification"],
                    "absent",
                )
                with self.assertRaisesRegex(
                    store.StateTransitionError, "exhausted"
                ):
                    reopened.begin_mutation(
                        reserved.bundle_key,
                        0,
                        packet["packet_id"],
                        "jlra-attempt-3",
                        LIMITS,
                        expected_base_sha="a" * 40,
                        precondition_digest=PRECONDITION,
                        now=NOW + timedelta(seconds=16),
                    )

    def test_confirmed_snapshot_reconstructs_receipt_after_confirm_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            packet = release_packet()
            with self.open_bound(path) as broker:
                reserved, _ = self.reserve_and_charge(broker, packet)
                self.confirm(broker, reserved, packet)

            # Simulate daemon restart after confirm_step committed but before
            # the signed terminal receipt was built and appended.
            with self.open_bound(path) as reopened:
                snapshot = reopened.bundle_snapshot(reserved.bundle_key)
                self.assertEqual(snapshot["state"], "executing")
                self.assertEqual(
                    snapshot["first_packet_id"], packet["packet_id"]
                )
                self.assertEqual(
                    snapshot["last_packet_id"], packet["packet_id"]
                )
                self.assertEqual(snapshot["default_branch"], "main")
                self.assertEqual(snapshot["step_count"], 1)
                self.assertIsNone(snapshot["terminal_at"])
                step = snapshot["steps"][0]
                self.assertEqual(step["state"], "confirmed")
                self.assertEqual(
                    step["confirmed_at"], "2026-07-16T12:00:20Z"
                )
                self.assertIsNone(step["terminal_detail"])
                self.assertIsNone(step["latest_recovery"])
                self.assertEqual(
                    step["latest_attempt"],
                    {
                        "attempt_id": "jlra-attempt-1",
                        "packet_id": packet["packet_id"],
                        "attempt_number": 1,
                        "precondition_digest": PRECONDITION,
                        "expected_base_sha": "a" * 40,
                        "state": "confirmed",
                        "started_at": "2026-07-16T12:00:11Z",
                        "terminal_at": "2026-07-16T12:00:20Z",
                        "merge_sha": "e" * 40,
                        "parent_sha": "a" * 40,
                        "tree_sha": "f" * 40,
                        "merged_by": "john-lomein-release[bot]",
                        "terminal_detail": None,
                    },
                )

    def test_confirmation_and_terminal_receipt_are_exactly_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            packet = release_packet()
            with self.open_bound(path) as broker:
                reserved, _ = self.reserve_and_charge(broker, packet)
                confirmed = self.confirm(broker, reserved, packet)
                self.assertEqual(confirmed.disposition, "confirmed")
                replayed_confirmation = self.confirm(
                    broker, reserved, packet
                )
                self.assertEqual(
                    replayed_confirmation.disposition,
                    "already_confirmed",
                )
                receipt = terminal_receipt(
                    packet, reserved.bundle_key, "succeeded"
                )
                terminal = broker.terminalize_bundle(
                    reserved.bundle_key,
                    packet["packet_id"],
                    "succeeded",
                    receipt,
                    LIMITS,
                    now=NOW + timedelta(seconds=21),
                )
                self.assertEqual(terminal.disposition, "terminalized")
                terminal_replay = broker.terminalize_bundle(
                    reserved.bundle_key,
                    packet["packet_id"],
                    "succeeded",
                    receipt,
                    LIMITS,
                    now=NOW + timedelta(seconds=22),
                )
                self.assertEqual(
                    terminal_replay.disposition, "receipt_replay"
                )
                exact_packet = broker.reserve(
                    packet, LIMITS, now=NOW + timedelta(hours=2)
                )
                self.assertEqual(
                    exact_packet.disposition, "exact_terminal_replay"
                )
                self.assertEqual(exact_packet.receipt, receipt)
                mutation_replay = broker.begin_mutation(
                    reserved.bundle_key,
                    0,
                    packet["packet_id"],
                    "jlra-never",
                    LIMITS,
                    expected_base_sha="a" * 40,
                    precondition_digest=PRECONDITION,
                    now=NOW + timedelta(hours=2),
                )
                self.assertEqual(
                    mutation_replay.disposition, "terminal_replay"
                )
                foreign_packet = release_packet(
                    packet_nonce=2,
                    bundle=packet["request"]["bundle"],
                )
                before_foreign = broker.counts()
                with self.assertRaisesRegex(
                    store.SemanticTerminalReplayError,
                    "fresh packet",
                ):
                    broker.reserve(
                        foreign_packet,
                        LIMITS,
                        now=NOW + timedelta(seconds=22),
                    )
                self.assertEqual(broker.counts(), before_foreign)
                self.assertIsNone(
                    broker.receipt_for_packet(
                        foreign_packet["packet_id"]
                    )
                )
                counts = broker.counts()
                self.assertEqual(counts["mutation_attempts"], 1)
                self.assertEqual(counts["receipts"], 1)
                self.assertEqual(
                    sum(
                        1
                        for row in broker._db.execute(
                            """
                            SELECT kind FROM budget_events
                            WHERE kind = 'confirmed_merge'
                            """
                        )
                    ),
                    1,
                )

    def test_recovered_confirmation_records_evidence_and_merge_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            packet = release_packet()
            with self.open_bound(path) as broker:
                reserved, _ = self.reserve_and_charge(broker, packet)
                recovered = broker.record_recovery(
                    reserved.bundle_key,
                    0,
                    packet["packet_id"],
                    "jlra-attempt-1",
                    "jlrr-confirmed-1",
                    "confirmed",
                    {
                        "merge_commit_sha": "e" * 40,
                        "observed_branch_sha": "e" * 40,
                    },
                    LIMITS,
                    merge_sha="e" * 40,
                    parent_sha="a" * 40,
                    tree_sha="f" * 40,
                    merged_by="release-bot",
                    now=NOW + timedelta(seconds=12),
                )
                self.assertEqual(recovered.disposition, "recorded")
                replay = broker.record_recovery(
                    reserved.bundle_key,
                    0,
                    packet["packet_id"],
                    "jlra-attempt-1",
                    "jlrr-confirmed-1",
                    "confirmed",
                    {
                        "merge_commit_sha": "e" * 40,
                        "observed_branch_sha": "e" * 40,
                    },
                    LIMITS,
                    merge_sha="e" * 40,
                    parent_sha="a" * 40,
                    tree_sha="f" * 40,
                    merged_by="release-bot",
                    now=NOW + timedelta(seconds=13),
                )
                self.assertEqual(replay.disposition, "already_recorded")
                recovery_snapshot = broker.bundle_snapshot(
                    reserved.bundle_key
                )
                recovery_step = recovery_snapshot["steps"][0]
                self.assertEqual(recovery_step["state"], "confirmed")
                self.assertEqual(
                    recovery_step["latest_attempt"]["attempt_id"],
                    "jlra-attempt-1",
                )
                self.assertEqual(
                    recovery_step["latest_recovery"],
                    {
                        "recovery_id": "jlrr-confirmed-1",
                        "attempt_id": "jlra-attempt-1",
                        "classification": "confirmed",
                        "evidence_digest": store.sha256_json(
                            {
                                "merge_commit_sha": "e" * 40,
                                "observed_branch_sha": "e" * 40,
                            }
                        ),
                        "evidence": {
                            "merge_commit_sha": "e" * 40,
                            "observed_branch_sha": "e" * 40,
                        },
                        "recorded_at": "2026-07-16T12:00:12Z",
                    },
                )
                self.assertEqual(broker.counts()["recovery_records"], 1)
                confirmed_events = broker._db.execute(
                    """
                    SELECT count(*)
                    FROM budget_events
                    WHERE kind = 'confirmed_merge'
                    """
                ).fetchone()[0]
                self.assertEqual(confirmed_events, 1)

    def test_each_budget_is_durable_and_exact_replay_is_free(self):
        cases = (
            (
                "unique_requests_per_hour",
                {
                    "unique_requests_per_hour": 1,
                    "owner_assertions_per_hour": 10,
                },
            ),
            (
                "owner_assertions_per_hour",
                {
                    "unique_requests_per_hour": 10,
                    "owner_assertions_per_hour": 1,
                },
            ),
            (
                "bundles_per_day",
                {
                    "unique_requests_per_hour": 10,
                    "owner_assertions_per_hour": 10,
                    "bundles_per_day": 1,
                },
            ),
        )
        for budget_name, overrides in cases:
            with self.subTest(budget=budget_name):
                with tempfile.TemporaryDirectory() as tmp:
                    path = self.state_path(Path(tmp))
                    values = {
                        "unique_requests_per_hour": 20,
                        "owner_assertions_per_hour": 20,
                        "bundles_per_day": 20,
                        "mutation_attempts_per_day": 20,
                        "confirmed_merges_per_day": 20,
                        "consecutive_indeterminate_limit": 2,
                    }
                    values.update(overrides)
                    limits = store.BudgetLimits(**values)
                    first_packet = release_packet(
                        packet_nonce=1,
                        bundle=release_bundle(bundle_nonce=1),
                    )
                    second_packet = release_packet(
                        packet_nonce=2,
                        bundle=release_bundle(
                            bundle_nonce=2,
                            repository_id=222222,
                            repository_full_name="acme/other",
                        ),
                    )
                    with self.open_bound(path) as broker:
                        broker.reserve(
                            first_packet,
                            limits,
                            now=NOW + timedelta(seconds=3),
                        )
                        broker.reserve(
                            first_packet,
                            limits,
                            now=NOW + timedelta(hours=2),
                        )
                        with self.assertRaises(store.BudgetExceeded) as ctx:
                            broker.reserve(
                                second_packet,
                                limits,
                                now=NOW + timedelta(seconds=3),
                            )
                        self.assertEqual(ctx.exception.budget, budget_name)

    def test_attempt_and_confirmed_merge_budgets_reserve_capacity_safely(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            attempt_limits = store.BudgetLimits(
                unique_requests_per_hour=20,
                owner_assertions_per_hour=20,
                bundles_per_day=20,
                mutation_attempts_per_day=1,
                confirmed_merges_per_day=20,
                consecutive_indeterminate_limit=2,
            )
            first_packet = release_packet(
                packet_nonce=1,
                bundle=release_bundle(
                    bundle_nonce=1,
                    repository_id=111111,
                    repository_full_name="acme/one",
                ),
            )
            second_packet = release_packet(
                packet_nonce=2,
                bundle=release_bundle(
                    bundle_nonce=2,
                    repository_id=222222,
                    repository_full_name="acme/two",
                ),
            )
            with self.open_bound(path) as broker:
                first = broker.reserve(
                    first_packet,
                    attempt_limits,
                    now=NOW + timedelta(seconds=3),
                )
                second = broker.reserve(
                    second_packet,
                    attempt_limits,
                    now=NOW + timedelta(seconds=3),
                )
                broker.begin_mutation(
                    first.bundle_key,
                    0,
                    first_packet["packet_id"],
                    "jlra-one",
                    attempt_limits,
                    expected_base_sha="a" * 40,
                    precondition_digest=PRECONDITION,
                    now=NOW + timedelta(seconds=4),
                )
                with self.assertRaises(store.BudgetExceeded) as ctx:
                    broker.begin_mutation(
                        second.bundle_key,
                        0,
                        second_packet["packet_id"],
                        "jlra-two",
                        attempt_limits,
                        expected_base_sha="a" * 40,
                        precondition_digest=PRECONDITION,
                        now=NOW + timedelta(seconds=4),
                    )
                self.assertEqual(
                    ctx.exception.budget, "mutation_attempts_per_day"
                )

        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            merge_limits = store.BudgetLimits(
                unique_requests_per_hour=20,
                owner_assertions_per_hour=20,
                bundles_per_day=20,
                mutation_attempts_per_day=20,
                confirmed_merges_per_day=1,
                consecutive_indeterminate_limit=2,
            )
            first_packet = release_packet(
                packet_nonce=1,
                bundle=release_bundle(
                    bundle_nonce=1,
                    repository_id=111111,
                    repository_full_name="acme/one",
                ),
            )
            second_packet = release_packet(
                packet_nonce=2,
                bundle=release_bundle(
                    bundle_nonce=2,
                    repository_id=222222,
                    repository_full_name="acme/two",
                ),
            )
            with self.open_bound(path) as broker:
                first = broker.reserve(
                    first_packet,
                    merge_limits,
                    now=NOW + timedelta(seconds=3),
                )
                second = broker.reserve(
                    second_packet,
                    merge_limits,
                    now=NOW + timedelta(seconds=3),
                )
                broker.begin_mutation(
                    first.bundle_key,
                    0,
                    first_packet["packet_id"],
                    "jlra-one",
                    merge_limits,
                    expected_base_sha="a" * 40,
                    precondition_digest=PRECONDITION,
                    now=NOW + timedelta(seconds=4),
                )
                with self.assertRaises(store.BudgetExceeded) as ctx:
                    broker.begin_mutation(
                        second.bundle_key,
                        0,
                        second_packet["packet_id"],
                        "jlra-two",
                        merge_limits,
                        expected_base_sha="a" * 40,
                        precondition_digest=PRECONDITION,
                        now=NOW + timedelta(seconds=4),
                    )
                self.assertEqual(
                    ctx.exception.budget, "confirmed_merges_per_day"
                )

    def test_rejected_snapshot_preserves_deterministic_stop_and_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            packet = release_packet()
            detail = {
                "reason": "head_changed_before_mutation",
                "authorized_head": "2" * 40,
                "observed_head": "9" * 40,
            }
            with self.open_bound(path) as broker:
                reserved = broker.reserve(
                    packet, LIMITS, now=NOW + timedelta(seconds=2)
                )
                broker.stop_step(
                    reserved.bundle_key,
                    0,
                    packet["packet_id"],
                    "rejected",
                    detail,
                    now=NOW + timedelta(seconds=3),
                )
                snapshot = broker.bundle_snapshot(reserved.bundle_key)
                self.assertEqual(
                    snapshot["last_packet_id"], packet["packet_id"]
                )
                step = snapshot["steps"][0]
                self.assertEqual(step["state"], "rejected")
                self.assertEqual(step["terminal_detail"], detail)
                self.assertIsNone(step["latest_attempt"])
                self.assertIsNone(step["latest_recovery"])
                self.assertIsNone(step["confirmed_at"])

    def test_threshold_and_immediate_circuits_block_new_bundles_not_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            packets = [
                release_packet(
                    packet_nonce=index,
                    bundle=release_bundle(bundle_nonce=index),
                )
                for index in (1, 2, 3)
            ]
            with self.open_bound(path) as broker:
                first = broker.reserve(
                    packets[0], LIMITS, now=NOW + timedelta(seconds=4)
                )
                broker.stop_step(
                    first.bundle_key,
                    0,
                    packets[0]["packet_id"],
                    "indeterminate",
                    {"reason": "transport_timeout"},
                    now=NOW + timedelta(seconds=5),
                )
                broker.terminalize_bundle(
                    first.bundle_key,
                    packets[0]["packet_id"],
                    "indeterminate",
                    terminal_receipt(
                        packets[0], first.bundle_key, "indeterminate"
                    ),
                    LIMITS,
                    now=NOW + timedelta(seconds=6),
                )
                self.assertEqual(
                    broker.circuit_status(
                        "widget-production", 987654
                    )["state"],
                    "closed",
                )
                second = broker.reserve(
                    packets[1], LIMITS, now=NOW + timedelta(seconds=7)
                )
                broker.stop_step(
                    second.bundle_key,
                    0,
                    packets[1]["packet_id"],
                    "indeterminate",
                    {"reason": "transport_timeout_again"},
                    now=NOW + timedelta(seconds=8),
                )
                broker.terminalize_bundle(
                    second.bundle_key,
                    packets[1]["packet_id"],
                    "indeterminate",
                    terminal_receipt(
                        packets[1], second.bundle_key, "indeterminate"
                    ),
                    LIMITS,
                    now=NOW + timedelta(seconds=9),
                )
                status = broker.circuit_status(
                    "widget-production", 987654
                )
                self.assertEqual(status["state"], "open")
                self.assertEqual(status["consecutive_indeterminate"], 2)
                with self.assertRaises(store.CircuitOpenError):
                    broker.reserve(
                        packets[2],
                        LIMITS,
                        now=NOW + timedelta(seconds=10),
                    )
                replay = broker.reserve(
                    packets[1],
                    LIMITS,
                    now=NOW + timedelta(hours=2),
                )
                self.assertEqual(
                    replay.disposition, "exact_terminal_replay"
                )
                broker.close_circuit(
                    "widget-production",
                    987654,
                    "acme/widget",
                    now=NOW + timedelta(seconds=11),
                )
                self.assertEqual(
                    broker.circuit_status(
                        "widget-production", 987654
                    )["state"],
                    "closed",
                )

        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            with self.open_bound(path) as broker:
                broker.open_circuit(
                    instance_slug="widget-production",
                    repository_id=987654,
                    repository_full_name="acme/widget",
                    reason={"reason": "unexpected_parent"},
                    now=NOW,
                )
                broker.open_circuit(
                    instance_slug="widget-production",
                    repository_id=987654,
                    repository_full_name="acme/widget",
                    reason={"reason": "unexpected_parent"},
                    now=NOW + timedelta(seconds=1),
                )
                self.assertEqual(
                    broker.circuit_status(
                        "widget-production", 987654
                    )["consecutive_indeterminate"],
                    1,
                )
                with self.assertRaises(store.CircuitOpenError):
                    broker.reserve(
                        release_packet(),
                        LIMITS,
                        now=NOW + timedelta(seconds=2),
                    )

    def test_indeterminate_recovery_can_open_immediate_circuit_and_waits_for_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            packet = release_packet()
            with self.open_bound(path) as broker:
                reserved, _ = self.reserve_and_charge(broker, packet)
                broker.record_recovery(
                    reserved.bundle_key,
                    0,
                    packet["packet_id"],
                    "jlra-attempt-1",
                    "jlrr-indeterminate-1",
                    "indeterminate",
                    {
                        "expected_parent": "a" * 40,
                        "observed_parent": "9" * 40,
                    },
                    LIMITS,
                    circuit_mode="immediate",
                    now=NOW + timedelta(seconds=12),
                )
                snapshot = broker.bundle_snapshot(reserved.bundle_key)
                step = snapshot["steps"][0]
                expected_evidence = {
                    "expected_parent": "a" * 40,
                    "observed_parent": "9" * 40,
                }
                self.assertEqual(step["state"], "indeterminate")
                self.assertEqual(
                    step["latest_attempt"]["state"], "indeterminate"
                )
                self.assertEqual(
                    step["latest_attempt"]["terminal_at"],
                    "2026-07-16T12:00:12Z",
                )
                self.assertEqual(
                    step["latest_attempt"]["terminal_detail"],
                    expected_evidence,
                )
                self.assertEqual(step["terminal_detail"], expected_evidence)
                self.assertEqual(
                    step["latest_recovery"],
                    {
                        "recovery_id": "jlrr-indeterminate-1",
                        "attempt_id": "jlra-attempt-1",
                        "classification": "indeterminate",
                        "evidence_digest": store.sha256_json(
                            expected_evidence
                        ),
                        "evidence": expected_evidence,
                        "recorded_at": "2026-07-16T12:00:12Z",
                    },
                )
                self.assertEqual(
                    broker.circuit_status(
                        "widget-production", 987654
                    )["state"],
                    "open",
                )
                self.assertEqual(
                    broker.bundles_awaiting_terminal_receipt(),
                    [reserved.bundle_key],
                )
                terminal = broker.terminalize_bundle(
                    reserved.bundle_key,
                    packet["packet_id"],
                    "indeterminate",
                    terminal_receipt(
                        packet, reserved.bundle_key, "indeterminate"
                    ),
                    LIMITS,
                    circuit_mode="none",
                    now=NOW + timedelta(seconds=13),
                )
                self.assertEqual(terminal.disposition, "terminalized")
                self.assertEqual(
                    broker.bundles_awaiting_terminal_receipt(), []
                )

    def test_one_indeterminate_bundle_is_counted_once_across_recovery_and_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            packet = release_packet()
            with self.open_bound(path) as broker:
                reserved, _ = self.reserve_and_charge(broker, packet)
                broker.record_recovery(
                    reserved.bundle_key,
                    0,
                    packet["packet_id"],
                    "jlra-attempt-1",
                    "jlrr-threshold-1",
                    "indeterminate",
                    {"reason": "ambiguous_readback"},
                    LIMITS,
                    circuit_mode="threshold",
                    now=NOW + timedelta(seconds=12),
                )
                self.assertEqual(
                    broker.circuit_status(
                        "widget-production", 987654
                    )["consecutive_indeterminate"],
                    1,
                )
                broker.terminalize_bundle(
                    reserved.bundle_key,
                    packet["packet_id"],
                    "indeterminate",
                    terminal_receipt(
                        packet, reserved.bundle_key, "indeterminate"
                    ),
                    LIMITS,
                    # The default is threshold.  Durable circuit event
                    # idempotency must keep this same bundle from counting
                    # twice.
                    now=NOW + timedelta(seconds=13),
                )
                status = broker.circuit_status(
                    "widget-production", 987654
                )
                self.assertEqual(status["state"], "closed")
                self.assertEqual(status["consecutive_indeterminate"], 1)

    def test_receipt_chain_is_append_only_and_tamper_evident(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            packet_one = release_packet(
                packet_nonce=1,
                bundle=release_bundle(
                    bundle_nonce=1,
                    repository_id=111111,
                    repository_full_name="acme/one",
                ),
            )
            packet_two = release_packet(
                packet_nonce=2,
                bundle=release_bundle(
                    bundle_nonce=2,
                    repository_id=222222,
                    repository_full_name="acme/two",
                ),
            )
            with self.open_bound(path) as broker:
                first, _ = self.reserve_and_charge(
                    broker,
                    packet_one,
                    attempt_id="jlra-one",
                )
                self.confirm(
                    broker,
                    first,
                    packet_one,
                    attempt_id="jlra-one",
                    merge_sha="e" * 40,
                )
                first_terminal = broker.terminalize_bundle(
                    first.bundle_key,
                    packet_one["packet_id"],
                    "succeeded",
                    terminal_receipt(
                        packet_one, first.bundle_key, "succeeded"
                    ),
                    LIMITS,
                    expected_previous_chain_digest=store.ZERO_DIGEST,
                    now=NOW + timedelta(seconds=21),
                )
                second, _ = self.reserve_and_charge(
                    broker,
                    packet_two,
                    attempt_id="jlra-two",
                )
                self.confirm(
                    broker,
                    second,
                    packet_two,
                    attempt_id="jlra-two",
                    merge_sha="8" * 40,
                    tree_sha="7" * 40,
                )
                with self.assertRaisesRegex(
                    store.StateTransitionError, "chain head changed"
                ):
                    broker.terminalize_bundle(
                        second.bundle_key,
                        packet_two["packet_id"],
                        "succeeded",
                        terminal_receipt(
                            packet_two, second.bundle_key, "succeeded"
                        ),
                        LIMITS,
                        expected_previous_chain_digest=store.ZERO_DIGEST,
                        now=NOW + timedelta(seconds=22),
                    )
                second_terminal = broker.terminalize_bundle(
                    second.bundle_key,
                    packet_two["packet_id"],
                    "succeeded",
                    terminal_receipt(
                        packet_two, second.bundle_key, "succeeded"
                    ),
                    LIMITS,
                    expected_previous_chain_digest=(
                        first_terminal.chain_digest
                    ),
                    now=NOW + timedelta(seconds=22),
                )
                self.assertNotEqual(
                    first_terminal.chain_digest,
                    second_terminal.chain_digest,
                )
                self.assertEqual(
                    broker.latest_receipt_chain_digest(),
                    second_terminal.chain_digest,
                )
                rows = broker._db.execute(
                    """
                    SELECT receipt_sequence, previous_chain_digest,
                           chain_digest
                    FROM receipts
                    ORDER BY receipt_sequence
                    """
                ).fetchall()
                self.assertEqual(
                    rows[0]["previous_chain_digest"], store.ZERO_DIGEST
                )
                self.assertEqual(
                    rows[1]["previous_chain_digest"],
                    rows[0]["chain_digest"],
                )
                with self.assertRaises(sqlite3.IntegrityError):
                    broker._db.execute(
                        """
                        UPDATE receipts
                        SET previous_chain_digest = ?
                        WHERE receipt_sequence = 2
                        """,
                        ("sha256:" + ("9" * 64),),
                    )

                # A privileged database tamperer can drop a trigger, but the
                # explicit chain verifier still detects modified metadata.
                broker._db.execute("DROP TRIGGER receipts_no_update")
                broker._db.execute(
                    """
                    UPDATE receipts
                    SET previous_chain_digest = ?
                    WHERE receipt_sequence = 2
                    """,
                    ("sha256:" + ("9" * 64),),
                )
                with self.assertRaisesRegex(
                    store.StoreCorruptionError, "predecessor"
                ):
                    broker.verify_receipt_chain()

    def test_snapshot_rejects_attempt_recovery_and_detail_corruption(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            packet = release_packet()
            with self.open_bound(path) as broker:
                reserved, _ = self.reserve_and_charge(broker, packet)
                broker._db.execute(
                    """
                    UPDATE mutation_attempts
                    SET precondition_digest = 'not-a-digest'
                    WHERE attempt_id = 'jlra-attempt-1'
                    """
                )
                with self.assertRaisesRegex(
                    store.StoreCorruptionError, "precondition digest"
                ):
                    broker.bundle_snapshot(reserved.bundle_key)

        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            packet = release_packet()
            with self.open_bound(path) as broker:
                reserved, _ = self.reserve_and_charge(broker, packet)
                broker.record_recovery(
                    reserved.bundle_key,
                    0,
                    packet["packet_id"],
                    "jlra-attempt-1",
                    "jlrr-corrupt-evidence",
                    "absent",
                    {"branch_sha": "a" * 40, "pr_merged": False},
                    LIMITS,
                    now=NOW + timedelta(seconds=12),
                )
                broker._db.execute(
                    "DROP TRIGGER recovery_records_no_update"
                )
                broker._db.execute(
                    """
                    UPDATE recovery_records
                    SET evidence_digest = ?
                    WHERE recovery_id = 'jlrr-corrupt-evidence'
                    """,
                    ("sha256:" + ("9" * 64),),
                )
                with self.assertRaisesRegex(
                    store.StoreCorruptionError, "evidence digest"
                ):
                    broker.bundle_snapshot(reserved.bundle_key)

        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            packet = release_packet()
            with self.open_bound(path) as broker:
                reserved = broker.reserve(
                    packet, LIMITS, now=NOW + timedelta(seconds=2)
                )
                broker.stop_step(
                    reserved.bundle_key,
                    0,
                    packet["packet_id"],
                    "rejected",
                    {"reason": "head_changed"},
                    now=NOW + timedelta(seconds=3),
                )
                broker._db.execute(
                    """
                    UPDATE bundle_steps
                    SET terminal_detail_json = '{"z":1,"a":2}'
                    WHERE bundle_key = ? AND position = 0
                    """,
                    (reserved.bundle_key,),
                )
                with self.assertRaisesRegex(
                    store.StoreCorruptionError, "not canonical"
                ):
                    broker.bundle_snapshot(reserved.bundle_key)

    def test_step_tamper_and_invalid_success_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.state_path(Path(tmp))
            packet = release_packet()
            with self.open_bound(path) as broker:
                reserved = broker.reserve(
                    packet, LIMITS, now=NOW + timedelta(seconds=2)
                )
                with self.assertRaisesRegex(
                    store.StateTransitionError, "every step"
                ):
                    broker.terminalize_bundle(
                        reserved.bundle_key,
                        packet["packet_id"],
                        "succeeded",
                        terminal_receipt(
                            packet, reserved.bundle_key, "succeeded"
                        ),
                        LIMITS,
                        now=NOW + timedelta(seconds=3),
                    )
                broker._db.execute(
                    """
                    UPDATE bundle_steps
                    SET step_json = ?
                    WHERE bundle_key = ? AND position = 0
                    """,
                    (
                        store.canonical_json({"tampered": True}),
                        reserved.bundle_key,
                    ),
                )
                with self.assertRaisesRegex(
                    store.StoreCorruptionError, "step digest"
                ):
                    broker.bundle_snapshot(reserved.bundle_key)


if __name__ == "__main__":
    unittest.main()
