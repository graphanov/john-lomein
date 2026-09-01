#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_broker import john_lomein_release_broker_protocol as protocol
from release_broker.john_lomein_release_broker_actions import (
    validate_preflight,
)
from release_broker.john_lomein_release_broker_github_live import (
    ReleaseGitHubLiveError,
)
from release_broker.john_lomein_release_broker_service import (
    ProtectedReleaseBrokerService,
)
from release_broker.john_lomein_release_broker_store import (
    BudgetLimits,
    ReleaseBrokerStore,
)
from tests.test_release_broker_actions import snapshot as base_snapshot
from tests.test_release_broker_protocol import (
    owner_envelope,
    release_bundle,
    release_config,
    release_packet,
)


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
APPROVAL = (
    "APPROVE JOHN-LOMEIN RELEASE BUNDLE: squash-merge the exact "
    "listed PR; DO NOT publish."
)
MERGE = "d" * 40
MERGE_TREE = "e" * 40


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def submission_for(
    key: Ed25519PrivateKey,
    *,
    bundle: dict[str, Any] | None = None,
    nonce: str = "c" * 64,
) -> dict[str, Any]:
    bundle = copy.deepcopy(bundle or release_bundle())
    assertion = owner_envelope(
        bundle, key, approval_text=APPROVAL
    )
    assertion["payload"]["nonce"] = nonce
    assertion["signature"] = (
        base64.urlsafe_b64encode(
            key.sign(protocol.canonical_json(assertion["payload"]))
        )
        .decode("ascii")
        .rstrip("=")
    )
    packet = release_packet(
        bundle, assertion, approval_text=APPROVAL
    )
    return {
        "schema_version": protocol.SUBMISSION_SCHEMA,
        "packet": packet,
    }


def fake_signer(
    payload: Mapping[str, Any],
    _config: Mapping[str, Any],
    _packet: Mapping[str, Any],
) -> Mapping[str, Any]:
    return {
        "schema_version": "test-release-signed-receipt.v1",
        "payload": dict(payload),
        "signature": "test-only",
    }


def fake_verifier(
    receipt: Mapping[str, Any],
    _config: Mapping[str, Any],
    _packet: Mapping[str, Any],
    _now: datetime,
) -> Mapping[str, Any]:
    return receipt


def live_snapshot(packet: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base_snapshot())
    bundle = packet["request"]["bundle"]
    pr = bundle["ordered_prs"][0]
    result["repository"] = bundle["repository"]["full_name"]
    result["repository_id"] = bundle["repository"]["id"]
    result["pr"].update(
        {
            "number": pr["number"],
            "url": pr["url"],
            "head_oid": pr["head_sha"],
            "base_branch": pr["base_branch"],
            "base_oid": bundle["initial_base_sha"],
            "author_login": pr["author_login"],
            "changed_files": pr["changed_path_count"],
            "potential_merge_commit_oid": "f" * 40,
            "potential_merge_tree_oid": pr[
                "expected_merge_tree_sha"
            ],
            "potential_merge_parent_oids": [
                bundle["initial_base_sha"],
                pr["head_sha"],
            ],
        }
    )
    result["default_branch"]["commit"]["oid"] = bundle[
        "initial_base_sha"
    ]
    result["files"] = [
        {
            "path": path,
            "additions": 1,
            "deletions": 0,
            "change_type": "MODIFIED",
        }
        for path in pr["changed_paths"]
    ]
    result["issue_comments"][0]["body"] = (
        "<!-- john-lomein-release-review:v1 "
        f"head={pr['head_sha']} verdict=clean -->"
    )
    return result


class FakeLive:
    def __init__(self, packet: Mapping[str, Any]) -> None:
        self.packet = packet
        self.mutations = 0
        self.merged = False
        self.base_race = False
        self.preflight_failure = False
        self.preflight_tree_mismatch = False
        self.mutation_ambiguous = False
        self.readback_unavailable = False
        self.wrong_actor = False
        self.wrong_parent = False
        self.merge_oid = MERGE
        self.merge_tree = MERGE_TREE

    @property
    def bundle(self) -> Mapping[str, Any]:
        return self.packet["request"]["bundle"]

    @property
    def pr(self) -> Mapping[str, Any]:
        return self.bundle["ordered_prs"][0]

    def fetch_merge_snapshot(self, *, pr_number: int) -> dict[str, Any]:
        if pr_number != self.pr["number"]:
            raise AssertionError("wrong PR")
        value = live_snapshot(self.packet)
        if self.preflight_failure:
            value["checks"][0]["conclusion"] = "FAILURE"
        if self.preflight_tree_mismatch:
            value["pr"]["potential_merge_tree_oid"] = "9" * 40
        return value

    def fetch_default_branch_state(self) -> dict[str, Any]:
        branch = copy.deepcopy(
            live_snapshot(self.packet)["default_branch"]
        )
        if self.base_race:
            branch["commit"]["oid"] = "f" * 40
        return branch

    def merge_pull_request(
        self,
        *,
        pr_number: int,
        expected_head_oid: str,
    ) -> dict[str, Any]:
        if (
            pr_number != self.pr["number"]
            or expected_head_oid != self.pr["head_sha"]
        ):
            raise AssertionError("mutation binding mismatch")
        self.mutations += 1
        if self.mutation_ambiguous:
            raise ReleaseGitHubLiveError("transport ended")
        self.merged = True
        return {
            "merged": True,
            "merge_commit_oid": self.merge_oid,
            "message": "merged",
        }

    def fetch_merge_readback(self, *, pr_number: int) -> dict[str, Any]:
        if pr_number != self.pr["number"]:
            raise AssertionError("wrong PR")
        if self.readback_unavailable:
            raise ReleaseGitHubLiveError("readback unavailable")
        base = self.bundle["initial_base_sha"]
        merged = self.merged
        return {
            "repository": self.bundle["repository"]["full_name"],
            "repository_id": self.bundle["repository"]["id"],
            "repository_policy": {
                "is_archived": False,
                "is_disabled": False,
                "squash_merge_allowed": True,
            },
            "pr": {
                "number": self.pr["number"],
                "state": "MERGED" if merged else "OPEN",
                "merged": merged,
                "merged_at": (
                    "2026-07-16T12:00:00Z" if merged else None
                ),
                "head_oid": self.pr["head_sha"],
                "merge_commit_oid": self.merge_oid if merged else None,
                "merged_by_login": (
                    "attacker"
                    if self.wrong_actor and merged
                    else (
                        "john-lomein-release[bot]"
                        if merged
                        else None
                    )
                ),
            },
            "default_branch": {
                "name": "main",
                "qualified_name": "refs/heads/main",
                "commit": {
                    "oid": self.merge_oid if merged else base,
                    "tree_oid": (
                        self.merge_tree if merged else "1" * 40
                    ),
                    "parent_oids": (
                        ["9" * 40 if self.wrong_parent else base]
                        if merged
                        else ["0" * 40]
                    ),
                    "committed_at": "2026-07-16T12:00:00Z",
                    "author": {
                        "name": "Release",
                        "email": "release.invalid",
                        "date": "2026-07-16T12:00:00Z",
                        "github_login": (
                            "john-lomein-release[bot]"
                        ),
                    },
                    "committer": {
                        "name": "GitHub",
                        "email": "github.invalid",
                        "date": "2026-07-16T12:00:00Z",
                        "github_login": "web-flow",
                    },
                },
            },
            "minimum_rate_limit_remaining": 4000,
        }

    def validate_merge_readback(
        self,
        readback: Mapping[str, Any],
        *,
        expected_head_oid: str,
        expected_previous_default_oid: str,
        expected_merge_oid: str,
        expected_merged_by_login: str,
        expected_tree_oid: str,
        **_unused: Any,
    ) -> None:
        pr = readback["pr"]
        commit = readback["default_branch"]["commit"]
        if (
            pr["state"] != "MERGED"
            or pr["merged"] is not True
            or pr["head_oid"] != expected_head_oid
            or pr["merge_commit_oid"] != expected_merge_oid
            or pr["merged_by_login"] != expected_merged_by_login
            or commit["oid"] != expected_merge_oid
            or commit["parent_oids"] != [
                expected_previous_default_oid
            ]
            or commit["tree_oid"] != expected_tree_oid
        ):
            raise ReleaseGitHubLiveError(
                "readback does not prove exact merge"
            )


class ProtectedReleaseBrokerServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        keys = self.root / "keys"
        keys.mkdir(mode=0o700)
        self.owner_key = Ed25519PrivateKey.generate()
        self.owner_public = self.owner_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        owner_path = keys / "owner.pub.pem"
        owner_path.write_bytes(self.owner_public)
        owner_path.chmod(0o400)
        self.config = release_config(self.root)
        self.config["enabled"] = True
        self.config["broker_private_gid"] = os.getgid()
        self.config["transport"]["submit_gid"] = os.getgid() + 1
        self.config["owner_assertion"]["maximum_ttl_seconds"] = 900
        self.config["owner_assertion"]["public_key_sha256"] = (
            protocol.sha256_bytes(self.owner_public)
        )
        self.config["state"]["database_path"] = str(
            self.root / "release.sqlite3"
        )
        self.clock = MutableClock(NOW)
        self.submission = submission_for(self.owner_key)
        self.live = FakeLive(self.submission["packet"])
        self.store = ReleaseBrokerStore(
            self.config["state"]["database_path"]
        )
        self.service = ProtectedReleaseBrokerService(
            self.config,
            store=self.store,
            live_factory=lambda _now: self.live,
            signer=fake_signer,
            verifier=fake_verifier,
            clock=self.clock,
            trusted_key_root=self.root,
        )

    def tearDown(self) -> None:
        self.service.close()
        self.temporary.cleanup()

    def test_success_merges_once_and_exact_receipt_replays(self):
        first = self.service.handle(self.submission)
        second = self.service.handle(self.submission)
        self.assertEqual(first, second)
        self.assertEqual(self.live.mutations, 1)
        self.assertEqual(first["payload"]["outcome"], "succeeded")
        self.assertEqual(
            first["payload"]["reason_code"], "release_merged"
        )
        self.assertEqual(
            first["payload"]["steps"][0]["merge_sha"], MERGE
        )
        self.assertEqual(
            first["payload"]["steps"][0]["tree_sha"], MERGE_TREE
        )

    def test_live_client_uses_root_owned_private_key_contract(self):
        app = mock.Mock()
        credential = object()
        app.authenticate_installation.return_value = credential
        live = object()
        with (
            mock.patch(
                "release_broker.john_lomein_release_broker_service."
                "ReleaseGitHubAppClient",
                return_value=app,
            ) as app_class,
            mock.patch(
                "release_broker.john_lomein_release_broker_service."
                "ReleaseGitHubLiveClient",
                return_value=live,
            ) as live_class,
        ):
            self.assertIs(self.service._build_live_client(NOW), live)
        app_class.assert_called_once_with(
            app_id=self.config["github_app"]["app_id"],
            installation_id=self.config["github_app"][
                "installation_id"
            ],
            app_slug=self.config["github_app"]["app_slug"],
            private_key_path=Path(
                self.config["github_app"]["private_key_path"]
            ),
            private_key_owner_uid=0,
            private_key_gid=os.getgid(),
            private_key_mode=0o640,
            repository_id=self.config["instance"]["repository"]["id"],
            timeout_seconds=self.config["transport"][
                "request_timeout_seconds"
            ],
        )
        app.authenticate_installation.assert_called_once_with(now=NOW)
        live_class.assert_called_once()
        self.assertIs(
            live_class.call_args.kwargs["credential"], credential
        )

    def test_exact_terminal_receipt_replays_after_expiry(self):
        receipt = self.service.handle(self.submission)
        self.clock.value = NOW + timedelta(hours=1)
        self.assertEqual(
            self.service.handle(self.submission), receipt
        )
        self.assertEqual(self.live.mutations, 1)

    def test_deterministic_preflight_failure_is_signed_rejected(self):
        self.live.preflight_failure = True
        receipt = self.service.handle(self.submission)
        self.assertEqual(receipt["payload"]["outcome"], "rejected")
        self.assertTrue(
            receipt["payload"]["reason_code"].startswith(
                "precondition_"
            )
        )
        self.assertEqual(self.live.mutations, 0)
        self.assertEqual(
            self.service.handle(self.submission), receipt
        )

    def test_signed_expected_merge_tree_mismatch_rejects_preflight(self):
        self.live.preflight_tree_mismatch = True
        receipt = self.service.handle(self.submission)
        self.assertEqual(receipt["payload"]["outcome"], "rejected")
        self.assertEqual(
            receipt["payload"]["reason_code"],
            "precondition_potential_merge_tree_mismatch",
        )
        self.assertEqual(self.live.mutations, 0)

    def test_immediate_base_race_is_known_absent_and_rejected(self):
        self.live.base_race = True
        receipt = self.service.handle(self.submission)
        self.assertEqual(receipt["payload"]["outcome"], "rejected")
        self.assertEqual(
            receipt["payload"]["reason_code"],
            "precondition_immediate_base_fence_failed",
        )
        self.assertEqual(self.live.mutations, 0)
        self.assertEqual(
            self.store.counts()["mutation_attempts"], 1
        )

    def test_ambiguous_mutation_is_indeterminate_and_never_retried(self):
        self.live.mutation_ambiguous = True
        receipt = self.service.handle(self.submission)
        self.assertEqual(receipt["payload"]["outcome"], "indeterminate")
        self.assertEqual(
            receipt["payload"]["reason_code"],
            "indeterminate_merge_transport",
        )
        self.assertEqual(self.live.mutations, 1)
        self.assertEqual(
            self.service.handle(self.submission), receipt
        )
        self.assertEqual(self.live.mutations, 1)
        self.assertEqual(
            self.store.circuit_status(
                self.config["instance"]["slug"],
                self.config["instance"]["repository"]["id"],
            )["state"],
            "closed",
        )

    def test_ambiguous_readback_is_indeterminate_threshold(self):
        self.live.readback_unavailable = True
        receipt = self.service.handle(self.submission)
        self.assertEqual(receipt["payload"]["outcome"], "indeterminate")
        self.assertEqual(
            receipt["payload"]["reason_code"],
            "indeterminate_merge_readback_unavailable",
        )
        status = self.store.circuit_status(
            self.config["instance"]["slug"],
            self.config["instance"]["repository"]["id"],
        )
        self.assertEqual(status["state"], "closed")
        self.assertEqual(status["consecutive_indeterminate"], 1)

    def test_wrong_readback_actor_opens_immediate_circuit(self):
        self.live.wrong_actor = True
        receipt = self.service.handle(self.submission)
        self.assertEqual(receipt["payload"]["outcome"], "indeterminate")
        status = self.store.circuit_status(
            self.config["instance"]["slug"],
            self.config["instance"]["repository"]["id"],
        )
        self.assertEqual(status["state"], "open")
        self.assertEqual(self.live.mutations, 1)

    def test_wrong_signed_tree_readback_opens_immediate_circuit(self):
        self.live.merge_tree = "9" * 40
        receipt = self.service.handle(self.submission)
        self.assertEqual(receipt["payload"]["outcome"], "indeterminate")
        self.assertEqual(
            receipt["payload"]["reason_code"],
            "indeterminate_merge_readback_mismatch",
        )
        status = self.store.circuit_status(
            self.config["instance"]["slug"],
            self.config["instance"]["repository"]["id"],
        )
        self.assertEqual(status["state"], "open")
        self.assertEqual(self.live.mutations, 1)

    def _reserve_and_charge(self) -> tuple[str, str, str]:
        packet = self.submission["packet"]
        reservation = self.store.reserve(
            packet, self.service.limits, now=NOW
        )
        preflight = validate_preflight(
            self.live.fetch_merge_snapshot(pr_number=17),
            packet["request"]["bundle"],
            self.config["instance"]["policy"],
        )
        attempt_id = "jlra-crash-test"
        self.store.begin_mutation(
            reservation.bundle_key,
            0,
            packet["packet_id"],
            attempt_id,
            self.service.limits,
            expected_base_sha=preflight.expected_base_sha,
            precondition_digest=preflight.precondition_digest,
            now=NOW,
        )
        return (
            reservation.bundle_key,
            attempt_id,
            preflight.precondition_digest,
        )

    def test_startup_reconciles_external_merge_without_resending_put(self):
        self._reserve_and_charge()
        self.live.merged = True
        self.service.recover_pending()
        receipt = self.store.receipt_for_packet(
            self.submission["packet"]["packet_id"]
        )
        assert receipt is not None
        self.assertEqual(receipt["payload"]["outcome"], "succeeded")
        self.assertEqual(self.live.mutations, 0)

    def test_recovery_wrong_signed_tree_opens_immediate_circuit(self):
        self._reserve_and_charge()
        self.live.merged = True
        self.live.merge_tree = "9" * 40
        self.service.recover_pending()
        receipt = self.store.receipt_for_packet(
            self.submission["packet"]["packet_id"]
        )
        assert receipt is not None
        self.assertEqual(receipt["payload"]["outcome"], "indeterminate")
        self.assertEqual(
            receipt["payload"]["reason_code"],
            "indeterminate_recovery_readback_mismatch",
        )
        status = self.store.circuit_status(
            self.config["instance"]["slug"],
            self.config["instance"]["repository"]["id"],
        )
        self.assertEqual(status["state"], "open")
        self.assertEqual(self.live.mutations, 0)

    def test_startup_does_not_advance_proven_absent_attempt(self):
        self._reserve_and_charge()
        self.service.recover_pending()
        self.assertIsNone(
            self.store.receipt_for_packet(
                self.submission["packet"]["packet_id"]
            )
        )
        self.assertEqual(len(self.store.pending_recovery()), 1)
        receipt = self.service.handle(self.submission)
        self.assertEqual(receipt["payload"]["outcome"], "succeeded")
        self.assertEqual(self.live.mutations, 1)

    def test_crash_after_confirmation_is_finalized_from_store_evidence(self):
        bundle_key, attempt_id, _ = self._reserve_and_charge()
        self.store.confirm_step(
            bundle_key,
            0,
            self.submission["packet"]["packet_id"],
            attempt_id,
            merge_sha=MERGE,
            parent_sha="a" * 40,
            tree_sha=MERGE_TREE,
            merged_by="john-lomein-release[bot]",
            now=NOW,
        )
        self.service.recover_pending()
        receipt = self.store.receipt_for_packet(
            self.submission["packet"]["packet_id"]
        )
        assert receipt is not None
        self.assertEqual(receipt["payload"]["outcome"], "succeeded")
        self.assertEqual(receipt["payload"]["steps"][0]["attempt_id"], attempt_id)

    def test_crash_after_preflight_stop_is_finalized_from_store_evidence(self):
        packet = self.submission["packet"]
        reservation = self.store.reserve(
            packet, self.service.limits, now=NOW
        )
        digest = protocol.sha256_json({"failed": "preflight"})
        self.store.stop_step(
            reservation.bundle_key,
            0,
            packet["packet_id"],
            "rejected",
            {
                "schema_version": "john-lomein.release-stop-detail.v1",
                "reason_code": "precondition_test_failure",
                "precondition_digest": digest,
                "started_at": "2026-07-16T12:00:00Z",
                "completed_at": "2026-07-16T12:00:00Z",
                "evidence": {},
            },
            now=NOW,
        )
        self.service.recover_pending()
        receipt = self.store.receipt_for_packet(packet["packet_id"])
        assert receipt is not None
        self.assertEqual(receipt["payload"]["outcome"], "rejected")
        self.assertEqual(
            receipt["payload"]["reason_code"],
            "precondition_test_failure",
        )

    def test_reused_owner_nonce_is_rejected_before_second_mutation(self):
        self.service.handle(self.submission)
        bundle = release_bundle(
            pr_number=18,
            head_sha="8" * 40,
        )
        second = submission_for(
            self.owner_key, bundle=bundle, nonce="c" * 64
        )
        self.live.packet = second["packet"]
        with self.assertRaises(protocol.ReleaseBrokerProtocolError):
            self.service.handle(second)
        self.assertEqual(self.live.mutations, 1)

    def test_new_packet_cannot_alias_terminal_semantic_receipt(self):
        first = self.service.handle(self.submission)
        second = submission_for(
            self.owner_key,
            bundle=self.submission["packet"]["request"]["bundle"],
            nonce="f" * 64,
        )
        with self.assertRaises(protocol.ReleaseBrokerProtocolError):
            self.service.handle(second)
        self.assertEqual(
            first["payload"]["packet"]["packet_id"],
            self.submission["packet"]["packet_id"],
        )
        self.assertEqual(self.live.mutations, 1)

    def test_new_packet_cannot_alias_pending_semantic_bundle(self):
        packet = self.submission["packet"]
        self.store.reserve(
            packet, self.service.limits, now=NOW
        )
        alias = submission_for(
            self.owner_key,
            bundle=packet["request"]["bundle"],
            nonce="6" * 64,
        )
        with self.assertRaises(protocol.ReleaseBrokerProtocolError):
            self.service.handle(alias)
        receipt = self.service.handle(self.submission)
        self.assertEqual(receipt["payload"]["outcome"], "succeeded")
        self.assertEqual(
            receipt["payload"]["packet"]["packet_id"],
            packet["packet_id"],
        )
        self.assertEqual(self.live.mutations, 1)

    def test_bundle_budget_and_open_circuit_reject_new_authority(self):
        self.service.handle(self.submission)
        self.store.open_circuit(
            instance_slug=self.config["instance"]["slug"],
            repository_id=self.config["instance"]["repository"]["id"],
            repository_full_name=self.config["instance"]["repository"][
                "full_name"
            ],
            reason={"reason": "operator-test"},
            now=NOW,
        )
        bundle = release_bundle(
            pr_number=19,
            head_sha="9" * 40,
        )
        second = submission_for(
            self.owner_key, bundle=bundle, nonce="9" * 64
        )
        with self.assertRaises(protocol.ReleaseBrokerProtocolError):
            self.service.handle(second)
        self.assertEqual(self.live.mutations, 1)

    def test_bundle_budget_rejects_before_second_authority(self):
        self.service.limits = BudgetLimits(
            unique_requests_per_hour=20,
            owner_assertions_per_hour=20,
            bundles_per_day=1,
            mutation_attempts_per_day=20,
            confirmed_merges_per_day=20,
            consecutive_indeterminate_limit=2,
        )
        self.service.handle(self.submission)
        bundle = release_bundle(
            pr_number=20,
            head_sha="7" * 40,
        )
        second = submission_for(
            self.owner_key, bundle=bundle, nonce="7" * 64
        )
        self.live.packet = second["packet"]
        with self.assertRaises(protocol.ReleaseBrokerProtocolError):
            self.service.handle(second)
        self.assertEqual(self.live.mutations, 1)

    def test_disabled_config_refuses_service_startup(self):
        disabled = copy.deepcopy(self.config)
        disabled["enabled"] = False
        disabled["state"]["database_path"] = str(
            self.root / "disabled.sqlite3"
        )
        with self.assertRaisesRegex(
            RuntimeError, "disabled"
        ):
            ProtectedReleaseBrokerService(
                disabled,
                live_factory=lambda _now: self.live,
                signer=fake_signer,
                verifier=fake_verifier,
                clock=self.clock,
                trusted_key_root=self.root,
            )

    def test_service_refuses_wrong_os_uid_or_private_gid(self):
        wrong_uid = copy.deepcopy(self.config)
        wrong_uid["broker_uid"] = os.getuid() + 2
        wrong_uid["state"]["database_path"] = str(
            self.root / "wrong-uid.sqlite3"
        )
        with self.assertRaisesRegex(
            RuntimeError, "OS identity"
        ):
            ProtectedReleaseBrokerService(
                wrong_uid,
                live_factory=lambda _now: self.live,
                signer=fake_signer,
                verifier=fake_verifier,
                clock=self.clock,
                trusted_key_root=self.root,
            )

        wrong_gid = copy.deepcopy(self.config)
        wrong_gid["broker_private_gid"] = os.getgid() + 2
        if (
            wrong_gid["broker_private_gid"]
            == wrong_gid["transport"]["submit_gid"]
        ):
            wrong_gid["broker_private_gid"] += 1
        wrong_gid["state"]["database_path"] = str(
            self.root / "wrong-gid.sqlite3"
        )
        with self.assertRaisesRegex(
            RuntimeError, "private-key group"
        ):
            ProtectedReleaseBrokerService(
                wrong_gid,
                live_factory=lambda _now: self.live,
                signer=fake_signer,
                verifier=fake_verifier,
                clock=self.clock,
                trusted_key_root=self.root,
            )


if __name__ == "__main__":
    unittest.main()
