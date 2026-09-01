#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_broker import john_lomein_release_broker_protocol as protocol
from release_broker import john_lomein_release_broker_receipts as receipts


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
APP = {
    "app_id": 12345,
    "app_slug": "john-lomein-release",
    "installation_id": 67890,
}
CONFIG_DIGEST = "sha256:" + ("1" * 64)


class StatView:
    def __init__(self, source: os.stat_result, **overrides: int) -> None:
        self._source = source
        self._overrides = overrides

    def __getattr__(self, name: str) -> Any:
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._source, name)


def utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def release_bundle(
    *,
    pr_number: int = 17,
    head_sha: str = "b" * 40,
    initial_base_sha: str = "a" * 40,
    expected_merge_tree_sha: str = "e" * 40,
) -> dict:
    paths = [f"src/change_{pr_number}.py", f"tests/test_{pr_number}.py"]
    bundle = {
        "schema_version": protocol.BUNDLE_SCHEMA,
        "bundle_id": "",
        "instance_slug": "widget-production",
        "repository": {
            "id": 987654,
            "full_name": "acme/widget",
            "default_branch": "main",
        },
        "created_at": "2026-07-16T11:55:00Z",
        "expires_at": "2026-07-16T12:30:00Z",
        "initial_base_sha": initial_base_sha,
        "merge_method": "squash",
        "publish": False,
        "ordered_prs": [
            {
                "position": 0,
                "number": pr_number,
                "url": f"https://github.com/acme/widget/pull/{pr_number}",
                "head_sha": head_sha,
                "expected_merge_tree_sha": expected_merge_tree_sha,
                "base_branch": "main",
                "author_login": "john-lomein[bot]",
                "changed_paths": paths,
                "changed_paths_digest": protocol.sha256_json(paths),
                "changed_path_count": len(paths),
                "risk_class": "low",
                "review_quorum_sha256": "sha256:" + "a" * 64,
                "review_quorum_policy_sha256": "sha256:" + "b" * 64,
            }
        ],
        "train_attestation_digest": None,
        "actions": {"merge": True, "publish": False},
        "bundle_digest": "",
    }
    bundle["bundle_digest"] = protocol.release_bundle_digest(bundle)
    bundle["bundle_id"] = protocol.release_bundle_id(bundle)
    return bundle


def owner_assertion(
    bundle: dict,
    key: Ed25519PrivateKey,
    *,
    nonce: str = "c" * 64,
) -> dict:
    approval = "Approve the exact squash-only release; do not publish."
    payload = {
        "schema_version": protocol.OWNER_ASSERTION_SCHEMA,
        "purpose": "release_merge",
        "issuer": "trusted-owner-gateway",
        "actor_id": "owner-123",
        "actor_login": "maintainer",
        "tier": "owner",
        "issued_at": "2026-07-16T11:59:00Z",
        "expires_at": "2026-07-16T12:10:00Z",
        "nonce": nonce,
        "instance_slug": bundle["instance_slug"],
        "repository_id": bundle["repository"]["id"],
        "repository_full_name": bundle["repository"]["full_name"],
        "bundle_id": bundle["bundle_id"],
        "bundle_digest": bundle["bundle_digest"],
        "approval_text_sha256": protocol.sha256_text(approval),
        "action": protocol.RELEASE_ACTION,
        "merge_method": "squash",
        "publish": False,
        "ordered_prs_digest": protocol.ordered_prs_digest(bundle),
        "changed_paths_digest": protocol.changed_paths_digest(bundle),
        "risk_class": protocol.aggregate_risk_class(bundle),
    }
    signature = key.sign(protocol.canonical_json(payload))
    return {
        "schema_version": protocol.SIGNED_ENVELOPE_SCHEMA,
        "algorithm": protocol.SIGNATURE_ALGORITHM,
        "key_id": "owner-2026-01",
        "payload": payload,
        "signature": (
            base64.urlsafe_b64encode(signature)
            .decode("ascii")
            .rstrip("=")
        ),
    }


def release_packet(
    bundle: dict,
    owner_key: Ed25519PrivateKey,
    *,
    nonce: str = "c" * 64,
) -> dict:
    approval = "Approve the exact squash-only release; do not publish."
    assertion = owner_assertion(bundle, owner_key, nonce=nonce)
    request = {
        "action": protocol.RELEASE_ACTION,
        "bundle": bundle,
        "approval": {
            "text": approval,
            "text_sha256": protocol.sha256_text(approval),
        },
        "owner_assertion": assertion,
        "train_attestation": None,
    }
    body = {
        "schema_version": protocol.PACKET_SCHEMA,
        "created_at": "2026-07-16T12:00:00Z",
        "expires_at": "2026-07-16T12:05:00Z",
        "authority": protocol.PACKET_AUTHORITY,
        "requested_by": {
            "component": protocol.REQUEST_COMPONENT,
            "instance_slug": bundle["instance_slug"],
        },
        "request": request,
    }
    return {
        **body,
        "packet_id": (
            "jlrp-"
            + protocol.sha256_json(body).removeprefix("sha256:")[:24]
        ),
        "request_digest": protocol.sha256_json(request),
    }


def pem_pair(
    key: Ed25519PrivateKey,
) -> tuple[bytes, bytes]:
    return (
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


def refresh_receipt_id(payload: dict) -> dict:
    payload["receipt_id"] = ""
    payload["receipt_id"] = (
        "jlrrc-"
        + protocol.sha256_json(
            {
                key: value
                for key, value in payload.items()
                if key != "receipt_id"
            }
        ).removeprefix("sha256:")[:24]
    )
    return payload


class ReleaseBrokerReceiptTest(unittest.TestCase):
    def setUp(self) -> None:
        self.owner_key = Ed25519PrivateKey.generate()
        self.receipt_key = Ed25519PrivateKey.generate()
        self.private_pem, self.public_pem = pem_pair(self.receipt_key)
        self.fingerprint = protocol.sha256_bytes(self.public_pem)
        self.bundle = release_bundle()
        self.packet = release_packet(self.bundle, self.owner_key)

    def success_step(
        self,
        *,
        pr_number: int = 17,
        head_sha: str = "b" * 40,
        base_sha: str = "a" * 40,
        merge_sha: str = "d" * 40,
        tree_sha: str = "e" * 40,
        start: datetime = NOW + timedelta(minutes=1),
    ) -> dict:
        return {
            "position": 0,
            "pr_number": pr_number,
            "authorized_head_sha": head_sha,
            "expected_base_sha": base_sha,
            "precondition_digest": protocol.sha256_json(
                {"snapshot": "exact", "pr": pr_number}
            ),
            "attempt_id": f"jlra-attempt-{pr_number}",
            "outcome": "merged",
            "reason_code": "merge_confirmed",
            "merge_sha": merge_sha,
            "parent_sha": base_sha,
            "tree_sha": tree_sha,
            "merged_by": "john-lomein-release[bot]",
            "started_at": start,
            "attempted_at": start + timedelta(seconds=10),
            "completed_at": start + timedelta(seconds=30),
        }

    def build_success(
        self,
        *,
        packet: dict | None = None,
        previous: str = receipts.ZERO_DIGEST,
        start: datetime = NOW + timedelta(minutes=1),
    ) -> dict:
        packet = packet or self.packet
        bundle = packet["request"]["bundle"]
        pr = bundle["ordered_prs"][0]
        step = self.success_step(
            pr_number=pr["number"],
            head_sha=pr["head_sha"],
            base_sha=bundle["initial_base_sha"],
            merge_sha="d" * 40,
            tree_sha="e" * 40,
            start=start,
        )
        return receipts.build_receipt_payload(
            packet,
            broker_id="release-production",
            broker_uid=os.geteuid(),
            config_sha256=CONFIG_DIGEST,
            signing_key_id="release-receipts-2026-01",
            signing_public_key_sha256=self.fingerprint,
            github_app=APP,
            steps=[step],
            final_branch={
                "name": "main",
                "head_sha": step["merge_sha"],
                "tree_sha": step["tree_sha"],
                "observed_at": start + timedelta(seconds=40),
            },
            outcome="succeeded",
            reason_code="release_merged",
            started_at=start,
            completed_at=start + timedelta(seconds=45),
            previous_receipt_sha256=previous,
        )

    def write_keys(
        self,
        root: Path,
        *,
        private_pem: bytes | None = None,
        public_pem: bytes | None = None,
    ) -> tuple[Path, Path]:
        key_dir = root / "keys"
        key_dir.mkdir(mode=0o700)
        private = key_dir / "receipt-private.pem"
        public = key_dir / "receipt-public.pem"
        private.write_bytes(private_pem or self.private_pem)
        public.write_bytes(public_pem or self.public_pem)
        private.chmod(0o600)
        public.chmod(0o644)
        return private, public

    def sign(
        self,
        payload: dict,
        private: Path,
        public: Path,
        root: Path,
        *,
        packet: dict | None = None,
    ) -> dict:
        return receipts.sign_receipt(
            payload,
            private_key_path=private,
            public_key_path=public,
            expected_public_key_sha256=self.fingerprint,
            expected_key_id="release-receipts-2026-01",
            key_owner_uids=os.geteuid(),
            parent_owner_uids=os.geteuid(),
            trusted_path_root=root / "keys",
            private_key_owner_uid=os.geteuid(),
            private_key_gid=os.getegid(),
            private_key_mode=0o600,
            packet=packet,
        )

    def test_build_binds_packet_owner_repository_app_and_merge_evidence(self):
        payload = self.build_success()
        self.assertEqual(
            payload["schema_version"],
            receipts.RECEIPT_PAYLOAD_SCHEMA,
        )
        self.assertEqual(
            payload["packet"]["packet_digest"],
            protocol.sha256_json(self.packet),
        )
        self.assertEqual(
            payload["packet"]["owner_assertion_digest"],
            protocol.owner_assertion_digest(
                self.packet["request"]["owner_assertion"]
            ),
        )
        self.assertEqual(
            payload["repository"], self.bundle["repository"]
        )
        self.assertEqual(payload["instance_slug"], "widget-production")
        self.assertEqual(payload["github_app"], APP)
        self.assertEqual(payload["bundle"]["merge_method"], "squash")
        self.assertIs(payload["bundle"]["publish"], False)
        self.assertEqual(payload["steps"][0]["parent_sha"], "a" * 40)
        serialized = protocol.canonical_json(payload).decode("utf-8")
        self.assertNotIn(
            self.packet["request"]["owner_assertion"]["payload"]["nonce"],
            serialized,
        )
        self.assertNotIn(
            self.packet["request"]["approval"]["text"], serialized
        )

    def test_sign_and_verify_offline_and_from_trusted_path(self):
        payload = self.build_success()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, public = self.write_keys(root)
            signed = self.sign(
                payload, private, public, root, packet=self.packet
            )
            self.assertEqual(
                signed["schema_version"],
                receipts.RECEIPT_ENVELOPE_SCHEMA,
            )
            self.assertEqual(signed["algorithm"], "ed25519")
            verified = receipts.verify_receipt_with_public_key(
                protocol.canonical_json(signed),
                public_key=self.public_pem,
                expected_public_key_sha256=self.fingerprint,
                expected_key_id="release-receipts-2026-01",
                expected_broker_id="release-production",
                expected_broker_uid=os.geteuid(),
                expected_config_sha256=CONFIG_DIGEST,
                expected_instance_slug="widget-production",
                expected_repository_id=987654,
                expected_repository_full_name="acme/widget",
                expected_github_app=APP,
                packet=self.packet,
                now=NOW + timedelta(minutes=2),
            )
            self.assertEqual(verified, signed)
            self.assertEqual(
                receipts.verify_signed_receipt(
                    protocol.canonical_json(signed),
                    self.public_pem,
                    "release-receipts-2026-01",
                ),
                signed,
            )
            from_path = receipts.verify_receipt(
                signed,
                public_key_path=public,
                expected_public_key_sha256=self.fingerprint,
                expected_key_id="release-receipts-2026-01",
                public_key_owner_uids=os.geteuid(),
                parent_owner_uids=os.geteuid(),
                trusted_path_root=root / "keys",
                packet=self.packet,
            )
            self.assertEqual(from_path, signed)

    def test_tampering_any_signed_evidence_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, public = self.write_keys(root)
            signed = self.sign(self.build_success(), private, public, root)
            mutations = [
                ("packet", "packet_digest", "sha256:" + "9" * 64),
                ("repository", "id", 22),
                ("github_app", "installation_id", 22),
                ("bundle", "initial_base_sha", "9" * 40),
            ]
            for section, field, value in mutations:
                candidate = copy.deepcopy(signed)
                candidate["payload"][section][field] = value
                refresh_receipt_id(candidate["payload"])
                candidate["payload_sha256"] = protocol.sha256_bytes(
                    protocol.canonical_json(candidate["payload"])
                )
                with self.subTest(section=section, field=field):
                    with self.assertRaises(
                        receipts.ReleaseBrokerReceiptError
                    ):
                        receipts.verify_receipt_with_public_key(
                            candidate,
                            public_key=self.public_pem,
                            expected_public_key_sha256=self.fingerprint,
                        )

            candidate = copy.deepcopy(signed)
            candidate["payload"]["steps"][0]["merge_sha"] = "9" * 40
            refresh_receipt_id(candidate["payload"])
            candidate["payload_sha256"] = protocol.sha256_bytes(
                protocol.canonical_json(candidate["payload"])
            )
            with self.assertRaises(receipts.ReleaseBrokerReceiptError):
                receipts.verify_receipt_with_public_key(
                    candidate,
                    public_key=self.public_pem,
                    expected_public_key_sha256=self.fingerprint,
                )

    def test_wrong_key_fingerprint_key_id_and_key_pair_are_rejected(self):
        other = Ed25519PrivateKey.generate()
        other_private, other_public = pem_pair(other)
        payload = self.build_success()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, public = self.write_keys(root)
            signed = self.sign(payload, private, public, root)
            with self.assertRaisesRegex(
                receipts.ReleaseBrokerReceiptError, "fingerprint"
            ):
                receipts.verify_receipt_with_public_key(
                    signed,
                    public_key=other_public,
                    expected_public_key_sha256=protocol.sha256_bytes(
                        other_public
                    ),
                )
            with self.assertRaisesRegex(
                receipts.ReleaseBrokerReceiptError, "key ID"
            ):
                receipts.verify_receipt_with_public_key(
                    signed,
                    public_key=self.public_pem,
                    expected_public_key_sha256=self.fingerprint,
                    expected_key_id="wrong-key",
                )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, public = self.write_keys(
                root,
                private_pem=other_private,
                public_pem=self.public_pem,
            )
            with self.assertRaisesRegex(
                receipts.ReleaseBrokerReceiptError, "do not match"
            ):
                self.sign(payload, private, public, root)

    def test_rejected_partial_and_indeterminate_semantics_are_strict(self):
        success = self.build_success()

        rejected = copy.deepcopy(success)
        step = rejected["steps"][0]
        step.update(
            {
                "attempt_id": None,
                "outcome": "rejected",
                "reason_code": "precondition_base_drift",
                "merge_sha": None,
                "parent_sha": None,
                "tree_sha": None,
                "merged_by": None,
                "attempted_at": None,
            }
        )
        rejected["final_branch"].update(
            {"head_sha": None, "tree_sha": None, "observed_at": None}
        )
        rejected["outcome"] = "rejected"
        rejected["reason_code"] = "precondition_base_drift"
        self.assertEqual(
            receipts.normalize_receipt_payload(
                refresh_receipt_id(rejected)
            )["outcome"],
            "rejected",
        )

        partial = copy.deepcopy(success)
        partial["bundle"]["pr_count"] = 2
        partial["bundle"]["ordered_prs_digest"] = (
            "sha256:" + ("2" * 64)
        )
        partial["bundle"]["changed_paths_digest"] = (
            "sha256:" + ("3" * 64)
        )
        second = {
            "position": 1,
            "pr_number": 18,
            "authorized_head_sha": "f" * 40,
            "expected_base_sha": partial["steps"][0]["merge_sha"],
            "precondition_digest": "sha256:" + ("4" * 64),
            "attempt_id": None,
            "outcome": "rejected",
            "reason_code": "precondition_base_drift",
            "merge_sha": None,
            "parent_sha": None,
            "tree_sha": None,
            "merged_by": None,
            "started_at": "2026-07-16T12:01:31Z",
            "attempted_at": None,
            "completed_at": "2026-07-16T12:01:35Z",
        }
        partial["steps"].append(second)
        partial["outcome"] = "partial"
        partial["reason_code"] = "partial_precondition_drift"
        self.assertEqual(
            receipts.normalize_receipt_payload(
                refresh_receipt_id(partial)
            )["outcome"],
            "partial",
        )

        indeterminate = copy.deepcopy(success)
        indeterminate["steps"][0].update(
            {
                "outcome": "indeterminate",
                "reason_code": "indeterminate_readback",
                "merge_sha": None,
                "parent_sha": None,
                "tree_sha": None,
                "merged_by": None,
            }
        )
        indeterminate["final_branch"].update(
            {"head_sha": None, "tree_sha": None, "observed_at": None}
        )
        indeterminate["outcome"] = "indeterminate"
        indeterminate["reason_code"] = "indeterminate_readback"
        self.assertEqual(
            receipts.normalize_receipt_payload(
                refresh_receipt_id(indeterminate)
            )["outcome"],
            "indeterminate",
        )

        invalid = copy.deepcopy(rejected)
        invalid["outcome"] = "succeeded"
        invalid["reason_code"] = "release_merged"
        with self.assertRaisesRegex(
            receipts.ReleaseBrokerReceiptError, "every merge"
        ):
            receipts.normalize_receipt_payload(refresh_receipt_id(invalid))

    def test_full_oids_base_parent_order_and_timestamps_are_enforced(self):
        candidates = []
        abbreviated = self.build_success()
        abbreviated["steps"][0]["authorized_head_sha"] = "abc1234"
        candidates.append(abbreviated)

        wrong_parent = self.build_success()
        wrong_parent["steps"][0]["parent_sha"] = "9" * 40
        candidates.append(wrong_parent)

        backwards = self.build_success()
        backwards["steps"][0]["attempted_at"] = (
            "2026-07-16T12:00:59Z"
        )
        candidates.append(backwards)

        wrong_branch = self.build_success()
        wrong_branch["final_branch"]["name"] = "develop"
        candidates.append(wrong_branch)

        for candidate in candidates:
            with self.subTest(candidate=candidate):
                with self.assertRaises(
                    receipts.ReleaseBrokerReceiptError
                ):
                    receipts.normalize_receipt_payload(
                        refresh_receipt_id(candidate)
                    )

    def test_packet_context_and_pinned_runtime_bindings_fail_closed(self):
        payload = self.build_success()
        other_packet = release_packet(
            release_bundle(pr_number=18, head_sha="f" * 40),
            self.owner_key,
            nonce="d" * 64,
        )
        with self.assertRaisesRegex(
            receipts.ReleaseBrokerReceiptError, "packet binding"
        ):
            receipts.assert_receipt_packet_binding(
                payload, other_packet
            )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, public = self.write_keys(root)
            signed = self.sign(payload, private, public, root)
            checks = [
                {"expected_broker_id": "other"},
                {"expected_broker_uid": os.geteuid() + 1},
                {"expected_config_sha256": "sha256:" + "9" * 64},
                {"expected_instance_slug": "other-instance"},
                {"expected_repository_id": 1},
                {"expected_repository_full_name": "other/repo"},
                {
                    "expected_github_app": {
                        **APP,
                        "installation_id": 1,
                    }
                },
            ]
            for kwargs in checks:
                with self.subTest(kwargs=kwargs):
                    with self.assertRaises(
                        receipts.ReleaseBrokerReceiptError
                    ):
                        receipts.verify_receipt_with_public_key(
                            signed,
                            public_key=self.public_pem,
                            expected_public_key_sha256=self.fingerprint,
                            **kwargs,
                        )

    def test_configured_build_sign_and_verify_bind_the_complete_config(self):
        from tests.test_release_broker_protocol import release_config

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, public = self.write_keys(root)
            config = release_config(root)
            config["enabled"] = True
            config["broker_id"] = "release-production"
            config["github_app"].update(APP)
            config["receipt_signing"].update(
                {
                    "private_key_path": str(private),
                    "public_key_path": str(public),
                    "public_key_sha256": self.fingerprint,
                }
            )
            step = self.success_step()
            payload = receipts.build_configured_receipt_payload(
                config,
                self.packet,
                steps=[step],
                final_branch={
                    "name": "main",
                    "head_sha": step["merge_sha"],
                    "tree_sha": step["tree_sha"],
                    "observed_at": NOW
                    + timedelta(minutes=1, seconds=40),
                },
                outcome="succeeded",
                reason_code="release_merged",
                started_at=NOW + timedelta(minutes=1),
                completed_at=NOW
                + timedelta(minutes=1, seconds=45),
            )
            self.assertEqual(
                payload["broker"]["config_sha256"],
                protocol.config_digest(config),
            )
            real_read = receipts.read_trusted_key

            def configured_read(path: Path, **kwargs: Any) -> bytes:
                if kwargs["private"]:
                    self.assertEqual(kwargs["expected_owner_uids"], 0)
                    self.assertEqual(
                        kwargs["expected_gid"],
                        config["broker_private_gid"],
                    )
                    self.assertEqual(kwargs["expected_mode"], 0o640)
                    return self.private_pem
                return real_read(path, **kwargs)

            with mock.patch.object(
                receipts,
                "read_trusted_key",
                side_effect=configured_read,
            ):
                signed = receipts.sign_configured_receipt(
                    payload,
                    config,
                    key_owner_uids=os.geteuid(),
                    parent_owner_uids=os.geteuid(),
                    trusted_path_root=root / "keys",
                    packet=self.packet,
                )
            verified = receipts.verify_configured_receipt(
                signed,
                config,
                public_key_owner_uids=os.geteuid(),
                parent_owner_uids=os.geteuid(),
                trusted_path_root=root / "keys",
                packet=self.packet,
            )
            self.assertEqual(verified, signed)

            changed = copy.deepcopy(config)
            changed["instance"]["budgets"][
                "bundles_per_day"
            ] += 1
            with self.assertRaisesRegex(
                receipts.ReleaseBrokerReceiptError, "config"
            ):
                receipts.assert_receipt_config_binding(payload, changed)
            disabled = copy.deepcopy(config)
            disabled["enabled"] = False
            with self.assertRaisesRegex(
                receipts.ReleaseBrokerReceiptError, "disabled"
            ):
                receipts.build_configured_receipt_payload(
                    disabled,
                    self.packet,
                    steps=[step],
                    final_branch={
                        "name": "main",
                        "head_sha": step["merge_sha"],
                        "tree_sha": step["tree_sha"],
                        "observed_at": NOW
                        + timedelta(minutes=1, seconds=40),
                    },
                    outcome="succeeded",
                    reason_code="release_merged",
                    started_at=NOW + timedelta(minutes=1),
                    completed_at=NOW
                    + timedelta(minutes=1, seconds=45),
                )

    def test_append_chain_verifies_signatures_order_identity_and_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, public = self.write_keys(root)
            first = self.sign(
                self.build_success(
                    start=NOW + timedelta(seconds=30)
                ),
                private,
                public,
                root,
            )
            second_bundle = release_bundle(
                pr_number=18,
                head_sha="f" * 40,
                initial_base_sha="d" * 40,
            )
            second_packet = release_packet(
                second_bundle, self.owner_key, nonce="d" * 64
            )
            second = self.sign(
                self.build_success(
                    packet=second_packet,
                    previous=receipts.receipt_digest(first),
                    start=NOW + timedelta(minutes=2),
                ),
                private,
                public,
                root,
            )
            chain = receipts.verify_receipt_chain(
                [first, second],
                public_keys={
                    "release-receipts-2026-01": self.public_pem
                },
                expected_broker_id="release-production",
                expected_broker_uid=os.geteuid(),
                expected_repository_id=987654,
            )
            self.assertEqual(chain, [first, second])
            self.assertEqual(
                receipts.assert_append_binding(first, second), second
            )
            with self.assertRaisesRegex(
                receipts.ReleaseBrokerReceiptError, "repeats"
            ):
                replay = copy.deepcopy(first)
                replay["payload"]["previous_receipt_sha256"] = (
                    receipts.receipt_digest(first)
                )
                replay["payload"]["started_at"] = (
                    "2026-07-16T12:01:16Z"
                )
                replay["payload"]["completed_at"] = (
                    "2026-07-16T12:02:01Z"
                )
                replay["payload"]["steps"][0]["started_at"] = (
                    "2026-07-16T12:01:16Z"
                )
                replay["payload"]["steps"][0]["attempted_at"] = (
                    "2026-07-16T12:01:26Z"
                )
                replay["payload"]["steps"][0]["completed_at"] = (
                    "2026-07-16T12:01:46Z"
                )
                replay["payload"]["final_branch"]["observed_at"] = (
                    "2026-07-16T12:01:56Z"
                )
                refresh_receipt_id(replay["payload"])
                replay = self.sign(
                    replay["payload"], private, public, root
                )
                receipts.verify_receipt_chain(
                    [first, replay],
                    public_keys={
                        "release-receipts-2026-01": self.public_pem
                    },
                )

            wrong = copy.deepcopy(second)
            wrong["payload"]["previous_receipt_sha256"] = receipts.ZERO_DIGEST
            refresh_receipt_id(wrong["payload"])
            with self.assertRaises(
                receipts.ReleaseBrokerReceiptError
            ):
                receipts.assert_append_binding(first, wrong)
            with self.assertRaises(
                receipts.ReleaseBrokerReceiptError
            ):
                receipts.verify_receipt_chain(
                    [second, first],
                    public_keys={
                        "release-receipts-2026-01": self.public_pem
                    },
                )

    def test_chain_supports_pinned_key_rotation(self):
        second_key = Ed25519PrivateKey.generate()
        second_private_pem, second_public_pem = pem_pair(second_key)
        second_fingerprint = protocol.sha256_bytes(second_public_pem)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, public = self.write_keys(root)
            first = self.sign(
                self.build_success(
                    start=NOW + timedelta(seconds=30)
                ),
                private,
                public,
                root,
            )
            second_bundle = release_bundle(
                pr_number=18,
                head_sha="f" * 40,
                initial_base_sha="d" * 40,
            )
            second_packet = release_packet(
                second_bundle, self.owner_key, nonce="d" * 64
            )
            second_payload = self.build_success(
                packet=second_packet,
                previous=receipts.receipt_digest(first),
                start=NOW + timedelta(minutes=2),
            )
            second_payload["broker"]["signing_key"] = {
                "key_id": "release-receipts-2026-02",
                "public_key_sha256": second_fingerprint,
            }
            refresh_receipt_id(second_payload)

            root2 = root / "rotation"
            root2.mkdir(mode=0o700)
            private2, public2 = self.write_keys(
                root2,
                private_pem=second_private_pem,
                public_pem=second_public_pem,
            )
            second = receipts.sign_receipt(
                second_payload,
                private_key_path=private2,
                public_key_path=public2,
                expected_public_key_sha256=second_fingerprint,
                expected_key_id="release-receipts-2026-02",
                key_owner_uids=os.geteuid(),
                parent_owner_uids=os.geteuid(),
                trusted_path_root=root2 / "keys",
                private_key_owner_uid=os.geteuid(),
                private_key_gid=os.getegid(),
                private_key_mode=0o600,
            )
            verified = receipts.verify_receipt_chain(
                [first, second],
                public_keys={
                    "release-receipts-2026-01": self.public_pem,
                    "release-receipts-2026-02": second_public_pem,
                },
            )
            self.assertEqual(len(verified), 2)

    def test_unknown_duplicate_oversized_and_malformed_fields_are_rejected(self):
        payload = self.build_success()
        unknown = copy.deepcopy(payload)
        unknown["debug"] = "secret"
        with self.assertRaisesRegex(
            receipts.ReleaseBrokerReceiptError, "unknown fields"
        ):
            receipts.normalize_receipt_payload(unknown)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, public = self.write_keys(root)
            signed = self.sign(payload, private, public, root)
            encoded = protocol.canonical_json(signed)
            duplicate = encoded.replace(
                b'{"algorithm":',
                b'{"algorithm":"ed25519","algorithm":',
                1,
            )
            with self.assertRaisesRegex(
                receipts.ReleaseBrokerReceiptError, "duplicate"
            ):
                receipts.load_receipt(duplicate)
            with self.assertRaisesRegex(
                receipts.ReleaseBrokerReceiptError, "size limit"
            ):
                receipts.load_receipt(
                    b"{" + (b" " * receipts.MAX_RECEIPT_BYTES) + b"}"
                )

            bad_schema = copy.deepcopy(signed)
            bad_schema["schema_version"] = "future"
            with self.assertRaisesRegex(
                receipts.ReleaseBrokerReceiptError, "unsupported"
            ):
                receipts.normalize_receipt_envelope(bad_schema)

            bad_signature = copy.deepcopy(signed)
            bad_signature["signature"] = "=" + signed["signature"][1:]
            with self.assertRaisesRegex(
                receipts.ReleaseBrokerReceiptError, "encoding"
            ):
                receipts.normalize_receipt_envelope(bad_signature)

    def test_key_loader_rejects_unsafe_modes_symlinks_and_hardlinks(self):
        payload = self.build_success()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, public = self.write_keys(root)
            private.chmod(0o640)
            with self.assertRaisesRegex(
                receipts.ReleaseBrokerReceiptError, "exactly 0600"
            ):
                self.sign(payload, private, public, root)
            private.chmod(0o600)

            link = root / "keys" / "public-link.pem"
            link.symlink_to(public)
            with self.assertRaises(receipts.ReleaseBrokerReceiptError):
                receipts.verify_receipt(
                    {},
                    public_key_path=link,
                    expected_public_key_sha256=self.fingerprint,
                    public_key_owner_uids=os.geteuid(),
                    parent_owner_uids=os.geteuid(),
                    trusted_path_root=root / "keys",
                )

            hardlink = root / "keys" / "public-hardlink.pem"
            os.link(public, hardlink)
            with self.assertRaisesRegex(
                receipts.ReleaseBrokerReceiptError, "hard links"
            ):
                receipts.read_trusted_key(
                    public,
                    field="test public key",
                    private=False,
                    expected_owner_uids=os.geteuid(),
                    parent_owner_uids=os.geteuid(),
                    trusted_path_root=root / "keys",
                )

    def test_configured_private_key_requires_root_gid_0640_stable_snapshot(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, _ = self.write_keys(root)
            private.chmod(0o640)
            expected_gid = 4242
            real_fstat = os.fstat
            real_lstat = os.lstat

            with self.assertRaisesRegex(
                receipts.ReleaseBrokerReceiptError,
                "trust policy must be explicit",
            ):
                receipts.read_trusted_key(
                    private,
                    field="test private key",
                    private=True,
                    expected_owner_uids=os.geteuid(),
                    parent_owner_uids=os.geteuid(),
                    trusted_path_root=root / "keys",
                )

            def trusted(info: os.stat_result, **overrides: int) -> StatView:
                values = {
                    "st_uid": 0,
                    "st_gid": expected_gid,
                    "st_mode": stat.S_IFMT(info.st_mode) | 0o640,
                }
                values.update(overrides)
                return StatView(info, **values)

            def trusted_lstat(path: os.PathLike[str] | str) -> Any:
                info = real_lstat(path)
                if Path(path) == private:
                    return trusted(info)
                return info

            with (
                mock.patch.object(
                    receipts.os,
                    "fstat",
                    side_effect=lambda fd: trusted(real_fstat(fd)),
                ),
                mock.patch.object(
                    receipts.os, "lstat", side_effect=trusted_lstat
                ),
            ):
                self.assertEqual(
                    receipts.read_trusted_key(
                        private,
                        field="configured private key",
                        private=True,
                        expected_owner_uids=0,
                        parent_owner_uids=os.geteuid(),
                        trusted_path_root=root / "keys",
                        expected_gid=expected_gid,
                        expected_mode=0o640,
                    ),
                    self.private_pem,
                )

            cases = [
                ("owner", {"st_uid": 1}, "owner is untrusted"),
                ("group", {"st_gid": expected_gid + 1}, "group is untrusted"),
                (
                    "mode",
                    {"st_mode": stat.S_IFMT(real_lstat(private).st_mode) | 0o600},
                    "exactly 0640",
                ),
            ]
            for label, overrides, message in cases:
                with self.subTest(label=label):
                    with mock.patch.object(
                        receipts.os,
                        "fstat",
                        side_effect=lambda fd, values=overrides: trusted(
                            real_fstat(fd), **values
                        ),
                    ):
                        with self.assertRaisesRegex(
                            receipts.ReleaseBrokerReceiptError, message
                        ):
                            receipts.read_trusted_key(
                                private,
                                field="configured private key",
                                private=True,
                                expected_owner_uids=0,
                                parent_owner_uids=os.geteuid(),
                                trusted_path_root=root / "keys",
                                expected_gid=expected_gid,
                                expected_mode=0o640,
                            )

            hardlink = private.with_name("receipt-private-hardlink.pem")
            os.link(private, hardlink)
            try:
                with mock.patch.object(
                    receipts.os,
                    "fstat",
                    side_effect=lambda fd: trusted(real_fstat(fd)),
                ):
                    with self.assertRaisesRegex(
                        receipts.ReleaseBrokerReceiptError, "hard links"
                    ):
                        receipts.read_trusted_key(
                            private,
                            field="configured private key",
                            private=True,
                            expected_owner_uids=0,
                            parent_owner_uids=os.geteuid(),
                            trusted_path_root=root / "keys",
                            expected_gid=expected_gid,
                            expected_mode=0o640,
                        )
            finally:
                hardlink.unlink()

            def swapped_lstat(path: os.PathLike[str] | str) -> Any:
                info = real_lstat(path)
                if Path(path) == private:
                    return trusted(info, st_ino=info.st_ino + 1)
                return info

            with (
                mock.patch.object(
                    receipts.os,
                    "fstat",
                    side_effect=lambda fd: trusted(real_fstat(fd)),
                ),
                mock.patch.object(
                    receipts.os, "lstat", side_effect=swapped_lstat
                ),
            ):
                with self.assertRaisesRegex(
                    receipts.ReleaseBrokerReceiptError,
                    "changed while being read",
                ):
                    receipts.read_trusted_key(
                        private,
                        field="configured private key",
                        private=True,
                        expected_owner_uids=0,
                        parent_owner_uids=os.geteuid(),
                        trusted_path_root=root / "keys",
                        expected_gid=expected_gid,
                        expected_mode=0o640,
                    )

    def test_non_ed25519_keys_and_noncanonical_fingerprints_are_rejected(self):
        rsa = generate_private_key(public_exponent=65537, key_size=2048)
        rsa_private = rsa.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        rsa_public = rsa.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, public = self.write_keys(
                root, private_pem=rsa_private, public_pem=rsa_public
            )
            payload = self.build_success()
            payload["broker"]["signing_key"][
                "public_key_sha256"
            ] = protocol.sha256_bytes(rsa_public)
            refresh_receipt_id(payload)
            with self.assertRaisesRegex(
                receipts.ReleaseBrokerReceiptError, "not Ed25519"
            ):
                receipts.sign_receipt(
                    payload,
                    private_key_path=private,
                    public_key_path=public,
                    expected_public_key_sha256=protocol.sha256_bytes(
                        rsa_public
                    ),
                    expected_key_id="release-receipts-2026-01",
                    key_owner_uids=os.geteuid(),
                    parent_owner_uids=os.geteuid(),
                    trusted_path_root=root / "keys",
                    private_key_owner_uid=os.geteuid(),
                    private_key_gid=os.getegid(),
                    private_key_mode=0o600,
                )
        with self.assertRaises(
            receipts.ReleaseBrokerReceiptError
        ):
            receipts.verify_receipt_with_public_key(
                {},
                public_key=self.public_pem,
                expected_public_key_sha256=self.fingerprint.removeprefix(
                    "sha256:"
                ),
            )

    def test_completion_requires_a_verified_successful_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, public = self.write_keys(root)
            signed = self.sign(self.build_success(), private, public, root)
            self.assertTrue(
                receipts.is_completion_receipt(
                    signed,
                    public_key_path=public,
                    expected_public_key_sha256=self.fingerprint,
                    expected_key_id="release-receipts-2026-01",
                    public_key_owner_uids=os.geteuid(),
                    parent_owner_uids=os.geteuid(),
                    trusted_path_root=root / "keys",
                )
            )
            tampered = copy.deepcopy(signed)
            tampered["payload"]["reason_code"] = "release_other"
            self.assertFalse(
                receipts.is_completion_receipt(
                    tampered,
                    public_key_path=public,
                    expected_public_key_sha256=self.fingerprint,
                    public_key_owner_uids=os.geteuid(),
                    parent_owner_uids=os.geteuid(),
                    trusted_path_root=root / "keys",
                )
            )

    def test_receipt_sources_reject_symlinks_and_future_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, public = self.write_keys(root)
            signed = self.sign(self.build_success(), private, public, root)
            receipt_file = root / "receipt.json"
            receipt_file.write_bytes(protocol.canonical_json(signed))
            link = root / "receipt-link.json"
            link.symlink_to(receipt_file)
            with self.assertRaises(receipts.ReleaseBrokerReceiptError):
                receipts.load_receipt(link)
            with self.assertRaisesRegex(
                receipts.ReleaseBrokerReceiptError, "future"
            ):
                receipts.verify_receipt_with_public_key(
                    signed,
                    public_key=self.public_pem,
                    expected_public_key_sha256=self.fingerprint,
                    now=NOW - timedelta(hours=1),
                )


if __name__ == "__main__":
    unittest.main()
