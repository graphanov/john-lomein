#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_broker import john_lomein_release_broker_protocol as protocol


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)


def release_bundle(
    *,
    paths: list[str] | None = None,
    risk_class: str = "low",
    pr_number: int = 17,
    head_sha: str = "b" * 40,
    expected_merge_tree_sha: str = "e" * 40,
) -> dict:
    paths = ["src/widget.py", "tests/test_widget.py"] if paths is None else paths
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
        "initial_base_sha": "a" * 40,
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
                "risk_class": risk_class,
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


def owner_envelope(
    bundle: dict,
    private_key: Ed25519PrivateKey,
    *,
    approval_text: str,
    actor_id: str = "owner-123",
    issued_at: str = "2026-07-16T11:59:00Z",
    expires_at: str = "2026-07-16T12:10:00Z",
) -> dict:
    payload = {
        "schema_version": protocol.OWNER_ASSERTION_SCHEMA,
        "purpose": "release_merge",
        "issuer": "trusted-owner-gateway",
        "actor_id": actor_id,
        "actor_login": "maintainer",
        "tier": "owner",
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": "c" * 64,
        "instance_slug": bundle["instance_slug"],
        "repository_id": bundle["repository"]["id"],
        "repository_full_name": bundle["repository"]["full_name"],
        "bundle_id": bundle["bundle_id"],
        "bundle_digest": bundle["bundle_digest"],
        "approval_text_sha256": protocol.sha256_text(approval_text),
        "action": protocol.RELEASE_ACTION,
        "merge_method": "squash",
        "publish": False,
        "ordered_prs_digest": protocol.ordered_prs_digest(bundle),
        "changed_paths_digest": protocol.changed_paths_digest(bundle),
        "risk_class": protocol.aggregate_risk_class(bundle),
    }
    signature = private_key.sign(protocol.canonical_json(payload))
    return {
        "schema_version": protocol.SIGNED_ENVELOPE_SCHEMA,
        "algorithm": protocol.SIGNATURE_ALGORITHM,
        "key_id": "owner-2026-01",
        "payload": payload,
        "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }


def release_packet(
    bundle: dict,
    assertion: dict,
    *,
    approval_text: str,
) -> dict:
    request = {
        "action": protocol.RELEASE_ACTION,
        "bundle": bundle,
        "approval": {
            "text": approval_text,
            "text_sha256": protocol.sha256_text(approval_text),
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
    packet = {
        **body,
        "packet_id": (
            "jlrp-"
            + protocol.sha256_json(body).removeprefix("sha256:")[:24]
        ),
        "request_digest": protocol.sha256_json(request),
    }
    return packet


def release_config(root: Path) -> dict:
    uid = os.getuid()
    submit_gid = os.getgid()
    broker_private_gid = 1 if submit_gid != 1 else 2
    return {
        "schema_version": protocol.CONFIG_SCHEMA,
        "enabled": False,
        "broker_id": "john-lomein-release-widget",
        "broker_uid": uid,
        "broker_private_gid": broker_private_gid,
        "transport": {
            "kind": protocol.TRANSPORT_KIND,
            "peer_credentials": protocol.PEER_CREDENTIAL_PROTOCOL,
            "socket_path": str(root / "run" / "release.sock"),
            "requester_uid": uid + 1,
            "submit_gid": submit_gid,
            "max_request_bytes": 1024 * 1024,
            "request_timeout_seconds": 10,
        },
        "github_app": {
            "app_id": 1234,
            "app_slug": "john-lomein-release",
            "installation_id": 5678,
            "private_key_path": str(root / "keys" / "github.pem"),
            "api_base_url": "https://api.github.com",
        },
        "owner_assertion": {
            "issuer": "trusted-owner-gateway",
            "key_id": "owner-2026-01",
            "public_key_path": str(root / "keys" / "owner.pub.pem"),
            "public_key_sha256": "sha256:" + "a" * 64,
            "allowed_actor_ids": ["owner-123", "owner-456"],
            "maximum_ttl_seconds": 600,
            "maximum_clock_skew_seconds": 30,
        },
        "receipt_signing": {
            "key_id": "release-receipts-2026-01",
            "private_key_path": str(
                root / "keys" / "receipt.private.pem"
            ),
            "public_key_path": str(
                root / "keys" / "receipt.public.pem"
            ),
            "public_key_sha256": "sha256:" + "b" * 64,
        },
        "state": {
            "database_path": str(root / "state" / "release.sqlite3"),
        },
        "instance": {
            "slug": "widget-production",
            "repository": {
                "id": 987654,
                "full_name": "acme/widget",
                "default_branch": "main",
            },
            "policy": {
                "expected_pr_author_logins": [
                    "john-lomein[bot]",
                    "maintainer",
                ],
                "expected_merge_actor_login": (
                    "john-lomein-release[bot]"
                ),
                "codex_evidence_author_logins": [
                    "chatgpt-codex-connector[bot]"
                ],
                "required_checks": [
                    {
                        "kind": "check_run",
                        "name": "CI / test",
                        "producer_app_id": 15368,
                        "producer_slug": "github-actions",
                        "producer_login": None,
                    }
                ],
                "forbidden_path_prefixes": [
                    ".github/workflows",
                    "release",
                ],
                "require_same_repository_head": True,
                "require_codex_evidence": True,
                "reject_unconfigured_failures": True,
                "maximum_changed_files_per_pr": 300,
                "maximum_total_changed_files": 300,
                "minimum_rate_limit_remaining": 100,
                "maximum_bundle_ttl_seconds": 3600,
                "maximum_packet_ttl_seconds": 600,
                "maximum_execution_seconds": 300,
                "max_prs_per_bundle": 1,
                "merge_method": "squash",
                "publish": False,
                "delete_branch": False,
            },
            "budgets": {
                "unique_requests_per_hour": 20,
                "owner_assertions_per_hour": 10,
                "bundles_per_day": 5,
                "mutation_attempts_per_day": 5,
                "confirmed_merges_per_day": 3,
                "consecutive_indeterminate_limit": 2,
            },
        },
    }


class ReleaseBrokerProtocolTest(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.approval = (
            "APPROVE JOHN-LOMEIN RELEASE BUNDLE: squash-merge the exact "
            "listed PR; DO NOT publish."
        )
        self.bundle = release_bundle()
        self.assertion = owner_envelope(
            self.bundle,
            self.private_key,
            approval_text=self.approval,
        )
        self.packet = release_packet(
            self.bundle,
            self.assertion,
            approval_text=self.approval,
        )

    def test_valid_packet_is_strict_digest_bound_and_request_only(self):
        normalized = protocol.normalize_release_packet(
            self.packet, now=NOW
        )
        self.assertEqual(normalized, self.packet)
        self.assertEqual(
            normalized["authority"],
            "request_only_no_execution_authority",
        )
        self.assertEqual(len(normalized["request"]["bundle"]["ordered_prs"]), 1)
        self.assertEqual(
            protocol.normalize_submission(
                {
                    "schema_version": protocol.SUBMISSION_SCHEMA,
                    "packet": self.packet,
                },
                now=NOW,
            )["packet"],
            self.packet,
        )

    def test_bundle_digest_binds_order_head_paths_risk_and_action_scope(self):
        mutations = []
        for mutate in (
            lambda value: value["ordered_prs"][0].update(
                {"head_sha": "d" * 40}
            ),
            lambda value: value["ordered_prs"][0].update(
                {"expected_merge_tree_sha": "d" * 40}
            ),
            lambda value: value["ordered_prs"][0]["changed_paths"].append(
                "z-last"
            ),
            lambda value: value["ordered_prs"][0].update(
                {"risk_class": "critical"}
            ),
            lambda value: value["actions"].update({"publish": True}),
            lambda value: value.update({"publish": True}),
        ):
            candidate = copy.deepcopy(self.bundle)
            mutate(candidate)
            mutations.append(candidate)
        for candidate in mutations:
            with self.subTest(candidate=candidate):
                with self.assertRaises(protocol.ReleaseBrokerProtocolError):
                    protocol.normalize_release_bundle(candidate)

        second = release_bundle(
            pr_number=18,
            head_sha="e" * 40,
            paths=["src/second.py"],
        )["ordered_prs"][0]
        ordered = copy.deepcopy(self.bundle)
        second["position"] = 1
        ordered["ordered_prs"].append(second)
        ordered["bundle_digest"] = protocol.release_bundle_digest(ordered)
        ordered["bundle_id"] = protocol.release_bundle_id(ordered)
        normalized = protocol.normalize_release_bundle(ordered)
        reversed_bundle = copy.deepcopy(normalized)
        reversed_bundle["ordered_prs"].reverse()
        for index, pr in enumerate(reversed_bundle["ordered_prs"]):
            pr["position"] = index
        self.assertNotEqual(
            protocol.release_bundle_digest(reversed_bundle),
            normalized["bundle_digest"],
        )

    def test_bundle_rejects_unknown_fields_unsafe_paths_and_nonfull_oids(self):
        unknown = copy.deepcopy(self.bundle)
        unknown["compatibility_projection"] = {}
        with self.assertRaisesRegex(
            protocol.ReleaseBrokerProtocolError, "unknown fields"
        ):
            protocol.normalize_release_bundle(unknown)

        unsafe = release_bundle(paths=["../secrets"])
        with self.assertRaisesRegex(
            protocol.ReleaseBrokerProtocolError, "unsafe"
        ):
            protocol.normalize_release_bundle(unsafe)

        abbreviated = copy.deepcopy(self.bundle)
        abbreviated["initial_base_sha"] = "abc1234"
        abbreviated["bundle_digest"] = protocol.release_bundle_digest(
            abbreviated
        )
        abbreviated["bundle_id"] = protocol.release_bundle_id(abbreviated)
        with self.assertRaisesRegex(
            protocol.ReleaseBrokerProtocolError, "full Git OID"
        ):
            protocol.normalize_release_bundle(abbreviated)

        abbreviated_tree = copy.deepcopy(self.bundle)
        abbreviated_tree["ordered_prs"][0][
            "expected_merge_tree_sha"
        ] = "abc1234"
        abbreviated_tree["bundle_digest"] = (
            protocol.release_bundle_digest(abbreviated_tree)
        )
        abbreviated_tree["bundle_id"] = protocol.release_bundle_id(
            abbreviated_tree
        )
        with self.assertRaisesRegex(
            protocol.ReleaseBrokerProtocolError, "full Git OID"
        ):
            protocol.normalize_release_bundle(abbreviated_tree)

    def test_bound_github_urls_reject_queries_fragments_and_suffixes(self):
        for value in (
            "https://github.com/acme/widget/pull/17/files",
            "https://github.com/acme/widget/pull/17?token=secret",
            "https://github.com/acme/widget/pull/17#discussion_r1",
            "https://evil.example/acme/widget/pull/17",
        ):
            candidate = copy.deepcopy(self.bundle)
            candidate["ordered_prs"][0]["url"] = value
            candidate["bundle_digest"] = protocol.release_bundle_digest(
                candidate
            )
            candidate["bundle_id"] = protocol.release_bundle_id(candidate)
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    protocol.ReleaseBrokerProtocolError,
                    "bound GitHub PR",
                ):
                    protocol.normalize_release_bundle(candidate)

    def test_packet_cross_binds_every_owner_authorized_dimension(self):
        fields = {
            "instance_slug": "other-instance",
            "repository_id": 22,
            "repository_full_name": "other/repo",
            "bundle_id": "jlb-" + "d" * 24,
            "bundle_digest": "sha256:" + "d" * 64,
            "approval_text_sha256": "sha256:" + "d" * 64,
            "ordered_prs_digest": "sha256:" + "d" * 64,
            "changed_paths_digest": "sha256:" + "d" * 64,
            "risk_class": "critical",
        }
        for field, value in fields.items():
            packet = copy.deepcopy(self.packet)
            packet["request"]["owner_assertion"]["payload"][field] = value
            request = packet["request"]
            packet["request_digest"] = protocol.sha256_json(request)
            body = {
                key: packet[key]
                for key in (
                    "schema_version",
                    "created_at",
                    "expires_at",
                    "authority",
                    "requested_by",
                    "request",
                )
            }
            packet["packet_id"] = (
                "jlrp-"
                + protocol.sha256_json(body).removeprefix("sha256:")[:24]
            )
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    protocol.ReleaseBrokerProtocolError,
                    f"assertion {field}",
                ):
                    protocol.normalize_release_packet(packet, now=NOW)

    def test_packet_rejects_multiple_prs_until_train_verifier_exists(self):
        bundle = copy.deepcopy(self.bundle)
        second = release_bundle(
            pr_number=18,
            head_sha="e" * 40,
            paths=["src/second.py"],
        )["ordered_prs"][0]
        second["position"] = 1
        bundle["ordered_prs"].append(second)
        bundle["bundle_digest"] = protocol.release_bundle_digest(bundle)
        bundle["bundle_id"] = protocol.release_bundle_id(bundle)
        assertion = owner_envelope(
            bundle, self.private_key, approval_text=self.approval
        )
        packet = release_packet(
            bundle, assertion, approval_text=self.approval
        )
        with self.assertRaisesRegex(
            protocol.ReleaseBrokerProtocolError, "exactly one PR"
        ):
            protocol.normalize_release_packet(packet, now=NOW)

    def test_expiry_future_time_and_outliving_bundle_fail_closed(self):
        with self.assertRaisesRegex(
            protocol.ReleaseBrokerProtocolError, "expired"
        ):
            protocol.normalize_release_packet(
                self.packet, now=NOW + timedelta(minutes=6)
            )
        future = copy.deepcopy(self.packet)
        future["created_at"] = "2026-07-16T12:10:00Z"
        future["expires_at"] = "2026-07-16T12:15:00Z"
        body = {
            key: future[key]
            for key in (
                "schema_version",
                "created_at",
                "expires_at",
                "authority",
                "requested_by",
                "request",
            )
        }
        future["packet_id"] = (
            "jlrp-"
            + protocol.sha256_json(body).removeprefix("sha256:")[:24]
        )
        with self.assertRaisesRegex(
            protocol.ReleaseBrokerProtocolError, "future"
        ):
            protocol.normalize_release_packet(future, now=NOW)

        outlives = copy.deepcopy(self.packet)
        outlives["expires_at"] = "2026-07-16T12:35:00Z"
        body["created_at"] = outlives["created_at"]
        body["expires_at"] = outlives["expires_at"]
        outlives["packet_id"] = (
            "jlrp-"
            + protocol.sha256_json(body).removeprefix("sha256:")[:24]
        )
        with self.assertRaisesRegex(
            protocol.ReleaseBrokerProtocolError, "outlives"
        ):
            protocol.normalize_release_packet(outlives, now=NOW)

    def test_root_owned_configuration_binding_is_exact(self):
        normalized = protocol.normalize_release_packet(
            self.packet, now=NOW
        )
        self.assertIs(
            protocol.validate_packet_binding(
                normalized,
                instance_slug="widget-production",
                repository_id=987654,
                repository_full_name="acme/widget",
                default_branch="main",
            ),
            normalized,
        )
        with self.assertRaisesRegex(
            protocol.ReleaseBrokerProtocolError, "repository ID"
        ):
            protocol.validate_packet_binding(
                normalized,
                instance_slug="widget-production",
                repository_id=1,
                repository_full_name="acme/widget",
                default_branch="main",
            )

    def test_duplicate_float_and_non_nfc_json_are_rejected(self):
        with self.assertRaisesRegex(
            protocol.ReleaseBrokerProtocolError, "duplicate"
        ):
            protocol.parse_json_bytes(
                b'{"schema_version":"x","schema_version":"y"}',
                field="packet",
            )
        with self.assertRaisesRegex(
            protocol.ReleaseBrokerProtocolError, "floats"
        ):
            protocol.parse_json_bytes(b'{"value":1.5}', field="packet")
        decomposed = json.dumps(
            {"actor": "e\u0301"}, ensure_ascii=False
        ).encode("utf-8")
        with self.assertRaisesRegex(
            protocol.ReleaseBrokerProtocolError, "NFC"
        ):
            protocol.parse_json_bytes(decomposed, field="packet")

    def test_root_owned_config_is_explicit_disabled_and_digest_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = release_config(Path(temporary))
            normalized = protocol.normalize_config(config)
            self.assertEqual(normalized, config)
            self.assertFalse(normalized["enabled"])
            self.assertEqual(
                normalized["instance"]["policy"]["max_prs_per_bundle"],
                1,
            )
            self.assertTrue(
                protocol.config_digest(config).startswith("sha256:")
            )
            changed = copy.deepcopy(config)
            changed["instance"]["budgets"]["bundles_per_day"] = 4
            self.assertNotEqual(
                protocol.config_digest(config),
                protocol.config_digest(changed),
            )

    def test_config_rejects_authority_inflation_and_identity_aliasing(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = release_config(Path(temporary))
            mutations = [
                ("multi PR", lambda value: value["instance"]["policy"].update(
                    {"max_prs_per_bundle": 2}
                )),
                ("publishing", lambda value: value["instance"]["policy"].update(
                    {"publish": True}
                )),
                ("deletion", lambda value: value["instance"]["policy"].update(
                    {"delete_branch": True}
                )),
                ("origin", lambda value: value["github_app"].update(
                    {"api_base_url": "https://proxy.invalid"}
                )),
                ("same UID", lambda value: value["transport"].update(
                    {"requester_uid": value["broker_uid"]}
                )),
                ("root private GID", lambda value: value.update(
                    {"broker_private_gid": 0}
                )),
                ("shared private and submit GID", lambda value: value.update(
                    {
                        "broker_private_gid": value["transport"][
                            "submit_gid"
                        ]
                    }
                )),
                ("aliased key", lambda value: value["receipt_signing"].update(
                    {
                        "public_key_path": value["owner_assertion"][
                            "public_key_path"
                        ]
                    }
                )),
            ]
            for label, mutate in mutations:
                candidate = copy.deepcopy(base)
                mutate(candidate)
                with self.subTest(label=label):
                    with self.assertRaises(
                        protocol.ReleaseBrokerProtocolError
                    ):
                        protocol.normalize_config(candidate)

            missing_private_gid = copy.deepcopy(base)
            del missing_private_gid["broker_private_gid"]
            with self.assertRaisesRegex(
                protocol.ReleaseBrokerProtocolError, "missing required"
            ):
                protocol.normalize_config(missing_private_gid)

            invalid_private_gid = copy.deepcopy(base)
            invalid_private_gid["broker_private_gid"] = "1"
            with self.assertRaisesRegex(
                protocol.ReleaseBrokerProtocolError, "must be a GID"
            ):
                protocol.normalize_config(invalid_private_gid)

    def test_config_requires_exact_check_producer_and_sorted_policies(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = release_config(Path(temporary))
            missing_producer = copy.deepcopy(base)
            del missing_producer["instance"]["policy"]["required_checks"][0][
                "producer_app_id"
            ]
            with self.assertRaisesRegex(
                protocol.ReleaseBrokerProtocolError, "missing required"
            ):
                protocol.normalize_config(missing_producer)

            unsorted = copy.deepcopy(base)
            unsorted["owner_assertion"]["allowed_actor_ids"].reverse()
            with self.assertRaisesRegex(
                protocol.ReleaseBrokerProtocolError, "sorted and unique"
            ):
                protocol.normalize_config(unsorted)

    def test_config_file_and_requester_identity_use_trusted_local_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            config = release_config(root)
            path = root / "release-broker.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            path.chmod(0o600)
            loaded = protocol.load_config(
                path,
                expected_owner_uids={os.getuid()},
                parent_owner_uids={os.getuid()},
                trusted_path_root=root,
            )
            self.assertEqual(loaded, config)
            self.assertEqual(
                protocol.validate_requester_uid(
                    loaded,
                    config["transport"]["requester_uid"],
                ),
                config["transport"]["requester_uid"],
            )
            with self.assertRaisesRegex(
                protocol.ReleaseBrokerProtocolError, "unauthorized"
            ):
                protocol.validate_requester_uid(loaded, os.getuid() + 99)


if __name__ == "__main__":
    unittest.main()
