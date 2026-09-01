#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from broker import john_lomein_broker_protocol as protocol
from broker import john_lomein_broker_receipts as receipts


PROTECTED_SCRIPT = (
    ROOT / "scripts" / "john_lomein_protected_actions.py"
)
spec = importlib.util.spec_from_file_location(
    "test_broker_protected_actions", PROTECTED_SCRIPT
)
assert spec and spec.loader
protected = importlib.util.module_from_spec(spec)
spec.loader.exec_module(protected)


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)


def _run(*argv: str) -> None:
    subprocess.run(
        list(argv),
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )


def _write_ed25519_pair(private_path: Path, public_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    private_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True),
        encoding="utf-8",
    )
    path.chmod(0o600)


def protected_input(
    action: str = "mark_pr_ready",
    *,
    pr_number: int = 17,
    thread_count: int = 1,
) -> dict:
    resolving = action == "resolve_review_thread"
    node_ids = (
        [f"PRRT_thread_{index}" for index in range(thread_count)]
        if resolving
        else []
    )
    thread_urls = (
        [
            f"https://github.com/acme/widget/pull/{pr_number}"
            f"#discussion_r{100 + index}"
            for index in range(thread_count)
        ]
        if resolving
        else []
    )
    return {
        "schema_version": protected.INPUT_SCHEMA,
        "instance_slug": "widget-production",
        "action": action,
        "observed_at": "2026-07-16T11:59:00Z",
        "repo": "acme/widget",
        "pr": {
            "number": pr_number,
            "url": (
                f"https://github.com/acme/widget/pull/{pr_number}"
            ),
            "base_branch": "main",
            "head_sha": "a" * 40,
            "author_login": "john-lomein[bot]",
            "is_draft": action == "mark_pr_ready",
        },
        "preconditions": {
            "checks_state": "success",
            "unresolved_thread_count": (
                thread_count if resolving else 0
            ),
            "forbidden_paths_clear": True,
            "bot_authorship_verified": True,
            "verification": {
                "passed": True,
                "commands_sha256": "b" * 64,
                "result_sha256": "c" * 64,
            },
            "evidence_comment_url": (
                f"https://github.com/acme/widget/pull/{pr_number}"
                "#issuecomment-123"
            ),
        },
        "targets": {
            "thread_node_ids": node_ids,
            "thread_urls": thread_urls,
        },
    }


def packet_for(
    action: str = "mark_pr_ready",
    *,
    pr_number: int = 17,
    thread_count: int = 1,
    ttl_seconds: int = 300,
) -> dict:
    return protected.prepare_packet(
        protected_input(
            action,
            pr_number=pr_number,
            thread_count=thread_count,
        ),
        now=NOW,
        ttl_seconds=ttl_seconds,
    )


def submission_for(packet: dict) -> dict:
    return {
        "schema_version": protocol.SUBMISSION_SCHEMA,
        "packet": packet,
    }


class BrokerFixture:
    root: Path
    keys: Path
    config_path: Path
    github_private: Path
    receipt_private: Path
    receipt_public: Path
    config: dict

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.keys = self.root / "keys"
        self.keys.mkdir(mode=0o700)
        self.github_private = self.keys / "github-app.pem"
        self.receipt_private = self.keys / "receipt-private.pem"
        self.receipt_public = self.keys / "receipt-public.pem"
        _run(
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            str(self.github_private),
        )
        _write_ed25519_pair(self.receipt_private, self.receipt_public)
        for path in (
            self.github_private,
            self.receipt_private,
            self.receipt_public,
        ):
            path.chmod(0o600)
        fingerprint = hashlib.sha256(
            self.receipt_public.read_bytes()
        ).hexdigest()
        uid = os.getuid()
        self.config = {
            "schema_version": protocol.CONFIG_SCHEMA,
            "enabled": True,
            "broker_id": "john-lomein-broker-widget",
            "broker_uid": uid,
            "transport": {
                "kind": protocol.TRANSPORT_KIND,
                "peer_credentials": (
                    protocol.PEER_CREDENTIAL_PROTOCOL
                ),
                "socket_path": str(self.root / "broker.sock"),
                "requester_uid": uid + 1,
                "submit_gid": os.getgid(),
                "max_request_bytes": 256 * 1024,
                "request_timeout_seconds": 10,
            },
            "github_app": {
                "app_id": 1234,
                "app_slug": "john-lomein-broker",
                "installation_id": 5678,
                "private_key_path": str(self.github_private),
                "api_base_url": protocol.GITHUB_API_BASE_URL,
            },
            "receipt_signing": {
                "key_id": "widget-receipts-2026-01",
                "private_key_path": str(self.receipt_private),
                "public_key_path": str(self.receipt_public),
                "public_key_sha256": fingerprint,
            },
            "state": {
                "database_path": str(self.root / "broker.sqlite"),
            },
            "instance": {
                "slug": "widget-production",
                "repository": {
                    "full_name": "acme/widget",
                    "id": 987654,
                    "default_branch": "main",
                },
                "policy": {
                    "allowed_actions": [
                        "mark_pr_ready",
                        "resolve_review_thread",
                    ],
                    "expected_pr_author_login": (
                        "john-lomein[bot]"
                    ),
                    "required_checks": ["CI / test"],
                    "allow_no_required_checks": False,
                    "forbidden_path_prefixes": [
                        ".github/workflows",
                        "release",
                    ],
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
        self.config_path = self.root / "broker.json"
        _write_json(self.config_path, self.config)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def load_config(self) -> dict:
        uid = os.getuid()
        return protocol.load_config(
            self.config_path,
            config_owner_uids={uid},
            key_owner_uids={uid},
            parent_owner_uids={uid},
            trusted_path_root=self.root,
            expected_broker_uid=uid,
        )

    def sign(
        self,
        payload: dict,
        submission: dict,
        config: dict | None = None,
    ) -> dict:
        uid = os.getuid()
        return receipts.sign_receipt(
            payload,
            config or self.config,
            submission,
            key_owner_uids={uid},
            parent_owner_uids={uid},
            trusted_path_root=self.root,
        )

    def verify(
        self,
        envelope: object,
        *,
        config: dict | None = None,
        submission: dict | None = None,
        now: datetime | None = None,
    ) -> dict:
        uid = os.getuid()
        return receipts.verify_receipt(
            envelope,
            public_key_path=self.receipt_public,
            expected_public_key_sha256=self.config[
                "receipt_signing"
            ]["public_key_sha256"],
            expected_key_id=self.config["receipt_signing"]["key_id"],
            public_key_owner_uids={uid},
            parent_owner_uids={uid},
            trusted_path_root=self.root,
            config=config,
            submission=submission,
            now=now,
        )

    def completion(
        self,
        envelope: object,
        *,
        config: dict,
        submission: dict,
        now: datetime | None = None,
    ) -> bool:
        uid = os.getuid()
        return receipts.is_completion_receipt(
            envelope,
            public_key_path=self.receipt_public,
            expected_public_key_sha256=self.config[
                "receipt_signing"
            ]["public_key_sha256"],
            expected_key_id=self.config["receipt_signing"]["key_id"],
            public_key_owner_uids={uid},
            parent_owner_uids={uid},
            trusted_path_root=self.root,
            config=config,
            submission=submission,
            now=now,
        )

    def success_payload(
        self,
        config: dict,
        submission: dict,
        *,
        precondition_digest: str = "d" * 64,
    ) -> dict:
        return receipts.build_receipt_payload(
            config,
            submission,
            precondition_digest=precondition_digest,
            outcome="succeeded",
            reason_code="readback_verified",
            mutation_status="applied",
            readback_status="confirmed",
            started_at=NOW,
            mutation_attempted_at=NOW + timedelta(seconds=1),
            readback_observed_at=NOW + timedelta(seconds=2),
            completed_at=NOW + timedelta(seconds=3),
            operation_id="github-mutation-123",
            readback_head_sha="a" * 40,
            readback_pr_is_draft=False,
        )


class BrokerConfigTest(BrokerFixture, unittest.TestCase):
    def test_loads_complete_root_style_config_and_canonical_digest(self):
        loaded = self.load_config()
        self.assertEqual(loaded, self.config)
        self.assertEqual(
            protocol.config_digest(loaded),
            hashlib.sha256(
                protocol.canonical_json(loaded)
            ).hexdigest(),
        )
        reordered = json.loads(
            json.dumps(self.config, sort_keys=False)
        )
        self.assertEqual(
            protocol.config_digest(reordered),
            protocol.config_digest(loaded),
        )
        changed = copy.deepcopy(loaded)
        changed["instance"]["repository"]["id"] += 1
        self.assertNotEqual(
            protocol.config_digest(changed),
            protocol.config_digest(loaded),
        )

    def test_config_is_strict_and_binds_safety_policy(self):
        cases: list[tuple[str, object]] = []
        unknown = copy.deepcopy(self.config)
        unknown["surprise"] = True
        cases.append(("unknown fields", unknown))
        shared_uid = copy.deepcopy(self.config)
        shared_uid["transport"]["requester_uid"] = os.getuid()
        cases.append(("must be different", shared_uid))
        unsafe_checks = copy.deepcopy(self.config)
        unsafe_checks["instance"]["policy"][
            "accepted_check_conclusions"
        ] = ["FAILURE", "SUCCESS"]
        cases.append(("conclusions are unsafe", unsafe_checks))
        loose_thread_policy = copy.deepcopy(self.config)
        loose_thread_policy["instance"]["policy"][
            "resolve_outdated_threads_only"
        ] = False
        cases.append(("must remain enabled", loose_thread_policy))
        broad_thread_request = copy.deepcopy(self.config)
        broad_thread_request["instance"]["budgets"][
            "max_threads_per_submission"
        ] = 2
        cases.append(("outside the allowed range", broad_thread_request))
        bad_api = copy.deepcopy(self.config)
        bad_api["github_app"]["api_base_url"] = (
            "https://github.example.test/api"
        )
        cases.append(("base URL is unsupported", bad_api))
        for message, value in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(
                    protocol.BrokerProtocolError, message
                ):
                    protocol.normalize_config(value)

    def test_config_and_key_files_reject_writable_or_symlinked_paths(self):
        self.config_path.chmod(0o666)
        with self.assertRaisesRegex(
            protocol.BrokerProtocolError,
            "group/other writable",
        ):
            self.load_config()
        self.config_path.chmod(0o600)

        self.keys.chmod(0o777)
        with self.assertRaisesRegex(
            protocol.BrokerProtocolError,
            "parent directory is group/other writable",
        ):
            self.load_config()
        self.keys.chmod(0o700)

        database = Path(self.config["state"]["database_path"])
        database.write_bytes(b"sqlite")
        database.chmod(0o666)
        with self.assertRaisesRegex(
            protocol.BrokerProtocolError,
            "state database is group/other writable",
        ):
            self.load_config()
        database.unlink()
        os.symlink(self.root / "missing.sqlite", database)
        with self.assertRaisesRegex(
            protocol.BrokerProtocolError,
            "state database is unsafe",
        ):
            self.load_config()
        database.unlink()

        real_config = self.root / "real-config.json"
        self.config_path.rename(real_config)
        os.symlink(real_config, self.config_path)
        with self.assertRaisesRegex(
            protocol.BrokerProtocolError, "unreadable"
        ):
            self.load_config()

    def test_config_loader_rejects_duplicate_json_fields(self):
        raw = json.dumps(self.config, sort_keys=True)
        raw = raw.replace(
            '"enabled": true',
            '"enabled": true, "enabled": false',
            1,
        )
        self.config_path.write_text(raw, encoding="utf-8")
        self.config_path.chmod(0o600)
        with self.assertRaisesRegex(
            protocol.BrokerProtocolError, "duplicate"
        ):
            self.load_config()

    def test_key_fingerprint_and_owner_expectations_fail_closed(self):
        config = copy.deepcopy(self.config)
        config["receipt_signing"]["public_key_sha256"] = "f" * 64
        _write_json(self.config_path, config)
        with self.assertRaisesRegex(
            protocol.BrokerProtocolError,
            "fingerprint does not match",
        ):
            self.load_config()

        _write_json(self.config_path, self.config)
        with self.assertRaisesRegex(
            protocol.BrokerProtocolError,
            "owner is untrusted",
        ):
            protocol.load_config(
                self.config_path,
                config_owner_uids={os.getuid() + 1},
                trusted_path_root=self.root,
            )


class BrokerSubmissionTest(BrokerFixture, unittest.TestCase):
    def test_exact_submission_schema_and_separate_peer_authentication(self):
        config = self.load_config()
        submission = submission_for(packet_for())
        normalized = protocol.normalize_submission(
            submission, config, now=NOW
        )
        self.assertEqual(normalized, submission)
        self.assertEqual(
            protocol.validate_requester_uid(
                config, config["transport"]["requester_uid"]
            ),
            config["transport"]["requester_uid"],
        )
        with self.assertRaisesRegex(
            protocol.BrokerProtocolError, "not authorized"
        ):
            protocol.validate_requester_uid(config, os.getuid() + 2)

        for extra in ("requester_uid", "broker_config_sha256"):
            hostile = copy.deepcopy(submission)
            hostile[extra] = (
                123 if extra == "requester_uid" else "d" * 64
            )
            with self.subTest(extra=extra), self.assertRaisesRegex(
                protocol.BrokerProtocolError, "unknown fields"
            ):
                protocol.normalize_submission(
                    hostile, config, now=NOW
                )

    def test_submission_loader_rejects_duplicate_fields_and_symlinks(self):
        config = self.load_config()
        duplicate = (
            b'{"schema_version":"'
            + protocol.SUBMISSION_SCHEMA.encode("ascii")
            + b'","packet":null,"packet":null}'
        )
        with self.assertRaisesRegex(
            protocol.BrokerProtocolError, "duplicate"
        ):
            protocol.load_submission(duplicate, config, now=NOW)

        source = self.root / "submission.json"
        target = self.root / "real-submission.json"
        _write_json(target, submission_for(packet_for()))
        os.symlink(target, source)
        with self.assertRaisesRegex(
            protocol.BrokerProtocolError, "unreadable"
        ):
            protocol.load_submission(source, config, now=NOW)

    def test_submission_binds_instance_repo_branch_author_action_and_ttl(self):
        config = self.load_config()
        base_submission = submission_for(packet_for())
        cases: list[tuple[str, dict]] = []
        wrong_instance = copy.deepcopy(config)
        wrong_instance["instance"]["slug"] = "other-production"
        cases.append(("instance does not match", wrong_instance))
        wrong_repo = copy.deepcopy(config)
        wrong_repo["instance"]["repository"]["full_name"] = (
            "acme/other"
        )
        cases.append(("repository does not match", wrong_repo))
        wrong_branch = copy.deepcopy(config)
        wrong_branch["instance"]["repository"]["default_branch"] = (
            "trunk"
        )
        cases.append(("default branch does not match", wrong_branch))
        wrong_author = copy.deepcopy(config)
        wrong_author["instance"]["policy"][
            "expected_pr_author_login"
        ] = "other-bot[bot]"
        cases.append(("PR author does not match", wrong_author))
        no_action = copy.deepcopy(config)
        no_action["instance"]["policy"]["allowed_actions"] = [
            "resolve_review_thread"
        ]
        cases.append(("action is not allowed", no_action))
        short_ttl = copy.deepcopy(config)
        short_ttl["instance"]["policy"][
            "maximum_packet_ttl_seconds"
        ] = 120
        cases.append(("exceeds the policy TTL", short_ttl))
        for message, test_config in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                protocol.BrokerProtocolError, message
            ):
                protocol.normalize_submission(
                    base_submission, test_config, now=NOW
                )

    def test_broker_uses_local_packet_validator_and_one_thread_limit(self):
        config = self.load_config()
        packet = packet_for()
        forged = copy.deepcopy(packet)
        forged["request"]["repo"] = "evil/repository"
        with mock.patch.object(
            protected, "verify_packet", return_value=forged
        ):
            with self.assertRaisesRegex(
                protocol.BrokerProtocolError,
                "must target the bound PR|digest does not match",
            ):
                protocol.normalize_submission(
                    submission_for(forged), config, now=NOW
                )

        two_threads = submission_for(
            packet_for(
                "resolve_review_thread", thread_count=2
            )
        )
        with self.assertRaisesRegex(
            protocol.BrokerProtocolError,
            "exactly one review thread",
        ):
            protocol.normalize_submission(
                two_threads, config, now=NOW
            )

    def test_disabled_config_and_policy_clock_skew_fail_closed(self):
        disabled = self.load_config()
        disabled["enabled"] = False
        with self.assertRaisesRegex(
            protocol.BrokerProtocolError, "disabled"
        ):
            protocol.normalize_submission(
                submission_for(packet_for()), disabled, now=NOW
            )

        future_now = NOW - timedelta(seconds=31)
        with self.assertRaisesRegex(
            protocol.BrokerProtocolError, "policy clock skew"
        ):
            protocol.normalize_submission(
                submission_for(packet_for()),
                self.load_config(),
                now=future_now,
            )
        with self.assertRaisesRegex(
            protocol.BrokerProtocolError, "timezone-aware"
        ):
            protocol.normalize_submission(
                submission_for(packet_for()),
                self.load_config(),
                now=datetime(2026, 7, 16, 12, 0),
            )

    def test_exact_evidence_marker_is_derived_from_packet(self):
        packet = packet_for()
        self.assertEqual(
            protocol.evidence_marker_for_packet(packet),
            "<!-- john-lomein-protected-evidence:v1 "
            "instance=widget-production "
            "action=mark_pr_ready "
            f"head={'a' * 40} commands={'b' * 64} "
            f"result={'c' * 64} -->",
        )
        changed = packet_for(pr_number=18)
        changed["request"]["pr"]["head_sha"] = "e" * 40
        with self.assertRaisesRegex(
            protocol.BrokerProtocolError, "digest does not match"
        ):
            protocol.evidence_marker_for_packet(changed)


class BrokerReceiptTest(BrokerFixture, unittest.TestCase):
    def test_success_receipt_is_signed_pinned_context_bound_and_historical(self):
        config = self.load_config()
        submission = submission_for(packet_for())
        payload = self.success_payload(config, submission)
        envelope = self.sign(payload, submission, config)
        verified = self.verify(
            envelope,
            config=config,
            submission=submission,
            now=NOW + timedelta(days=30),
        )
        self.assertEqual(verified, envelope)
        self.assertEqual(
            verified["payload"]["github_app"]["app_slug"],
            "john-lomein-broker",
        )
        self.assertTrue(
            self.completion(
                envelope,
                config=config,
                submission=submission,
                now=NOW + timedelta(days=30),
            )
        )

    def test_only_success_plus_confirmed_readback_counts_as_completion(self):
        config = self.load_config()
        submission = submission_for(packet_for())
        rejected = receipts.build_receipt_payload(
            config,
            submission,
            precondition_digest="d" * 64,
            outcome="rejected",
            reason_code="precondition_policy_denied",
            mutation_status="not_attempted",
            readback_status="not_attempted",
            started_at=NOW,
            completed_at=NOW + timedelta(seconds=1),
        )
        envelope = self.sign(rejected, submission, config)
        self.verify(
            envelope, config=config, submission=submission
        )
        self.assertFalse(
            self.completion(
                envelope, config=config, submission=submission
            )
        )
        already_satisfied = receipts.build_receipt_payload(
            config,
            submission,
            precondition_digest="d" * 64,
            outcome="succeeded",
            reason_code="already_satisfied",
            mutation_status="already_satisfied",
            readback_status="confirmed",
            started_at=NOW,
            readback_observed_at=NOW + timedelta(seconds=1),
            completed_at=NOW + timedelta(seconds=2),
            readback_head_sha="a" * 40,
            readback_pr_is_draft=False,
        )
        already_envelope = self.sign(
            already_satisfied, submission, config
        )
        self.assertTrue(
            self.completion(
                already_envelope,
                config=config,
                submission=submission,
            )
        )
        with self.assertRaisesRegex(
            receipts.BrokerReceiptError,
            "successful receipt requires",
        ):
            receipts.build_receipt_payload(
                config,
                submission,
                precondition_digest="d" * 64,
                outcome="succeeded",
                reason_code="readback_verified",
                mutation_status="applied",
                readback_status="not_confirmed",
                operation_id="github-mutation-123",
                started_at=NOW,
                mutation_attempted_at=NOW
                + timedelta(seconds=1),
                readback_observed_at=NOW
                + timedelta(seconds=2),
                completed_at=NOW + timedelta(seconds=3),
                readback_head_sha="a" * 40,
                readback_pr_is_draft=True,
            )
        with self.assertRaisesRegex(
            receipts.BrokerReceiptError, "reason_code is invalid"
        ):
            receipts.build_receipt_payload(
                config,
                submission,
                precondition_digest="d" * 64,
                outcome="rejected",
                reason_code="raw exception: token leaked",
                mutation_status="not_attempted",
                readback_status="not_attempted",
                started_at=NOW,
                completed_at=NOW + timedelta(seconds=1),
            )

    def test_signature_tampering_and_wrong_pin_fail_closed(self):
        config = self.load_config()
        submission = submission_for(packet_for())
        first = self.sign(
            self.success_payload(config, submission),
            submission,
            config,
        )
        second_payload = self.success_payload(
            config,
            submission,
            precondition_digest="e" * 64,
        )
        forged = copy.deepcopy(first)
        forged["payload"] = second_payload
        forged["payload_sha256"] = hashlib.sha256(
            protocol.canonical_json(second_payload)
        ).hexdigest()
        with self.assertRaisesRegex(
            receipts.BrokerReceiptError,
            "signature verification failed",
        ):
            self.verify(
                forged, config=config, submission=submission
            )
        with self.assertRaisesRegex(
            receipts.BrokerReceiptError, "not pinned"
        ):
            receipts.verify_receipt(
                first,
                public_key_path=self.receipt_public,
                expected_public_key_sha256="f" * 64,
                public_key_owner_uids={os.getuid()},
                parent_owner_uids={os.getuid()},
                trusted_path_root=self.root,
            )
        with self.assertRaisesRegex(
            receipts.BrokerReceiptError, "key ID is not pinned"
        ):
            receipts.verify_receipt(
                first,
                public_key_path=self.receipt_public,
                expected_public_key_sha256=self.config[
                    "receipt_signing"
                ]["public_key_sha256"],
                expected_key_id="wrong-receipt-key",
                public_key_owner_uids={os.getuid()},
                parent_owner_uids={os.getuid()},
                trusted_path_root=self.root,
            )

    def test_receipt_context_rejects_other_packet_repo_or_app(self):
        config = self.load_config()
        submission = submission_for(packet_for())
        envelope = self.sign(
            self.success_payload(config, submission),
            submission,
            config,
        )
        other_submission = submission_for(
            packet_for(pr_number=18)
        )
        with self.assertRaisesRegex(
            receipts.BrokerReceiptError,
            "packet binding does not match",
        ):
            self.sign(
                self.success_payload(config, submission),
                other_submission,
                config,
            )
        with self.assertRaisesRegex(
            receipts.BrokerReceiptError,
            "packet binding does not match",
        ):
            self.verify(
                envelope,
                config=config,
                submission=other_submission,
            )
        other_config = copy.deepcopy(config)
        other_config["github_app"]["installation_id"] += 1
        with self.assertRaisesRegex(
            receipts.BrokerReceiptError,
            "broker_config_sha256 binding does not match",
        ):
            self.verify(
                envelope,
                config=other_config,
                submission=submission,
            )

    def test_signing_and_verification_use_stable_key_snapshots(self):
        config = self.load_config()
        submission = submission_for(packet_for())
        payload = self.success_payload(config, submission)
        attacker_private = self.keys / "attacker-private.pem"
        attacker_public = self.keys / "attacker-public.pem"
        _write_ed25519_pair(attacker_private, attacker_public)
        original_reader = receipts.read_trusted_file
        swapped_private = False

        def swap_private_after_read(*args, **kwargs):
            nonlocal swapped_private
            data = original_reader(*args, **kwargs)
            if (
                kwargs.get("field")
                == "broker receipt private key"
                and not swapped_private
            ):
                swapped_private = True
                self.receipt_private.write_bytes(
                    attacker_private.read_bytes()
                )
                self.receipt_private.chmod(0o600)
            return data

        with mock.patch.object(
            receipts,
            "read_trusted_file",
            side_effect=swap_private_after_read,
        ):
            envelope = self.sign(payload, submission, config)
        self.assertTrue(swapped_private)

        original_public = self.receipt_public.read_bytes()
        swapped_public = False

        def swap_public_after_read(*args, **kwargs):
            nonlocal swapped_public
            if (
                kwargs.get("field")
                == "broker receipt verification public key"
            ):
                self.receipt_public.write_bytes(original_public)
                data = original_reader(*args, **kwargs)
                self.receipt_public.write_bytes(
                    attacker_public.read_bytes()
                )
                self.receipt_public.chmod(0o600)
                swapped_public = True
                return data
            return original_reader(*args, **kwargs)

        with mock.patch.object(
            receipts,
            "read_trusted_file",
            side_effect=swap_public_after_read,
        ):
            verified = self.verify(
                envelope,
                config=config,
                submission=submission,
            )
        self.assertTrue(swapped_public)
        self.assertEqual(verified, envelope)

    def test_public_key_symlink_and_duplicate_envelope_are_rejected(self):
        config = self.load_config()
        submission = submission_for(packet_for())
        envelope = self.sign(
            self.success_payload(config, submission),
            submission,
            config,
        )
        encoded = json.dumps(envelope, sort_keys=True)
        duplicate = (
            '{"schema_version":"'
            + receipts.RECEIPT_ENVELOPE_SCHEMA
            + '","schema_version":"'
            + receipts.RECEIPT_ENVELOPE_SCHEMA
            + '","algorithm":"Ed25519","public_key_sha256":"'
            + self.config["receipt_signing"]["public_key_sha256"]
            + '","payload_sha256":"'
            + envelope["payload_sha256"]
            + '","payload":'
            + json.dumps(envelope["payload"], sort_keys=True)
            + ',"signature":'
            + json.dumps(envelope["signature"])
            + "}"
        )
        self.assertTrue(encoded)
        with self.assertRaisesRegex(
            receipts.BrokerReceiptError, "duplicate"
        ):
            receipts.load_receipt(duplicate.encode("utf-8"))

        real_public = self.keys / "real-public.pem"
        self.receipt_public.rename(real_public)
        os.symlink(real_public, self.receipt_public)
        with self.assertRaisesRegex(
            receipts.BrokerReceiptError, "unreadable"
        ):
            self.verify(
                envelope,
                config=config,
                submission=submission,
            )

    def test_confirmed_readback_must_prove_exact_action_and_head(self):
        config = self.load_config()
        mark_submission = submission_for(packet_for())
        with self.assertRaisesRegex(
            receipts.BrokerReceiptError,
            "does not prove promotion",
        ):
            receipts.build_receipt_payload(
                config,
                mark_submission,
                precondition_digest="d" * 64,
                outcome="succeeded",
                reason_code="readback_verified",
                mutation_status="applied",
                readback_status="confirmed",
                operation_id="github-mutation-123",
                started_at=NOW,
                mutation_attempted_at=NOW
                + timedelta(seconds=1),
                readback_observed_at=NOW
                + timedelta(seconds=2),
                completed_at=NOW + timedelta(seconds=3),
                readback_head_sha="a" * 40,
                readback_pr_is_draft=True,
            )

        thread_submission = submission_for(
            packet_for("resolve_review_thread")
        )
        with self.assertRaisesRegex(
            receipts.BrokerReceiptError,
            "exact target resolution",
        ):
            receipts.build_receipt_payload(
                config,
                thread_submission,
                precondition_digest="d" * 64,
                outcome="succeeded",
                reason_code="readback_verified",
                mutation_status="applied",
                readback_status="confirmed",
                operation_id="github-mutation-123",
                started_at=NOW,
                mutation_attempted_at=NOW
                + timedelta(seconds=1),
                readback_observed_at=NOW
                + timedelta(seconds=2),
                completed_at=NOW + timedelta(seconds=3),
                readback_head_sha="a" * 40,
                readback_pr_is_draft=False,
                resolved_thread_node_ids=[],
            )
        resolved = receipts.build_receipt_payload(
            config,
            thread_submission,
            precondition_digest="d" * 64,
            outcome="succeeded",
            reason_code="readback_verified",
            mutation_status="applied",
            readback_status="confirmed",
            started_at=NOW,
            mutation_attempted_at=NOW + timedelta(seconds=1),
            readback_observed_at=NOW + timedelta(seconds=2),
            completed_at=NOW + timedelta(seconds=3),
            operation_id="github-thread-mutation-123",
            readback_head_sha="a" * 40,
            readback_pr_is_draft=False,
            resolved_thread_node_ids=["PRRT_thread_0"],
        )
        self.assertTrue(
            self.completion(
                self.sign(resolved, thread_submission, config),
                config=config,
                submission=thread_submission,
            )
        )


if __name__ == "__main__":
    unittest.main()
