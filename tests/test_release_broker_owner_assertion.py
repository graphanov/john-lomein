#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import os
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_broker import john_lomein_release_broker_protocol as protocol
from tests.test_release_broker_protocol import (
    NOW,
    owner_envelope,
    release_bundle,
    release_config,
    release_packet,
)


APPROVAL = (
    "APPROVE JOHN-LOMEIN RELEASE BUNDLE: squash-merge the exact listed PR; "
    "DO NOT publish."
)


class ReleaseOwnerAssertionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.bundle = release_bundle()
        self.envelope = owner_envelope(
            self.bundle,
            self.private_key,
            approval_text=APPROVAL,
        )

    def test_ed25519_assertion_verifies_with_pinned_identity(self):
        normalized = protocol.verify_owner_assertion_signature(
            self.envelope,
            public_key=self.public_key,
            expected_public_key_sha256=protocol.sha256_bytes(
                self.public_key
            ),
            expected_key_id="owner-2026-01",
            expected_issuer="trusted-owner-gateway",
            allowed_actor_ids={"owner-123"},
            now=NOW,
        )
        self.assertEqual(normalized, self.envelope)
        self.assertEqual(
            normalized["payload"]["tier"],
            "owner",
        )

    def test_wrong_key_signature_actor_issuer_and_key_id_fail(self):
        other_key = Ed25519PrivateKey.generate()
        other_public = other_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        cases = [
            {
                "public_key": other_public,
                "error": "signature",
            },
            {
                "public_key": self.public_key,
                "expected_public_key_sha256": "sha256:" + "f" * 64,
                "error": "fingerprint",
            },
            {
                "public_key": self.public_key,
                "expected_key_id": "other-key",
                "error": "key ID",
            },
            {
                "public_key": self.public_key,
                "expected_issuer": "other-gateway",
                "error": "issuer",
            },
            {
                "public_key": self.public_key,
                "allowed_actor_ids": {"someone-else"},
                "error": "actor",
            },
        ]
        for case in cases:
            error = str(case.pop("error"))
            with self.subTest(error=error):
                with self.assertRaisesRegex(
                    protocol.ReleaseBrokerProtocolError, error
                ):
                    protocol.verify_owner_assertion_signature(
                        self.envelope, now=NOW, **case
                    )

    def test_payload_tampering_is_not_authorized_by_recomputed_packet_digest(self):
        tampered = copy.deepcopy(self.envelope)
        tampered["payload"]["actor_login"] = "attacker"
        with self.assertRaisesRegex(
            protocol.ReleaseBrokerProtocolError, "signature"
        ):
            protocol.verify_owner_assertion_signature(
                tampered,
                public_key=self.public_key,
                now=NOW,
            )

    def test_non_owner_wrong_purpose_publish_and_weak_nonce_are_rejected(self):
        mutations = {
            "tier": "public",
            "purpose": "route",
            "publish": True,
            "nonce": "abcd",
            "merge_method": "merge",
        }
        for field, value in mutations.items():
            candidate = copy.deepcopy(self.envelope)
            candidate["payload"][field] = value
            with self.subTest(field=field):
                with self.assertRaises(protocol.ReleaseBrokerProtocolError):
                    protocol.normalize_owner_assertion_envelope(
                        candidate, now=NOW
                    )

    def test_expired_assertion_is_only_structurally_allowed_for_recovery(self):
        expired = owner_envelope(
            self.bundle,
            self.private_key,
            approval_text=APPROVAL,
            issued_at="2026-07-16T11:40:00Z",
            expires_at="2026-07-16T11:50:00Z",
        )
        with self.assertRaisesRegex(
            protocol.ReleaseBrokerProtocolError, "expired"
        ):
            protocol.verify_owner_assertion_signature(
                expired,
                public_key=self.public_key,
                now=NOW,
            )
        recovered = protocol.verify_owner_assertion_signature(
            expired,
            public_key=self.public_key,
            now=NOW,
            allow_expired=True,
        )
        self.assertEqual(recovered, expired)

    def test_future_and_overlong_assertions_fail(self):
        future = owner_envelope(
            self.bundle,
            self.private_key,
            approval_text=APPROVAL,
            issued_at="2026-07-16T12:10:00Z",
            expires_at="2026-07-16T12:11:00Z",
        )
        with self.assertRaisesRegex(
            protocol.ReleaseBrokerProtocolError, "future"
        ):
            protocol.normalize_owner_assertion_envelope(future, now=NOW)

        overlong = owner_envelope(
            self.bundle,
            self.private_key,
            approval_text=APPROVAL,
            issued_at="2026-07-16T11:59:00Z",
            expires_at="2026-07-16T12:30:00Z",
        )
        with self.assertRaisesRegex(
            protocol.ReleaseBrokerProtocolError, "lifetime"
        ):
            protocol.normalize_owner_assertion_envelope(overlong, now=NOW)

    def test_signature_encoding_must_be_exact_unpadded_base64url(self):
        padded = copy.deepcopy(self.envelope)
        padded["signature"] += "=="
        with self.assertRaisesRegex(
            protocol.ReleaseBrokerProtocolError, "encoding"
        ):
            protocol.normalize_owner_assertion_envelope(padded, now=NOW)

        short = copy.deepcopy(self.envelope)
        short["signature"] = base64.urlsafe_b64encode(b"short").decode(
            "ascii"
        ).rstrip("=")
        with self.assertRaisesRegex(
            protocol.ReleaseBrokerProtocolError, "encoding"
        ):
            protocol.normalize_owner_assertion_envelope(short, now=NOW)

    def test_expired_packet_and_assertion_recovery_are_separate_switches(self):
        expired_assertion = owner_envelope(
            self.bundle,
            self.private_key,
            approval_text=APPROVAL,
            issued_at="2026-07-16T11:40:00Z",
            expires_at="2026-07-16T11:50:00Z",
        )
        packet = release_packet(
            self.bundle,
            expired_assertion,
            approval_text=APPROVAL,
        )
        with self.assertRaisesRegex(
            protocol.ReleaseBrokerProtocolError, "assertion has expired"
        ):
            protocol.normalize_release_packet(packet, now=NOW)
        normalized = protocol.normalize_release_packet(
            packet,
            now=NOW,
            allow_expired_assertion=True,
        )
        self.assertEqual(normalized, packet)
        with self.assertRaisesRegex(
            protocol.ReleaseBrokerProtocolError, "packet has expired"
        ):
            protocol.normalize_release_packet(
                packet,
                now=NOW + timedelta(minutes=6),
                allow_expired_assertion=True,
            )

    def test_configured_submission_pins_key_actor_repo_and_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            keys = root / "keys"
            keys.mkdir(mode=0o700)
            public_path = keys / "owner.pub.pem"
            public_path.write_bytes(self.public_key)
            public_path.chmod(0o600)
            config = release_config(root)
            config["enabled"] = True
            config["owner_assertion"]["public_key_sha256"] = (
                protocol.sha256_bytes(self.public_key)
            )
            configured_assertion = owner_envelope(
                self.bundle,
                self.private_key,
                approval_text=APPROVAL,
                expires_at="2026-07-16T12:09:00Z",
            )
            submission = {
                "schema_version": protocol.SUBMISSION_SCHEMA,
                "packet": release_packet(
                    self.bundle,
                    configured_assertion,
                    approval_text=APPROVAL,
                ),
            }
            normalized = protocol.normalize_configured_submission(
                submission,
                config,
                now=NOW,
                key_owner_uids={os.getuid()},
                parent_owner_uids={os.getuid()},
                trusted_path_root=root,
            )
            self.assertEqual(
                normalized["packet"], submission["packet"]
            )
            self.assertEqual(
                normalized["owner_assertion"]["payload"]["actor_id"],
                "owner-123",
            )

            forbidden = copy.deepcopy(config)
            forbidden["instance"]["policy"][
                "forbidden_path_prefixes"
            ] = ["src"]
            with self.assertRaisesRegex(
                protocol.ReleaseBrokerProtocolError, "forbidden path"
            ):
                protocol.normalize_configured_submission(
                    submission,
                    forbidden,
                    now=NOW,
                    key_owner_uids={os.getuid()},
                    parent_owner_uids={os.getuid()},
                    trusted_path_root=root,
                )

    def test_configured_owner_key_rejects_writable_symlink_and_hardlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            keys = root / "keys"
            keys.mkdir(mode=0o700)
            public_path = keys / "owner.pub.pem"
            public_path.write_bytes(self.public_key)
            public_path.chmod(0o666)
            config = release_config(root)
            config["owner_assertion"]["public_key_sha256"] = (
                protocol.sha256_bytes(self.public_key)
            )
            with self.assertRaisesRegex(
                protocol.ReleaseBrokerProtocolError, "writable"
            ):
                protocol.verify_configured_owner_assertion(
                    self.envelope,
                    config,
                    now=NOW,
                    key_owner_uids={os.getuid()},
                    parent_owner_uids={os.getuid()},
                    trusted_path_root=root,
                )
            public_path.chmod(0o600)
            hardlink = keys / "owner-hardlink.pem"
            os.link(public_path, hardlink)
            with self.assertRaisesRegex(
                protocol.ReleaseBrokerProtocolError, "hard links"
            ):
                protocol.verify_configured_owner_assertion(
                    self.envelope,
                    config,
                    now=NOW,
                    key_owner_uids={os.getuid()},
                    parent_owner_uids={os.getuid()},
                    trusted_path_root=root,
                )
            hardlink.unlink()
            target = keys / "real-owner.pem"
            public_path.rename(target)
            public_path.symlink_to(target)
            with self.assertRaisesRegex(
                protocol.ReleaseBrokerProtocolError, "unreadable"
            ):
                protocol.verify_configured_owner_assertion(
                    self.envelope,
                    config,
                    now=NOW,
                    key_owner_uids={os.getuid()},
                    parent_owner_uids={os.getuid()},
                    trusted_path_root=root,
                )


if __name__ == "__main__":
    unittest.main()
