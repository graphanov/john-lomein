#!/usr/bin/env python3
from __future__ import annotations

import copy
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from owner_gateway import john_lomein_release_owner_signer as signer
from release_broker import john_lomein_release_broker_protocol as protocol
from tests.test_release_broker_protocol import release_bundle


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)


def snowflake(at: datetime, increment: int) -> str:
    milliseconds = int(at.timestamp() * 1000)
    return str(
        ((milliseconds - signer.DISCORD_EPOCH_MS) << 22)
        | (increment & ((1 << 22) - 1))
    )


class ReleaseOwnerSignerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.key_root = self.root / "keys"
        self.key_root.mkdir(mode=0o700)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.private = Ed25519PrivateKey.generate()
        self.private_bytes = self.private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.public_bytes = self.private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.private_path = self.key_root / "owner.pem"
        self.public_path = self.key_root / "owner.pub.pem"
        self.private_path.write_bytes(self.private_bytes)
        self.private_path.chmod(0o640)
        self.public_path.write_bytes(self.public_bytes)
        self.public_path.chmod(0o440)
        self.uid = os.geteuid()
        self.gid = os.getegid()
        self.application_id = snowflake(NOW - timedelta(days=300), 1)
        self.guild_id = snowflake(NOW - timedelta(days=250), 2)
        self.channel_id = snowflake(NOW - timedelta(days=200), 3)
        self.actor_id = snowflake(NOW - timedelta(days=150), 4)
        self.config = {
            "schema_version": signer.CONFIG_SCHEMA,
            "enabled": True,
            "signer_id": "owner-gateway-widget",
            "signer_uid": self.uid or 1,
            "signer_gid": self.gid or 1,
            "runtime_uid": (self.uid or 1) + 100,
            "issuer": "trusted-owner-gateway",
            "key_id": "owner-2026-01",
            "private_key_path": str(self.private_path),
            "public_key_path": str(self.public_path),
            "public_key_sha256": protocol.sha256_bytes(self.public_bytes),
            "state_directory": str(self.state),
            "assertion_ttl_seconds": 300,
            "maximum_event_age_seconds": 120,
            "maximum_observation_delay_seconds": 30,
            "maximum_clock_skew_seconds": 5,
            "instance": {
                "slug": "widget-production",
                "repository": {
                    "id": 987654,
                    "full_name": "acme/widget",
                    "default_branch": "main",
                },
            },
            "discord": {
                "application_id": self.application_id,
                "guild_id": self.guild_id,
                "approval_channel_ids": [self.channel_id],
                "owner_actors": [
                    {
                        "user_id": self.actor_id,
                        "actor_login": "maintainer",
                    }
                ],
            },
        }
        self.bundle = release_bundle()
        self.approval = signer.expected_release_approval_text(self.bundle)
        self.message_created = NOW - timedelta(seconds=10)
        self.message_id = snowflake(self.message_created, 5)
        self.event = {
            "schema_version": signer.EVENT_SCHEMA,
            "platform": "discord",
            "application_id": self.application_id,
            "guild_id": self.guild_id,
            "channel_id": self.channel_id,
            "message_id": self.message_id,
            "actor_user_id": self.actor_id,
            "actor_is_bot": False,
            "created_at": self.message_created.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "observed_at": (self.message_created + timedelta(seconds=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "text": self.approval,
        }

    def test_self_check_is_nonnetwork_and_emits_only_boolean_health(self):
        from owner_gateway import john_lomein_discord_release_source as source

        state_fd = os.open(self.state, os.O_RDONLY)
        with (
            mock.patch.object(
                signer,
                "load_configured_key_pair",
                return_value=(self.private_bytes, self.public_bytes),
            ),
            mock.patch.object(
                source,
                "load_source_config",
                return_value={"enabled": True},
            ),
            mock.patch.object(
                source,
                "load_bot_token",
                return_value="redacted-token",
            ),
            mock.patch.object(
                source,
                "fetch_normalized_event",
                side_effect=AssertionError("self-check must not use network"),
            ),
            mock.patch.object(
                signer,
                "_directory_fd",
                return_value=state_fd,
            ),
        ):
            result = signer.self_check(
                config=self.config,
                discord_source_config=self.root / "source.json",
            )
        self.assertEqual(
            result,
            {
                "schema_version": signer.SELF_CHECK_SCHEMA,
                "enabled": True,
                "healthy": True,
            },
        )

        with (
            mock.patch.object(
                signer,
                "load_configured_key_pair",
                return_value=(self.private_bytes, self.public_bytes),
            ),
            mock.patch.object(
                source,
                "load_source_config",
                return_value={"enabled": False},
            ),
            mock.patch.object(
                source,
                "load_bot_token",
                return_value="redacted-token",
            ),
            mock.patch.object(
                signer,
                "_directory_fd",
                return_value=os.open(self.state, os.O_RDONLY),
            ),
        ):
            disabled = signer.self_check(
                config=self.config,
                discord_source_config=self.root / "source.json",
            )
        self.assertFalse(disabled["enabled"])

    def build(self, *, salt_byte: bytes = b"x") -> dict:
        return signer.build_signing_record(
            config=self.config,
            bundle=self.bundle,
            approval_text=self.approval,
            source_event=self.event,
            private_key_bytes=self.private_bytes,
            public_key_bytes=self.public_bytes,
            now=NOW,
            random_bytes=lambda size: salt_byte * size,
        )

    def test_authenticated_event_mints_broker_verifiable_exact_assertion(self):
        record = self.build()
        assertion = record["owner_assertion"]
        verified = protocol.verify_owner_assertion_signature(
            assertion,
            public_key=self.public_bytes,
            expected_public_key_sha256=self.config["public_key_sha256"],
            expected_key_id=self.config["key_id"],
            expected_issuer=self.config["issuer"],
            allowed_actor_ids={self.actor_id},
            now=NOW,
            maximum_ttl_seconds=self.config["assertion_ttl_seconds"],
            maximum_clock_skew_seconds=self.config[
                "maximum_clock_skew_seconds"
            ],
        )
        self.assertEqual(verified, assertion)
        payload = assertion["payload"]
        self.assertEqual(payload["actor_id"], self.actor_id)
        self.assertEqual(payload["actor_login"], "maintainer")
        self.assertEqual(payload["bundle_id"], self.bundle["bundle_id"])
        self.assertEqual(payload["approval_text_sha256"], protocol.sha256_text(self.approval))
        self.assertEqual(payload["nonce"], record["source_commitment"]["nonce"])
        normalized = signer.verify_signing_record(
            record,
            config=self.config,
            public_key_bytes=self.public_bytes,
            now=NOW,
        )
        self.assertEqual(normalized, record)

    def test_nonce_is_random_and_commits_to_source_event_and_request(self):
        first = self.build(salt_byte=b"a")
        second = self.build(salt_byte=b"b")
        self.assertNotEqual(
            first["source_commitment"]["nonce"],
            second["source_commitment"]["nonce"],
        )
        tampered = copy.deepcopy(first)
        tampered["source_event"]["channel_id"] = snowflake(
            NOW - timedelta(days=190), 9
        )
        with self.assertRaises(signer.ReleaseOwnerSignerError):
            signer.verify_signing_record(
                tampered,
                config=self.config,
                public_key_bytes=self.public_bytes,
                now=NOW,
            )

    def test_actor_channel_guild_application_and_bot_policy_fail_closed(self):
        mutations = {
            "actor_user_id": snowflake(NOW - timedelta(days=140), 10),
            "channel_id": snowflake(NOW - timedelta(days=130), 11),
            "guild_id": snowflake(NOW - timedelta(days=120), 12),
            "application_id": snowflake(NOW - timedelta(days=110), 13),
            "actor_is_bot": True,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                event = copy.deepcopy(self.event)
                event[field] = value
                with self.assertRaises(signer.ReleaseOwnerSignerError):
                    signer.build_signing_record(
                        config=self.config,
                        bundle=self.bundle,
                        approval_text=self.approval,
                        source_event=event,
                        private_key_bytes=self.private_bytes,
                        public_key_bytes=self.public_bytes,
                        now=NOW,
                    )

    def test_freshness_observation_and_snowflake_time_are_enforced(self):
        stale = copy.deepcopy(self.event)
        old = NOW - timedelta(minutes=3)
        stale["created_at"] = old.strftime("%Y-%m-%dT%H:%M:%SZ")
        stale["observed_at"] = (old + timedelta(seconds=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        stale["message_id"] = snowflake(old, 20)
        with self.assertRaisesRegex(signer.ReleaseOwnerSignerError, "stale"):
            signer.normalize_discord_event(stale, self.config, now=NOW)

        late = copy.deepcopy(self.event)
        late_created = NOW - timedelta(seconds=60)
        late["created_at"] = late_created.strftime("%Y-%m-%dT%H:%M:%SZ")
        late["observed_at"] = (
            late_created + timedelta(seconds=31)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        late["message_id"] = snowflake(late_created, 21)
        with self.assertRaisesRegex(signer.ReleaseOwnerSignerError, "too late"):
            signer.normalize_discord_event(late, self.config, now=NOW)

        forged_time = copy.deepcopy(self.event)
        forged_created = self.message_created - timedelta(minutes=1)
        forged_time["created_at"] = forged_created.strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        forged_time["observed_at"] = (
            forged_created + timedelta(seconds=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.assertRaisesRegex(
            signer.ReleaseOwnerSignerError, "snowflake"
        ):
            signer.normalize_discord_event(forged_time, self.config, now=NOW)

    def test_exact_approval_bundle_and_single_pr_are_required(self):
        with self.assertRaisesRegex(
            signer.ReleaseOwnerSignerError, "exactly match"
        ):
            signer.build_signing_record(
                config=self.config,
                bundle=self.bundle,
                approval_text=self.approval + " please",
                source_event=self.event,
                private_key_bytes=self.private_bytes,
                public_key_bytes=self.public_bytes,
                now=NOW,
            )
        tampered_bundle = copy.deepcopy(self.bundle)
        tampered_bundle["ordered_prs"][0]["head_sha"] = "f" * 40
        with self.assertRaises(protocol.ReleaseBrokerProtocolError):
            signer.build_signing_record(
                config=self.config,
                bundle=tampered_bundle,
                approval_text=self.approval,
                source_event=self.event,
                private_key_bytes=self.private_bytes,
                public_key_bytes=self.public_bytes,
                now=NOW,
            )
        second = release_bundle(
            pr_number=18,
            head_sha="e" * 40,
            paths=["src/second.py"],
        )["ordered_prs"][0]
        second["position"] = 1
        multi = copy.deepcopy(self.bundle)
        multi["ordered_prs"].append(second)
        multi["bundle_digest"] = protocol.release_bundle_digest(multi)
        multi["bundle_id"] = protocol.release_bundle_id(multi)
        approval = signer.expected_release_approval_text(multi)
        event = copy.deepcopy(self.event)
        event["text"] = approval
        with self.assertRaisesRegex(signer.ReleaseOwnerSignerError, "exactly one"):
            signer.build_signing_record(
                config=self.config,
                bundle=multi,
                approval_text=approval,
                source_event=event,
                private_key_bytes=self.private_bytes,
                public_key_bytes=self.public_bytes,
                now=NOW,
            )

    def test_process_identity_is_distinct_from_hermes_runtime(self):
        signer.assert_process_identity(
            self.config,
            process_uid=self.config["signer_uid"],
            process_gid=self.config["signer_gid"],
        )
        with self.assertRaisesRegex(
            signer.ReleaseOwnerSignerError, "process UID"
        ):
            signer.assert_process_identity(
                self.config,
                process_uid=self.config["runtime_uid"],
                process_gid=self.config["signer_gid"],
            )
        same = copy.deepcopy(self.config)
        same["runtime_uid"] = same["signer_uid"]
        with self.assertRaisesRegex(signer.ReleaseOwnerSignerError, "distinct"):
            signer.normalize_signer_config(same)

    def test_configured_key_loader_requires_root_style_read_only_modes(self):
        private, public = signer.load_configured_key_pair(
            self.config,
            expected_key_owner_uid=self.uid,
            trusted_root=self.root,
        )
        self.assertEqual(private, self.private_bytes)
        self.assertEqual(public, self.public_bytes)
        self.private_path.chmod(0o600)
        with self.assertRaisesRegex(signer.ReleaseOwnerSignerError, "mode"):
            signer.load_configured_key_pair(
                self.config,
                expected_key_owner_uid=self.uid,
                trusted_root=self.root,
            )
        self.private_path.chmod(0o640)
        hardlink = self.key_root / "owner-copy.pem"
        os.link(self.private_path, hardlink)
        with self.assertRaisesRegex(signer.ReleaseOwnerSignerError, "hard links"):
            signer.load_configured_key_pair(
                self.config,
                expected_key_owner_uid=self.uid,
                trusted_root=self.root,
            )

    def test_wrong_fingerprint_key_pair_and_key_type_fail(self):
        wrong_fingerprint = copy.deepcopy(self.config)
        wrong_fingerprint["public_key_sha256"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(
            signer.ReleaseOwnerSignerError, "fingerprint"
        ):
            signer.build_signing_record(
                config=wrong_fingerprint,
                bundle=self.bundle,
                approval_text=self.approval,
                source_event=self.event,
                private_key_bytes=self.private_bytes,
                public_key_bytes=self.public_bytes,
                now=NOW,
            )
        other = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        mismatch = copy.deepcopy(self.config)
        mismatch["public_key_sha256"] = protocol.sha256_bytes(other)
        with self.assertRaisesRegex(signer.ReleaseOwnerSignerError, "pair"):
            signer.build_signing_record(
                config=mismatch,
                bundle=self.bundle,
                approval_text=self.approval,
                source_event=self.event,
                private_key_bytes=self.private_bytes,
                public_key_bytes=other,
                now=NOW,
            )
        rsa = generate_private_key(public_exponent=65537, key_size=2048)
        rsa_private = rsa.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with self.assertRaisesRegex(signer.ReleaseOwnerSignerError, "Ed25519"):
            signer.build_signing_record(
                config=self.config,
                bundle=self.bundle,
                approval_text=self.approval,
                source_event=self.event,
                private_key_bytes=rsa_private,
                public_key_bytes=self.public_bytes,
                now=NOW,
            )

    def test_persistence_is_idempotent_mode_0600_and_conflict_safe(self):
        first = self.build(salt_byte=b"a")
        saved, path = signer.persist_signing_record(
            self.config,
            first,
            public_key_bytes=self.public_bytes,
            now=NOW,
        )
        self.assertEqual(saved, first)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        second = self.build(salt_byte=b"b")
        replay, replay_path = signer.persist_signing_record(
            self.config,
            second,
            public_key_bytes=self.public_bytes,
            now=NOW,
        )
        self.assertEqual(replay_path, path)
        self.assertEqual(replay["owner_assertion"], first["owner_assertion"])

        other_bundle = release_bundle(pr_number=19, head_sha="d" * 40)
        other_approval = signer.expected_release_approval_text(other_bundle)
        other_event = copy.deepcopy(self.event)
        other_event["text"] = other_approval
        conflicting = signer.build_signing_record(
            config=self.config,
            bundle=other_bundle,
            approval_text=other_approval,
            source_event=other_event,
            private_key_bytes=self.private_bytes,
            public_key_bytes=self.public_bytes,
            now=NOW,
            random_bytes=lambda size: b"c" * size,
        )
        with self.assertRaisesRegex(
            signer.ReleaseOwnerSignerError, "different request"
        ):
            signer.persist_signing_record(
                self.config,
                conflicting,
                public_key_bytes=self.public_bytes,
                now=NOW,
            )

    def test_persistence_rejects_symlinked_records_directory(self):
        record = self.build()
        outside = self.root / "outside"
        outside.mkdir()
        (self.state / "records").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(signer.ReleaseOwnerSignerError, "unsafe"):
            signer.persist_signing_record(
                self.config,
                record,
                public_key_bytes=self.public_bytes,
                now=NOW,
            )

    def test_record_tampering_and_expiry_are_distinct(self):
        record = self.build()
        later = NOW + timedelta(minutes=10)
        verified = signer.verify_signing_record(
            record,
            config=self.config,
            public_key_bytes=self.public_bytes,
            now=later,
            allow_expired_assertion=True,
        )
        self.assertEqual(verified, record)
        with self.assertRaisesRegex(
            signer.ReleaseOwnerSignerError, "expired"
        ):
            signer.verify_signing_record(
                record,
                config=self.config,
                public_key_bytes=self.public_bytes,
                now=later,
                allow_expired_assertion=False,
            )
        tampered = copy.deepcopy(record)
        tampered["owner_assertion"]["payload"]["actor_login"] = "attacker"
        with self.assertRaises(signer.ReleaseOwnerSignerError):
            signer.verify_signing_record(
                tampered,
                config=self.config,
                public_key_bytes=self.public_bytes,
                now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
