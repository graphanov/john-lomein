#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import traceback
import unittest
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import john_lomein_continuity as continuity  # noqa: E402
import john_lomein_continuity_protocol as protocol  # noqa: E402


NOW = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)
LEDGER_ID = "jlcl-000000000000000000000001"
INSTANCE_ID = "john-production-1"
REPOSITORY = "owner/repo"
KEY_ID = "owner-continuity-2026-01"
POLICY_ID = "owner-private-memory-v1"
WRITE_ID = "jlcw-00000000000000000000000000000001"
ED25519_FIELD_PRIME = 2**255 - 19
ED25519_SUBGROUP_ORDER = (
    2**252 + 27742317777372353535851937790883648493
)


def raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def encoded_signature(envelope: dict) -> bytes:
    return base64.urlsafe_b64decode(envelope["signature"] + "==")


def signature_text(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def add_order_two_component(encoded: bytes) -> bytes:
    """Return P + (0,-1) = (-x,-y) for a non-torsion encoded point P."""

    value = int.from_bytes(encoded, "little")
    x_sign = value >> 255
    y = value & ((1 << 255) - 1)
    mixed_y = (-y) % ED25519_FIELD_PRIME
    return (
        mixed_y | ((x_sign ^ 1) << 255)
    ).to_bytes(32, "little")


class SignedContinuityFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.public = raw_public_key(self.private)
        self.authority = {
            "class": "owner",
            "source_kind": "owner",
            "source_trust": "owner_asserted",
            "source_actor": "owner-gateway",
        }
        self.policy = self.make_policy()
        self.config = self.make_config()
        self.body = self.make_put_body()
        self.envelope = self.seal(self.body)
        self.raw = protocol.canonical_json(self.envelope)

    def make_policy(
        self,
        *,
        state: str = "active",
        authority: dict | None = None,
        key_id: str = KEY_ID,
        public: bytes | None = None,
        operations: list[str] | None = None,
        kinds: list[str] | None = None,
        commitment_kinds: list[str] | None = None,
        privacy: list[str] | None = None,
        roles: list[str] | None = None,
    ) -> dict:
        selected_authority = authority or self.authority
        is_owner = selected_authority["class"] == "owner"
        return {
            "schema_version": protocol.KEY_POLICY_SCHEMA,
            "policy_id": (
                POLICY_ID if is_owner else "observer-outcome-memory-v1"
            ),
            "key_id": key_id,
            "algorithm": protocol.SIGNATURE_ALGORITHM,
            "public_key_sha256": hashlib.sha256(
                public or self.public
            ).hexdigest(),
            "state": state,
            "valid_from": "2026-07-17T00:00:00Z",
            "valid_until": "2026-07-20T00:00:00Z",
            "authority": copy.deepcopy(selected_authority),
            "permissions": {
                "operations": (
                    ["put", "suppress"] if operations is None else operations
                ),
                "entry_kinds": (
                    ["user_correction", "user_preference"]
                    if is_owner
                    else ["verified_outcome"]
                )
                if kinds is None
                else kinds,
                "source_commitment_kinds": (
                    ["owner_discord"]
                    if is_owner
                    else ["github_observer"]
                )
                if commitment_kinds is None
                else commitment_kinds,
                "privacy": (
                    ["private", "public"] if privacy is None else privacy
                ),
                "visible_to_roles": [
                    "maintainer",
                    "forge",
                    "guide",
                    "overwatch",
                    "learning_steward",
                ]
                if roles is None
                else roles,
            },
        }

    def make_config(
        self,
        *,
        policy: dict | None = None,
        enabled: bool = True,
        instance_id: str = INSTANCE_ID,
        repository: str = REPOSITORY,
        ledger_id: str = LEDGER_ID,
        maximum_ttl_seconds: int = 300,
        maximum_clock_skew_seconds: int = 10,
    ) -> dict:
        return {
            "schema_version": protocol.CONFIG_SCHEMA,
            "enabled": enabled,
            "instance_id": instance_id,
            "repository": repository,
            "ledger_id": ledger_id,
            "maximum_ttl_seconds": maximum_ttl_seconds,
            "maximum_clock_skew_seconds": maximum_clock_skew_seconds,
            "key_policies": [copy.deepcopy(policy or self.policy)],
        }

    def head(
        self,
        *,
        ledger_id: str = LEDGER_ID,
        sequence: int = 0,
        entry_sha256: str = continuity.ZERO_HASH,
        ledger_size_bytes: int = 0,
        updated_at: str = "2026-07-18T11:59:00Z",
    ) -> dict:
        base = {
            "schema_version": continuity.HEAD_SCHEMA,
            "ledger_id": ledger_id,
            "sequence": sequence,
            "head_entry_sha256": entry_sha256,
            "ledger_size_bytes": ledger_size_bytes,
            "updated_at": updated_at,
        }
        return {**base, "head_sha256": continuity.sha256_json(base)}

    def make_put_body(
        self,
        *,
        authority: dict | None = None,
        policy: dict | None = None,
        write_id: str = WRITE_ID,
        issued_at: str = "2026-07-18T12:00:00Z",
        expires_at: str = "2026-07-18T12:05:00Z",
        kind: str = "user_correction",
        payload: dict | None = None,
        privacy: str = "private",
        roles: list[str] | None = None,
        repository: str = REPOSITORY,
        ledger_id: str = LEDGER_ID,
        expected_head: dict | None = None,
        commitment_kind: str = "owner_discord",
    ) -> dict:
        selected_authority = copy.deepcopy(authority or self.authority)
        selected_policy = policy or self.policy
        default_payloads = {
            "user_correction": {"correction_kind": "requirement"},
            "user_preference": {"preference": "avoid"},
            "verified_outcome": {
                "outcome_kind": "pr_merged",
                "claim_id": "claim-1",
                "reputation_event_sha256": "a" * 64,
            },
        }
        # commitment_kind is accepted only to keep call sites explicit; the
        # actual commitment is attached by seal().
        self.assertIsInstance(commitment_kind, str)
        return {
            "schema_version": protocol.EFFECT_SCHEMA,
            "instance_id": INSTANCE_ID,
            "repository": repository,
            "ledger_id": ledger_id,
            "expected_head": copy.deepcopy(expected_head or self.head(ledger_id=ledger_id)),
            "policy_id": selected_policy["policy_id"],
            "policy_sha256": protocol.policy_authorization_sha256(
                selected_policy
            ),
            "write_id": write_id,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "authority": selected_authority,
            "operation": "put",
            "scope": {
                "privacy": privacy,
                "visible_to_roles": roles or ["maintainer"],
                "repository": repository,
            },
            "put": {
                "kind": kind,
                "subject": "repository-requirement",
                "summary": "Keep the protected boundary explicit.",
                "payload": payload or default_payloads[kind],
                "memory_expires_at": "2026-08-18T12:00:00Z",
                "supersedes_entry_id": None,
            },
            "suppression": None,
        }

    def make_suppression_body(
        self,
        *,
        policy: dict | None = None,
        write_id: str = "jlcw-00000000000000000000000000000002",
    ) -> dict:
        selected_policy = policy or self.policy
        body = self.make_put_body(
            policy=selected_policy,
            write_id=write_id,
        )
        body["operation"] = "suppress"
        body["put"] = None
        body["suppression"] = {
            "target_entry_id": "jlce-000000000000000000000099",
            "target_entry_sha256": "9" * 64,
            "reason": "privacy_request",
        }
        return body

    def seal(
        self,
        body: dict,
        *,
        private: Ed25519PrivateKey | None = None,
        key_id: str = KEY_ID,
        commitment_kind: str | None = None,
        commitment_digest: str | None = None,
        signing_prefix: bytes | None = None,
    ) -> dict:
        normalized_body = copy.deepcopy(body)
        kind = commitment_kind or (
            "owner_discord"
            if normalized_body["authority"]["class"] == "owner"
            else "github_observer"
        )
        salted = commitment_digest or protocol.salted_source_commitment_sha256(
            kind=kind,
            effect_binding_sha256=protocol.effect_binding_sha256(
                normalized_body
            ),
            source_event_sha256=hashlib.sha256(
                b"private-test-source-event"
            ).hexdigest(),
            salt=b"s" * 32,
        )
        commitment = protocol.build_source_commitment(
            effect=normalized_body,
            kind=kind,
            commitment_sha256=salted,
        )
        effect = {**normalized_body, "source_commitment": commitment}
        unsigned = protocol.prepare_unsigned_envelope(
            key_id=key_id,
            effect=effect,
        )
        signing_input = protocol.signing_bytes(unsigned)
        if signing_prefix is not None:
            signing_input = signing_prefix + protocol.canonical_json(unsigned)
        signature = (private or self.private).sign(signing_input)
        return {
            **unsigned,
            "signature": base64.urlsafe_b64encode(signature)
            .decode("ascii")
            .rstrip("="),
        }

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(protocol.ContinuityProtocolError) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)


class SignedContinuityProtocolTest(SignedContinuityFixture):
    def test_valid_owner_admission_derives_only_post_verification_write(self):
        result = protocol.verify_for_new_admission(
            self.raw,
            config=self.config,
            public_keys={KEY_ID: self.public},
            now=NOW,
        )
        self.assertEqual(result["mode"], "new_admission")
        self.assertEqual(result["source_authentication"], "not_proven")
        self.assertEqual(
            result["derived_entry_id"],
            protocol.entry_id_for_write_id(WRITE_ID),
        )
        self.assertEqual(result["expected_head"], self.body["expected_head"])
        write = result["continuity_write"]
        self.assertEqual(write["entry_id"], result["derived_entry_id"])
        self.assertEqual(write["source"]["kind"], "owner")
        self.assertEqual(write["source"]["trust"], "owner_asserted")
        self.assertEqual(write["source"]["actor"], "owner-gateway")
        self.assertEqual(
            write["source"]["locator"],
            f"signed-continuity:{KEY_ID}:{WRITE_ID}",
        )
        self.assertEqual(
            write["source"]["sha256"],
            result["effect"]["source_commitment"]["commitment_sha256"],
        )
        self.assertNotIn("entry_id", result["effect"])
        self.assertNotIn("source", result["effect"])
        self.assertNotIn("write", result["effect"])

    def test_source_commitment_is_opaque_but_effect_cross_bound(self):
        commitment = self.envelope["effect"]["source_commitment"]
        self.assertEqual(
            set(commitment),
            {
                "schema_version",
                "kind",
                "effect_binding_sha256",
                "commitment_sha256",
            },
        )
        encoded = protocol.canonical_json(commitment)
        self.assertNotIn(b"locator", encoded)
        self.assertNotIn(b"salt", encoded)
        self.assertNotIn(b"source_content", encoded)
        self.assertEqual(
            commitment["effect_binding_sha256"],
            protocol.effect_binding_sha256(self.body),
        )
        source_digest = hashlib.sha256(b"private-test-source-event").hexdigest()
        salted = protocol.salted_source_commitment_sha256(
            kind="owner_discord",
            effect_binding_sha256=commitment["effect_binding_sha256"],
            source_event_sha256=source_digest,
            salt=b"s" * 32,
        )
        self.assertEqual(salted, commitment["commitment_sha256"])
        self.assertNotEqual(
            salted,
            protocol.salted_source_commitment_sha256(
                kind="owner_discord",
                effect_binding_sha256="f" * 64,
                source_event_sha256=source_digest,
                salt=b"s" * 32,
            ),
        )
        self.assert_code(
            "source_commitment_invalid",
            protocol.salted_source_commitment_sha256,
            kind="owner_discord",
            effect_binding_sha256=commitment["effect_binding_sha256"],
            source_event_sha256=source_digest,
            salt=b"short",
        )

        for field in ("instance_id", "repository", "ledger_id", "write_id"):
            mutated = copy.deepcopy(self.body)
            mutated[field] = (
                "other-instance"
                if field == "instance_id"
                else (
                    "other/repo"
                    if field == "repository"
                    else (
                        "jlcl-ffffffffffffffffffffffff"
                        if field == "ledger_id"
                        else "jlcw-ffffffffffffffffffffffffffffffff"
                    )
                )
            )
            if field == "repository":
                mutated["scope"]["repository"] = "other/repo"
            if field == "ledger_id":
                mutated["expected_head"] = self.head(
                    ledger_id="jlcl-ffffffffffffffffffffffff"
                )
            self.assertNotEqual(
                protocol.effect_binding_sha256(mutated),
                commitment["effect_binding_sha256"],
            )

        payload_mutation = copy.deepcopy(self.body)
        payload_mutation["put"]["summary"] = "A different bounded summary."
        self.assertNotEqual(
            protocol.effect_binding_sha256(payload_mutation),
            commitment["effect_binding_sha256"],
        )
        anchor_mutation = copy.deepcopy(self.body)
        anchor_mutation["expected_head"] = self.head(
            sequence=1,
            entry_sha256="b" * 64,
            ledger_size_bytes=200,
        )
        self.assertNotEqual(
            protocol.effect_binding_sha256(anchor_mutation),
            commitment["effect_binding_sha256"],
        )

        stale_commitment = copy.deepcopy(self.envelope["effect"])
        stale_commitment["put"]["summary"] = "Changed after commitment."
        self.assert_code(
            "source_commitment_invalid",
            protocol.normalize_effect,
            stale_commitment,
        )

    def test_expected_head_is_complete_canonical_and_cross_bound(self):
        self.assertEqual(
            set(self.envelope["effect"]["expected_head"]),
            {
                "schema_version",
                "ledger_id",
                "sequence",
                "head_entry_sha256",
                "ledger_size_bytes",
                "updated_at",
                "head_sha256",
            },
        )
        mutations = {
            "schema_version": "john-lomein.continuity-head.v0",
            "ledger_id": "jlcl-ffffffffffffffffffffffff",
            "sequence": 1,
            "head_entry_sha256": "f" * 64,
            "ledger_size_bytes": 1,
            "updated_at": "2026-07-18T11:58:59Z",
            "head_sha256": "f" * 64,
        }
        for field, hostile in mutations.items():
            corrupted = copy.deepcopy(self.body)
            corrupted["expected_head"][field] = hostile
            with self.subTest(head_field=field):
                self.assert_code(
                    "schema_invalid",
                    protocol.effect_binding_sha256,
                    corrupted,
                )
        wrong_ledger = copy.deepcopy(self.body)
        wrong_ledger["expected_head"] = self.head(
            ledger_id="jlcl-ffffffffffffffffffffffff"
        )
        self.assert_code(
            "ledger_mismatch",
            protocol.effect_binding_sha256,
            wrong_ledger,
        )

    def test_deterministic_write_id_to_entry_id(self):
        first = protocol.entry_id_for_write_id(WRITE_ID)
        self.assertEqual(first, protocol.entry_id_for_write_id(WRITE_ID))
        self.assertRegex(first, r"^jlce-[0-9a-f]{24}$")
        self.assertNotEqual(
            first,
            protocol.entry_id_for_write_id(
                "jlcw-00000000000000000000000000000002"
            ),
        )
        self.assert_code(
            "schema_invalid",
            protocol.entry_id_for_write_id,
            "caller-selected-entry-id",
        )

    def test_parser_rejects_malformed_duplicate_noncanonical_and_oversized(self):
        self.assert_code("malformed_json", protocol.parse_envelope, b"{")
        self.assert_code(
            "duplicate_field",
            protocol.parse_envelope,
            b'{"algorithm":"Ed25519","algorithm":"Ed25519"}',
        )
        pretty = json.dumps(
            self.envelope,
            sort_keys=True,
            indent=2,
        ).encode("utf-8")
        self.assert_code(
            "noncanonical_json",
            protocol.parse_envelope,
            pretty,
        )
        self.assert_code(
            "noncanonical_json",
            protocol.parse_envelope,
            b'{"number":1.0}',
        )
        unknown = {**self.envelope, "hostile": "do-not-reflect-this"}
        self.assert_code(
            "schema_invalid",
            protocol.parse_envelope,
            protocol.canonical_json(unknown),
        )
        self.assert_code(
            "size_exceeded",
            protocol.parse_envelope,
            b"x" * (protocol.MAX_ENVELOPE_BYTES + 1),
        )

    def test_config_parser_is_exact_bounded_and_canonical(self):
        raw = protocol.canonical_json(protocol.normalize_config(self.config))
        self.assertEqual(protocol.parse_config(raw), protocol.normalize_config(self.config))
        pretty = json.dumps(self.config, indent=2, sort_keys=True).encode()
        self.assert_code("noncanonical_json", protocol.parse_config, pretty)
        self.assert_code(
            "duplicate_field",
            protocol.parse_config,
            b'{"enabled":false,"enabled":true}',
        )
        with_float = copy.deepcopy(self.config)
        with_float["maximum_ttl_seconds"] = 120.0
        self.assert_code(
            "noncanonical_json",
            protocol.parse_config,
            json.dumps(with_float, sort_keys=True, separators=(",", ":")).encode(),
        )

    def test_capacity_ceiling_is_exact_and_leaves_importer_wrapper_budget(self):
        self.assertEqual(protocol.MAX_ENVELOPE_BYTES, 4096)
        self.assertLessEqual(
            protocol.MAX_ENVELOPE_BYTES,
            continuity.MAX_LINE_BYTES // 2,
        )
        self.assert_code(
            "malformed_json",
            protocol.parse_envelope,
            b"x" * protocol.MAX_ENVELOPE_BYTES,
        )
        self.assert_code(
            "size_exceeded",
            protocol.parse_envelope,
            b"x" * (protocol.MAX_ENVELOPE_BYTES + 1),
        )
        maximum = copy.deepcopy(self.body)
        maximum["scope"]["privacy"] = "public"
        maximum["scope"]["visible_to_roles"] = list(continuity.OPERATIONAL_ROLES)
        maximum["put"]["subject"] = "s" * 192
        maximum["put"]["summary"] = "m" * continuity.MAX_SUMMARY_BYTES
        raw = protocol.canonical_json(self.seal(maximum))
        self.assertLessEqual(len(raw), protocol.MAX_ENVELOPE_BYTES)

    def test_wrong_key_fingerprint_signature_algorithm_and_domain_fail(self):
        other = Ed25519PrivateKey.generate()
        other_public = raw_public_key(other)
        self.assert_code(
            "key_fingerprint_mismatch",
            protocol.verify_for_new_admission,
            self.raw,
            config=self.config,
            public_keys={KEY_ID: other_public},
            now=NOW,
        )
        bad_fingerprint = copy.deepcopy(self.config)
        bad_fingerprint["key_policies"][0]["public_key_sha256"] = "f" * 64
        self.assert_code(
            "key_fingerprint_mismatch",
            protocol.verify_for_new_admission,
            self.raw,
            config=bad_fingerprint,
            public_keys={KEY_ID: self.public},
            now=NOW,
        )
        wrong_signature = self.seal(self.body, private=other)
        self.assert_code(
            "signature_invalid",
            protocol.verify_for_new_admission,
            protocol.canonical_json(wrong_signature),
            config=self.config,
            public_keys={KEY_ID: self.public},
            now=NOW,
        )
        wrong_domain = self.seal(
            self.body,
            signing_prefix=b"OTHER-DOMAIN\x00",
        )
        self.assert_code(
            "signature_invalid",
            protocol.verify_for_new_admission,
            protocol.canonical_json(wrong_domain),
            config=self.config,
            public_keys={KEY_ID: self.public},
            now=NOW,
        )
        wrong_algorithm = copy.deepcopy(self.envelope)
        wrong_algorithm["algorithm"] = "Ed448"
        self.assert_code(
            "unsupported_algorithm",
            protocol.parse_envelope,
            protocol.canonical_json(wrong_algorithm),
        )
        algorithm_policy = copy.deepcopy(self.config)
        algorithm_policy["key_policies"][0]["algorithm"] = "RSA"
        self.assert_code(
            "unsupported_algorithm",
            protocol.verify_for_new_admission,
            self.raw,
            config=algorithm_policy,
            public_keys={KEY_ID: self.public},
            now=NOW,
        )
        self.assert_code(
            "key_material_invalid",
            protocol.verify_for_new_admission,
            self.raw,
            config=self.config,
            public_keys={KEY_ID: b"short"},
            now=NOW,
        )
        unknown_key = self.seal(self.body, key_id="unknown-key")
        self.assert_code(
            "key_unknown",
            protocol.verify_for_new_admission,
            protocol.canonical_json(unknown_key),
            config=self.config,
            public_keys={KEY_ID: self.public},
            now=NOW,
        )

    def test_identity_key_and_identity_signature_forgery_fail_closed(self):
        identity = b"\x01" + b"\x00" * 31
        identity_policy = self.make_policy(public=identity)
        config = self.make_config(policy=identity_policy)
        body = self.make_put_body(policy=identity_policy)

        # A structurally valid R/S signed by a different real key reaches the
        # configured-key validator and proves the weak key itself is rejected.
        mismatched_but_well_formed = self.seal(body)
        self.assert_code(
            "key_material_invalid",
            protocol.verify_for_new_admission,
            protocol.canonical_json(mismatched_but_well_formed),
            config=config,
            public_keys={KEY_ID: identity},
            now=NOW,
        )
        self.assert_code(
            "key_material_invalid",
            protocol.public_key_fingerprint,
            identity,
        )

        # cryptography 49 accepted this identity A / identity R / S=0 tuple
        # for arbitrary messages on the affected backend.  The protocol must
        # reject it before dependency verification.
        forged = copy.deepcopy(mismatched_but_well_formed)
        forged["signature"] = signature_text(identity + b"\x00" * 32)
        self.assert_code(
            "signature_invalid",
            protocol.verify_for_new_admission,
            protocol.canonical_json(forged),
            config=config,
            public_keys={KEY_ID: identity},
            now=NOW,
        )

    def test_public_keys_require_canonical_nonidentity_prime_order_points(self):
        identity = b"\x01" + b"\x00" * 31
        order_two = (ED25519_FIELD_PRIME - 1).to_bytes(32, "little")
        noncanonical_y = ED25519_FIELD_PRIME.to_bytes(32, "little")
        off_curve_y = (2).to_bytes(32, "little")
        mixed_order = add_order_two_component(self.public)
        noncanonical_x_zero_sign = (
            1 | (1 << 255)
        ).to_bytes(32, "little")
        hostile_keys = {
            "identity": identity,
            "order_two": order_two,
            "noncanonical_y": noncanonical_y,
            "off_curve": off_curve_y,
            "mixed_order": mixed_order,
            "x_zero_with_sign": noncanonical_x_zero_sign,
        }
        for label, hostile_key in hostile_keys.items():
            with self.subTest(public_key=label):
                self.assert_code(
                    "key_material_invalid",
                    protocol.public_key_fingerprint,
                    hostile_key,
                )

        # Exercise the verification path, not only the public fingerprint API.
        mixed_policy = self.make_policy(public=mixed_order)
        mixed_config = self.make_config(policy=mixed_policy)
        mixed_body = self.make_put_body(policy=mixed_policy)
        mixed_envelope = self.seal(mixed_body)
        self.assert_code(
            "key_material_invalid",
            protocol.verify_for_new_admission,
            protocol.canonical_json(mixed_envelope),
            config=mixed_config,
            public_keys={KEY_ID: mixed_order},
            now=NOW,
        )
        self.assertEqual(
            protocol.public_key_fingerprint(self.public),
            hashlib.sha256(self.public).hexdigest(),
        )

        # Exercise a sample of dependency-generated points and signatures, so
        # the strict subgroup gate cannot accidentally reject normal keys.
        for index in range(8):
            private = Ed25519PrivateKey.generate()
            public = raw_public_key(private)
            key_id = f"generated-key-{index}"
            policy = self.make_policy(
                key_id=key_id,
                public=public,
            )
            config = self.make_config(policy=policy)
            body = self.make_put_body(
                policy=policy,
                write_id=f"jlcw-{index + 16:032x}",
            )
            envelope = self.seal(
                body,
                private=private,
                key_id=key_id,
            )
            with self.subTest(generated_key=index):
                result = protocol.verify_for_new_admission(
                    protocol.canonical_json(envelope),
                    config=config,
                    public_keys={key_id: public},
                    now=NOW,
                )
                self.assertEqual(result["mode"], "new_admission")

    def test_signature_R_and_S_are_strictly_decoded_before_backend_verify(self):
        valid_signature = encoded_signature(self.envelope)
        valid_r = valid_signature[:32]
        valid_s = valid_signature[32:]
        identity = b"\x01" + b"\x00" * 31
        hostile_r_values = {
            "identity": identity,
            "order_two": (ED25519_FIELD_PRIME - 1).to_bytes(32, "little"),
            "noncanonical_y": ED25519_FIELD_PRIME.to_bytes(32, "little"),
            "off_curve": (2).to_bytes(32, "little"),
            "mixed_order": add_order_two_component(valid_r),
            "x_zero_with_sign": (
                1 | (1 << 255)
            ).to_bytes(32, "little"),
        }
        for label, hostile_r in hostile_r_values.items():
            candidate = copy.deepcopy(self.envelope)
            candidate["signature"] = signature_text(hostile_r + valid_s)
            with self.subTest(signature_r=label):
                self.assert_code(
                    "signature_invalid",
                    protocol.normalize_envelope,
                    candidate,
                )

        for label, scalar in {
            "equal_to_L": ED25519_SUBGROUP_ORDER,
            "above_L": ED25519_SUBGROUP_ORDER + 1,
            "maximum_256_bit": 2**256 - 1,
        }.items():
            candidate = copy.deepcopy(self.envelope)
            candidate["signature"] = signature_text(
                valid_r + scalar.to_bytes(32, "little")
            )
            with self.subTest(signature_s=label):
                self.assert_code(
                    "signature_invalid",
                    protocol.normalize_envelope,
                    candidate,
                )

        # S=0 and S=L-1 are canonical scalars; encoding normalization accepts
        # them, while the actual group equation still rejects the forgery.
        self.assertNotEqual(int.from_bytes(valid_s, "little"), 0)
        for scalar in (0, ED25519_SUBGROUP_ORDER - 1):
            candidate = copy.deepcopy(self.envelope)
            candidate["signature"] = signature_text(
                valid_r + scalar.to_bytes(32, "little")
            )
            protocol.normalize_envelope(candidate)
            self.assert_code(
                "signature_invalid",
                protocol.verify_for_new_admission,
                protocol.canonical_json(candidate),
                config=self.config,
                public_keys={KEY_ID: self.public},
                now=NOW,
            )

    def test_hostile_objects_and_timezones_never_escape_redacted_errors(self):
        marker = "HOSTILE_VALUE_MUST_NOT_ESCAPE"

        class HostileMapping(Mapping):
            def __getitem__(self, key):
                raise RuntimeError(marker)

            def __iter__(self):
                raise RuntimeError(marker)

            def __len__(self):
                raise RuntimeError(marker)

        with self.assertRaises(protocol.ContinuityProtocolError) as caught:
            protocol.normalize_config(HostileMapping())
        self.assertEqual(caught.exception.code, "schema_invalid")
        self.assertNotIn(marker, "".join(traceback.format_exception(caught.exception)))

        class OneShotKey:
            def __init__(self):
                self.hash_calls = 0

            def __hash__(self):
                self.hash_calls += 1
                if self.hash_calls > 1:
                    raise RuntimeError(marker)
                return 7

        hostile_key = OneShotKey()
        hostile_dict = {hostile_key: "value"}
        self.assert_code(
            "schema_invalid",
            protocol.normalize_config,
            hostile_dict,
        )
        self.assertEqual(hostile_key.hash_calls, 1)

        class HostileScalar:
            def __eq__(self, _):
                raise RuntimeError(marker)

            def __hash__(self):
                raise RuntimeError(marker)

        hostile_scalar_cases = []
        hostile_schema = copy.deepcopy(self.config)
        hostile_schema["schema_version"] = HostileScalar()
        hostile_scalar_cases.append(
            (protocol.normalize_config, hostile_schema)
        )
        hostile_algorithm = copy.deepcopy(self.policy)
        hostile_algorithm["algorithm"] = HostileScalar()
        hostile_scalar_cases.append(
            (protocol.normalize_key_policy, hostile_algorithm)
        )
        hostile_authority = copy.deepcopy(self.body)
        hostile_authority["authority"]["class"] = HostileScalar()
        hostile_scalar_cases.append(
            (protocol.effect_binding_sha256, hostile_authority)
        )
        hostile_operation = copy.deepcopy(self.body)
        hostile_operation["operation"] = HostileScalar()
        hostile_scalar_cases.append(
            (protocol.effect_binding_sha256, hostile_operation)
        )
        for callable_, hostile_value in hostile_scalar_cases:
            with self.subTest(hostile_scalar=callable_.__name__):
                with self.assertRaises(
                    protocol.ContinuityProtocolError
                ) as scalar_error:
                    callable_(hostile_value)
                self.assertNotIn(
                    marker,
                    "".join(
                        traceback.format_exception(scalar_error.exception)
                    ),
                )

        hostile_head = copy.deepcopy(self.body)
        hostile_head["expected_head"] = HostileMapping()
        hostile_payload = copy.deepcopy(self.body)
        hostile_payload["put"]["payload"] = HostileMapping()
        for hostile_nested in (hostile_head, hostile_payload):
            with self.assertRaises(
                protocol.ContinuityProtocolError
            ) as nested_error:
                protocol.effect_binding_sha256(hostile_nested)
            self.assertEqual(nested_error.exception.code, "schema_invalid")
            self.assertNotIn(
                marker,
                "".join(traceback.format_exception(nested_error.exception)),
            )

        malformed_effects = []
        bad_privacy = copy.deepcopy(self.body)
        bad_privacy["scope"]["privacy"] = []
        malformed_effects.append(bad_privacy)
        bad_kind = copy.deepcopy(self.body)
        bad_kind["put"]["kind"] = []
        malformed_effects.append(bad_kind)
        bad_reason = self.make_suppression_body()
        bad_reason["suppression"]["reason"] = []
        malformed_effects.append(bad_reason)
        bad_external_source = copy.deepcopy(self.body)
        bad_external_source["authority"] = {
            "class": "external_observer",
            "source_kind": [],
            "source_trust": "externally_verified",
            "source_actor": "observer",
        }
        malformed_effects.append(bad_external_source)
        surrogate = copy.deepcopy(self.body)
        surrogate["put"]["subject"] = "\ud800"
        malformed_effects.append(surrogate)
        for index, malformed in enumerate(malformed_effects):
            with self.subTest(malformed_effect=index):
                with self.assertRaises(
                    protocol.ContinuityProtocolError
                ) as malformed_error:
                    protocol.effect_binding_sha256(malformed)
                self.assertIn(
                    malformed_error.exception.code,
                    {"schema_invalid", "kind_denied", "authority_mismatch"},
                )
                self.assertIsNone(malformed_error.exception.__cause__)
                self.assertNotIn(
                    marker,
                    "".join(
                        traceback.format_exception(
                            malformed_error.exception
                        )
                    ),
                )

        class EvilTimezone(tzinfo):
            def utcoffset(self, _):
                raise RuntimeError(marker)

            def dst(self, _):
                return None

        hostile_times = (
            datetime(2026, 7, 18, 12, tzinfo=EvilTimezone()),
            datetime.max.replace(tzinfo=timezone(timedelta(hours=-23))),
            datetime.min.replace(tzinfo=timezone(timedelta(hours=23))),
        )
        for hostile_now in hostile_times:
            with self.subTest(hostile_now=repr(hostile_now)):
                with self.assertRaises(
                    protocol.ContinuityProtocolError
                ) as time_error:
                    protocol.verify_for_new_admission(
                        self.raw,
                        config=self.config,
                        public_keys={KEY_ID: self.public},
                        now=hostile_now,
                    )
                self.assertEqual(time_error.exception.code, "time_invalid")
                self.assertNotIn(
                    marker,
                    "".join(traceback.format_exception(time_error.exception)),
                )

        with self.assertRaises(protocol.ContinuityProtocolError) as key_error:
            protocol.verify_for_new_admission(
                self.raw,
                config=self.config,
                public_keys=HostileMapping(),
                now=NOW,
            )
        self.assertEqual(key_error.exception.code, "key_material_invalid")
        self.assertNotIn(marker, "".join(traceback.format_exception(key_error.exception)))

        class CollidingKey(str):
            def __hash__(self):
                return hash(KEY_ID)

            def __eq__(self, _):
                raise RuntimeError(marker)

        with self.assertRaises(protocol.ContinuityProtocolError) as bundle_error:
            protocol.verify_for_new_admission(
                self.raw,
                config=self.config,
                public_keys={CollidingKey("collision"): self.public},
                now=NOW,
            )
        self.assertEqual(bundle_error.exception.code, "key_material_invalid")
        self.assertNotIn(
            marker,
            "".join(traceback.format_exception(bundle_error.exception)),
        )

        malformed_code = protocol.ContinuityProtocolError([])
        self.assertEqual(
            protocol.public_error(malformed_code)["error_code"],
            "schema_invalid",
        )
        mutated_code = protocol.ContinuityProtocolError("expired")
        mutated_code.code = []
        self.assertEqual(
            protocol.public_error(mutated_code)["error_code"],
            "schema_invalid",
        )
        deleted_code = protocol.ContinuityProtocolError("expired")
        del deleted_code.code
        self.assertEqual(
            protocol.public_error(deleted_code)["error_code"],
            "schema_invalid",
        )

    def test_signature_base64_is_unpadded_urlsafe_and_canonical(self):
        valid = self.envelope["signature"]
        invalid_values = {
            "padding": valid + "=",
            "standard_alphabet": "+" + valid[1:],
            "short": valid[:-1],
            "long": valid + "A",
        }
        alphabet = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789-_"
        )
        final_index = alphabet.index(valid[-1])
        # Same high two bits, different unused low padding bits: Python's
        # decoder accepts the alias, but canonical re-encoding must reject it.
        alias_index = (final_index & 0b110000) | (
            (final_index + 1) & 0b001111
        )
        invalid_values["noncanonical_alias"] = valid[:-1] + alphabet[alias_index]
        self.assertEqual(
            base64.urlsafe_b64decode(
                invalid_values["noncanonical_alias"] + "=="
            ),
            encoded_signature(self.envelope),
        )
        for label, invalid in invalid_values.items():
            candidate = copy.deepcopy(self.envelope)
            candidate["signature"] = invalid
            with self.subTest(base64_signature=label):
                self.assert_code(
                    "signature_invalid",
                    protocol.normalize_envelope,
                    candidate,
                )

    def test_all_object_and_signing_apis_enforce_envelope_capacity(self):
        oversized_policy = self.make_policy()
        oversized_policy["policy_id"] = "p" * 192
        oversized_policy["key_id"] = "k" * 192
        oversized_policy["authority"]["source_actor"] = "a" * 192
        body = self.make_put_body(policy=oversized_policy)
        body["instance_id"] = "i" * 192
        body["authority"] = copy.deepcopy(oversized_policy["authority"])
        body["put"]["subject"] = "é" * 96
        body["put"]["summary"] = "é" * 192
        commitment = protocol.build_source_commitment(
            effect=body,
            kind="owner_discord",
            commitment_sha256="a" * 64,
        )
        effect = protocol.normalize_effect(
            {**body, "source_commitment": commitment}
        )
        unsigned = {
            "schema_version": protocol.ENVELOPE_SCHEMA,
            "algorithm": protocol.SIGNATURE_ALGORITHM,
            "key_id": "k" * 192,
            "effect": effect,
        }
        projected = {
            **unsigned,
            # A valid existing signature is structurally canonical and has the
            # same fixed length as every Ed25519 signature.
            "signature": self.envelope["signature"],
        }
        projected_raw = protocol.canonical_json(projected)
        self.assertGreater(len(projected_raw), protocol.MAX_ENVELOPE_BYTES)
        for callable_, args, kwargs in (
            (
                protocol.prepare_unsigned_envelope,
                (),
                {"key_id": "k" * 192, "effect": effect},
            ),
            (protocol.signing_bytes, (unsigned,), {}),
            (protocol.normalize_envelope, (projected,), {}),
            (protocol.envelope_sha256, (projected,), {}),
            (protocol.parse_envelope, (projected_raw,), {}),
        ):
            with self.subTest(capacity_api=callable_.__name__):
                self.assert_code(
                    "size_exceeded",
                    callable_,
                    *args,
                    **kwargs,
                )

    def test_policy_instance_repository_ledger_and_authority_bindings(self):
        mutations: list[tuple[str, dict, str]] = []

        policy_body = copy.deepcopy(self.body)
        policy_body["policy_id"] = "other-policy"
        mutations.append(("policy", policy_body, "policy_mismatch"))

        instance_body = copy.deepcopy(self.body)
        instance_body["instance_id"] = "other-instance"
        mutations.append(("instance", instance_body, "instance_mismatch"))

        repository_body = copy.deepcopy(self.body)
        repository_body["repository"] = "other/repo"
        repository_body["scope"]["repository"] = "other/repo"
        mutations.append(("repository", repository_body, "scope_denied"))

        ledger_body = copy.deepcopy(self.body)
        ledger_body["ledger_id"] = "jlcl-ffffffffffffffffffffffff"
        ledger_body["expected_head"] = self.head(
            ledger_id="jlcl-ffffffffffffffffffffffff"
        )
        mutations.append(("ledger", ledger_body, "ledger_mismatch"))

        authority_body = copy.deepcopy(self.body)
        authority_body["authority"]["source_actor"] = "different-owner"
        mutations.append(("authority", authority_body, "authority_mismatch"))

        for label, body, code in mutations:
            with self.subTest(binding=label):
                raw = protocol.canonical_json(self.seal(body))
                self.assert_code(
                    code,
                    protocol.verify_for_new_admission,
                    raw,
                    config=self.config,
                    public_keys={KEY_ID: self.public},
                    now=NOW,
                )

    def test_scope_operation_kind_and_commitment_kind_permissions(self):
        private_policy = self.make_policy(
            privacy=["private"],
            operations=["put"],
            commitment_kinds=["owner_discord"],
        )
        config = self.make_config(policy=private_policy)

        public_body = self.make_put_body(
            policy=private_policy,
            privacy="public",
        )
        self.assert_code(
            "scope_denied",
            protocol.verify_for_new_admission,
            protocol.canonical_json(self.seal(public_body)),
            config=config,
            public_keys={KEY_ID: self.public},
            now=NOW,
        )

        suppression = self.make_suppression_body(policy=private_policy)
        self.assert_code(
            "operation_denied",
            protocol.verify_for_new_admission,
            protocol.canonical_json(self.seal(suppression)),
            config=config,
            public_keys={KEY_ID: self.public},
            now=NOW,
        )

        wrong_commitment_kind = self.seal(
            self.make_put_body(policy=private_policy),
            commitment_kind="owner_email",
        )
        self.assert_code(
            "source_commitment_invalid",
            protocol.verify_for_new_admission,
            protocol.canonical_json(wrong_commitment_kind),
            config=config,
            public_keys={KEY_ID: self.public},
            now=NOW,
        )

        wrong_kind = self.make_put_body(
            policy=private_policy,
            kind="verified_outcome",
        )
        self.assert_code(
            "kind_denied",
            protocol.effect_binding_sha256,
            wrong_kind,
        )
        private_guide = self.make_put_body(
            policy=private_policy,
            privacy="private",
            roles=["maintainer", "guide"],
        )
        self.assert_code(
            "scope_denied",
            protocol.effect_binding_sha256,
            private_guide,
        )

    def test_owner_suppression_binds_target_hash_reason_and_scope(self):
        suppress_only = self.make_policy(
            operations=["suppress"],
            kinds=[],
            privacy=["private"],
            roles=["maintainer"],
        )
        config = self.make_config(policy=suppress_only)
        body = self.make_suppression_body(policy=suppress_only)
        envelope = self.seal(body)
        result = protocol.verify_for_new_admission(
            protocol.canonical_json(envelope),
            config=config,
            public_keys={KEY_ID: self.public},
            now=NOW,
        )
        self.assertIsNone(result["continuity_write"])
        self.assertEqual(
            result["suppression"],
            {
                "target_entry_id": "jlce-000000000000000000000099",
                "target_entry_sha256": "9" * 64,
                "reason": "privacy_request",
            },
        )
        for field in ("target_entry_id", "target_entry_sha256", "reason"):
            changed = copy.deepcopy(body)
            changed["suppression"][field] = (
                "jlce-ffffffffffffffffffffffff"
                if field == "target_entry_id"
                else (
                    "f" * 64 if field == "target_entry_sha256" else "owner_request"
                )
            )
            self.assertNotEqual(
                protocol.effect_binding_sha256(changed),
                protocol.effect_binding_sha256(body),
            )
        scope_mutations = {
            "privacy": "public",
            "visible_to_roles": ["forge"],
            "repository": "other/repo",
        }
        for field, hostile in scope_mutations.items():
            changed = copy.deepcopy(body)
            changed["scope"][field] = hostile
            if field == "repository":
                # Keep the effect internally consistent; config binding is a
                # separate admission check.
                changed["repository"] = hostile
            with self.subTest(suppression_scope=field):
                self.assertNotEqual(
                    protocol.effect_binding_sha256(changed),
                    protocol.effect_binding_sha256(body),
                )
        public_suppression = copy.deepcopy(body)
        public_suppression["scope"]["privacy"] = "public"
        self.assert_code(
            "scope_denied",
            protocol.verify_for_new_admission,
            protocol.canonical_json(self.seal(public_suppression)),
            config=config,
            public_keys={KEY_ID: self.public},
            now=NOW,
        )
        latent_put = copy.deepcopy(suppress_only)
        latent_put["permissions"]["entry_kinds"] = ["user_correction"]
        self.assert_code(
            "schema_invalid",
            protocol.normalize_key_policy,
            latent_put,
        )
        put_without_kind = self.make_policy(
            operations=["put"],
            kinds=[],
        )
        self.assert_code(
            "schema_invalid",
            protocol.normalize_key_policy,
            put_without_kind,
        )

    def test_external_observer_can_only_put_verified_outcomes(self):
        external_private = Ed25519PrivateKey.generate()
        external_public = raw_public_key(external_private)
        external_authority = {
            "class": "external_observer",
            "source_kind": "github_app",
            "source_trust": "externally_verified",
            "source_actor": "github-observer",
        }
        external_policy = self.make_policy(
            authority=external_authority,
            key_id="github-observer-key",
            public=external_public,
            operations=["put"],
            kinds=["verified_outcome"],
            commitment_kinds=["github_observer"],
        )
        config = self.make_config(policy=external_policy)
        body = self.make_put_body(
            authority=external_authority,
            policy=external_policy,
            kind="verified_outcome",
            payload={
                "outcome_kind": "pr_merged",
                "claim_id": "claim-verified-1",
                "reputation_event_sha256": "c" * 64,
            },
            privacy="public",
            roles=["maintainer", "guide"],
        )
        envelope = self.seal(
            body,
            private=external_private,
            key_id="github-observer-key",
            commitment_kind="github_observer",
        )
        result = protocol.verify_for_new_admission(
            protocol.canonical_json(envelope),
            config=config,
            public_keys={"github-observer-key": external_public},
            now=NOW,
        )
        self.assertEqual(
            result["continuity_write"]["source"]["kind"],
            "github_app",
        )
        self.assertEqual(
            result["continuity_write"]["kind"],
            "verified_outcome",
        )

        preference = copy.deepcopy(body)
        preference["put"]["kind"] = "user_preference"
        preference["put"]["payload"] = {"preference": "avoid"}
        self.assert_code(
            "kind_denied",
            protocol.effect_binding_sha256,
            preference,
        )
        invalid_policy = copy.deepcopy(external_policy)
        invalid_policy["permissions"]["operations"] = ["put", "suppress"]
        self.assert_code(
            "operation_denied",
            protocol.normalize_key_policy,
            invalid_policy,
        )
        suppression = copy.deepcopy(body)
        suppression["operation"] = "suppress"
        suppression["put"] = None
        suppression["suppression"] = {
            "target_entry_id": "jlce-000000000000000000000099",
            "target_entry_sha256": "e" * 64,
            "reason": "owner_request",
        }
        self.assert_code(
            "operation_denied",
            protocol.effect_binding_sha256,
            suppression,
        )

    def test_time_policy_ttl_future_and_strict_expiry(self):
        too_early = self.make_put_body(
            issued_at="2026-07-16T23:59:00Z",
            expires_at="2026-07-17T00:04:00Z",
            expected_head=self.head(updated_at="2026-07-16T23:58:00Z"),
        )
        self.assert_code(
            "time_invalid",
            protocol.verify_for_new_admission,
            protocol.canonical_json(self.seal(too_early)),
            config=self.config,
            public_keys={KEY_ID: self.public},
            now=NOW,
        )

        future = self.make_put_body(
            issued_at="2026-07-18T12:00:11Z",
            expires_at="2026-07-18T12:05:11Z",
        )
        self.assert_code(
            "not_yet_valid",
            protocol.verify_for_new_admission,
            protocol.canonical_json(self.seal(future)),
            config=self.config,
            public_keys={KEY_ID: self.public},
            now=NOW,
        )

        expires_now = self.make_put_body(
            issued_at="2026-07-18T11:55:00Z",
            expires_at="2026-07-18T12:00:00Z",
            expected_head=self.head(updated_at="2026-07-18T11:54:00Z"),
        )
        self.assert_code(
            "expired",
            protocol.verify_for_new_admission,
            protocol.canonical_json(self.seal(expires_now)),
            config=self.config,
            public_keys={KEY_ID: self.public},
            now=NOW,
        )

        short = self.make_put_body(
            issued_at="2026-07-18T12:00:00Z",
            expires_at="2026-07-18T12:00:59Z",
        )
        self.assert_code("time_invalid", protocol.effect_binding_sha256, short)
        long = self.make_put_body(
            issued_at="2026-07-18T12:00:00Z",
            expires_at="2026-07-18T12:15:01Z",
        )
        self.assert_code("time_invalid", protocol.effect_binding_sha256, long)

        config_too_high = self.make_config(maximum_ttl_seconds=901)
        self.assert_code(
            "schema_invalid",
            protocol.normalize_config,
            config_too_high,
        )
        config_skew_high = self.make_config(maximum_clock_skew_seconds=31)
        self.assert_code(
            "schema_invalid",
            protocol.normalize_config,
            config_skew_high,
        )

    def test_disabled_is_default_safe_boundary_but_history_remains_readable(self):
        disabled = self.make_config(enabled=False)
        self.assert_code(
            "importer_disabled",
            protocol.verify_for_new_admission,
            self.raw,
            config=disabled,
            public_keys={KEY_ID: self.public},
            now=NOW,
        )
        historical = protocol.verify_historical_envelope(
            self.raw,
            config=disabled,
            public_keys={KEY_ID: self.public},
        )
        self.assertEqual(historical["mode"], "historical")

    def test_rotation_distinguishes_history_replay_and_new_admission(self):
        digest = protocol.envelope_sha256(self.envelope)
        historical = protocol.verify_historical_envelope(
            self.raw,
            config=self.config,
            public_keys={KEY_ID: self.public},
        )
        replay = protocol.verify_for_replay(
            self.raw,
            config=self.config,
            public_keys={KEY_ID: self.public},
            expected_envelope_sha256=digest,
        )
        self.assertEqual(historical["key_state"], "active")
        self.assertEqual(replay["mode"], "replay")
        self.assert_code(
            "replay_digest_mismatch",
            protocol.verify_for_replay,
            self.raw,
            config=self.config,
            public_keys={KEY_ID: self.public},
            expected_envelope_sha256="f" * 64,
        )

        retired_policy = self.make_policy(state="retired")
        self.assertEqual(
            protocol.policy_authorization_sha256(retired_policy),
            protocol.policy_authorization_sha256(self.policy),
        )
        retired = self.make_config(policy=retired_policy, enabled=False)
        self.assertEqual(
            protocol.verify_historical_envelope(
                self.raw,
                config=retired,
                public_keys={KEY_ID: self.public},
            )["key_state"],
            "retired",
        )
        self.assertEqual(
            protocol.verify_for_replay(
                self.raw,
                config=retired,
                public_keys={KEY_ID: self.public},
                expected_envelope_sha256=digest,
            )["key_state"],
            "retired",
        )
        expired_body = self.make_put_body(
            policy=retired_policy,
            issued_at="2026-07-18T10:00:00Z",
            expires_at="2026-07-18T10:05:00Z",
            expected_head=self.head(updated_at="2026-07-18T09:59:00Z"),
        )
        expired_envelope = self.seal(expired_body)
        expired_raw = protocol.canonical_json(expired_envelope)
        self.assertEqual(
            protocol.verify_for_replay(
                expired_raw,
                config=retired,
                public_keys={KEY_ID: self.public},
                expected_envelope_sha256=protocol.envelope_sha256(
                    expired_envelope
                ),
            )["key_state"],
            "retired",
        )
        self.assert_code(
            "key_retired",
            protocol.verify_for_new_admission,
            self.raw,
            config=self.make_config(policy=retired_policy),
            public_keys={KEY_ID: self.public},
            now=NOW,
        )

        revoked_policy = self.make_policy(state="revoked")
        revoked = self.make_config(policy=revoked_policy)
        for verifier, kwargs in (
            (protocol.verify_historical_envelope, {}),
            (
                protocol.verify_for_replay,
                {"expected_envelope_sha256": digest},
            ),
            (protocol.verify_for_new_admission, {"now": NOW}),
        ):
            with self.subTest(verifier=verifier.__name__):
                self.assert_code(
                    "key_revoked",
                    verifier,
                    self.raw,
                    config=revoked,
                    public_keys={KEY_ID: self.public},
                    **kwargs,
                )

    def test_errors_are_stable_and_do_not_reflect_hostile_input(self):
        secret = "gh" + "p_THIS_MUST_NEVER_APPEAR"
        hostile = {**self.envelope, secret: secret}
        raw = protocol.canonical_json(hostile)
        with self.assertRaises(protocol.ContinuityProtocolError) as caught:
            protocol.parse_envelope(raw)
        projection = protocol.public_error(caught.exception)
        rendered = json.dumps(projection, sort_keys=True)
        self.assertEqual(projection["error_code"], "schema_invalid")
        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn(secret, rendered)
        self.assertEqual(
            protocol.public_error(RuntimeError(secret))["error_code"],
            "schema_invalid",
        )
        self.assertRegex(
            projection["error_code"],
            r"^[a-z][a-z0-9_]*$",
        )

    def test_protocol_contains_no_private_key_or_signing_implementation(self):
        source = (SCRIPTS / "john_lomein_continuity_protocol.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("Ed25519PrivateKey", source)
        self.assertNotIn("load_pem_private_key", source)
        self.assertFalse(hasattr(protocol, "sign_envelope"))
        self.assertFalse(hasattr(protocol, "load_private_key"))


if __name__ == "__main__":
    unittest.main()
