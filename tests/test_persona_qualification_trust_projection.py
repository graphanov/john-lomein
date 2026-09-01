from __future__ import annotations

import base64
import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_attestor as core,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_binding as adoption_binding,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_source_revalidation_binding
    as source_revalidation_binding,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_trust_projection as trust,
)


class PersonaQualificationTrustProjectionTests(unittest.TestCase):
    @staticmethod
    def adoption_evidence(*, adopted_at_unix: int) -> dict[str, object]:
        return {
            "capture_creator_uid": 504,
            "capture_export_gid": 505,
            "capture_adopted_uid": 0,
            "capture_adoption_receipt_sha256": "9" * 64,
            "capture_adoption_policy_sha256": "a" * 64,
            "capture_object_identity_sha256": "b" * 64,
            "capture_content_inventory_sha256": "c" * 64,
            "capture_adopted_at_unix": adopted_at_unix,
            "capture_request_sha256": "d" * 64,
            "capture_boundary_policy_sha256": "e" * 64,
            "capture_helper_activation_policy_sha256": "f" * 64,
        }

    def setUp(self) -> None:
        key = Ed25519PrivateKey.generate()
        self.private_bytes = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.public_bytes = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.fingerprint = core.public_key_fingerprint(self.public_bytes)
        self.config = {
            "schema_version": 1,
            "instance_slug": "john-example",
            "qualification_public_root": "/safe/operator/evidence-public",
            "qualification_private_root": "/safe/operator/evidence-private",
            "expected_evidence_uid": 501,
            "attestor_key_id": "john-example-persona-ed25519-1",
            "private_key_path": "/safe/operator/keys/private.pem",
            "public_key_path": "/safe/operator/keys/public.pem",
            "public_key_sha256": self.fingerprint,
            "head_path": "/safe/operator/state/head.json",
        }
        self.policy = {
            "schema_version": core.OPERATOR_POLICY_SCHEMA,
            "instance_slug": "john-example",
            "expected_evidence_uid": 501,
            "expected_capture_uid": 504,
            "expected_capture_export_gid": 505,
            "expected_adopted_uid": 0,
            "capture_adoption_binding_schema": (
                adoption_binding.ADOPTION_BINDING_SCHEMA
            ),
            "capture_adoption_required": True,
            "instance_manifest_sha256": "0" * 64,
            "verifier_uid": 502,
            "verifier_gid": 503,
            "verifier_python_sha256": "1" * 64,
            "verifier_bundle_sha256": "2" * 64,
            "verifier_version": (
                "john-lomein.persona.operator-verifier.v1"
            ),
            "verifier_timeout_seconds": 300,
            "verification_execution_policy_sha256": "3" * 64,
            "capture_selection_sha256": "a" * 64,
            "claim_strength": core.CLAIM_STRENGTH,
            "public_reputation_eligible": False,
        }
        evidence = {
            "run_id": "run-001",
            "summary_sha256": "4" * 64,
            "binding_sha256": "5" * 64,
            "status": "qualified",
            "qualified_at_unix": 100,
            "expires_at_unix": 1000,
            "verifier_version": self.policy["verifier_version"],
            "verifier_uid": self.policy["verifier_uid"],
            "verifier_bundle_sha256": self.policy[
                "verifier_bundle_sha256"
            ],
            "verification_policy_sha256": "6" * 64,
            "capture_manifest_sha256": "7" * 64,
            "capture_plan_sha256": "8" * 64,
            "operator_policy_sha256": core.sha256_json(self.policy),
            "claim_strength": core.CLAIM_STRENGTH,
            "public_reputation_eligible": False,
            "verified_at_unix": 110,
            "observed_evidence_uid": 501,
            **self.adoption_evidence(adopted_at_unix=109),
        }
        receipt = {
            "schema_version": (
                source_revalidation_binding
                .SOURCE_REVALIDATION_RECEIPT_SCHEMA
            ),
            "status": (
                source_revalidation_binding.SOURCE_REVALIDATION_STATUS
            ),
            "capture_adoption_receipt_sha256": evidence[
                "capture_adoption_receipt_sha256"
            ],
            "capture_object_identity_sha256": evidence[
                "capture_object_identity_sha256"
            ],
            "capture_plan_sha256": evidence["capture_plan_sha256"],
            "capture_manifest_sha256": evidence[
                "capture_manifest_sha256"
            ],
            "verifier_output_sha256": "9" * 64,
            "revalidator_uid": 0,
            "revalidated_at_unix": 111,
        }
        evidence.update(
            {
                "post_verifier_live_source_revalidation_receipt": (
                    receipt
                ),
                "post_verifier_live_source_revalidation_receipt_sha256": (
                    source_revalidation_binding
                    .source_revalidation_receipt_sha256(receipt)
                ),
            }
        )
        payload = core.build_attestation_payload(
            self.config,
            evidence,
            public_key_bytes=self.public_bytes,
            chain_sequence=1,
            previous_attestation_sha256=None,
        )
        self.envelope = core.sign_attestation_payload(
            payload,
            private_key_bytes=self.private_bytes,
            public_key_bytes=self.public_bytes,
        )
        self.head = core._verified_head_for_envelope(
            core.normalize_config(self.config),
            self.envelope,
            updated_at_unix=120,
        )

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(trust.TrustProjectionError) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def projection(self) -> dict:
        return trust.build_projection(
            self.config,
            self.policy,
            self.head,
            self.envelope,
            public_key_bytes=self.public_bytes,
            generated_at_unix=130,
        )

    def test_projection_is_self_contained_signed_and_privacy_safe(self) -> None:
        projection = self.projection()
        verified = trust.verify_projection(
            projection,
            expected_instance_slug="john-example",
            expected_key_id="john-example-persona-ed25519-1",
            expected_public_key_sha256=self.fingerprint,
            now_unix=140,
        )
        self.assertEqual(verified, projection)
        serialized = json.dumps(projection, sort_keys=True)
        self.assertNotIn("/safe/operator", serialized)
        self.assertNotIn("attestation_path", serialized)
        self.assertFalse(projection["public_reputation_eligible"])
        self.assertFalse(
            projection["claim_limits"]["whole_store_rollback_detected"]
        )
        self.assertFalse(
            projection["claim_limits"]["independent_third_party"]
        )
        self.assertEqual(projection["head"]["verified_at_unix"], 111)
        self.assertEqual(
            projection["operator_policy"]["schema_version"],
            "john-lomein.persona-qualification-operator-policy.v3",
        )
        self.assertEqual(
            {
                field: projection["operator_policy"][field]
                for field in (
                    "expected_capture_uid",
                    "expected_capture_export_gid",
                    "expected_adopted_uid",
                    "capture_adoption_binding_schema",
                    "capture_adoption_required",
                )
            },
            {
                "expected_capture_uid": 504,
                "expected_capture_export_gid": 505,
                "expected_adopted_uid": 0,
                "capture_adoption_binding_schema": (
                    adoption_binding.ADOPTION_BINDING_SCHEMA
                ),
                "capture_adoption_required": True,
            },
        )
        self.assertEqual(
            projection["attestation"]["payload"]["schema_version"],
            5,
        )
        verification = projection["attestation"]["payload"]["verification"]
        self.assertEqual(
            {
                field: verification[field]
                for field in adoption_binding.ADOPTION_EVIDENCE_FIELDS
            },
            self.adoption_evidence(adopted_at_unix=109),
        )
        self.assertEqual(
            verification[
                "post_verifier_live_source_"
                "revalidation_receipt"
            ]["revalidated_at_unix"],
            111,
        )

    def test_historical_v4_projection_remains_read_verifiable(self) -> None:
        historical_payload = copy.deepcopy(self.envelope["payload"])
        historical_payload["schema_version"] = (
            core.HISTORICAL_PAYLOAD_SCHEMA_VERSION
        )
        historical_payload["verification"].pop(
            "post_verifier_live_source_revalidation_receipt"
        )
        historical_payload["verification"].pop(
            "post_verifier_live_source_revalidation_receipt_sha256"
        )
        historical_private_key = serialization.load_pem_private_key(
            self.private_bytes,
            password=None,
        )
        signature = historical_private_key.sign(
            core.canonical_json(historical_payload)
        )
        historical_envelope = {
            "schema_version": core.ENVELOPE_SCHEMA_VERSION,
            "payload": historical_payload,
            "signature": {
                "algorithm": core.ALGORITHM,
                "key_id": historical_payload["attestor"]["key_id"],
                "value_base64": base64.urlsafe_b64encode(signature)
                .decode("ascii")
                .rstrip("="),
            },
        }
        historical_head = core._verified_head_for_envelope(
            core.normalize_config(self.config),
            historical_envelope,
            updated_at_unix=120,
        )
        projection = trust.build_projection(
            self.config,
            self.policy,
            historical_head,
            historical_envelope,
            public_key_bytes=self.public_bytes,
            generated_at_unix=130,
        )
        verified = trust.verify_projection(
            projection,
            expected_instance_slug="john-example",
            expected_key_id="john-example-persona-ed25519-1",
            expected_public_key_sha256=self.fingerprint,
            now_unix=140,
        )
        self.assertEqual(verified, projection)
        self.assertEqual(
            verified["attestation"]["payload"]["schema_version"],
            core.HISTORICAL_PAYLOAD_SCHEMA_VERSION,
        )
        self.assertEqual(verified["head"]["verified_at_unix"], 110)
        self.assertNotIn(
            "post_verifier_live_source_revalidation_receipt",
            verified["attestation"]["payload"]["verification"],
        )

    def test_projection_requires_one_exact_canonical_public_key(self) -> None:
        projection = self.projection()
        canonical = projection["public_key_pem"]
        for malformed in (
            "/private/secret/path\n" + canonical,
            canonical + "/private/secret/path\n",
            canonical + canonical,
            canonical + "\n",
        ):
            with self.subTest(malformed=malformed[-40:]):
                candidate = copy.deepcopy(projection)
                candidate["public_key_pem"] = malformed
                self.assert_code(
                    "projection_public_key_invalid",
                    trust.normalize_projection,
                    candidate,
                )

    def test_projection_rejects_unpinned_tampered_or_expired_claims(self) -> None:
        projection = self.projection()
        self.assert_code(
            "trust_projection_public_key_not_pinned",
            trust.verify_projection,
            projection,
            expected_instance_slug="john-example",
            expected_key_id="john-example-persona-ed25519-1",
            expected_public_key_sha256="f" * 64,
            now_unix=140,
        )
        self.assert_code(
            "attestor_key_id_not_pinned",
            trust.verify_projection,
            projection,
            expected_instance_slug="john-example",
            expected_key_id="john-example-persona-ed25519-wrong",
            expected_public_key_sha256=self.fingerprint,
            now_unix=140,
        )
        tampered = copy.deepcopy(projection)
        tampered["operator_policy"]["verifier_uid"] = 506
        self.assert_code(
            "operator_policy_attestation_binding_mismatch",
            trust.verify_projection,
            tampered,
            expected_instance_slug="john-example",
            expected_key_id="john-example-persona-ed25519-1",
            expected_public_key_sha256=self.fingerprint,
            now_unix=140,
        )
        tampered_selection = copy.deepcopy(projection)
        tampered_selection["operator_policy"][
            "capture_selection_sha256"
        ] = "b" * 64
        self.assert_code(
            "operator_policy_digest_mismatch",
            trust.verify_projection,
            tampered_selection,
            expected_instance_slug="john-example",
            expected_key_id="john-example-persona-ed25519-1",
            expected_public_key_sha256=self.fingerprint,
            now_unix=140,
        )
        for field, changed_value in (
            ("capture_creator_uid", 506),
            ("capture_adoption_receipt_sha256", "8" * 64),
            ("capture_adopted_at_unix", 108),
        ):
            with self.subTest(signed_adoption_field=field):
                tampered_adoption = copy.deepcopy(projection)
                tampered_adoption["attestation"]["payload"][
                    "verification"
                ][field] = changed_value
                if field == "capture_adoption_receipt_sha256":
                    receipt = tampered_adoption["attestation"][
                        "payload"
                    ]["verification"][
                        "post_verifier_live_source_"
                        "revalidation_receipt"
                    ]
                    receipt[field] = changed_value
                    tampered_adoption["attestation"]["payload"][
                        "verification"
                    ][
                        "post_verifier_live_source_"
                        "revalidation_receipt_sha256"
                    ] = (
                        source_revalidation_binding
                        .source_revalidation_receipt_sha256(receipt)
                    )
                self.assert_code(
                    "attestation_signature_invalid",
                    trust.verify_projection,
                    tampered_adoption,
                    expected_instance_slug="john-example",
                    expected_key_id=(
                        "john-example-persona-ed25519-1"
                    ),
                    expected_public_key_sha256=self.fingerprint,
                    now_unix=140,
                )
        missing_selection = copy.deepcopy(projection)
        del missing_selection["operator_policy"][
            "capture_selection_sha256"
        ]
        self.assert_code(
            "operator_policy_fields_invalid",
            trust.normalize_projection,
            missing_selection,
        )
        reputational = copy.deepcopy(projection)
        reputational["public_reputation_eligible"] = True
        self.assert_code(
            "trust_projection_reputation_claim_invalid",
            trust.verify_projection,
            reputational,
            expected_instance_slug="john-example",
            expected_key_id="john-example-persona-ed25519-1",
            expected_public_key_sha256=self.fingerprint,
            now_unix=140,
        )
        self.assert_code(
            "attestation_expired",
            trust.verify_projection,
            projection,
            expected_instance_slug="john-example",
            expected_key_id="john-example-persona-ed25519-1",
            expected_public_key_sha256=self.fingerprint,
            now_unix=1000,
        )

    def test_projection_publication_is_atomic_monotonic_and_path_safe(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o755)
            path = root / "current.json"
            projection = self.projection()
            published, status = trust.publish_projection(
                projection,
                path,
                expected_instance_slug="john-example",
                expected_key_id="john-example-persona-ed25519-1",
                expected_public_key_sha256=self.fingerprint,
                now_unix=140,
                publication_owner_uid=os.geteuid(),
            )
            self.assertEqual(status, "published")
            self.assertEqual(published, projection)
            self.assertEqual(path.stat().st_mode & 0o777, 0o444)
            again, status = trust.publish_projection(
                {
                    **projection,
                    "generated_at_unix": 131,
                },
                path,
                expected_instance_slug="john-example",
                expected_key_id="john-example-persona-ed25519-1",
                expected_public_key_sha256=self.fingerprint,
                now_unix=140,
                publication_owner_uid=os.geteuid(),
            )
            self.assertEqual(status, "idempotent")
            self.assertEqual(again, projection)

            second_evidence = {
                "run_id": "run-002",
                "summary_sha256": "8" * 64,
                "binding_sha256": "9" * 64,
                "status": "qualified",
                "qualified_at_unix": 200,
                "expires_at_unix": 1200,
                "verifier_version": self.policy["verifier_version"],
                "verifier_uid": self.policy["verifier_uid"],
                "verifier_bundle_sha256": self.policy[
                    "verifier_bundle_sha256"
                ],
                "verification_policy_sha256": "a" * 64,
                "capture_manifest_sha256": "b" * 64,
                "capture_plan_sha256": "c" * 64,
                "operator_policy_sha256": core.sha256_json(self.policy),
                "claim_strength": core.CLAIM_STRENGTH,
                "public_reputation_eligible": False,
                "verified_at_unix": 210,
                "observed_evidence_uid": 501,
                **self.adoption_evidence(adopted_at_unix=209),
            }
            second_receipt = {
                "schema_version": (
                    source_revalidation_binding
                    .SOURCE_REVALIDATION_RECEIPT_SCHEMA
                ),
                "status": (
                    source_revalidation_binding
                    .SOURCE_REVALIDATION_STATUS
                ),
                "capture_adoption_receipt_sha256": second_evidence[
                    "capture_adoption_receipt_sha256"
                ],
                "capture_object_identity_sha256": second_evidence[
                    "capture_object_identity_sha256"
                ],
                "capture_plan_sha256": second_evidence[
                    "capture_plan_sha256"
                ],
                "capture_manifest_sha256": second_evidence[
                    "capture_manifest_sha256"
                ],
                "verifier_output_sha256": "d" * 64,
                "revalidator_uid": 0,
                "revalidated_at_unix": 211,
            }
            second_evidence.update(
                {
                    "post_verifier_live_source_revalidation_receipt": (
                        second_receipt
                    ),
                    (
                        "post_verifier_live_source_"
                        "revalidation_receipt_sha256"
                    ): (
                        source_revalidation_binding
                        .source_revalidation_receipt_sha256(
                            second_receipt
                        )
                    ),
                }
            )
            second_payload = core.build_attestation_payload(
                self.config,
                second_evidence,
                public_key_bytes=self.public_bytes,
                chain_sequence=2,
                previous_attestation_sha256=core.sha256_json(
                    self.envelope
                ),
            )
            second_envelope = core.sign_attestation_payload(
                second_payload,
                private_key_bytes=self.private_bytes,
                public_key_bytes=self.public_bytes,
            )
            second_head = core._verified_head_for_envelope(
                core.normalize_config(self.config),
                second_envelope,
                updated_at_unix=220,
            )
            second_projection = trust.build_projection(
                self.config,
                self.policy,
                second_head,
                second_envelope,
                public_key_bytes=self.public_bytes,
                generated_at_unix=230,
            )
            current, status = trust.publish_projection(
                second_projection,
                path,
                expected_instance_slug="john-example",
                expected_key_id="john-example-persona-ed25519-1",
                expected_public_key_sha256=self.fingerprint,
                now_unix=240,
                publication_owner_uid=os.geteuid(),
            )
            self.assertEqual(status, "published")
            self.assertEqual(current["head"]["chain_sequence"], 2)
            self.assert_code(
                "public_projection_rollback_rejected",
                trust.publish_projection,
                projection,
                path,
                expected_instance_slug="john-example",
                expected_key_id="john-example-persona-ed25519-1",
                expected_public_key_sha256=self.fingerprint,
                now_unix=240,
                publication_owner_uid=os.geteuid(),
            )
            self.assert_code(
                "attestation_expired",
                trust.publish_projection,
                projection,
                root / "expired.json",
                expected_instance_slug="john-example",
                expected_key_id="john-example-persona-ed25519-1",
                expected_public_key_sha256=self.fingerprint,
                now_unix=1000,
                publication_owner_uid=os.geteuid(),
            )
            noncanonical = root / "noncanonical.json"
            noncanonical.write_bytes(
                b"\n" + core.canonical_json(projection) + b"\n"
            )
            noncanonical.chmod(0o444)
            self.assert_code(
                "public_projection_not_canonical",
                trust.publish_projection,
                projection,
                noncanonical,
                expected_instance_slug="john-example",
                expected_key_id="john-example-persona-ed25519-1",
                expected_public_key_sha256=self.fingerprint,
                now_unix=140,
                publication_owner_uid=os.geteuid(),
            )
            self.assertNotIn(
                "/safe/operator",
                path.read_text(encoding="utf-8"),
            )
            self.assertFalse(list(root.glob(".*.tmp")))
            path.chmod(0o600)


if __name__ == "__main__":
    unittest.main()
