from __future__ import annotations

import base64
import copy
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_binding as adoption_binding,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_attestor as core,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_public_verifier as public_verifier,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_source_revalidation_binding
    as source_revalidation_binding,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_trust_projection as trust,
)


class PublicQualificationVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o755)
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
            "qualification_public_root": "/safe/evidence-public",
            "qualification_private_root": "/safe/evidence-private",
            "expected_evidence_uid": 501,
            "attestor_key_id": "john-example-key-1",
            "private_key_path": "/safe/keys/private.pem",
            "public_key_path": "/safe/keys/public.pem",
            "public_key_sha256": self.fingerprint,
            "head_path": "/safe/state/head.json",
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
                "john-lomein.persona.operator-verifier.v2"
            ),
            "verifier_timeout_seconds": 300,
            "verification_execution_policy_sha256": core.sha256_json(
                core.VERIFICATION_EXECUTION_POLICY
            ),
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
            "expires_at_unix": 1_000,
            "verifier_version": self.policy["verifier_version"],
            "verifier_uid": 502,
            "verifier_bundle_sha256": "2" * 64,
            "verification_policy_sha256": "6" * 64,
            "capture_manifest_sha256": "7" * 64,
            "capture_plan_sha256": "8" * 64,
            "operator_policy_sha256": core.sha256_json(self.policy),
            "claim_strength": core.CLAIM_STRENGTH,
            "public_reputation_eligible": False,
            "verified_at_unix": 110,
            "observed_evidence_uid": 501,
            "capture_creator_uid": 504,
            "capture_export_gid": 505,
            "capture_adopted_uid": 0,
            "capture_adoption_receipt_sha256": "9" * 64,
            "capture_adoption_policy_sha256": "a" * 64,
            "capture_object_identity_sha256": "b" * 64,
            "capture_content_inventory_sha256": "c" * 64,
            "capture_adopted_at_unix": 109,
            "capture_request_sha256": "d" * 64,
            "capture_boundary_policy_sha256": "e" * 64,
            "capture_helper_activation_policy_sha256": "f" * 64,
        }
        receipt = {
            "schema_version": (
                source_revalidation_binding
                .SOURCE_REVALIDATION_RECEIPT_SCHEMA
            ),
            "status": source_revalidation_binding.SOURCE_REVALIDATION_STATUS,
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
            "verifier_output_sha256": "0" * 64,
            "revalidator_uid": 0,
            "revalidated_at_unix": 115,
        }
        evidence[
            "post_verifier_live_source_revalidation_receipt"
        ] = receipt
        evidence[
            "post_verifier_live_source_revalidation_receipt_sha256"
        ] = (
            source_revalidation_binding
            .source_revalidation_receipt_sha256(receipt)
        )
        payload = core.build_attestation_payload(
            self.config,
            evidence,
            public_key_bytes=self.public_bytes,
            chain_sequence=1,
            previous_attestation_sha256=None,
        )
        envelope = core.sign_attestation_payload(
            payload,
            private_key_bytes=self.private_bytes,
            public_key_bytes=self.public_bytes,
        )
        self.envelope = envelope
        head = core._verified_head_for_envelope(
            core.normalize_config(self.config),
            envelope,
            updated_at_unix=120,
        )
        projection = trust.build_projection(
            self.config,
            self.policy,
            head,
            envelope,
            public_key_bytes=self.public_bytes,
            generated_at_unix=130,
        )
        self.projection_path = self.root / "current.json"
        trust.publish_projection(
            projection,
            self.projection_path,
            expected_instance_slug="john-example",
            expected_key_id="john-example-key-1",
            expected_public_key_sha256=self.fingerprint,
            now_unix=140,
            publication_owner_uid=os.geteuid(),
        )
        self.pin_path = self.root / "pins.json"
        self.pins = {
            "schema_version": public_verifier.PIN_CONFIG_SCHEMA,
            "projection_path": str(self.projection_path),
            "instance_slug": "john-example",
            "attestor_key_id": "john-example-key-1",
            "public_key_sha256": self.fingerprint,
        }
        self.pin_path.write_bytes(core.canonical_json(self.pins) + b"\n")
        self.pin_path.chmod(0o444)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_default_pin_avoids_macos_etc_symlink(self) -> None:
        expected_prefix = "/private/etc/" if sys.platform == "darwin" else "/etc/"
        self.assertTrue(
            str(public_verifier.DEFAULT_PIN_CONFIG_PATH).startswith(
                expected_prefix
            )
        )

    def verify(self) -> dict:
        return public_verifier.verify_installed_projection(
            self.pin_path,
            now_unix=140,
            installation_owner_uid=os.geteuid(),
            projection_owner_uid=os.geteuid(),
        )

    def test_zero_network_public_result_is_pinned_and_sanitized(self) -> None:
        schema = json.loads(
            (
                ROOT
                / "qualification_attestor"
                / "schemas"
                / (
                    "persona-qualification-public-verifier-config."
                    "v1.schema.json"
                )
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(
            list(Draft202012Validator(schema).iter_errors(self.pins))
        )
        result = self.verify()
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["run_id"], "run-001")
        self.assertEqual(result["public_key_sha256"], self.fingerprint)
        self.assertRegex(result["projection_sha256"], r"^[0-9a-f]{64}$")
        self.assertFalse(result["public_reputation_eligible"])
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn(str(self.root), serialized)
        self.assertNotIn("BEGIN PUBLIC KEY", serialized)
        self.assertNotIn("signature", serialized)

    def test_historical_v4_projection_remains_publicly_verifiable(
        self,
    ) -> None:
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
        key = serialization.load_pem_private_key(
            self.private_bytes,
            password=None,
        )
        signature = key.sign(core.canonical_json(historical_payload))
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
        historical_projection = trust.build_projection(
            self.config,
            self.policy,
            historical_head,
            historical_envelope,
            public_key_bytes=self.public_bytes,
            generated_at_unix=130,
        )
        self.projection_path.chmod(0o600)
        self.projection_path.write_bytes(
            core.canonical_json(historical_projection) + b"\n"
        )
        self.projection_path.chmod(0o444)

        result = self.verify()
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["run_id"], "run-001")
        self.assertEqual(
            historical_projection["head"]["verified_at_unix"],
            110,
        )

    def test_pin_mismatch_and_expiry_fail_closed(self) -> None:
        wrong = dict(self.pins)
        wrong["public_key_sha256"] = "f" * 64
        self.pin_path.chmod(0o600)
        self.pin_path.write_bytes(core.canonical_json(wrong) + b"\n")
        self.pin_path.chmod(0o444)
        with self.assertRaises(
            public_verifier.PublicQualificationVerifierError
        ) as caught:
            self.verify()
        self.assertEqual(
            caught.exception.code,
            "trust_projection_public_key_not_pinned",
        )

        self.pin_path.chmod(0o600)
        self.pin_path.write_bytes(core.canonical_json(self.pins) + b"\n")
        self.pin_path.chmod(0o444)
        with self.assertRaises(
            public_verifier.PublicQualificationVerifierError
        ) as caught:
            public_verifier.verify_installed_projection(
                self.pin_path,
                now_unix=1_000,
                installation_owner_uid=os.geteuid(),
                projection_owner_uid=os.geteuid(),
            )
        self.assertEqual(caught.exception.code, "attestation_expired")

    def test_capture_selection_policy_tampering_fails_closed(self) -> None:
        projection = trust.read_public_projection(
            self.projection_path,
            publication_owner_uid=os.geteuid(),
        )
        projection["operator_policy"]["capture_selection_sha256"] = (
            "b" * 64
        )
        self.projection_path.chmod(0o600)
        self.projection_path.write_bytes(
            core.canonical_json(projection) + b"\n"
        )
        self.projection_path.chmod(0o444)

        with self.assertRaises(
            public_verifier.PublicQualificationVerifierError
        ) as caught:
            self.verify()
        self.assertEqual(
            caught.exception.code,
            "operator_policy_digest_mismatch",
        )

    def test_pin_file_must_be_exact_canonical_read_only_file(self) -> None:
        self.pin_path.chmod(0o644)
        with self.assertRaises(
            public_verifier.PublicQualificationVerifierError
        ) as caught:
            self.verify()
        self.assertEqual(
            caught.exception.code,
            "public_verifier_config_unsafe",
        )

        self.pin_path.chmod(0o600)
        self.pin_path.write_bytes(
            b"\n" + core.canonical_json(self.pins) + b"\n"
        )
        self.pin_path.chmod(0o444)
        with self.assertRaises(
            public_verifier.PublicQualificationVerifierError
        ) as caught:
            self.verify()
        self.assertEqual(
            caught.exception.code,
            "public_verifier_config_noncanonical",
        )

    def test_command_accepts_no_path_or_pin_override(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = public_verifier.main(["--projection", "/tmp/x"])
        self.assertEqual(exit_code, 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(
            result["reason"],
            "command_arguments_unsupported",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
