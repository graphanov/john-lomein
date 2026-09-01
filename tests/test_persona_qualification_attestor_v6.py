from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_binding
    as adoption_binding,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_result
    as adoption_result,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_attestor as attestor,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_recovered_adoption_evidence
    as recovered_adoption,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_source_revalidation_binding
    as source_revalidation,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_trust_projection as trust,
)


class PersonaQualificationAttestorV6Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.from_private_bytes(
            bytes(range(1, 33))
        )
        self.private_bytes = self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.public_bytes = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def digest(label: str) -> str:
        return hashlib.sha256(label.encode("ascii")).hexdigest()

    def config(
        self,
        root: Path = Path("/safe/operator"),
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "instance_slug": "john-example",
            "qualification_public_root": str(
                root / "evidence-public"
            ),
            "qualification_private_root": str(
                root / "evidence-private"
            ),
            "expected_evidence_uid": 501,
            "attestor_key_id": "john-example-persona-ed25519-1",
            "private_key_path": str(root / "keys" / "private.pem"),
            "public_key_path": str(root / "keys" / "public.pem"),
            "public_key_sha256": attestor.public_key_fingerprint(
                self.public_bytes
            ),
            "head_path": str(root / "state" / "head.json"),
        }

    def operator_policy(
        self,
        evidence: dict[str, object],
    ) -> dict[str, object]:
        return {
            "schema_version": attestor.OPERATOR_POLICY_SCHEMA,
            "instance_slug": "john-example",
            "expected_evidence_uid": evidence[
                "observed_evidence_uid"
            ],
            "expected_capture_uid": evidence["capture_creator_uid"],
            "expected_capture_export_gid": evidence[
                "capture_export_gid"
            ],
            "expected_adopted_uid": 0,
            "capture_adoption_binding_schema": (
                adoption_binding.ADOPTION_BINDING_SCHEMA
            ),
            "capture_adoption_required": True,
            "instance_manifest_sha256": self.digest(
                "instance-manifest"
            ),
            "verifier_uid": evidence["verifier_uid"],
            "verifier_gid": 504,
            "verifier_python_sha256": self.digest(
                "verifier-python"
            ),
            "verifier_bundle_sha256": evidence[
                "verifier_bundle_sha256"
            ],
            "verifier_version": evidence["verifier_version"],
            "verifier_timeout_seconds": 300,
            "verification_execution_policy_sha256": self.digest(
                "verification-execution-policy"
            ),
            "capture_selection_sha256": self.digest(
                "capture-selection"
            ),
            "claim_strength": attestor.CLAIM_STRENGTH,
            "public_reputation_eligible": False,
        }

    def future_operator_policy(
        self,
        evidence: dict[str, object],
    ) -> dict[str, object]:
        policy = self.operator_policy(evidence)
        policy["schema_version"] = (
            attestor.FUTURE_OPERATOR_POLICY_SCHEMA
        )
        policy.pop("capture_adoption_binding_schema")
        policy.update(
            {
                "capture_adoption_result_schema": (
                    adoption_result.CAPTURE_ADOPTION_RESULT_SCHEMA
                ),
                "capture_adoption_provenance_schema": (
                    adoption_result.CAPTURE_ADOPTION_PROVENANCE_SCHEMA
                ),
                "capture_adoption_permitted_kinds": list(
                    attestor.FUTURE_CAPTURE_ADOPTION_PERMITTED_KINDS
                ),
                "verifier_request_schema": (
                    attestor.VERIFIER_REQUEST_V5_SCHEMA
                ),
                "verifier_output_schema": (
                    attestor.VERIFIER_OUTPUT_V4_SCHEMA
                ),
                "verification_execution_policy_schema": (
                    attestor
                    .VERIFICATION_EXECUTION_POLICY_V6_SCHEMA
                ),
                "verification_execution_policy_sha256": (
                    attestor.sha256_json(
                        attestor.VERIFICATION_EXECUTION_POLICY_V6
                    )
                ),
            }
        )
        return policy

    def v5_evidence(self) -> dict[str, object]:
        evidence = {
            "run_id": "run-001",
            "summary_sha256": "1" * 64,
            "binding_sha256": "2" * 64,
            "status": "qualified",
            "qualified_at_unix": 100,
            "expires_at_unix": 1000,
            "verifier_version": (
                "john-lomein.persona.operator-verifier.v4"
            ),
            "verifier_uid": 502,
            "verifier_bundle_sha256": "3" * 64,
            "verification_policy_sha256": "4" * 64,
            "capture_manifest_sha256": "5" * 64,
            "capture_plan_sha256": "7" * 64,
            "operator_policy_sha256": "6" * 64,
            "claim_strength": attestor.CLAIM_STRENGTH,
            "public_reputation_eligible": False,
            "verified_at_unix": 110,
            "observed_evidence_uid": 501,
            "capture_creator_uid": 503,
            "capture_export_gid": 505,
            "capture_adopted_uid": 0,
            "capture_adoption_receipt_sha256": "8" * 64,
            "capture_adoption_policy_sha256": "9" * 64,
            "capture_object_identity_sha256": "a" * 64,
            "capture_content_inventory_sha256": "b" * 64,
            "capture_adopted_at_unix": 109,
            "capture_request_sha256": "c" * 64,
            "capture_boundary_policy_sha256": "d" * 64,
            "capture_helper_activation_policy_sha256": "e" * 64,
        }
        receipt = {
            "schema_version": (
                source_revalidation.SOURCE_REVALIDATION_RECEIPT_SCHEMA
            ),
            "status": source_revalidation.SOURCE_REVALIDATION_STATUS,
            "capture_adoption_receipt_sha256": evidence[
                "capture_adoption_receipt_sha256"
            ],
            "capture_object_identity_sha256": evidence[
                "capture_object_identity_sha256"
            ],
            "capture_plan_sha256": evidence[
                "capture_plan_sha256"
            ],
            "capture_manifest_sha256": evidence[
                "capture_manifest_sha256"
            ],
            "verifier_output_sha256": "f" * 64,
            "revalidator_uid": 0,
            "revalidated_at_unix": 111,
        }
        return {
            **evidence,
            "post_verifier_live_source_revalidation_receipt": receipt,
            "post_verifier_live_source_revalidation_receipt_sha256": (
                source_revalidation
                .source_revalidation_receipt_sha256(receipt)
            ),
        }

    def provenance(
        self,
        kind: str,
        *,
        variant: str,
        verified_at: int,
    ) -> dict[str, object]:
        if kind == adoption_result.NORMAL_ADOPTION_KIND:
            evidence_schema = adoption_binding.ADOPTION_RECEIPT_SCHEMA
            details = {"adopted_at_unix": verified_at - 1}
        else:
            evidence_schema = (
                recovered_adoption.RECOVERED_ADOPTION_EVIDENCE_SCHEMA
            )
            details = {
                "transaction_journal_schema": (
                    recovered_adoption.TRANSACTION_JOURNAL_SCHEMA
                ),
                "adoption_reconciliation_record_sha256": self.digest(
                    f"reconciliation-record-{variant}"
                ),
                "adoption_reconciliation_receipt_sha256": self.digest(
                    f"reconciliation-receipt-{variant}"
                ),
            }
        return adoption_result.normalize_capture_adoption_provenance(
            {
                "schema_version": (
                    adoption_result
                    .CAPTURE_ADOPTION_PROVENANCE_SCHEMA
                ),
                "kind": kind,
                "evidence_schema": evidence_schema,
                "evidence_sha256": self.digest(
                    f"adoption-evidence-{kind}-{variant}"
                ),
                "details": details,
            }
        )

    def v6_evidence(
        self,
        kind: str,
        *,
        variant: str = "one",
        verified_at: int = 110,
        plan_sha256: str | None = None,
    ) -> dict[str, object]:
        provenance = self.provenance(
            kind,
            variant=variant,
            verified_at=verified_at,
        )
        provenance_sha256 = (
            adoption_result.capture_adoption_provenance_sha256(
                provenance
            )
        )
        evidence = {
            "run_id": "run-001",
            "summary_sha256": self.digest("summary"),
            "binding_sha256": self.digest("binding"),
            "status": "qualified",
            "qualified_at_unix": 100,
            "expires_at_unix": 1000,
            "verifier_version": (
                "john-lomein.persona.operator-verifier.v5"
            ),
            "verifier_uid": 502,
            "verifier_bundle_sha256": self.digest("verifier-bundle"),
            "verification_policy_sha256": self.digest(
                "verification-policy"
            ),
            "capture_manifest_sha256": self.digest(
                f"manifest-{variant}"
            ),
            "capture_plan_sha256": (
                self.digest("plan")
                if plan_sha256 is None
                else plan_sha256
            ),
            "operator_policy_sha256": self.digest("operator-policy"),
            "claim_strength": attestor.CLAIM_STRENGTH,
            "public_reputation_eligible": False,
            "verified_at_unix": verified_at,
            "observed_evidence_uid": 501,
            "capture_creator_uid": 503,
            "capture_export_gid": 505,
            "capture_adopted_uid": 0,
            "capture_adoption_policy_sha256": self.digest(
                f"adoption-policy-{variant}"
            ),
            "capture_object_identity_sha256": self.digest(
                f"object-{variant}"
            ),
            "capture_content_inventory_sha256": self.digest(
                f"inventory-{variant}"
            ),
            "capture_request_sha256": self.digest(
                f"capture-request-{variant}"
            ),
            "capture_boundary_policy_sha256": self.digest(
                "boundary-policy"
            ),
            "capture_helper_activation_policy_sha256": self.digest(
                "helper-policy"
            ),
            "capture_adoption_provenance": provenance,
            "capture_adoption_provenance_sha256": provenance_sha256,
        }
        receipt = {
            "schema_version": (
                source_revalidation
                .SOURCE_REVALIDATION_RECEIPT_V2_SCHEMA
            ),
            "status": source_revalidation.SOURCE_REVALIDATION_STATUS,
            "capture_adoption_provenance": provenance,
            "capture_adoption_provenance_sha256": provenance_sha256,
            "capture_object_identity_sha256": evidence[
                "capture_object_identity_sha256"
            ],
            "capture_plan_sha256": evidence[
                "capture_plan_sha256"
            ],
            "capture_manifest_sha256": evidence[
                "capture_manifest_sha256"
            ],
            "verifier_output_sha256": self.digest(
                f"verifier-output-{variant}"
            ),
            "revalidator_uid": 0,
            "revalidated_at_unix": verified_at + 1,
        }
        return {
            **evidence,
            "post_verifier_live_source_revalidation_receipt": receipt,
            "post_verifier_live_source_revalidation_receipt_sha256": (
                source_revalidation
                .source_revalidation_receipt_v2_sha256(receipt)
            ),
        }

    def payload_v6(self, kind: str) -> dict[str, object]:
        return attestor.build_attestation_payload_v6(
            self.config(),
            self.v6_evidence(kind),
            public_key_bytes=self.public_bytes,
            chain_sequence=1,
            previous_attestation_sha256=None,
        )

    def externally_signed_v6(
        self,
        kind: str,
        *,
        config: dict[str, object] | None = None,
        use_future_policy: bool = False,
    ) -> tuple[
        dict[str, object],
        dict[str, object],
        dict[str, object],
    ]:
        selected_config = self.config() if config is None else config
        evidence = self.v6_evidence(kind)
        policy = (
            self.future_operator_policy(evidence)
            if use_future_policy
            else self.operator_policy(evidence)
        )
        evidence["operator_policy_sha256"] = attestor.sha256_json(
            policy
        )
        payload = attestor.build_attestation_payload_v6(
            selected_config,
            evidence,
            public_key_bytes=self.public_bytes,
            chain_sequence=1,
            previous_attestation_sha256=None,
        )
        signature = self.private_key.sign(
            attestor.canonical_json(payload)
        )
        envelope = attestor.normalize_envelope(
            {
                "schema_version": attestor.ENVELOPE_SCHEMA_VERSION,
                "payload": payload,
                "signature": {
                    "algorithm": attestor.ALGORITHM,
                    "key_id": payload["attestor"]["key_id"],
                    "value_base64": (
                        base64.urlsafe_b64encode(signature)
                        .decode("ascii")
                        .rstrip("=")
                    ),
                },
            }
        )
        return envelope, policy, evidence

    def assert_code(
        self,
        code: str,
        callable_,
        *args,
        **kwargs,
    ) -> None:
        with self.assertRaises(
            attestor.QualificationAttestorError
        ) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_v4_verifier_evidence_preserves_exact_provenance_kind(
        self,
    ) -> None:
        for kind in adoption_result.CAPTURE_ADOPTION_KINDS:
            with self.subTest(kind=kind):
                evidence = self.v6_evidence(kind)
                raw = {
                    field: evidence[field]
                    for field in attestor.VERIFIER_EVIDENCE_V4_FIELDS
                }
                normalized = attestor.normalize_verifier_evidence_v4(
                    raw,
                    expected_evidence_uid=501,
                )
                self.assertEqual(normalized, raw)
                self.assertEqual(
                    set(normalized),
                    attestor.VERIFIER_EVIDENCE_V4_FIELDS,
                )
                self.assertEqual(
                    normalized["capture_adoption_provenance"]["kind"],
                    kind,
                )
                self.assertNotIn(
                    "capture_adoption_receipt_sha256",
                    normalized,
                )
                self.assertNotIn(
                    "capture_adopted_at_unix",
                    normalized,
                )
                if kind == adoption_result.RECOVERED_ADOPTION_KIND:
                    self.assertNotIn(
                        "adopted_at_unix",
                        json.dumps(normalized, sort_keys=True),
                    )

    def test_normal_time_and_recovered_shape_fail_closed(self) -> None:
        normal = self.v6_evidence(
            adoption_result.NORMAL_ADOPTION_KIND
        )
        raw = {
            field: normal[field]
            for field in attestor.VERIFIER_EVIDENCE_V4_FIELDS
        }
        raw["capture_adoption_provenance"]["details"][
            "adopted_at_unix"
        ] = raw["verified_at_unix"] + 1
        raw["capture_adoption_provenance_sha256"] = (
            adoption_result.capture_adoption_provenance_sha256(
                raw["capture_adoption_provenance"]
            )
        )
        self.assert_code(
            "verification_v4_capture_adoption_time_invalid",
            attestor.normalize_verifier_evidence_v4,
            raw,
            expected_evidence_uid=501,
        )

        recovered = self.v6_evidence(
            adoption_result.RECOVERED_ADOPTION_KIND
        )
        raw = {
            field: recovered[field]
            for field in attestor.VERIFIER_EVIDENCE_V4_FIELDS
        }
        raw["capture_adoption_provenance"]["details"][
            "adopted_at_unix"
        ] = 109
        self.assert_code(
            "verified_evidence_v4_adoption_provenance_invalid",
            attestor.normalize_verifier_evidence_v4,
            raw,
            expected_evidence_uid=501,
        )

    def test_provenance_digest_and_source_receipt_are_exact(
        self,
    ) -> None:
        for kind in adoption_result.CAPTURE_ADOPTION_KINDS:
            with self.subTest(kind=kind):
                evidence = self.v6_evidence(kind)
                normalized = attestor.normalize_verified_evidence_v6(
                    evidence,
                    expected_evidence_uid=501,
                )
                self.assertEqual(normalized, evidence)
                self.assertEqual(
                    set(normalized),
                    attestor.VERIFIED_EVIDENCE_V6_FIELDS,
                )
                changed = copy.deepcopy(evidence)
                changed[
                    "capture_adoption_provenance_sha256"
                ] = self.digest("wrong-provenance")
                self.assert_code(
                    (
                        "verified_evidence_v4_"
                        "adoption_provenance_digest_mismatch"
                    ),
                    attestor.normalize_verified_evidence_v6,
                    changed,
                    expected_evidence_uid=501,
                )

    def test_cross_kind_and_same_kind_source_substitution_fail(
        self,
    ) -> None:
        normal = self.v6_evidence(
            adoption_result.NORMAL_ADOPTION_KIND
        )
        recovered = self.v6_evidence(
            adoption_result.RECOVERED_ADOPTION_KIND
        )
        for replacement in (
            recovered["capture_adoption_provenance"],
            self.provenance(
                adoption_result.NORMAL_ADOPTION_KIND,
                variant="substitute",
                verified_at=110,
            ),
        ):
            with self.subTest(kind=replacement["kind"]):
                changed = copy.deepcopy(normal)
                receipt = changed[
                    "post_verifier_live_source_revalidation_receipt"
                ]
                receipt["capture_adoption_provenance"] = copy.deepcopy(
                    replacement
                )
                receipt[
                    "capture_adoption_provenance_sha256"
                ] = (
                    adoption_result
                    .capture_adoption_provenance_sha256(replacement)
                )
                changed[
                    "post_verifier_live_source_"
                    "revalidation_receipt_sha256"
                ] = (
                    source_revalidation
                    .source_revalidation_receipt_v2_sha256(receipt)
                )
                self.assert_code(
                    (
                        "source_revalidation_receipt_v2_"
                        "capture_adoption_provenance_mismatch"
                    ),
                    attestor.normalize_verified_evidence_v6,
                    changed,
                    expected_evidence_uid=501,
                )

    def test_v6_payload_normalization_and_extraction_are_exact(
        self,
    ) -> None:
        for kind in adoption_result.CAPTURE_ADOPTION_KINDS:
            with self.subTest(kind=kind):
                evidence = self.v6_evidence(kind)
                payload = attestor.build_attestation_payload_v6(
                    self.config(),
                    evidence,
                    public_key_bytes=self.public_bytes,
                    chain_sequence=1,
                    previous_attestation_sha256=None,
                )
                self.assertEqual(
                    payload["schema_version"],
                    attestor.FUTURE_PAYLOAD_SCHEMA_VERSION,
                )
                self.assertEqual(
                    attestor.normalize_payload(payload),
                    payload,
                )
                self.assertEqual(
                    attestor._verified_evidence_from_payload(
                        payload,
                        expected_evidence_uid=501,
                    ),
                    attestor.normalize_verified_evidence_v6(
                        evidence,
                        expected_evidence_uid=501,
                    ),
                )
                verification = payload["verification"]
                self.assertEqual(
                    set(verification),
                    attestor.PAYLOAD_VERIFICATION_FIELDS_V6,
                )
                self.assertNotIn(
                    "capture_adoption_receipt_sha256",
                    verification,
                )
                self.assertNotIn(
                    "capture_adopted_at_unix",
                    verification,
                )
                self.assertEqual(
                    attestor.effective_verified_at_unix(payload),
                    111,
                )
                if kind == adoption_result.RECOVERED_ADOPTION_KIND:
                    self.assertNotIn(
                        "adopted_at_unix",
                        json.dumps(payload, sort_keys=True),
                    )

    def test_v6_is_offline_only_and_current_builder_stays_v5(
        self,
    ) -> None:
        current = attestor.build_attestation_payload(
            self.config(),
            self.v5_evidence(),
            public_key_bytes=self.public_bytes,
            chain_sequence=1,
            previous_attestation_sha256=None,
        )
        future = self.payload_v6(
            adoption_result.NORMAL_ADOPTION_KIND
        )
        self.assertEqual(
            attestor.PAYLOAD_SCHEMA_VERSION,
            5,
        )
        self.assertEqual(current["schema_version"], 5)
        self.assertEqual(future["schema_version"], 6)
        self.assertFalse(attestor.V6_PRODUCTION_ACTIVATION)
        self.assertEqual(
            attestor.SUPPORTED_PAYLOAD_SCHEMA_VERSIONS,
            frozenset({4, 5, 6}),
        )
        self.assertEqual(
            attestor.VERIFIER_OUTPUT_SCHEMA,
            "john-lomein.persona.operator-verification.v3",
        )
        self.assertEqual(
            attestor.VERIFIER_OUTPUT_V4_SCHEMA,
            "john-lomein.persona.operator-verification.v4",
        )
        self.assert_code(
            "payload_schema_not_signable",
            attestor.normalize_payload,
            future,
            require_current=True,
        )
        self.assert_code(
            "payload_schema_not_signable",
            attestor.sign_attestation_payload,
            future,
            private_key_bytes=self.private_bytes,
            public_key_bytes=self.public_bytes,
        )

    def test_future_execution_policy_is_exact_and_dormant(
        self,
    ) -> None:
        future = attestor.VERIFICATION_EXECUTION_POLICY_V6
        self.assertEqual(
            attestor.FUTURE_OPERATOR_POLICY_SCHEMA,
            "john-lomein.persona-qualification-operator-policy.v4",
        )
        self.assertEqual(
            attestor.VERIFICATION_EXECUTION_POLICY_V6_SCHEMA,
            (
                "john-lomein.persona-qualification-"
                "verification-execution-policy.v6"
            ),
        )
        self.assertEqual(
            future["schema_version"],
            attestor.VERIFICATION_EXECUTION_POLICY_V6_SCHEMA,
        )
        self.assertEqual(
            future["verifier_request_schema"],
            attestor.VERIFIER_REQUEST_V5_SCHEMA,
        )
        self.assertEqual(
            future["verifier_output_schema"],
            attestor.VERIFIER_OUTPUT_V4_SCHEMA,
        )
        self.assertEqual(
            future[
                "post_verifier_live_source_"
                "revalidation_receipt_schema"
            ],
            source_revalidation.SOURCE_REVALIDATION_RECEIPT_V2_SCHEMA,
        )
        self.assertEqual(
            future["capture_adoption_result_schema"],
            adoption_result.CAPTURE_ADOPTION_RESULT_SCHEMA,
        )
        self.assertEqual(
            future["capture_adoption_provenance_schema"],
            adoption_result.CAPTURE_ADOPTION_PROVENANCE_SCHEMA,
        )
        self.assertEqual(
            future["capture_adoption_permitted_kinds"],
            [
                adoption_result.NORMAL_ADOPTION_KIND,
                adoption_result.RECOVERED_ADOPTION_KIND,
            ],
        )
        self.assertIs(
            future["recovered_outer_ack_clearance_required"],
            True,
        )
        self.assertIs(
            future[
                "pre_post_descriptor_binding_equality_required"
            ],
            True,
        )
        self.assertIs(future["child_stdout_journal_safe"], True)
        self.assertEqual(future["child_stdout_max_bytes"], 48 * 1024)
        self.assertTrue(
            future["activation_state"].startswith("disabled-")
        )
        self.assertEqual(
            attestor.sha256_json(future),
            (
                "e800b3bb741b7f2d5df4a623462dc1ad"
                "9d6f9e8d331a985d327ab532eedee32c"
            ),
        )
        self.assertEqual(attestor.OPERATOR_POLICY_SCHEMA[-2:], "v3")
        self.assertEqual(
            attestor.VERIFICATION_EXECUTION_POLICY_SCHEMA[-2:],
            "v5",
        )
        self.assertEqual(
            attestor.VERIFICATION_EXECUTION_POLICY[
                "child_stdout_max_bytes"
            ],
            1_000_000,
        )

    def test_operator_policy_v4_dispatch_is_strict(self) -> None:
        evidence = self.v6_evidence(
            adoption_result.NORMAL_ADOPTION_KIND
        )
        legacy = self.operator_policy(evidence)
        future = self.future_operator_policy(evidence)
        self.assertEqual(
            trust.normalize_operator_policy(legacy),
            legacy,
        )
        self.assertEqual(
            trust.normalize_operator_policy(future),
            future,
        )
        self.assertEqual(
            set(future),
            trust.OPERATOR_POLICY_V4_FIELDS,
        )
        self.assertNotIn(
            "capture_adoption_binding_schema",
            future,
        )

        hybrid = copy.deepcopy(future)
        hybrid["capture_adoption_binding_schema"] = (
            adoption_binding.ADOPTION_BINDING_SCHEMA
        )
        hybrid.pop("capture_adoption_result_schema")
        with self.assertRaises(
            trust.TrustProjectionError
        ) as caught:
            trust.normalize_operator_policy(hybrid)
        self.assertEqual(
            caught.exception.code,
            "operator_policy_fields_invalid",
        )

        wrong_kinds = copy.deepcopy(future)
        wrong_kinds["capture_adoption_permitted_kinds"] = list(
            reversed(
                wrong_kinds["capture_adoption_permitted_kinds"]
            )
        )
        with self.assertRaises(
            trust.TrustProjectionError
        ) as caught:
            trust.normalize_operator_policy(wrong_kinds)
        self.assertEqual(
            caught.exception.code,
            "operator_policy_v4_capture_adoption_invalid",
        )

        wrong_execution = copy.deepcopy(future)
        wrong_execution[
            "verification_execution_policy_sha256"
        ] = self.digest("wrong-execution-policy")
        with self.assertRaises(
            trust.TrustProjectionError
        ) as caught:
            trust.normalize_operator_policy(wrong_execution)
        self.assertEqual(
            caught.exception.code,
            "operator_policy_v4_execution_policy_invalid",
        )

    def test_operator_policy_schema_semantics_precede_digest(
        self,
    ) -> None:
        for kind in adoption_result.CAPTURE_ADOPTION_KINDS:
            with self.subTest(compatible_kind=kind):
                evidence = self.v6_evidence(kind)
                policy = self.future_operator_policy(evidence)
                evidence["operator_policy_sha256"] = (
                    attestor.sha256_json(policy)
                )
                payload = attestor.build_attestation_payload_v6(
                    self.config(),
                    evidence,
                    public_key_bytes=self.public_bytes,
                    chain_sequence=1,
                    previous_attestation_sha256=None,
                )
                trust._assert_policy_binding(
                    trust.normalize_operator_policy(policy),
                    {"payload": payload},
                )

            with self.subTest(legacy_policy_kind=kind):
                evidence = self.v6_evidence(kind)
                legacy = self.operator_policy(evidence)
                evidence["operator_policy_sha256"] = (
                    attestor.sha256_json(legacy)
                )
                payload = attestor.build_attestation_payload_v6(
                    self.config(),
                    evidence,
                    public_key_bytes=self.public_bytes,
                    chain_sequence=1,
                    previous_attestation_sha256=None,
                )
                with self.assertRaises(
                    trust.TrustProjectionError
                ) as caught:
                    trust._assert_policy_binding(
                        trust.normalize_operator_policy(legacy),
                        {"payload": payload},
                    )
                self.assertEqual(
                    caught.exception.code,
                    "operator_policy_payload_schema_incompatible",
                )

        current_evidence = self.v5_evidence()
        current_policy = self.operator_policy(current_evidence)
        current_evidence["operator_policy_sha256"] = (
            attestor.sha256_json(current_policy)
        )
        current_payload = attestor.build_attestation_payload(
            self.config(),
            current_evidence,
            public_key_bytes=self.public_bytes,
            chain_sequence=1,
            previous_attestation_sha256=None,
        )
        trust._assert_policy_binding(
            trust.normalize_operator_policy(current_policy),
            {"payload": current_payload},
        )

        relabelled_evidence = self.v5_evidence()
        relabelled_evidence["verifier_version"] = (
            attestor.VERIFIER_V5_VERSION
        )
        future_policy = self.future_operator_policy(
            relabelled_evidence
        )
        relabelled_evidence["operator_policy_sha256"] = (
            attestor.sha256_json(future_policy)
        )
        current_payload = attestor.build_attestation_payload(
            self.config(),
            relabelled_evidence,
            public_key_bytes=self.public_bytes,
            chain_sequence=1,
            previous_attestation_sha256=None,
        )
        with self.assertRaises(
            trust.TrustProjectionError
        ) as caught:
            trust._assert_policy_binding(
                trust.normalize_operator_policy(future_policy),
                {"payload": current_payload},
            )
        self.assertEqual(
            caught.exception.code,
            "operator_policy_payload_schema_incompatible",
        )

    def test_future_policy_route_works_only_under_test_activation(
        self,
    ) -> None:
        for kind in adoption_result.CAPTURE_ADOPTION_KINDS:
            with self.subTest(kind=kind):
                config = self.config()
                envelope, policy, _ = self.externally_signed_v6(
                    kind,
                    config=config,
                    use_future_policy=True,
                )
                head = attestor._verified_head_for_envelope(
                    attestor.normalize_config(config),
                    envelope,
                    updated_at_unix=112,
                )
                with mock.patch.object(
                    attestor,
                    "V6_PRODUCTION_ACTIVATION",
                    True,
                ):
                    projection = trust.build_projection(
                        config,
                        policy,
                        head,
                        envelope,
                        public_key_bytes=self.public_bytes,
                        generated_at_unix=112,
                    )
                    verified = trust.verify_projection(
                        projection,
                        expected_instance_slug=config[
                            "instance_slug"
                        ],
                        expected_key_id=config["attestor_key_id"],
                        expected_public_key_sha256=config[
                            "public_key_sha256"
                        ],
                        now_unix=113,
                    )
                self.assertEqual(verified, projection)
                self.assertEqual(
                    projection["operator_policy"]["schema_version"],
                    attestor.FUTURE_OPERATOR_POLICY_SCHEMA,
                )
                self.assertEqual(
                    projection["attestation"]["payload"][
                        "verification"
                    ]["capture_adoption_provenance"]["kind"],
                    kind,
                )

    def test_externally_signed_v6_cannot_bind_or_mutate_a_head(
        self,
    ) -> None:
        config = self.config()
        envelope, _, _ = self.externally_signed_v6(
            adoption_result.RECOVERED_ADOPTION_KIND,
            config=config,
        )
        self.assertEqual(
            attestor.normalize_envelope(envelope),
            envelope,
        )
        self.assertEqual(
            attestor.verify_attestation_envelope(
                envelope,
                public_key_bytes=self.public_bytes,
                expected_key_id=config["attestor_key_id"],
                expected_public_key_sha256=config[
                    "public_key_sha256"
                ],
                expected_instance_slug=config["instance_slug"],
                now_unix=112,
            ),
            envelope,
        )

        normalized_config = attestor.normalize_config(config)
        path = attestor._expected_attestation_path(
            normalized_config,
            envelope,
        )
        initial = attestor.initial_head(
            config["instance_slug"],
            updated_at_unix=0,
        )
        self.assert_code(
            "payload_schema_not_activated",
            attestor.plan_verified_head_transition,
            config,
            initial,
            envelope,
            public_key_bytes=self.public_bytes,
            attestation_path=path,
            updated_at_unix=112,
        )
        self.assert_code(
            "payload_schema_not_activated",
            attestor.publish_attestation,
            config,
            envelope,
            public_key_bytes=self.public_bytes,
            updated_at_unix=112,
            publication_owner_uid=os.geteuid(),
        )

        dormant_head = attestor._verified_head_for_envelope(
            normalized_config,
            envelope,
            updated_at_unix=112,
        )
        self.assert_code(
            "payload_schema_not_activated",
            attestor.verify_published_attestation_head,
            config,
            dormant_head,
            envelope,
            public_key_bytes=self.public_bytes,
            now_unix=112,
        )

    def test_externally_signed_v6_cannot_enter_archive_reconciliation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as raw_root:
            root = Path(raw_root).resolve()
            root.chmod(0o700)
            state = root / "state"
            state.mkdir(mode=0o700)
            archive = state / "attestations"
            archive.mkdir(mode=0o700)
            config = self.config(root)
            envelope, _, _ = self.externally_signed_v6(
                adoption_result.RECOVERED_ADOPTION_KIND,
                config=config,
            )
            archive_path = Path(
                attestor._expected_attestation_path(
                    attestor.normalize_config(config),
                    envelope,
                )
            )
            archive_path.write_bytes(
                attestor.canonical_json(envelope) + b"\n"
            )
            archive_path.chmod(0o600)

            self.assert_code(
                "payload_schema_not_activated",
                attestor.read_attestation_chain_tip,
                config,
                public_key_bytes=self.public_bytes,
                publication_owner_uid=os.geteuid(),
            )
            self.assert_code(
                "payload_schema_not_activated",
                attestor.sign_and_publish_attestation,
                config,
                self.v5_evidence(),
                public_key_bytes=self.public_bytes,
                private_key_loader=lambda: (_ for _ in ()).throw(
                    AssertionError(
                        "dormant archive reached private key loader"
                    )
                ),
                updated_at_unix=112,
                publication_owner_uid=os.geteuid(),
            )
            self.assertFalse(Path(config["head_path"]).exists())
            self.assertEqual(
                archive_path.read_bytes(),
                attestor.canonical_json(envelope) + b"\n",
            )

    def test_externally_signed_v6_cannot_enter_public_trust_route(
        self,
    ) -> None:
        config = self.config()
        envelope, policy, _ = self.externally_signed_v6(
            adoption_result.RECOVERED_ADOPTION_KIND,
            config=config,
        )
        payload = envelope["payload"]
        qualification = payload["qualification"]
        dormant_head = attestor._verified_head_for_envelope(
            attestor.normalize_config(config),
            envelope,
            updated_at_unix=112,
        )
        self.assert_code(
            "payload_schema_not_activated",
            trust.build_projection,
            config,
            policy,
            dormant_head,
            envelope,
            public_key_bytes=self.public_bytes,
            generated_at_unix=112,
        )

        raw_projection = {
            "schema_version": trust.PROJECTION_SCHEMA,
            "generated_at_unix": 112,
            "claim_strength": attestor.CLAIM_STRENGTH,
            "public_reputation_eligible": False,
            "claim_limits": dict(trust.CLAIM_LIMITS),
            "public_key_pem": self.public_bytes.decode("ascii"),
            "operator_policy": policy,
            "head": {
                "schema_version": trust.PUBLIC_HEAD_SCHEMA,
                "state": "verified",
                "instance_slug": payload["instance"]["slug"],
                "chain_sequence": payload["chain"]["sequence"],
                "previous_attestation_sha256": payload["chain"][
                    "previous_attestation_sha256"
                ],
                "run_id": qualification["run_id"],
                "summary_sha256": qualification["summary_sha256"],
                "binding_sha256": qualification["binding_sha256"],
                "qualified_at_unix": qualification[
                    "qualified_at_unix"
                ],
                "verified_at_unix": (
                    attestor.effective_verified_at_unix(payload)
                ),
                "expires_at_unix": qualification["expires_at_unix"],
                "attestation_sha256": attestor.sha256_json(envelope),
            },
            "attestation": envelope,
        }
        self.assertEqual(
            trust.normalize_projection(raw_projection),
            raw_projection,
        )
        with self.assertRaises(
            trust.TrustProjectionError
        ) as caught:
            trust.verify_projection(
                raw_projection,
                expected_instance_slug=config["instance_slug"],
                expected_key_id=config["attestor_key_id"],
                expected_public_key_sha256=config[
                    "public_key_sha256"
                ],
                now_unix=113,
            )
        self.assertEqual(
            caught.exception.code,
            "payload_schema_not_activated",
        )

    def test_v4_and_v5_canonical_vectors_remain_pinned(self) -> None:
        current = attestor.build_attestation_payload(
            self.config(),
            self.v5_evidence(),
            public_key_bytes=self.public_bytes,
            chain_sequence=1,
            previous_attestation_sha256=None,
        )
        historical = copy.deepcopy(current)
        historical["schema_version"] = 4
        historical["verification"].pop(
            "post_verifier_live_source_revalidation_receipt"
        )
        historical["verification"].pop(
            "post_verifier_live_source_revalidation_receipt_sha256"
        )
        self.assertEqual(attestor.normalize_payload(current), current)
        self.assertEqual(
            attestor.normalize_payload(historical),
            historical,
        )
        self.assertEqual(
            attestor.sha256_json(current),
            (
                "9746e4e40453419923c08e0ad9613a4d"
                "68a789bfdc362488092e8d2938f6bf15"
            ),
        )
        self.assertEqual(
            attestor.sha256_json(historical),
            (
                "d3f970d1f63aaa47c086c3d0184c1aba"
                "1f1e74acf1ee867dc1ca874f2c2c7c47"
            ),
        )

    def test_v6_payload_cannot_be_relabelled_as_v5_or_vice_versa(
        self,
    ) -> None:
        future = self.payload_v6(
            adoption_result.NORMAL_ADOPTION_KIND
        )
        relabelled = copy.deepcopy(future)
        relabelled["schema_version"] = 5
        self.assert_code(
            "payload_verification_fields_invalid",
            attestor.normalize_payload,
            relabelled,
        )
        current = attestor.build_attestation_payload(
            self.config(),
            self.v5_evidence(),
            public_key_bytes=self.public_bytes,
            chain_sequence=1,
            previous_attestation_sha256=None,
        )
        relabelled = copy.deepcopy(current)
        relabelled["schema_version"] = 6
        self.assert_code(
            "payload_v6_verification_fields_invalid",
            attestor.normalize_payload,
            relabelled,
        )

    def test_recapture_equivalence_never_crosses_provenance_kind(
        self,
    ) -> None:
        normal_one = self.v6_evidence(
            adoption_result.NORMAL_ADOPTION_KIND,
            variant="one",
            verified_at=110,
        )
        normal_two = self.v6_evidence(
            adoption_result.NORMAL_ADOPTION_KIND,
            variant="two",
            verified_at=120,
        )
        recovered = self.v6_evidence(
            adoption_result.RECOVERED_ADOPTION_KIND,
            variant="two",
            verified_at=120,
        )
        self.assertTrue(
            attestor.equivalent_verified_evidence_recapture_v6(
                normal_one,
                normal_two,
                expected_evidence_uid=501,
            )
        )
        self.assertFalse(
            attestor.equivalent_verified_evidence_recapture_v6(
                normal_one,
                recovered,
                expected_evidence_uid=501,
            )
        )
        changed_plan = self.v6_evidence(
            adoption_result.NORMAL_ADOPTION_KIND,
            variant="two",
            verified_at=120,
            plan_sha256=self.digest("different-plan"),
        )
        self.assertFalse(
            attestor.equivalent_verified_evidence_recapture_v6(
                normal_one,
                changed_plan,
                expected_evidence_uid=501,
            )
        )


if __name__ == "__main__":
    unittest.main()
