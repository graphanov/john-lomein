from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_source_revalidation_binding as binding,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_binding
    as adoption_binding,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_result
    as adoption_result,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_recovered_adoption_evidence
    as recovered_adoption,
)


class PersonaQualificationSourceRevalidationBindingTests(
    unittest.TestCase
):
    def digest(self, label: str) -> str:
        return hashlib.sha256(label.encode("ascii")).hexdigest()

    def receipt(self) -> dict[str, object]:
        return {
            "schema_version": binding.SOURCE_REVALIDATION_RECEIPT_SCHEMA,
            "status": binding.SOURCE_REVALIDATION_STATUS,
            "capture_adoption_receipt_sha256": "1" * 64,
            "capture_object_identity_sha256": "2" * 64,
            "capture_plan_sha256": "3" * 64,
            "capture_manifest_sha256": "4" * 64,
            "verifier_output_sha256": "5" * 64,
            "revalidator_uid": 0,
            "revalidated_at_unix": 120,
        }

    def adoption_provenance(self, kind: str) -> dict[str, object]:
        if kind == adoption_result.NORMAL_ADOPTION_KIND:
            evidence_schema = adoption_binding.ADOPTION_RECEIPT_SCHEMA
            details = {"adopted_at_unix": 100}
        elif kind == adoption_result.RECOVERED_ADOPTION_KIND:
            evidence_schema = (
                recovered_adoption.RECOVERED_ADOPTION_EVIDENCE_SCHEMA
            )
            details = {
                "transaction_journal_schema": (
                    recovered_adoption.TRANSACTION_JOURNAL_SCHEMA
                ),
                "adoption_reconciliation_record_sha256": (
                    self.digest("reconciliation-record")
                ),
                "adoption_reconciliation_receipt_sha256": (
                    self.digest("reconciliation-receipt")
                ),
            }
        else:
            raise AssertionError(f"unsupported adoption kind {kind!r}")
        return {
            "schema_version": (
                adoption_result.CAPTURE_ADOPTION_PROVENANCE_SCHEMA
            ),
            "kind": kind,
            "evidence_schema": evidence_schema,
            "evidence_sha256": self.digest(f"{kind}-evidence"),
            "details": details,
        }

    def receipt_v2(self, kind: str) -> dict[str, object]:
        provenance = self.adoption_provenance(kind)
        return {
            "schema_version": (
                binding.SOURCE_REVALIDATION_RECEIPT_V2_SCHEMA
            ),
            "status": binding.SOURCE_REVALIDATION_STATUS,
            "capture_adoption_provenance": provenance,
            "capture_adoption_provenance_sha256": (
                adoption_result.capture_adoption_provenance_sha256(
                    provenance
                )
            ),
            "capture_object_identity_sha256": self.digest(
                f"{kind}-object"
            ),
            "capture_plan_sha256": self.digest(f"{kind}-plan"),
            "capture_manifest_sha256": self.digest(
                f"{kind}-manifest"
            ),
            "verifier_output_sha256": self.digest(
                f"{kind}-verifier-output"
            ),
            "revalidator_uid": 0,
            "revalidated_at_unix": 120,
        }

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(
            binding.SourceRevalidationBindingError
        ) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def bind(self, receipt=None, **overrides):
        value = self.receipt() if receipt is None else receipt
        arguments = {
            "expected_receipt_sha256": (
                binding.source_revalidation_receipt_sha256(value)
            ),
            "expected_capture_adoption_receipt_sha256": "1" * 64,
            "expected_capture_object_identity_sha256": "2" * 64,
            "expected_capture_plan_sha256": "3" * 64,
            "expected_capture_manifest_sha256": "4" * 64,
            "expected_verifier_output_sha256": "5" * 64,
            "verified_at_unix": 110,
            "expires_at_unix": 1000,
        }
        arguments.update(overrides)
        return binding.bind_source_revalidation_receipt(
            value,
            **arguments,
        )

    def bind_v2(
        self,
        receipt=None,
        *,
        expected_receipt=None,
        **overrides,
    ):
        value = (
            self.receipt_v2(adoption_result.NORMAL_ADOPTION_KIND)
            if receipt is None
            else receipt
        )
        expected = value if expected_receipt is None else expected_receipt
        expected_provenance = expected[
            "capture_adoption_provenance"
        ]
        arguments = {
            "expected_receipt_sha256": (
                binding.source_revalidation_receipt_v2_sha256(value)
            ),
            "expected_capture_adoption_provenance": (
                expected_provenance
            ),
            "expected_capture_adoption_provenance_sha256": (
                adoption_result.capture_adoption_provenance_sha256(
                    expected_provenance
                )
            ),
            "expected_capture_object_identity_sha256": expected[
                "capture_object_identity_sha256"
            ],
            "expected_capture_plan_sha256": expected[
                "capture_plan_sha256"
            ],
            "expected_capture_manifest_sha256": expected[
                "capture_manifest_sha256"
            ],
            "expected_verifier_output_sha256": expected[
                "verifier_output_sha256"
            ],
            "verified_at_unix": 110,
            "expires_at_unix": 1000,
        }
        arguments.update(overrides)
        return binding.bind_source_revalidation_receipt_v2(
            value,
            **arguments,
        )

    def test_receipt_is_exact_canonical_and_path_free(self) -> None:
        receipt = self.receipt()
        normalized = binding.normalize_source_revalidation_receipt(
            receipt
        )
        self.assertEqual(normalized, receipt)
        self.assertEqual(
            set(normalized),
            binding.SOURCE_REVALIDATION_RECEIPT_FIELDS,
        )
        encoded = binding.canonical_json(normalized)
        self.assertEqual(
            encoded,
            json.dumps(
                normalized,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii"),
        )
        self.assertEqual(
            binding.source_revalidation_receipt_sha256(receipt),
            hashlib.sha256(encoded).hexdigest(),
        )
        serialized = encoded.decode("ascii")
        self.assertNotIn("/", serialized)
        self.assertNotIn("source_path", serialized)

    def test_receipt_rejects_shape_schema_status_uid_and_scalars(self) -> None:
        receipt = self.receipt()
        self.assert_code(
            "source_revalidation_receipt_not_object",
            binding.normalize_source_revalidation_receipt,
            [],
        )
        for candidate in (
            {key: value for key, value in receipt.items() if key != "status"},
            {**receipt, "extra": "x"},
        ):
            self.assert_code(
                "source_revalidation_receipt_fields_invalid",
                binding.normalize_source_revalidation_receipt,
                candidate,
            )
        for field, value, code in (
            (
                "schema_version",
                "john-lomein.invalid.v1",
                "source_revalidation_receipt_schema_unsupported",
            ),
            (
                "status",
                "failed",
                "source_revalidation_receipt_status_invalid",
            ),
            (
                "revalidator_uid",
                1,
                "source_revalidation_receipt_revalidator_uid_invalid",
            ),
            (
                "revalidator_uid",
                False,
                "source_revalidation_receipt_revalidator_uid_invalid",
            ),
            (
                "revalidated_at_unix",
                0,
                "source_revalidation_receipt_revalidated_at_unix_invalid",
            ),
            (
                "capture_manifest_sha256",
                "A" * 64,
                (
                    "source_revalidation_receipt_"
                    "capture_manifest_sha256_invalid"
                ),
            ),
        ):
            with self.subTest(field=field, value=value):
                self.assert_code(
                    code,
                    binding.normalize_source_revalidation_receipt,
                    {**receipt, field: value},
                )

    def test_binding_requires_exact_digest_and_capture_anchors(self) -> None:
        receipt = self.receipt()
        evidence = self.bind(receipt)
        self.assertEqual(
            set(evidence),
            binding.SOURCE_REVALIDATION_EVIDENCE_FIELDS,
        )
        self.assertEqual(
            evidence[
                "post_verifier_live_source_revalidation_receipt"
            ],
            receipt,
        )
        self.assertEqual(
            evidence[
                "post_verifier_live_source_revalidation_receipt_sha256"
            ],
            binding.source_revalidation_receipt_sha256(receipt),
        )
        self.assert_code(
            "source_revalidation_receipt_digest_mismatch",
            self.bind,
            receipt,
            expected_receipt_sha256="f" * 64,
        )
        for argument, code in (
            (
                "expected_capture_adoption_receipt_sha256",
                (
                    "source_revalidation_receipt_"
                    "capture_adoption_receipt_sha256_mismatch"
                ),
            ),
            (
                "expected_capture_object_identity_sha256",
                (
                    "source_revalidation_receipt_"
                    "capture_object_identity_sha256_mismatch"
                ),
            ),
            (
                "expected_capture_plan_sha256",
                (
                    "source_revalidation_receipt_"
                    "capture_plan_sha256_mismatch"
                ),
            ),
            (
                "expected_capture_manifest_sha256",
                (
                    "source_revalidation_receipt_"
                    "capture_manifest_sha256_mismatch"
                ),
            ),
            (
                "expected_verifier_output_sha256",
                (
                    "source_revalidation_receipt_"
                    "verifier_output_sha256_mismatch"
                ),
            ),
        ):
            with self.subTest(argument=argument):
                self.assert_code(
                    code,
                    self.bind,
                    receipt,
                    **{argument: "f" * 64},
                )

    def test_binding_time_is_completion_after_verifier_and_before_expiry(
        self,
    ) -> None:
        self.bind()
        for field, value in (
            ("verified_at_unix", 121),
            ("expires_at_unix", 120),
        ):
            with self.subTest(field=field):
                self.assert_code(
                    "source_revalidation_receipt_time_invalid",
                    self.bind,
                    self.receipt(),
                    **{field: value},
                )
        boundary = copy.deepcopy(self.receipt())
        boundary["revalidated_at_unix"] = 110
        self.bind(boundary)

    def test_v1_digest_vector_remains_unchanged(self) -> None:
        self.assertEqual(
            binding.source_revalidation_receipt_sha256(
                self.receipt()
            ),
            (
                "86666425b75967d1f18eef1da5b2052396d5e35c543cb2594"
                "b184d2415c22504"
            ),
        )

    def test_v2_normal_and_recovered_receipts_are_exact(
        self,
    ) -> None:
        for kind in adoption_result.CAPTURE_ADOPTION_KINDS:
            with self.subTest(kind=kind):
                receipt = self.receipt_v2(kind)
                normalized = (
                    binding.normalize_source_revalidation_receipt_v2(
                        receipt
                    )
                )
                self.assertEqual(normalized, receipt)
                self.assertEqual(
                    set(normalized),
                    binding.SOURCE_REVALIDATION_RECEIPT_V2_FIELDS,
                )
                self.assertNotIn(
                    "capture_adoption_receipt_sha256",
                    normalized,
                )
                self.assertEqual(
                    normalized["capture_adoption_provenance"][
                        "kind"
                    ],
                    kind,
                )
                encoded = binding.canonical_json(normalized)
                self.assertEqual(
                    (
                        binding
                        .source_revalidation_receipt_v2_sha256(
                            receipt
                        )
                    ),
                    hashlib.sha256(encoded).hexdigest(),
                )
                evidence = self.bind_v2(receipt)
                self.assertEqual(
                    set(evidence),
                    binding.SOURCE_REVALIDATION_EVIDENCE_FIELDS,
                )
                self.assertEqual(
                    evidence[
                        (
                            "post_verifier_live_source_"
                            "revalidation_receipt"
                        )
                    ],
                    receipt,
                )
                self.assertEqual(
                    evidence[
                        (
                            "post_verifier_live_source_"
                            "revalidation_receipt_sha256"
                        )
                    ],
                    (
                        binding
                        .source_revalidation_receipt_v2_sha256(
                            receipt
                        )
                    ),
                )

    def test_v1_and_v2_shapes_are_strictly_side_by_side(self) -> None:
        normal = self.receipt_v2(
            adoption_result.NORMAL_ADOPTION_KIND
        )
        self.assert_code(
            "source_revalidation_receipt_fields_invalid",
            binding.normalize_source_revalidation_receipt,
            normal,
        )
        self.assert_code(
            "source_revalidation_receipt_v2_fields_invalid",
            binding.normalize_source_revalidation_receipt_v2,
            self.receipt(),
        )
        for candidate in (
            {
                key: value
                for key, value in normal.items()
                if key != "capture_adoption_provenance"
            },
            {**normal, "capture_adoption_receipt_sha256": "1" * 64},
        ):
            self.assert_code(
                "source_revalidation_receipt_v2_fields_invalid",
                binding.normalize_source_revalidation_receipt_v2,
                candidate,
            )

    def test_v2_rejects_cross_kind_and_relabelled_provenance(
        self,
    ) -> None:
        normal = self.receipt_v2(
            adoption_result.NORMAL_ADOPTION_KIND
        )
        recovered = self.receipt_v2(
            adoption_result.RECOVERED_ADOPTION_KIND
        )
        for receipt, expected in (
            (normal, recovered),
            (recovered, normal),
        ):
            with self.subTest(
                receipt_kind=receipt[
                    "capture_adoption_provenance"
                ]["kind"],
                expected_kind=expected[
                    "capture_adoption_provenance"
                ]["kind"],
            ):
                self.assert_code(
                    (
                        "source_revalidation_receipt_v2_"
                        "capture_adoption_provenance_mismatch"
                    ),
                    self.bind_v2,
                    receipt,
                    expected_receipt=expected,
                )

        for source, replacement_kind in (
            (normal, adoption_result.RECOVERED_ADOPTION_KIND),
            (recovered, adoption_result.NORMAL_ADOPTION_KIND),
        ):
            changed = copy.deepcopy(source)
            changed["capture_adoption_provenance"][
                "kind"
            ] = replacement_kind
            changed["capture_adoption_provenance_sha256"] = (
                self.digest("attacker-relabelled-provenance")
            )
            self.assert_code(
                (
                    "source_revalidation_receipt_v2_"
                    "capture_adoption_provenance_invalid"
                ),
                binding.normalize_source_revalidation_receipt_v2,
                changed,
            )

    def test_v2_rejects_provenance_substitution_for_both_kinds(
        self,
    ) -> None:
        for kind in adoption_result.CAPTURE_ADOPTION_KINDS:
            original = self.receipt_v2(kind)
            substitutions = []

            evidence_changed = copy.deepcopy(original)
            evidence_changed["capture_adoption_provenance"][
                "evidence_sha256"
            ] = self.digest(f"{kind}-substituted-evidence")
            substitutions.append(evidence_changed)

            detail_changed = copy.deepcopy(original)
            if kind == adoption_result.NORMAL_ADOPTION_KIND:
                detail_changed["capture_adoption_provenance"][
                    "details"
                ]["adopted_at_unix"] += 1
            else:
                detail_changed["capture_adoption_provenance"][
                    "details"
                ][
                    "adoption_reconciliation_record_sha256"
                ] = self.digest("substituted-reconciliation-record")
            substitutions.append(detail_changed)

            for changed in substitutions:
                changed["capture_adoption_provenance_sha256"] = (
                    adoption_result
                    .capture_adoption_provenance_sha256(
                        changed["capture_adoption_provenance"]
                    )
                )
                with self.subTest(
                    kind=kind,
                    changed=changed[
                        "capture_adoption_provenance"
                    ],
                ):
                    self.assert_code(
                        (
                            "source_revalidation_receipt_v2_"
                            "capture_adoption_provenance_mismatch"
                        ),
                        self.bind_v2,
                        changed,
                        expected_receipt=original,
                    )

            digest_only = copy.deepcopy(original)
            digest_only["capture_adoption_provenance_sha256"] = (
                self.digest(f"{kind}-substituted-provenance")
            )
            self.assert_code(
                (
                    "source_revalidation_receipt_v2_"
                    "capture_adoption_provenance_digest_mismatch"
                ),
                binding.normalize_source_revalidation_receipt_v2,
                digest_only,
            )
            self.assert_code(
                (
                    "source_revalidation_receipt_v2_expected_"
                    "capture_adoption_provenance_digest_mismatch"
                ),
                self.bind_v2,
                original,
                expected_capture_adoption_provenance_sha256=(
                    self.digest(f"{kind}-wrong-expected-provenance")
                ),
            )

    def test_v2_binds_capture_anchors_root_uid_and_time(
        self,
    ) -> None:
        receipt = self.receipt_v2(
            adoption_result.RECOVERED_ADOPTION_KIND
        )
        self.bind_v2(receipt)
        for field in (
            "capture_object_identity_sha256",
            "capture_plan_sha256",
            "capture_manifest_sha256",
            "verifier_output_sha256",
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(receipt)
                changed[field] = self.digest(f"substituted-{field}")
                self.assert_code(
                    f"source_revalidation_receipt_v2_{field}_mismatch",
                    self.bind_v2,
                    changed,
                    expected_receipt=receipt,
                )

        for uid in (1, False):
            changed = copy.deepcopy(receipt)
            changed["revalidator_uid"] = uid
            self.assert_code(
                (
                    "source_revalidation_receipt_v2_"
                    "revalidator_uid_invalid"
                ),
                binding.normalize_source_revalidation_receipt_v2,
                changed,
            )
        for revalidated_at in (0, (1 << 53)):
            changed = copy.deepcopy(receipt)
            changed["revalidated_at_unix"] = revalidated_at
            self.assert_code(
                (
                    "source_revalidation_receipt_v2_"
                    "revalidated_at_unix_invalid"
                ),
                binding.normalize_source_revalidation_receipt_v2,
                changed,
            )
        for overrides in (
            {"verified_at_unix": 121},
            {"expires_at_unix": 120},
        ):
            self.assert_code(
                "source_revalidation_receipt_v2_time_invalid",
                self.bind_v2,
                receipt,
                **overrides,
            )
        self.bind_v2(
            receipt,
            verified_at_unix=120,
            expires_at_unix=121,
        )


if __name__ == "__main__":
    unittest.main()
