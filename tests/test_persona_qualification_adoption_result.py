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


class PersonaQualificationAdoptionResultTests(unittest.TestCase):
    def digest(self, label: str) -> str:
        return hashlib.sha256(label.encode("ascii")).hexdigest()

    def normal_evidence(self) -> dict:
        return {
            "schema_version": adoption_binding.ADOPTION_RECEIPT_SCHEMA,
            "status": adoption_binding.ADOPTION_STATUS,
            "session_id": self.digest("normal-session"),
            "capture_adoption_policy_sha256": self.digest(
                "normal-adoption-policy"
            ),
            "capture_selection_sha256": self.digest("normal-selection"),
            "capture_plan_sha256": self.digest("normal-plan"),
            "capture_manifest_sha256": self.digest("normal-manifest"),
            "capture_boundary_policy_sha256": self.digest(
                "normal-boundary-policy"
            ),
            "helper_activation_policy_sha256": self.digest(
                "normal-helper-policy"
            ),
            "request_sha256": self.digest("normal-request"),
            "capture_uid": 501,
            "capture_gid": 502,
            "adopted_uid": 0,
            "verifier_uid": 503,
            "verifier_gid": 504,
            "final_name": "opaque-capture-" + "a" * 32,
            "object_identity_sha256": self.digest("normal-object"),
            "provisional_stat_sha256": self.digest(
                "normal-provisional-stat"
            ),
            "adopted_stat_sha256": self.digest("normal-adopted-stat"),
            "content_inventory_sha256": self.digest(
                "normal-inventory"
            ),
            "file_count": 1,
            "directory_count": 2,
            "total_bytes": 10,
            "child_pid": 12_345,
            "child_exit_status": 0,
            "child_stderr_sha256": adoption_binding.EMPTY_SHA256,
            "process_group_reaped": True,
            "staging_namespace_revoked": True,
            "same_filesystem": True,
            "rename_noreplace": True,
            "rename_primitive": "renameatx_np_excl",
            "adopted_at_unix": 100,
        }

    def recovered_evidence(self) -> dict:
        evidence = {
            "schema_version": (
                recovered_adoption.RECOVERED_ADOPTION_EVIDENCE_SCHEMA
            ),
            "status": recovered_adoption.RECOVERED_ADOPTION_STATUS,
            "transaction_journal_schema": (
                recovered_adoption.TRANSACTION_JOURNAL_SCHEMA
            ),
            "adoption_reconciliation_receipt_schema": (
                recovered_adoption
                .ADOPTION_RECONCILIATION_RECEIPT_SCHEMA
            ),
            "instance_slug": "john-test",
            "capture_uid": 501,
            "capture_export_gid": 502,
            "final_object_owner_uid": 0,
            "verifier_gid": 504,
            "final_object_group_gid": 504,
            "final_name": "opaque-capture-" + "b" * 32,
            "final_parent_filesystem_device": 42,
            "adoption_limits": {
                "max_files": 100,
                "max_directories": 100,
                "max_bytes": 10_000,
                "max_file_bytes": 1_000,
                "max_depth": 10,
            },
            "reconciliation_result": (
                recovered_adoption.RECOVERED_ADOPTION_STATUS
            ),
            "final_observation": "exact_present",
            "staging_observation": "absent",
            "staging_terminal_disposition": "absent",
            "reconciled_file_count": 1,
            "reconciled_directory_count": 2,
            "reconciled_total_bytes": 10,
            "reconciled_largest_file_bytes": 10,
            "reconciled_maximum_depth": 1,
            "final_object_mode": recovered_adoption.ADOPTED_DIRECTORY_MODE,
            "final_object_nlink": 1,
            "final_parent_fsynced": True,
            "staging_parents_fsynced": True,
            "observations_rechecked_under_lock": True,
        }
        digest_fields = (
            "capture_session_id",
            "staging_transaction_intent_record_sha256",
            "capture_ready_record_sha256",
            "lifecycle_scope_empty_record_sha256",
            "lifecycle_scope_empty_receipt_sha256",
            "adoption_intent_record_sha256",
            "adoption_reconciliation_required_record_sha256",
            "adoption_reconciliation_record_sha256",
            "adoption_reconciliation_receipt_sha256",
            "capture_adoption_policy_sha256",
            "capture_selection_sha256",
            "capture_plan_sha256",
            "capture_manifest_sha256",
            "capture_request_sha256",
            "capture_boundary_policy_sha256",
            "helper_activation_policy_sha256",
            "final_parent_identity_sha256",
            "capture_object_identity_sha256",
            "reconciled_final_object_stat_sha256",
            "reconciled_content_inventory_sha256",
            "staging_terminal_receipt_sha256",
            "staging_tombstone_sha256",
            "dual_parent_lock_epoch_sha256",
        )
        evidence.update(
            {
                field: self.digest(f"recovered-{field}")
                for field in digest_fields
            }
        )
        return evidence

    def full_result(self, kind: str) -> dict:
        if kind == adoption_result.NORMAL_ADOPTION_KIND:
            evidence = self.normal_evidence()
        else:
            evidence = self.recovered_evidence()
        return adoption_result.build_capture_adoption_result(
            kind, evidence
        )

    def assert_code(self, code: str, callable_, *args) -> None:
        with self.assertRaises(
            adoption_result.CaptureAdoptionResultError
        ) as caught:
            callable_(*args)
        self.assertEqual(caught.exception.code, code)

    def test_normal_result_and_provenance_are_exact_and_canonical(
        self,
    ) -> None:
        result = self.full_result(adoption_result.NORMAL_ADOPTION_KIND)
        normalized = adoption_result.normalize_capture_adoption_result(
            result
        )
        self.assertEqual(normalized, result)
        provenance = (
            adoption_result.project_capture_adoption_provenance(result)
        )
        self.assertEqual(
            provenance,
            {
                "schema_version": (
                    adoption_result
                    .CAPTURE_ADOPTION_PROVENANCE_SCHEMA
                ),
                "kind": adoption_result.NORMAL_ADOPTION_KIND,
                "evidence_schema": (
                    adoption_binding.ADOPTION_RECEIPT_SCHEMA
                ),
                "evidence_sha256": result["evidence_sha256"],
                "details": {"adopted_at_unix": 100},
            },
        )
        self.assertEqual(
            adoption_result.capture_adoption_result_sha256(
                dict(reversed(tuple(result.items())))
            ),
            adoption_result.capture_adoption_result_sha256(result),
        )
        self.assertEqual(
            adoption_result.capture_adoption_provenance_sha256(
                dict(reversed(tuple(provenance.items())))
            ),
            adoption_result.capture_adoption_provenance_sha256(
                provenance
            ),
        )
        self.assert_code(
            "capture_adoption_result_kind_invalid",
            adoption_result.build_capture_adoption_result,
            "adopted",
            self.normal_evidence(),
        )

    def test_recovered_result_projects_only_recovered_provenance(
        self,
    ) -> None:
        result = self.full_result(
            adoption_result.RECOVERED_ADOPTION_KIND
        )
        normalized = adoption_result.normalize_capture_adoption_result(
            result
        )
        self.assertEqual(normalized, result)
        provenance = (
            adoption_result.project_capture_adoption_provenance(result)
        )
        evidence = result["evidence"]
        self.assertEqual(
            provenance,
            {
                "schema_version": (
                    adoption_result
                    .CAPTURE_ADOPTION_PROVENANCE_SCHEMA
                ),
                "kind": adoption_result.RECOVERED_ADOPTION_KIND,
                "evidence_schema": (
                    recovered_adoption
                    .RECOVERED_ADOPTION_EVIDENCE_SCHEMA
                ),
                "evidence_sha256": result["evidence_sha256"],
                "details": {
                    "transaction_journal_schema": (
                        recovered_adoption.TRANSACTION_JOURNAL_SCHEMA
                    ),
                    "adoption_reconciliation_record_sha256": evidence[
                        "adoption_reconciliation_record_sha256"
                    ],
                    "adoption_reconciliation_receipt_sha256": evidence[
                        "adoption_reconciliation_receipt_sha256"
                    ],
                },
            },
        )
        encoded = json.dumps(provenance, sort_keys=True)
        for forbidden in (
            "adopted_at_unix",
            "child_pid",
            "rename_primitive",
            "capture_adoption_receipt_sha256",
        ):
            self.assertNotIn(forbidden, encoded)

    def test_result_outer_fields_schema_and_kind_are_strict(self) -> None:
        result = self.full_result(adoption_result.NORMAL_ADOPTION_KIND)
        for field in adoption_result.CAPTURE_ADOPTION_RESULT_FIELDS:
            with self.subTest(missing=field):
                changed = copy.deepcopy(result)
                changed.pop(field)
                self.assert_code(
                    "capture_adoption_result_fields_invalid",
                    adoption_result.normalize_capture_adoption_result,
                    changed,
                )
        extra = copy.deepcopy(result)
        extra["extra"] = False
        self.assert_code(
            "capture_adoption_result_fields_invalid",
            adoption_result.normalize_capture_adoption_result,
            extra,
        )
        for value in (None, [], "result"):
            with self.subTest(value=value):
                self.assert_code(
                    "capture_adoption_result_fields_invalid",
                    adoption_result.normalize_capture_adoption_result,
                    value,
                )
        changed = copy.deepcopy(result)
        changed["schema_version"] = "wrong"
        self.assert_code(
            "capture_adoption_result_schema_invalid",
            adoption_result.normalize_capture_adoption_result,
            changed,
        )
        for kind in (
            None,
            "adopted",
            "recovery",
            1,
            [],
            {},
        ):
            with self.subTest(kind=kind):
                changed = copy.deepcopy(result)
                changed["kind"] = kind
                self.assert_code(
                    "capture_adoption_result_kind_invalid",
                    adoption_result.normalize_capture_adoption_result,
                    changed,
                )

    def test_cross_kind_and_inner_schema_substitution_fail_closed(
        self,
    ) -> None:
        normal = self.full_result(adoption_result.NORMAL_ADOPTION_KIND)
        recovered = self.full_result(
            adoption_result.RECOVERED_ADOPTION_KIND
        )
        for claimed, evidence_source in (
            (normal, recovered),
            (recovered, normal),
        ):
            changed = copy.deepcopy(claimed)
            changed["evidence"] = copy.deepcopy(
                evidence_source["evidence"]
            )
            changed["evidence_sha256"] = evidence_source[
                "evidence_sha256"
            ]
            self.assert_code(
                "capture_adoption_result_kind_evidence_mismatch",
                adoption_result.normalize_capture_adoption_result,
                changed,
            )
        for result in (normal, recovered):
            with self.subTest(kind=result["kind"]):
                changed = copy.deepcopy(result)
                changed["evidence"]["schema_version"] = "wrong"
                self.assert_code(
                    "capture_adoption_result_kind_evidence_mismatch",
                    adoption_result.normalize_capture_adoption_result,
                    changed,
                )
                changed = copy.deepcopy(result)
                changed["evidence"]["status"] = "wrong"
                self.assert_code(
                    "capture_adoption_result_kind_evidence_mismatch",
                    adoption_result.normalize_capture_adoption_result,
                    changed,
                )

    def test_evidence_digest_and_valid_inner_object_are_both_required(
        self,
    ) -> None:
        for kind in adoption_result.CAPTURE_ADOPTION_KINDS:
            with self.subTest(kind=kind):
                result = self.full_result(kind)
                changed = copy.deepcopy(result)
                changed["evidence_sha256"] = self.digest("substitute")
                self.assert_code(
                    "capture_adoption_result_evidence_digest_mismatch",
                    adoption_result.normalize_capture_adoption_result,
                    changed,
                )
                changed = copy.deepcopy(result)
                changed["evidence_sha256"] = None
                self.assert_code(
                    "capture_adoption_result_evidence_sha256_invalid",
                    adoption_result.normalize_capture_adoption_result,
                    changed,
                )
                changed = copy.deepcopy(result)
                changed["evidence_sha256"] = adoption_result.ZERO_SHA256
                self.assert_code(
                    "capture_adoption_result_evidence_sha256_invalid",
                    adoption_result.normalize_capture_adoption_result,
                    changed,
                )
                changed = copy.deepcopy(result)
                if kind == adoption_result.NORMAL_ADOPTION_KIND:
                    changed["evidence"]["adopted_at_unix"] += 1
                else:
                    changed["evidence"][
                        "dual_parent_lock_epoch_sha256"
                    ] = self.digest("replacement-epoch")
                self.assert_code(
                    "capture_adoption_result_evidence_digest_mismatch",
                    adoption_result.normalize_capture_adoption_result,
                    changed,
                )
                changed = copy.deepcopy(result)
                changed["evidence"]["extra"] = "forbidden"
                expected = (
                    "capture_adoption_result_normal_evidence_invalid"
                    if kind == adoption_result.NORMAL_ADOPTION_KIND
                    else (
                        "capture_adoption_result_"
                        "recovered_evidence_invalid"
                    )
                )
                self.assert_code(
                    expected,
                    adoption_result.normalize_capture_adoption_result,
                    changed,
                )

    def test_provenance_fields_are_exact_for_both_variants(self) -> None:
        for kind in adoption_result.CAPTURE_ADOPTION_KINDS:
            provenance = (
                adoption_result.project_capture_adoption_provenance(
                    self.full_result(kind)
                )
            )
            for field in (
                adoption_result.CAPTURE_ADOPTION_PROVENANCE_FIELDS
            ):
                with self.subTest(kind=kind, missing=field):
                    changed = copy.deepcopy(provenance)
                    changed.pop(field)
                    self.assert_code(
                        "capture_adoption_provenance_fields_invalid",
                        (
                            adoption_result
                            .normalize_capture_adoption_provenance
                        ),
                        changed,
                    )
            changed = copy.deepcopy(provenance)
            changed["extra"] = None
            self.assert_code(
                "capture_adoption_provenance_fields_invalid",
                adoption_result.normalize_capture_adoption_provenance,
                changed,
            )
            changed = copy.deepcopy(provenance)
            changed["details"]["extra"] = None
            self.assert_code(
                "capture_adoption_provenance_details_invalid",
                adoption_result.normalize_capture_adoption_provenance,
                changed,
            )

    def test_provenance_cannot_relabel_or_mix_variant_details(
        self,
    ) -> None:
        normal = adoption_result.project_capture_adoption_provenance(
            self.full_result(adoption_result.NORMAL_ADOPTION_KIND)
        )
        recovered = adoption_result.project_capture_adoption_provenance(
            self.full_result(adoption_result.RECOVERED_ADOPTION_KIND)
        )
        for source, replacement_kind in (
            (normal, adoption_result.RECOVERED_ADOPTION_KIND),
            (recovered, adoption_result.NORMAL_ADOPTION_KIND),
        ):
            changed = copy.deepcopy(source)
            changed["kind"] = replacement_kind
            self.assert_code(
                "capture_adoption_provenance_kind_schema_mismatch",
                adoption_result.normalize_capture_adoption_provenance,
                changed,
            )
        changed = copy.deepcopy(normal)
        changed["evidence_schema"] = (
            recovered_adoption.RECOVERED_ADOPTION_EVIDENCE_SCHEMA
        )
        self.assert_code(
            "capture_adoption_provenance_kind_schema_mismatch",
            adoption_result.normalize_capture_adoption_provenance,
            changed,
        )
        changed = copy.deepcopy(recovered)
        changed["evidence_schema"] = (
            adoption_binding.ADOPTION_RECEIPT_SCHEMA
        )
        self.assert_code(
            "capture_adoption_provenance_kind_schema_mismatch",
            adoption_result.normalize_capture_adoption_provenance,
            changed,
        )
        changed = copy.deepcopy(normal)
        changed["details"] = copy.deepcopy(recovered["details"])
        self.assert_code(
            "capture_adoption_provenance_details_invalid",
            adoption_result.normalize_capture_adoption_provenance,
            changed,
        )
        changed = copy.deepcopy(recovered)
        changed["details"] = copy.deepcopy(normal["details"])
        self.assert_code(
            "capture_adoption_provenance_details_invalid",
            adoption_result.normalize_capture_adoption_provenance,
            changed,
        )

    def test_provenance_values_and_journal_schema_are_strict(self) -> None:
        normal = adoption_result.project_capture_adoption_provenance(
            self.full_result(adoption_result.NORMAL_ADOPTION_KIND)
        )
        for value in (None, True, 0, (1 << 53)):
            with self.subTest(adopted_at=value):
                changed = copy.deepcopy(normal)
                changed["details"]["adopted_at_unix"] = value
                self.assert_code(
                    (
                        "capture_adoption_"
                        "provenance_adopted_at_unix_invalid"
                    ),
                    adoption_result.normalize_capture_adoption_provenance,
                    changed,
                )
        recovered = adoption_result.project_capture_adoption_provenance(
            self.full_result(adoption_result.RECOVERED_ADOPTION_KIND)
        )
        changed = copy.deepcopy(recovered)
        changed["details"]["transaction_journal_schema"] = "v4"
        self.assert_code(
            "capture_adoption_provenance_journal_schema_invalid",
            adoption_result.normalize_capture_adoption_provenance,
            changed,
        )
        for field in (
            "adoption_reconciliation_record_sha256",
            "adoption_reconciliation_receipt_sha256",
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(recovered)
                changed["details"][field] = "not-a-digest"
                self.assert_code(
                    f"capture_adoption_provenance_{field}_invalid",
                    adoption_result.normalize_capture_adoption_provenance,
                    changed,
                )

    def test_result_and_provenance_are_detached_and_activation_is_false(
        self,
    ) -> None:
        result = self.full_result(adoption_result.RECOVERED_ADOPTION_KIND)
        normalized = adoption_result.normalize_capture_adoption_result(
            result
        )
        normalized["evidence"]["adoption_limits"]["max_files"] = 1
        self.assertEqual(result["evidence"]["adoption_limits"]["max_files"], 100)
        provenance = (
            adoption_result.project_capture_adoption_provenance(result)
        )
        normalized_provenance = (
            adoption_result.normalize_capture_adoption_provenance(
                provenance
            )
        )
        normalized_provenance["details"][
            "transaction_journal_schema"
        ] = "changed"
        self.assertEqual(
            provenance["details"]["transaction_journal_schema"],
            recovered_adoption.TRANSACTION_JOURNAL_SCHEMA,
        )
        self.assertFalse(adoption_result.PRODUCTION_ACTIVATION)

    def test_noncanonical_json_values_are_rejected(self) -> None:
        provenance = (
            adoption_result.project_capture_adoption_provenance(
                self.full_result(adoption_result.NORMAL_ADOPTION_KIND)
            )
        )
        changed = copy.deepcopy(provenance)
        changed["details"]["adopted_at_unix"] = float("nan")
        self.assert_code(
            "capture_adoption_provenance_adopted_at_unix_invalid",
            adoption_result.normalize_capture_adoption_provenance,
            changed,
        )
        self.assert_code(
            "capture_adoption_result_json_invalid",
            adoption_result.canonical_json,
            {"bytes": b"forbidden"},
        )


if __name__ == "__main__":
    unittest.main()
