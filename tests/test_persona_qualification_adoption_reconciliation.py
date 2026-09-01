from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_reconciliation
    as reconciliation,
)


class PersonaQualificationAdoptionReconciliationTests(
    unittest.TestCase
):
    def digest(self, label: str) -> str:
        return hashlib.sha256(label.encode("ascii")).hexdigest()

    def receipt(
        self,
        *,
        final_observation: str = "exact_present",
        staging_observation: str = "absent",
        terminal_disposition: str = "absent",
        result: str = "recovered_adoption",
    ) -> dict:
        exact_final = final_observation == "exact_present"
        mismatch_final = final_observation == "identity_mismatch"
        observed_final = exact_final or mismatch_final
        quarantined_terminal = terminal_disposition == "quarantined"
        observed_staging = staging_observation in {
            "exact_quarantine",
            "identity_mismatch",
        }
        final_identity = (
            self.digest("object")
            if exact_final
            else (
                self.digest("replacement-object")
                if mismatch_final
                else None
            )
        )
        return {
            "schema_version": (
                reconciliation
                .ADOPTION_RECONCILIATION_RECEIPT_SCHEMA
            ),
            "status": (
                reconciliation.ADOPTION_RECONCILIATION_STATUS
            ),
            "result": result,
            "capture_session_id": "1" * 64,
            "adoption_intent_record_sha256": self.digest(
                "adoption-intent"
            ),
            "adoption_policy_sha256": self.digest("adoption-policy"),
            "lifecycle_scope_empty_receipt_sha256": self.digest(
                "scope-empty"
            ),
            "staging_transaction_intent_sha256": self.digest(
                "staging-intent"
            ),
            "staging_terminal_receipt_sha256": self.digest(
                "staging-terminal"
            ),
            "staging_tombstone_sha256": self.digest(
                "staging-tombstone"
            ),
            "staging_terminal_disposition": terminal_disposition,
            "staging_leaf_identity_sha256": self.digest(
                "staging-leaf"
            ),
            "staging_inspection_lock_epoch_sha256": self.digest(
                "staging-lock"
            ),
            "shared_root_identity_sha256": self.digest("shared-root"),
            "recovery_namespace_identity_sha256": self.digest(
                "recovery-namespace"
            ),
            "quarantine_namespace_identity_sha256": self.digest(
                "quarantine-namespace"
            ),
            "transactions_namespace_identity_sha256": self.digest(
                "transactions-namespace"
            ),
            "final_parent_identity_sha256": self.digest(
                "final-parent"
            ),
            "final_parent_filesystem_device": 42,
            "dual_parent_lock_epoch_sha256": self.digest(
                "dual-parent-lock"
            ),
            "final_name": "opaque-capture-" + "a" * 32,
            "expected_object_identity_sha256": self.digest("object"),
            "expected_verifier_gid": 503,
            "adoption_limits": {
                "max_files": 32,
                "max_directories": 32,
                "max_bytes": 1024 * 1024,
                "max_file_bytes": 256 * 1024,
                "max_depth": 16,
            },
            "final_observation": final_observation,
            "final_object_identity_sha256": final_identity,
            "final_object_stat_sha256": (
                self.digest("final-stat")
                if observed_final
                else None
            ),
            "final_content_inventory_sha256": (
                self.digest("inventory") if exact_final else None
            ),
            "final_file_count": 2 if exact_final else None,
            "final_directory_count": 3 if exact_final else None,
            "final_total_bytes": 120 if exact_final else None,
            "final_largest_file_bytes": 80 if exact_final else None,
            "final_maximum_depth": 2 if exact_final else None,
            "final_object_owner_uid": 0 if observed_final else None,
            "final_object_group_gid": 503 if observed_final else None,
            "final_object_mode": (
                reconciliation.ADOPTED_DIRECTORY_MODE
                if observed_final
                else None
            ),
            "final_object_nlink": 2 if observed_final else None,
            "staging_observation": staging_observation,
            "staging_observed_leaf_identity_sha256": (
                self.digest("staging-leaf")
                if staging_observation == "exact_quarantine"
                else (
                    self.digest("replacement-staging-leaf")
                    if staging_observation == "identity_mismatch"
                    else None
                )
            ),
            "staging_terminal_quarantine_name": (
                f"session-{'1' * 64}"
                if quarantined_terminal
                else None
            ),
            "staging_terminal_quarantine_reason_code": (
                "capture_failed" if quarantined_terminal else None
            ),
            "staging_terminal_quarantined_stat_sha256": (
                self.digest("terminal-quarantined-stat")
                if quarantined_terminal
                else None
            ),
            "staging_observed_quarantined_stat_sha256": (
                self.digest("terminal-quarantined-stat")
                if staging_observation == "exact_quarantine"
                else (
                    self.digest("replacement-quarantined-stat")
                    if observed_staging
                    else None
                )
            ),
            "final_parent_fsynced": True,
            "staging_parents_fsynced": True,
            "observations_rechecked_under_lock": True,
        }

    def assert_code(self, code: str, value: dict) -> None:
        with self.assertRaises(
            reconciliation.AdoptionReconciliationError
        ) as caught:
            reconciliation.normalize_adoption_reconciliation_receipt(
                value
            )
        self.assertEqual(caught.exception.code, code)

    def test_exact_recovered_adoption_is_canonical_and_path_free(
        self,
    ) -> None:
        value = self.receipt()
        normalized = (
            reconciliation
            .normalize_adoption_reconciliation_receipt(value)
        )
        self.assertEqual(normalized, value)
        self.assertEqual(
            reconciliation.adoption_reconciliation_receipt_sha256(
                dict(reversed(tuple(value.items())))
            ),
            reconciliation.adoption_reconciliation_receipt_sha256(
                value
            ),
        )
        encoded = json.dumps(normalized, sort_keys=True)
        for forbidden in (
            "path",
            "child_pid",
            "process_group",
            "private_key",
            "/private/",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertFalse(reconciliation.PRODUCTION_ACTIVATION)

    def test_result_is_derived_from_both_parent_observations(
        self,
    ) -> None:
        cases = (
            (
                "exact_present",
                "absent",
                "absent",
                "recovered_adoption",
            ),
            ("absent", "absent", "absent", "staging_absent"),
            (
                "absent",
                "exact_quarantine",
                "quarantined",
                "staging_quarantined",
            ),
            (
                "exact_present",
                "exact_quarantine",
                "quarantined",
                "operator_attention",
            ),
            (
                "identity_mismatch",
                "absent",
                "absent",
                "operator_attention",
            ),
            (
                "unreadable",
                "unreadable",
                "quarantined",
                "operator_attention",
            ),
        )
        for final, staging, disposition, result in cases:
            with self.subTest(
                final=final,
                staging=staging,
                disposition=disposition,
            ):
                normalized = (
                    reconciliation
                    .normalize_adoption_reconciliation_receipt(
                        self.receipt(
                            final_observation=final,
                            staging_observation=staging,
                            terminal_disposition=disposition,
                            result=result,
                        )
                    )
                )
                self.assertEqual(normalized["result"], result)

    def test_every_outer_and_namespace_binding_is_required(
        self,
    ) -> None:
        digest_fields = (
            "capture_session_id",
            "adoption_intent_record_sha256",
            "adoption_policy_sha256",
            "lifecycle_scope_empty_receipt_sha256",
            "staging_transaction_intent_sha256",
            "staging_terminal_receipt_sha256",
            "staging_tombstone_sha256",
            "staging_leaf_identity_sha256",
            "staging_inspection_lock_epoch_sha256",
            "shared_root_identity_sha256",
            "recovery_namespace_identity_sha256",
            "quarantine_namespace_identity_sha256",
            "transactions_namespace_identity_sha256",
            "final_parent_identity_sha256",
            "dual_parent_lock_epoch_sha256",
            "expected_object_identity_sha256",
        )
        for field in digest_fields:
            with self.subTest(field=field):
                changed = self.receipt()
                changed[field] = "not-a-digest"
                self.assert_code(
                    f"adoption_reconciliation_{field}_invalid",
                    changed,
                )
            with self.subTest(field=field, sentinel="zero"):
                changed = self.receipt()
                changed[field] = reconciliation.ZERO_SHA256
                self.assert_code(
                    f"adoption_reconciliation_{field}_invalid",
                    changed,
                )

        invalid_device = self.receipt()
        invalid_device["final_parent_filesystem_device"] = True
        self.assert_code(
            (
                "adoption_reconciliation_"
                "final_parent_filesystem_device_invalid"
            ),
            invalid_device,
        )

    def test_exact_final_object_metadata_cannot_be_weakened(
        self,
    ) -> None:
        mutations = {
            "identity": ("final_object_identity_sha256", self.digest("x")),
            "stat": ("final_object_stat_sha256", None),
            "inventory": ("final_content_inventory_sha256", None),
            "owner": ("final_object_owner_uid", 501),
            "group": ("final_object_group_gid", None),
            "wrong_group": ("final_object_group_gid", 504),
            "mode": ("final_object_mode", 0o777),
            "file_count": ("final_file_count", None),
            "directory_count": ("final_directory_count", None),
            "total_bytes": ("final_total_bytes", None),
            "largest_file": ("final_largest_file_bytes", None),
            "maximum_depth": ("final_maximum_depth", None),
        }
        for label, (field, replacement) in mutations.items():
            with self.subTest(field=label):
                changed = self.receipt()
                changed[field] = replacement
                self.assert_code(
                    "adoption_reconciliation_exact_final_object_invalid",
                    changed,
                )

    def test_directory_link_count_uses_real_filesystem_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "adopted"
            directory.mkdir()
            (directory / "nested").mkdir()
            observed_nlink = os.stat(directory).st_nlink
        self.assertGreaterEqual(observed_nlink, 1)
        value = self.receipt()
        value["final_object_nlink"] = observed_nlink
        self.assertEqual(
            reconciliation.normalize_adoption_reconciliation_receipt(
                value
            )["final_object_nlink"],
            observed_nlink,
        )

    def test_inventory_counts_and_adoption_limits_are_bound(self) -> None:
        mutations = (
            ("final_file_count", 33),
            ("final_directory_count", 33),
            ("final_directory_count", 2),
            ("final_total_bytes", 1024 * 1024 + 1),
            ("final_largest_file_bytes", 256 * 1024 + 1),
            ("final_largest_file_bytes", 0),
            ("final_maximum_depth", 17),
        )
        for field, replacement in mutations:
            with self.subTest(field=field):
                changed = self.receipt()
                changed[field] = replacement
                self.assert_code(
                    (
                        "adoption_reconciliation_"
                        "final_inventory_limits_invalid"
                    ),
                    changed,
                )

        larger_than_total = self.receipt()
        larger_than_total["final_largest_file_bytes"] = 121
        self.assert_code(
            "adoption_reconciliation_final_inventory_limits_invalid",
            larger_than_total,
        )

        no_files_with_bytes = self.receipt()
        no_files_with_bytes["final_file_count"] = 0
        self.assert_code(
            "adoption_reconciliation_final_inventory_limits_invalid",
            no_files_with_bytes,
        )

        invalid_limits = self.receipt()
        invalid_limits["adoption_limits"] = copy.deepcopy(
            invalid_limits["adoption_limits"]
        )
        invalid_limits["adoption_limits"]["extra"] = 1
        self.assert_code(
            "adoption_reconciliation_adoption_limits_invalid",
            invalid_limits,
        )

        inverted_limits = self.receipt()
        inverted_limits["adoption_limits"] = copy.deepcopy(
            inverted_limits["adoption_limits"]
        )
        inverted_limits["adoption_limits"]["max_bytes"] = 1
        self.assert_code(
            (
                "adoption_reconciliation_"
                "adoption_file_limit_exceeds_total"
            ),
            inverted_limits,
        )

        wrong_expected_group = self.receipt()
        wrong_expected_group["expected_verifier_gid"] = 504
        self.assert_code(
            "adoption_reconciliation_exact_final_object_invalid",
            wrong_expected_group,
        )

    def test_identity_mismatch_and_absence_shapes_are_exact(
        self,
    ) -> None:
        mismatch = self.receipt(
            final_observation="identity_mismatch",
            result="operator_attention",
        )
        mismatch["final_object_identity_sha256"] = mismatch[
            "expected_object_identity_sha256"
        ]
        self.assert_code(
            "adoption_reconciliation_final_mismatch_invalid",
            mismatch,
        )
        incomplete_mismatch = self.receipt(
            final_observation="identity_mismatch",
            result="operator_attention",
        )
        incomplete_mismatch["final_object_owner_uid"] = None
        self.assert_code(
            "adoption_reconciliation_final_mismatch_invalid",
            incomplete_mismatch,
        )

        absent = self.receipt(
            final_observation="absent",
            result="staging_absent",
        )
        absent["final_object_stat_sha256"] = self.digest(
            "fabricated-stat"
        )
        self.assert_code(
            "adoption_reconciliation_final_metadata_unexpected",
            absent,
        )

    def test_staging_observation_identity_is_exact(self) -> None:
        quarantined = self.receipt(
            final_observation="absent",
            staging_observation="exact_quarantine",
            terminal_disposition="quarantined",
            result="staging_quarantined",
        )
        quarantined[
            "staging_observed_leaf_identity_sha256"
        ] = self.digest("replacement")
        self.assert_code(
            "adoption_reconciliation_staging_identity_invalid",
            quarantined,
        )

        changed_stat = self.receipt(
            final_observation="absent",
            staging_observation="exact_quarantine",
            terminal_disposition="quarantined",
            result="staging_quarantined",
        )
        changed_stat[
            "staging_observed_quarantined_stat_sha256"
        ] = self.digest("changed-quarantine-stat")
        self.assert_code(
            "adoption_reconciliation_staging_identity_invalid",
            changed_stat,
        )

        missing_reason = self.receipt(
            final_observation="absent",
            staging_observation="exact_quarantine",
            terminal_disposition="quarantined",
            result="staging_quarantined",
        )
        missing_reason[
            "staging_terminal_quarantine_reason_code"
        ] = None
        self.assert_code(
            "adoption_reconciliation_terminal_quarantine_invalid",
            missing_reason,
        )

        rebound_name = self.receipt(
            final_observation="absent",
            staging_observation="exact_quarantine",
            terminal_disposition="quarantined",
            result="staging_quarantined",
        )
        rebound_name["staging_terminal_quarantine_name"] = (
            "session-" + "2" * 64
        )
        self.assert_code(
            "adoption_reconciliation_terminal_quarantine_invalid",
            rebound_name,
        )

        absent = self.receipt(
            final_observation="absent",
            result="staging_absent",
        )
        absent[
            "staging_observed_leaf_identity_sha256"
        ] = self.digest("fabricated")
        self.assert_code(
            "adoption_reconciliation_staging_identity_unexpected",
            absent,
        )

        absent_with_quarantine_claim = self.receipt(
            final_observation="absent",
            result="staging_absent",
        )
        absent_with_quarantine_claim[
            "staging_terminal_quarantine_reason_code"
        ] = "capture_failed"
        self.assert_code(
            "adoption_reconciliation_terminal_quarantine_unexpected",
            absent_with_quarantine_claim,
        )

    def test_result_and_durability_claims_cannot_be_fabricated(
        self,
    ) -> None:
        wrong_result = self.receipt()
        wrong_result["result"] = "staging_absent"
        self.assert_code(
            "adoption_reconciliation_result_mismatch",
            wrong_result,
        )
        for field in (
            "final_parent_fsynced",
            "staging_parents_fsynced",
            "observations_rechecked_under_lock",
        ):
            with self.subTest(field=field):
                changed = self.receipt()
                changed[field] = False
                self.assert_code(
                    f"adoption_reconciliation_{field}_invalid",
                    changed,
                )

    def test_fields_are_exact_and_hash_vector_is_stable(self) -> None:
        extra = self.receipt()
        extra["final_parent_path"] = "/private/secret"
        self.assert_code(
            "adoption_reconciliation_receipt_fields_invalid",
            extra,
        )
        missing = self.receipt()
        missing.pop("dual_parent_lock_epoch_sha256")
        self.assert_code(
            "adoption_reconciliation_receipt_fields_invalid",
            missing,
        )
        self.assertEqual(
            reconciliation.adoption_reconciliation_receipt_sha256(
                self.receipt()
            ),
            "f71bd1a26ea20dd40c4454a59cd330fc07d2f34665b641fe9296f9e0c50c0cf4",
        )


if __name__ == "__main__":
    unittest.main()
