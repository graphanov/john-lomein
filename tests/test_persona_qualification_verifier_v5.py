from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


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
    john_lomein_persona_qualification_capture_selection
    as capture_selection,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_recovered_adoption_evidence
    as recovered_adoption,
)
from qualification_verifier import (  # noqa: E402
    john_lomein_persona_qualification_verifier as verifier,
)


class PersonaQualificationVerifierV5Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.instance_manifest = self.base / "control" / "instance.yaml"
        self.private_root = self.base / "private"
        self.runtime_root = self.base / "runtime"
        self.public_root = (
            self.runtime_root / "state" / "persona-qualification"
        )
        self.evidence_home = self.base / "evidence"
        self.checkout_source = self.base / "sources" / "checkout"
        self.runtime_source = self.base / "sources" / "runtime"
        self.checkout_identity = self.base / "checkout"
        self.snapshot_root = (
            self.base / "captures" / ("opaque-capture-" + "a" * 32)
        )
        self.instance_slug = "qualification-test"
        self.capture_uid = 501
        self.export_gid = 502
        self.evidence_uid = 503
        self.verifier_uid = 504
        self.verifier_gid = 505
        self.adoption_limits = {
            "max_files": 100,
            "max_directories": 100,
            "max_bytes": 1_000_000,
            "max_file_bytes": 100_000,
            "max_depth": 10,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def digest(label: str) -> str:
        return hashlib.sha256(label.encode("ascii")).hexdigest()

    def selection(self) -> dict:
        return {
            "schema_version": capture_selection.CAPTURE_SELECTION_SCHEMA,
            "instance_slug": self.instance_slug,
            "evidence_uid": self.evidence_uid,
            "verifier_gid": self.verifier_gid,
            "source_roots": {
                "instance_manifest": str(self.instance_manifest),
                "runtime": str(self.runtime_root),
                "qualification_public": str(self.public_root),
                "qualification_private": str(self.private_root),
            },
            "path_identities": {
                "evidence_home": str(self.evidence_home),
                "checkout_source": str(self.checkout_source),
                "runtime_source": str(self.runtime_source),
                "checkout": str(self.checkout_identity),
                "runtime": str(self.runtime_root),
            },
            "role_profiles": dict(capture_selection.ROLE_PROFILES),
            "limits": {
                "max_files": 128,
                "max_directories": 128,
                "max_bytes": 4 * 1024 * 1024,
                "max_file_bytes": 1024 * 1024,
                "max_depth": 32,
            },
            "lifecycle": {
                "retention": "ephemeral",
                "max_capture_slots": 8,
                "max_orphan_age_seconds": 60,
            },
        }

    def verifier_limits(self, kind: str) -> dict[str, int]:
        if kind == adoption_result.NORMAL_ADOPTION_KIND:
            return dict(verifier.NORMAL_ADOPTION_VERIFIER_LIMITS)
        return copy.deepcopy(self.adoption_limits)

    def normal_evidence(self) -> dict:
        selection_sha256 = (
            capture_selection.capture_selection_sha256(self.selection())
        )
        return {
            "schema_version": adoption_binding.ADOPTION_RECEIPT_SCHEMA,
            "status": adoption_binding.ADOPTION_STATUS,
            "session_id": self.digest("session"),
            "capture_adoption_policy_sha256": self.digest(
                "adoption-policy"
            ),
            "capture_selection_sha256": selection_sha256,
            "capture_plan_sha256": self.digest("plan"),
            "capture_manifest_sha256": self.digest("manifest"),
            "capture_boundary_policy_sha256": self.digest(
                "boundary-policy"
            ),
            "helper_activation_policy_sha256": self.digest(
                "helper-policy"
            ),
            "request_sha256": self.digest("capture-request"),
            "capture_uid": self.capture_uid,
            "capture_gid": self.export_gid,
            "adopted_uid": 0,
            "verifier_uid": self.verifier_uid,
            "verifier_gid": self.verifier_gid,
            "final_name": self.snapshot_root.name,
            "object_identity_sha256": self.digest("object"),
            "provisional_stat_sha256": self.digest("provisional-stat"),
            "adopted_stat_sha256": self.digest("adopted-stat"),
            "content_inventory_sha256": self.digest("inventory"),
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
        selection_sha256 = (
            capture_selection.capture_selection_sha256(self.selection())
        )
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
            "instance_slug": self.instance_slug,
            "capture_uid": self.capture_uid,
            "capture_export_gid": self.export_gid,
            "final_object_owner_uid": 0,
            "verifier_gid": self.verifier_gid,
            "final_object_group_gid": self.verifier_gid,
            "final_name": self.snapshot_root.name,
            "final_parent_filesystem_device": 42,
            "adoption_limits": copy.deepcopy(self.adoption_limits),
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
        evidence.update(
            {
                "capture_session_id": self.digest("session"),
                "capture_adoption_policy_sha256": self.digest(
                    "adoption-policy"
                ),
                "capture_selection_sha256": selection_sha256,
                "capture_plan_sha256": self.digest("plan"),
                "capture_manifest_sha256": self.digest("manifest"),
                "capture_request_sha256": self.digest(
                    "capture-request"
                ),
                "capture_boundary_policy_sha256": self.digest(
                    "boundary-policy"
                ),
                "helper_activation_policy_sha256": self.digest(
                    "helper-policy"
                ),
            }
        )
        return recovered_adoption.normalize_recovered_adoption_evidence(
            evidence
        )

    def adoption_result(self, kind: str) -> dict:
        evidence = (
            self.normal_evidence()
            if kind == adoption_result.NORMAL_ADOPTION_KIND
            else self.recovered_evidence()
        )
        return adoption_result.build_capture_adoption_result(
            kind,
            evidence,
        )

    def request(self, kind: str) -> dict:
        selection = self.selection()
        result = self.adoption_result(kind)
        evidence = result["evidence"]
        return {
            "schema_version": verifier.REQUEST_V5_SCHEMA,
            "snapshot_root": str(self.snapshot_root),
            "capture_manifest_sha256": evidence[
                "capture_manifest_sha256"
            ],
            "capture_plan_sha256": evidence["capture_plan_sha256"],
            "capture_selection": selection,
            "capture_selection_sha256": (
                capture_selection.capture_selection_sha256(selection)
            ),
            "capture_adoption_result": result,
            "capture_adoption_result_sha256": (
                adoption_result.capture_adoption_result_sha256(result)
            ),
            "capture_adoption_policy_sha256": evidence[
                "capture_adoption_policy_sha256"
            ],
            "adoption_verifier_limits": self.verifier_limits(kind),
            "capture_session_id": (
                evidence["session_id"]
                if kind == adoption_result.NORMAL_ADOPTION_KIND
                else evidence["capture_session_id"]
            ),
            "capture_request_sha256": (
                evidence["request_sha256"]
                if kind == adoption_result.NORMAL_ADOPTION_KIND
                else evidence["capture_request_sha256"]
            ),
            "capture_boundary_policy_sha256": evidence[
                "capture_boundary_policy_sha256"
            ],
            "capture_helper_activation_policy_sha256": evidence[
                "helper_activation_policy_sha256"
            ],
            "expected_run_id": "run-001",
            "capture_uid": self.capture_uid,
            "capture_export_gid": self.export_gid,
            "adopted_uid": 0,
            "instance_manifest_path": str(self.instance_manifest),
            "instance_manifest_sha256": self.digest(
                "instance-manifest"
            ),
            "qualification_private_root": str(self.private_root),
            "qualification_public_root": str(self.public_root),
            "evidence_home_path": str(self.evidence_home),
            "checkout_identity_path": str(self.checkout_identity),
            "runtime_identity_path": str(self.runtime_root),
            "instance_slug": self.instance_slug,
            "evidence_uid": self.evidence_uid,
            "verifier_uid": self.verifier_uid,
            "verifier_gid": self.verifier_gid,
            "verifier_bundle_sha256": self.digest("verifier-bundle"),
            "verification_policy_sha256": self.digest(
                "verification-policy"
            ),
            "operator_policy_sha256": self.digest("operator-policy"),
            "verified_at_unix": 200,
        }

    def adoption_evidence(self, result: dict) -> dict:
        evidence = result["evidence"]
        provenance = adoption_result.project_capture_adoption_provenance(
            result
        )
        return {
            "capture_creator_uid": self.capture_uid,
            "capture_export_gid": self.export_gid,
            "capture_adopted_uid": 0,
            "capture_adoption_policy_sha256": evidence[
                "capture_adoption_policy_sha256"
            ],
            "capture_object_identity_sha256": (
                evidence["object_identity_sha256"]
                if result["kind"]
                == adoption_result.NORMAL_ADOPTION_KIND
                else evidence["capture_object_identity_sha256"]
            ),
            "capture_content_inventory_sha256": (
                evidence["content_inventory_sha256"]
                if result["kind"]
                == adoption_result.NORMAL_ADOPTION_KIND
                else evidence["reconciled_content_inventory_sha256"]
            ),
            "capture_request_sha256": (
                evidence["request_sha256"]
                if result["kind"]
                == adoption_result.NORMAL_ADOPTION_KIND
                else evidence["capture_request_sha256"]
            ),
            "capture_boundary_policy_sha256": evidence[
                "capture_boundary_policy_sha256"
            ],
            "capture_helper_activation_policy_sha256": evidence[
                "helper_activation_policy_sha256"
            ],
            "capture_adoption_provenance": provenance,
            "capture_adoption_provenance_sha256": (
                adoption_result.capture_adoption_provenance_sha256(
                    provenance
                )
            ),
        }

    def assert_code(
        self,
        code: str,
        callable_,
        *args,
        **kwargs,
    ) -> None:
        with self.assertRaises(
            verifier.QualificationVerifierError
        ) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_versions_and_exact_field_sets_leave_v4_main_inert(
        self,
    ) -> None:
        self.assertEqual(
            verifier.REQUEST_V4_SCHEMA,
            "john-lomein.persona.operator-verifier-request.v4",
        )
        self.assertEqual(
            verifier.OUTPUT_V4_SCHEMA,
            "john-lomein.persona.operator-verification.v3",
        )
        self.assertEqual(
            verifier.REQUEST_V5_SCHEMA,
            "john-lomein.persona.operator-verifier-request.v5",
        )
        self.assertEqual(
            verifier.OUTPUT_V5_SCHEMA,
            "john-lomein.persona.operator-verification.v4",
        )
        self.assertFalse(verifier.V5_PRODUCTION_ACTIVATION)
        self.assertEqual(
            verifier.V4_ADOPTION_EVIDENCE_FIELDS,
            frozenset(adoption_binding.ADOPTION_EVIDENCE_FIELDS),
        )
        self.assertEqual(
            verifier.V5_ADOPTION_EVIDENCE_FIELDS,
            adoption_binding.CAPTURE_ADOPTION_RESULT_EVIDENCE_FIELDS,
        )
        self.assertNotIn(
            "capture_adoption_receipt",
            verifier.SEALED_REQUEST_V5_FIELDS,
        )
        self.assertIn(
            "capture_adoption_result",
            verifier.SEALED_REQUEST_V5_FIELDS,
        )
        self.assertIn(
            "capture_adoption_policy_sha256",
            verifier.SEALED_REQUEST_V5_FIELDS,
        )
        self.assertIn(
            "adoption_verifier_limits",
            verifier.SEALED_REQUEST_V5_FIELDS,
        )
        self.assertIn(
            "expected_run_id",
            verifier.SEALED_REQUEST_V5_FIELDS,
        )
        with (
            mock.patch.object(verifier, "deny_same_uid_debugging"),
            mock.patch.object(verifier, "assert_privilege_confinement"),
            mock.patch.object(
                verifier,
                "_read_request_stdin",
                return_value={"request": "v4"},
            ),
            mock.patch.object(
                verifier,
                "verify_sealed_request",
                return_value={"verified": True},
            ) as verify_v4,
            mock.patch.object(
                verifier,
                "verify_sealed_request_v5",
            ) as verify_v5,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(verifier.main([]), 0)
        verify_v4.assert_called_once_with({"request": "v4"})
        verify_v5.assert_not_called()
        self.assertEqual(
            json.loads(output.getvalue())["schema_version"],
            verifier.OUTPUT_V4_SCHEMA,
        )

    def test_normal_and_recovered_requests_normalize_exactly(
        self,
    ) -> None:
        for kind in adoption_result.CAPTURE_ADOPTION_KINDS:
            with self.subTest(kind=kind):
                request = self.request(kind)
                normalized = verifier.normalize_sealed_request_v5(
                    request
                )
                self.assertEqual(normalized, request)
                self.assertIsNot(
                    normalized["capture_adoption_result"],
                    request["capture_adoption_result"],
                )
                normalized["adoption_verifier_limits"][
                    "max_files"
                ] = 1
                self.assertEqual(
                    request["adoption_verifier_limits"]["max_files"],
                    self.verifier_limits(kind)["max_files"],
                )

    def test_result_and_outer_digest_substitution_fail_closed(
        self,
    ) -> None:
        for kind in adoption_result.CAPTURE_ADOPTION_KINDS:
            with self.subTest(kind=kind):
                request = self.request(kind)
                changed = copy.deepcopy(request)
                changed["capture_adoption_result_sha256"] = self.digest(
                    "substitute-result"
                )
                self.assert_code(
                    (
                        "sealed_request_v5_"
                        "capture_adoption_result_digest_mismatch"
                    ),
                    verifier.normalize_sealed_request_v5,
                    changed,
                )
                changed = copy.deepcopy(request)
                evidence = changed["capture_adoption_result"]["evidence"]
                field = (
                    "adopted_at_unix"
                    if kind == adoption_result.NORMAL_ADOPTION_KIND
                    else "reconciled_total_bytes"
                )
                evidence[field] += 1
                self.assert_code(
                    "capture_adoption_result_evidence_digest_mismatch",
                    verifier.normalize_sealed_request_v5,
                    changed,
                )
                changed = copy.deepcopy(request)
                changed["capture_adoption_result"]["kind"] = (
                    adoption_result.RECOVERED_ADOPTION_KIND
                    if kind == adoption_result.NORMAL_ADOPTION_KIND
                    else adoption_result.NORMAL_ADOPTION_KIND
                )
                self.assert_code(
                    "capture_adoption_result_kind_evidence_mismatch",
                    verifier.normalize_sealed_request_v5,
                    changed,
                )

    def test_exact_fields_limits_and_selection_digest_are_strict(
        self,
    ) -> None:
        request = self.request(adoption_result.NORMAL_ADOPTION_KIND)
        for changed in (
            {**request, "extra": False},
            {
                key: value
                for key, value in request.items()
                if key != "capture_adoption_result"
            },
        ):
            self.assert_code(
                "sealed_request_v5_fields_invalid",
                verifier.normalize_sealed_request_v5,
                changed,
            )
        changed = copy.deepcopy(request)
        changed["schema_version"] = verifier.REQUEST_V4_SCHEMA
        self.assert_code(
            "sealed_request_v5_schema_unsupported",
            verifier.normalize_sealed_request_v5,
            changed,
        )
        changed = copy.deepcopy(request)
        changed["capture_selection_sha256"] = self.digest(
            "substitute-selection"
        )
        self.assert_code(
            "sealed_request_v5_capture_selection_digest_mismatch",
            verifier.normalize_sealed_request_v5,
            changed,
        )
        for limits, code in (
            (
                {
                    **request["adoption_verifier_limits"],
                    "extra": 1,
                },
                (
                    "sealed_request_adoption_verifier_limits_"
                    "fields_invalid"
                ),
            ),
            (
                {
                    **request["adoption_verifier_limits"],
                    "max_files": True,
                },
                (
                    "sealed_request_adoption_verifier_limits_"
                    "max_files_invalid"
                ),
            ),
            (
                {
                    **request["adoption_verifier_limits"],
                    "max_bytes": 10,
                    "max_file_bytes": 11,
                },
                (
                    "sealed_request_adoption_verifier_limits_"
                    "file_exceeds_total"
                ),
            ),
        ):
            with self.subTest(code=code):
                changed = copy.deepcopy(request)
                changed["adoption_verifier_limits"] = limits
                self.assert_code(
                    code,
                    verifier.normalize_sealed_request_v5,
                    changed,
                )
        changed = copy.deepcopy(request)
        changed["adoption_verifier_limits"]["max_files"] -= 1
        self.assert_code(
            (
                "sealed_request_normal_adoption_verifier_limits_"
                "not_canonical"
            ),
            verifier.normalize_sealed_request_v5,
            changed,
        )

    def test_all_result_request_duplicates_are_bound(self) -> None:
        normal = self.request(adoption_result.NORMAL_ADOPTION_KIND)
        for field, replacement in (
            (
                "capture_adoption_policy_sha256",
                self.digest("other-adoption-policy"),
            ),
            ("capture_plan_sha256", self.digest("other-plan")),
            ("capture_manifest_sha256", self.digest("other-manifest")),
            ("capture_session_id", self.digest("other-session")),
            (
                "capture_request_sha256",
                self.digest("other-request"),
            ),
            (
                "capture_boundary_policy_sha256",
                self.digest("other-boundary"),
            ),
            (
                "capture_helper_activation_policy_sha256",
                self.digest("other-helper"),
            ),
            ("capture_uid", self.capture_uid + 10),
            ("capture_export_gid", self.export_gid + 10),
            ("verifier_uid", self.verifier_uid + 10),
        ):
            with self.subTest(kind="normal", field=field):
                changed = copy.deepcopy(normal)
                changed[field] = replacement
                self.assert_code(
                    (
                        "sealed_request_capture_adoption_result_"
                        f"{field}_mismatch"
                    ),
                    verifier.normalize_sealed_request_v5,
                    changed,
                )
        changed = copy.deepcopy(normal)
        changed["snapshot_root"] = str(
            self.snapshot_root.with_name(
                "opaque-capture-" + "b" * 32
            )
        )
        self.assert_code(
            (
                "sealed_request_capture_adoption_result_"
                "snapshot_root_mismatch"
            ),
            verifier.normalize_sealed_request_v5,
            changed,
        )

        recovered = self.request(
            adoption_result.RECOVERED_ADOPTION_KIND
        )
        changed = copy.deepcopy(recovered)
        changed["adoption_verifier_limits"]["max_files"] -= 1
        self.assert_code(
            (
                "sealed_request_capture_adoption_result_"
                "adoption_verifier_limits_mismatch"
            ),
            verifier.normalize_sealed_request_v5,
            changed,
        )
        changed = copy.deepcopy(recovered)
        changed_result = changed["capture_adoption_result"]
        changed_evidence = changed_result["evidence"]
        changed_evidence["instance_slug"] = "other-instance"
        changed["capture_adoption_result"] = (
            adoption_result.build_capture_adoption_result(
                adoption_result.RECOVERED_ADOPTION_KIND,
                changed_evidence,
            )
        )
        changed["capture_adoption_result_sha256"] = (
            adoption_result.capture_adoption_result_sha256(
                changed["capture_adoption_result"]
            )
        )
        self.assert_code(
            (
                "sealed_request_capture_adoption_result_"
                "instance_slug_mismatch"
            ),
            verifier.normalize_sealed_request_v5,
            changed,
        )

    def test_all_identity_domains_remain_separate(self) -> None:
        request = self.request(adoption_result.NORMAL_ADOPTION_KIND)
        for field, replacement, code in (
            (
                "capture_uid",
                self.evidence_uid,
                "sealed_request_v5_capture_identity_not_separate",
            ),
            (
                "capture_export_gid",
                self.verifier_gid,
                "sealed_request_v5_capture_identity_not_separate",
            ),
            (
                "evidence_uid",
                self.verifier_uid,
                "sealed_request_v5_verifier_identity_not_separate",
            ),
            (
                "adopted_uid",
                1,
                "sealed_request_v5_adopted_uid_not_root",
            ),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(request)
                changed[field] = replacement
                self.assert_code(
                    code,
                    verifier.normalize_sealed_request_v5,
                    changed,
                )

    def result_verification_arguments(self, result: dict) -> dict:
        request = self.request(result["kind"])
        return {
            "capture_adoption_result": result,
            "expected_capture_adoption_result_sha256": (
                adoption_result.capture_adoption_result_sha256(result)
            ),
            "expected_capture_adoption_policy_sha256": request[
                "capture_adoption_policy_sha256"
            ],
            "expected_adoption_verifier_limits": request[
                "adoption_verifier_limits"
            ],
            "expected_capture_uid": self.capture_uid,
            "expected_capture_export_gid": self.export_gid,
            "expected_adopted_uid": 0,
            "expected_capture_session_id": request[
                "capture_session_id"
            ],
            "expected_capture_request_sha256": request[
                "capture_request_sha256"
            ],
            "expected_capture_boundary_policy_sha256": request[
                "capture_boundary_policy_sha256"
            ],
            "expected_capture_helper_activation_policy_sha256": (
                request[
                    "capture_helper_activation_policy_sha256"
                ]
            ),
            "snapshot_root": self.snapshot_root,
            "expected_capture_manifest_sha256": request[
                "capture_manifest_sha256"
            ],
            "expected_capture_plan_sha256": request[
                "capture_plan_sha256"
            ],
            "capture_selection": request["capture_selection"],
            "expected_capture_selection_sha256": request[
                "capture_selection_sha256"
            ],
            "instance_manifest": self.instance_manifest,
            "expected_instance_manifest_sha256": request[
                "instance_manifest_sha256"
            ],
            "private_root": self.private_root,
            "expected_public_root": self.public_root,
            "evidence_home": self.evidence_home,
            "checkout_identity": self.checkout_identity,
            "runtime_identity": self.runtime_root,
            "expected_instance_slug": self.instance_slug,
            "expected_evidence_uid": self.evidence_uid,
            "expected_verifier_uid": self.verifier_uid,
            "expected_verifier_gid": self.verifier_gid,
            "expected_run_id": request["expected_run_id"],
            "verifier_bundle_sha256": request[
                "verifier_bundle_sha256"
            ],
            "verification_policy_sha256": request[
                "verification_policy_sha256"
            ],
            "operator_policy_sha256": request[
                "operator_policy_sha256"
            ],
            "verified_at_unix": request["verified_at_unix"],
        }

    def test_result_verifier_dispatches_then_emits_only_common_fields(
        self,
    ) -> None:
        for kind in adoption_result.CAPTURE_ADOPTION_KINDS:
            with self.subTest(kind=kind):
                result = self.adoption_result(kind)
                adoption_evidence = self.adoption_evidence(result)
                opaque_evidence = {
                    "run_id": "run-001",
                    "verifier_version": verifier.VERIFIER_VERSION,
                    "capture_manifest_sha256": self.digest("manifest"),
                }
                order = []

                def verify_adoption(*args, **kwargs):
                    order.append("adoption")
                    self.assertEqual(args, (result,))
                    self.assertEqual(
                        kwargs["expected_instance_slug"],
                        self.instance_slug,
                    )
                    self.assertEqual(
                        kwargs["expected_adoption_limits"],
                        self.verifier_limits(kind),
                    )
                    return copy.deepcopy(adoption_evidence)

                def verify_opaque(**kwargs):
                    order.append("opaque")
                    self.assertEqual(kwargs["snapshot_owner_uid"], 0)
                    self.assertEqual(
                        kwargs["expected_run_id"], "run-001"
                    )
                    self.assertEqual(
                        kwargs["manifest_capture_uid"],
                        self.capture_uid,
                    )
                    return copy.deepcopy(opaque_evidence)

                with (
                    mock.patch.object(
                        verifier.adoption_binding_contract,
                        "verify_capture_adoption_result",
                        side_effect=verify_adoption,
                    ),
                    mock.patch.object(
                        verifier,
                        "verify_opaque_snapshot_evidence",
                        side_effect=verify_opaque,
                    ),
                ):
                    verified = (
                        verifier.verify_adopted_opaque_snapshot_result(
                            **self.result_verification_arguments(result)
                        )
                    )
                self.assertEqual(order, ["adoption", "opaque"])
                self.assertEqual(
                    verified["verifier_version"],
                    verifier.VERIFIER_V5_VERSION,
                )
                self.assertEqual(
                    set(verified) & verifier.V5_ADOPTION_EVIDENCE_FIELDS,
                    verifier.V5_ADOPTION_EVIDENCE_FIELDS,
                )
                self.assertNotIn(
                    "capture_adoption_receipt_sha256",
                    verified,
                )
                self.assertNotIn("capture_adopted_at_unix", verified)
                self.assertNotIn("adoption_verifier_limits", verified)
                self.assertNotIn("adoption_limits", verified)
                if kind == adoption_result.RECOVERED_ADOPTION_KIND:
                    encoded = json.dumps(verified, sort_keys=True)
                    for forbidden in (
                        "adopted_at_unix",
                        "child_pid",
                        "child_exit_status",
                        "rename_primitive",
                        "rename_noreplace",
                    ):
                        self.assertNotIn(forbidden, encoded)

    def test_result_verifier_rejects_noncommon_or_colliding_evidence(
        self,
    ) -> None:
        result = self.adoption_result(
            adoption_result.RECOVERED_ADOPTION_KIND
        )
        arguments = self.result_verification_arguments(result)
        adoption_evidence = self.adoption_evidence(result)
        with (
            mock.patch.object(
                verifier.adoption_binding_contract,
                "verify_capture_adoption_result",
                return_value={
                    **adoption_evidence,
                    "capture_adopted_at_unix": 100,
                },
            ),
            mock.patch.object(
                verifier,
                "verify_opaque_snapshot_evidence",
            ) as verify_opaque,
        ):
            self.assert_code(
                "adopted_opaque_result_evidence_fields_invalid",
                verifier.verify_adopted_opaque_snapshot_result,
                **arguments,
            )
        verify_opaque.assert_not_called()

        with (
            mock.patch.object(
                verifier.adoption_binding_contract,
                "verify_capture_adoption_result",
                return_value=adoption_evidence,
            ),
            mock.patch.object(
                verifier,
                "verify_opaque_snapshot_evidence",
                return_value={
                    "verifier_version": verifier.VERIFIER_VERSION,
                    "capture_creator_uid": self.capture_uid,
                },
            ),
        ):
            self.assert_code(
                "adopted_opaque_result_evidence_collision",
                verifier.verify_adopted_opaque_snapshot_result,
                **arguments,
            )

    def test_direct_normal_result_rejects_arbitrary_verifier_limits(
        self,
    ) -> None:
        result = self.adoption_result(
            adoption_result.NORMAL_ADOPTION_KIND
        )
        arguments = self.result_verification_arguments(result)
        arguments["expected_adoption_verifier_limits"] = {
            **arguments["expected_adoption_verifier_limits"],
            "max_files": (
                arguments["expected_adoption_verifier_limits"][
                    "max_files"
                ]
                - 1
            ),
        }
        with (
            mock.patch.object(
                verifier.adoption_binding_contract,
                "verify_capture_adoption_result",
            ) as verify_adoption,
            mock.patch.object(
                verifier,
                "verify_opaque_snapshot_evidence",
            ) as verify_opaque,
        ):
            self.assert_code(
                (
                    "adopted_opaque_result_normal_"
                    "adoption_verifier_limits_not_canonical"
                ),
                verifier.verify_adopted_opaque_snapshot_result,
                **arguments,
            )
        verify_adoption.assert_not_called()
        verify_opaque.assert_not_called()

    def test_opaque_verifier_rejects_extracted_run_id_substitution(
        self,
    ) -> None:
        request = self.request(
            adoption_result.RECOVERED_ADOPTION_KIND
        )
        selection = request["capture_selection"]
        plan = {"instance_slug": self.instance_slug}
        instance_entry = {
            "source_class": "instance_manifest",
            "source_path": str(self.instance_manifest),
            "sha256": request["instance_manifest_sha256"],
        }
        with (
            mock.patch.object(
                verifier,
                "_validate_sealed_verifier_identity",
                return_value=(self.verifier_uid, self.verifier_gid),
            ),
            mock.patch.object(
                verifier,
                "_bound_capture_selection",
                return_value=selection,
            ),
            mock.patch.object(
                verifier,
                "_opaque_manifest_and_plan",
                return_value=(
                    {},
                    plan,
                    request["capture_manifest_sha256"],
                    request["capture_plan_sha256"],
                ),
            ),
            mock.patch.object(
                verifier,
                "_opaque_file_entry",
                return_value=instance_entry,
            ),
            mock.patch.object(
                verifier,
                "_extract_opaque_run_id",
                return_value="different-run",
            ),
        ):
            self.assert_code(
                "qualification_opaque_expected_run_id_mismatch",
                verifier.verify_opaque_snapshot_evidence,
                snapshot_root=self.snapshot_root,
                expected_capture_manifest_sha256=request[
                    "capture_manifest_sha256"
                ],
                expected_capture_plan_sha256=request[
                    "capture_plan_sha256"
                ],
                capture_selection=selection,
                expected_capture_selection_sha256=request[
                    "capture_selection_sha256"
                ],
                instance_manifest=self.instance_manifest,
                expected_instance_manifest_sha256=request[
                    "instance_manifest_sha256"
                ],
                private_root=self.private_root,
                expected_public_root=self.public_root,
                evidence_home=self.evidence_home,
                checkout_identity=self.checkout_identity,
                runtime_identity=self.runtime_root,
                expected_instance_slug=self.instance_slug,
                expected_evidence_uid=self.evidence_uid,
                expected_verifier_uid=self.verifier_uid,
                expected_verifier_gid=self.verifier_gid,
                expected_run_id="run-001",
                verifier_bundle_sha256=request[
                    "verifier_bundle_sha256"
                ],
                verification_policy_sha256=request[
                    "verification_policy_sha256"
                ],
                operator_policy_sha256=request[
                    "operator_policy_sha256"
                ],
                verified_at_unix=request["verified_at_unix"],
            )

    def test_sealed_request_v5_routes_the_exact_normalized_contract(
        self,
    ) -> None:
        for kind in adoption_result.CAPTURE_ADOPTION_KINDS:
            with self.subTest(kind=kind):
                request = self.request(kind)
                sentinel = {"verified": kind}
                runner = object()
                with mock.patch.object(
                    verifier,
                    "verify_adopted_opaque_snapshot_result",
                    return_value=sentinel,
                ) as verify_result:
                    observed = verifier.verify_sealed_request_v5(
                        request,
                        process_uid=self.verifier_uid,
                        process_gid=self.verifier_gid,
                        process_groups=(self.verifier_gid,),
                        runner=runner,
                    )
                self.assertIs(observed, sentinel)
                arguments = verify_result.call_args.kwargs
                self.assertEqual(
                    arguments["capture_adoption_result"],
                    request["capture_adoption_result"],
                )
                self.assertEqual(
                    arguments[
                        "expected_capture_adoption_result_sha256"
                    ],
                    request["capture_adoption_result_sha256"],
                )
                self.assertEqual(
                    arguments[
                        "expected_capture_adoption_policy_sha256"
                    ],
                    request["capture_adoption_policy_sha256"],
                )
                self.assertEqual(
                    arguments[
                        "expected_adoption_verifier_limits"
                    ],
                    request["adoption_verifier_limits"],
                )
                self.assertEqual(
                    arguments["process_groups"],
                    (self.verifier_gid,),
                )
                self.assertEqual(
                    arguments["expected_run_id"],
                    request["expected_run_id"],
                )
                self.assertIs(arguments["runner"], runner)


if __name__ == "__main__":
    unittest.main()
