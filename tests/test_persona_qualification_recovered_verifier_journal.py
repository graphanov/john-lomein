from __future__ import annotations

import contextlib
import copy
import hashlib
import inspect
import json
import os
import pickle
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_result
    as adoption_result,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_selection
    as capture_selection,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_staging as staging,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_source_revalidation_binding
    as source_revalidation,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_transaction_journal as journal,
)
import test_persona_qualification_recovered_adoption_continuation as _continuation_tests  # noqa: E402


class RecoveredVerifierJournalTests(unittest.TestCase):
    @staticmethod
    def digest(label: str) -> str:
        return hashlib.sha256(label.encode("ascii")).hexdigest()

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(
            journal.TransactionJournalError
        ) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def _new_fixture(
        self,
    ) -> _continuation_tests.RecoveredAdoptionContinuationTests:
        fixture = (
            _continuation_tests.RecoveredAdoptionContinuationTests(
                "test_context_and_reserved_commit_use_exact_durable_successor"
            )
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def _acked_session(
        self,
        fixture: (
            _continuation_tests.RecoveredAdoptionContinuationTests
        ),
    ) -> journal.TransactionJournalSession:
        selection_sha256 = (
            capture_selection.capture_selection_sha256(
                self._selection(fixture)
            )
        )
        original_details_for = fixture.fixture.details_for

        def bound_details_for(session, state):
            details = original_details_for(session, state)
            if state == "capture_ready":
                details["capture_selection_sha256"] = (
                    selection_sha256
                )
                details["lifecycle_operation_binding"][
                    "supervisor_event_evidence_sha256"
                ] = journal._capture_event_evidence_sha256(
                    details
                )
            return details

        with mock.patch.object(
            fixture.fixture,
            "details_for",
            side_effect=bound_details_for,
        ):
            session, shared_root, _built = (
                fixture._build_real_recovered_head()
            )
        operation = session.begin_recovered_adoption_tombstone_ack()
        control = (
            staging._open_installed_capture_staging_control_for_test(
                shared_root
            )
        )
        operation.commit(control)
        self.assertEqual(session.state, "staging_tombstone_acked")
        return session

    def _selection(
        self,
        fixture: (
            _continuation_tests.RecoveredAdoptionContinuationTests
        ),
    ) -> dict:
        base = fixture.fixture.root / "verifier-contract"
        runtime_root = base / "runtime"
        return {
            "schema_version": (
                capture_selection.CAPTURE_SELECTION_SCHEMA
            ),
            "instance_slug": "john-test",
            "evidence_uid": 60_001,
            "verifier_gid": 503,
            "source_roots": {
                "instance_manifest": str(
                    base / "control" / "instance.yaml"
                ),
                "runtime": str(runtime_root),
                "qualification_public": str(
                    runtime_root
                    / "state"
                    / "persona-qualification"
                ),
                "qualification_private": str(base / "private"),
            },
            "path_identities": {
                "evidence_home": str(base / "evidence"),
                "checkout_source": str(
                    base / "sources" / "checkout"
                ),
                "runtime_source": str(
                    base / "sources" / "runtime"
                ),
                "checkout": str(base / "checkout"),
                "runtime": str(runtime_root),
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

    def _material_inputs(
        self,
        fixture: (
            _continuation_tests.RecoveredAdoptionContinuationTests
        ),
        session: journal.TransactionJournalSession,
    ) -> tuple[dict, dict]:
        context = session.mint_recovered_adoption_journal_context()
        result = context.capture_adoption_result
        recovered = result["evidence"]
        provenance = context.capture_adoption_provenance
        binding = context.journal_binding
        ack_recorded_at = session.latest_record.recorded_at_unix
        verified_at = ack_recorded_at + 1
        revalidated_at = ack_recorded_at + 2

        base = fixture.fixture.root / "verifier-contract"
        instance_manifest = base / "control" / "instance.yaml"
        runtime_root = base / "runtime"
        public_root = (
            runtime_root / "state" / "persona-qualification"
        )
        private_root = base / "private"
        evidence_home = base / "evidence"
        checkout_source = base / "sources" / "checkout"
        runtime_source = base / "sources" / "runtime"
        checkout_identity = base / "checkout"
        snapshot_root = (
            base / "captures" / recovered["final_name"]
        )
        evidence_uid = 60_001
        verifier_uid = evidence_uid + 1
        while verifier_uid in {
            evidence_uid,
            recovered["capture_uid"],
        }:
            verifier_uid += 1
        selection = self._selection(fixture)
        request = {
            "schema_version": journal.VERIFIER_REQUEST_V5_SCHEMA,
            "snapshot_root": str(snapshot_root),
            "capture_manifest_sha256": recovered[
                "capture_manifest_sha256"
            ],
            "capture_plan_sha256": recovered[
                "capture_plan_sha256"
            ],
            "capture_selection": selection,
            "capture_selection_sha256": (
                capture_selection.capture_selection_sha256(
                    selection
                )
            ),
            "capture_adoption_result": result,
            "capture_adoption_result_sha256": (
                adoption_result.capture_adoption_result_sha256(
                    result
                )
            ),
            "capture_adoption_policy_sha256": recovered[
                "capture_adoption_policy_sha256"
            ],
            "adoption_verifier_limits": copy.deepcopy(
                recovered["adoption_limits"]
            ),
            "capture_session_id": recovered["capture_session_id"],
            "capture_request_sha256": recovered[
                "capture_request_sha256"
            ],
            "capture_boundary_policy_sha256": recovered[
                "capture_boundary_policy_sha256"
            ],
            "capture_helper_activation_policy_sha256": recovered[
                "helper_activation_policy_sha256"
            ],
            "expected_run_id": "run-001",
            "capture_uid": recovered["capture_uid"],
            "capture_export_gid": recovered[
                "capture_export_gid"
            ],
            "adopted_uid": 0,
            "instance_manifest_path": str(instance_manifest),
            "instance_manifest_sha256": self.digest(
                "instance-manifest"
            ),
            "qualification_private_root": str(private_root),
            "qualification_public_root": str(public_root),
            "evidence_home_path": str(evidence_home),
            "checkout_identity_path": str(checkout_identity),
            "runtime_identity_path": str(runtime_root),
            "instance_slug": recovered["instance_slug"],
            "evidence_uid": evidence_uid,
            "verifier_uid": verifier_uid,
            "verifier_gid": recovered["verifier_gid"],
            "verifier_bundle_sha256": self.digest(
                "verifier-bundle"
            ),
            "verification_policy_sha256": self.digest(
                "verification-policy"
            ),
            "operator_policy_sha256": self.digest(
                "operator-policy"
            ),
            "verified_at_unix": verified_at,
        }
        output_evidence = {
            "run_id": "run-001",
            "summary_sha256": self.digest("summary"),
            "binding_sha256": self.digest("binding"),
            "status": "qualified",
            "qualified_at_unix": ack_recorded_at,
            "expires_at_unix": ack_recorded_at + 1_000,
            "verifier_version": journal.VERIFIER_V5_VERSION,
            "verifier_uid": verifier_uid,
            "verifier_bundle_sha256": request[
                "verifier_bundle_sha256"
            ],
            "verification_policy_sha256": request[
                "verification_policy_sha256"
            ],
            "capture_manifest_sha256": recovered[
                "capture_manifest_sha256"
            ],
            "capture_plan_sha256": recovered[
                "capture_plan_sha256"
            ],
            "operator_policy_sha256": request[
                "operator_policy_sha256"
            ],
            "claim_strength": (
                journal.VERIFIER_CLAIM_STRENGTH
            ),
            "public_reputation_eligible": False,
            "verified_at_unix": request["verified_at_unix"],
            "observed_evidence_uid": evidence_uid,
            "capture_creator_uid": recovered["capture_uid"],
            "capture_export_gid": recovered[
                "capture_export_gid"
            ],
            "capture_adopted_uid": 0,
            "capture_adoption_policy_sha256": recovered[
                "capture_adoption_policy_sha256"
            ],
            "capture_object_identity_sha256": recovered[
                "capture_object_identity_sha256"
            ],
            "capture_content_inventory_sha256": recovered[
                "reconciled_content_inventory_sha256"
            ],
            "capture_request_sha256": recovered[
                "capture_request_sha256"
            ],
            "capture_boundary_policy_sha256": recovered[
                "capture_boundary_policy_sha256"
            ],
            "capture_helper_activation_policy_sha256": recovered[
                "helper_activation_policy_sha256"
            ],
            "capture_adoption_provenance": provenance,
            "capture_adoption_provenance_sha256": (
                adoption_result.capture_adoption_provenance_sha256(
                    provenance
                )
            ),
        }
        output = {
            "schema_version": journal.VERIFIER_OUTPUT_V4_SCHEMA,
            "status": "verified",
            "evidence": output_evidence,
        }
        output_sha256 = journal.verifier_output_v4_sha256(
            output,
            expected_evidence_uid=evidence_uid,
        )
        receipt = {
            "schema_version": (
                source_revalidation
                .SOURCE_REVALIDATION_RECEIPT_V2_SCHEMA
            ),
            "status": (
                source_revalidation.SOURCE_REVALIDATION_STATUS
            ),
            "capture_adoption_provenance": provenance,
            "capture_adoption_provenance_sha256": (
                adoption_result.capture_adoption_provenance_sha256(
                    provenance
                )
            ),
            "capture_object_identity_sha256": recovered[
                "capture_object_identity_sha256"
            ],
            "capture_plan_sha256": recovered[
                "capture_plan_sha256"
            ],
            "capture_manifest_sha256": recovered[
                "capture_manifest_sha256"
            ],
            "verifier_output_sha256": output_sha256,
            "revalidator_uid": 0,
            "revalidated_at_unix": revalidated_at,
        }
        expected_v6 = journal.normalize_recovered_verified_evidence_v6(
            {
                **output_evidence,
                (
                    "post_verifier_live_source_"
                    "revalidation_receipt"
                ): receipt,
                (
                    "post_verifier_live_source_"
                    "revalidation_receipt_sha256"
                ): (
                    source_revalidation
                    .source_revalidation_receipt_v2_sha256(
                        receipt
                    )
                ),
            },
            expected_evidence_uid=evidence_uid,
            expected_verifier_output_sha256=output_sha256,
        )
        return {
            "verifier_request_v5": request,
            "verifier_output_v4": output,
            "source_revalidation_receipt_v2": receipt,
            (
                "pre_verifier_recovered_adoption_"
                "lease_binding"
            ): binding,
            (
                "post_verifier_recovered_adoption_"
                "lease_binding"
            ): binding,
        }, expected_v6

    def _commit_material(
        self,
        fixture: (
            _continuation_tests.RecoveredAdoptionContinuationTests
        ),
        session: journal.TransactionJournalSession,
    ) -> tuple[
        journal.RecoveredVerifierSourceEvidenceOperation,
        journal.RecoveredVerifierSourceEvidenceMaterial,
        journal.RecoveredVerifiedEvidenceV6Clearance,
        dict,
        dict,
    ]:
        inputs, expected_v6 = self._material_inputs(
            fixture, session
        )
        operation = (
            session.begin_recovered_verifier_source_evidence()
        )
        material = operation.mint_material(**inputs)
        clearance = operation.commit(material)
        self.assertEqual(
            clearance.verified_evidence_v6, expected_v6
        )
        return (
            operation,
            material,
            clearance,
            expected_v6,
            inputs,
        )

    def test_restart_each_cut_round_trips_full_v6_and_truthful_semantics(
        self,
    ) -> None:
        fixture = self._new_fixture()
        session = self._acked_session(fixture)
        (
            _operation,
            _material,
            clearance,
            expected_v6,
            committed_inputs,
        ) = (
            self._commit_material(fixture, session)
        )
        self.assertEqual(clearance.head_state, "verifier_output_bound")
        for copier in (
            copy.copy,
            copy.deepcopy,
            pickle.dumps,
        ):
            with self.assertRaises(TypeError):
                copier(clearance)
        with mock.patch.object(
            journal.os,
            "getpid",
            return_value=os.getpid() + 1,
        ):
            self.assert_code(
                (
                    "transaction_journal_recovered_verifier_"
                    "clearance_creator_process_mismatch"
                ),
                lambda: clearance.verified_evidence_v6,
            )
        envelope = clearance.recovered_verifier_source_evidence
        self.assertIs(
            envelope[
                "source_revalidation_effect_"
                "completed_under_acked_head"
            ],
            True,
        )
        self.assertEqual(
            envelope["source_revalidation_receipt_v2"],
            expected_v6[
                "post_verifier_live_source_revalidation_receipt"
            ],
        )
        self.assertEqual(
            session.latest_record.recorded_at_unix,
            envelope["source_revalidation_receipt_v2"][
                "revalidated_at_unix"
            ],
        )
        raw_record = json.dumps(
            session.latest_record.to_dict(),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        self.assertLessEqual(len(raw_record) + 1, journal.MAX_RECORD_BYTES)
        for path in (
            "snapshot_root",
            "instance_manifest_path",
            "qualification_private_root",
            "qualification_public_root",
            "evidence_home_path",
            "checkout_identity_path",
            "runtime_identity_path",
        ):
            self.assertNotIn(path.encode("ascii"), raw_record)
        request = committed_inputs["verifier_request_v5"]
        path_values = {
            request[field]
            for field in (
                "snapshot_root",
                "instance_manifest_path",
                "qualification_private_root",
                "qualification_public_root",
                "evidence_home_path",
                "checkout_identity_path",
                "runtime_identity_path",
            )
        }
        path_values.update(
            request["capture_selection"]["source_roots"].values()
        )
        path_values.update(
            request["capture_selection"]["path_identities"].values()
        )
        durable_prefix = b"\n".join(
            journal._canonical_json(record.to_dict())
            for record in session.records
        )
        for path_value in path_values:
            self.assertNotIn(
                path_value.encode("ascii"), durable_prefix
            )

        self.assertEqual(
            tuple(
                inspect.signature(
                    session.recover_recovered_verified_evidence_v6
                ).parameters
            ),
            (),
        )
        self.assertEqual(
            tuple(
                inspect.signature(
                    session.advance_recovered_verifier_source_evidence
                ).parameters
            ),
            (),
        )
        expected_receipt = copy.deepcopy(
            envelope["source_revalidation_receipt_v2"]
        )
        for expected_head in (
            "verifier_output_bound",
            "live_revalidation_started",
            "live_revalidation_receipt_complete",
        ):
            session._store.close()
            reopened = fixture.fixture.open_store()
            session = reopened.load_incomplete_sessions()[0]
            recovered = (
                session.recover_recovered_verified_evidence_v6()
            )
            self.assertEqual(recovered.head_state, expected_head)
            self.assertEqual(
                recovered.verified_evidence_v6, expected_v6
            )
            self.assertEqual(
                recovered.recovered_verifier_source_evidence[
                    "source_revalidation_receipt_v2"
                ],
                expected_receipt,
            )
            before = len(session.records)
            advanced = (
                session.advance_recovered_verifier_source_evidence()
            )
            if expected_head == "verifier_output_bound":
                self.assertEqual(
                    advanced.head_state,
                    "live_revalidation_started",
                )
            else:
                self.assertEqual(
                    advanced.head_state,
                    "live_revalidation_receipt_complete",
                )
            if (
                expected_head
                == "live_revalidation_receipt_complete"
            ):
                self.assertEqual(len(session.records), before)
            else:
                self.assertEqual(len(session.records), before + 1)
                self.assert_code(
                    (
                        "transaction_journal_recovered_verifier_"
                        "clearance_head_changed"
                    ),
                    lambda: recovered.verified_evidence_v6,
                )
                self.assertEqual(
                    session.latest_record.details[
                        "state_semantics"
                    ],
                    journal.RECOVERED_REVALIDATION_STATE_SEMANTICS,
                )
                self.assertEqual(
                    session.latest_record.recorded_at_unix,
                    expected_receipt["revalidated_at_unix"],
                )

    def test_generic_append_legacy_and_hostile_disk_cannot_mint_lineage(
        self,
    ) -> None:
        fixture = self._new_fixture()
        session = self._acked_session(fixture)
        plain_details = {
            "verifier_output_sha256": self.digest("forged-output")
        }
        self.assert_code(
            "transaction_journal_staging_cleanup_continuation_unsafe",
            session.append_event,
            expected_state="staging_tombstone_acked",
            next_state="verifier_output_bound",
            details=plain_details,
            recorded_at_unix=session.latest_record.recorded_at_unix,
        )
        inputs, _expected_v6 = self._material_inputs(
            fixture, session
        )
        operation = (
            session.begin_recovered_verifier_source_evidence()
        )
        material = operation.mint_material(**inputs)
        envelope = material.recovered_verifier_source_evidence
        operation.cancel()
        copied_details = {
            "verifier_output_sha256": (
                envelope["verifier_output_v4_sha256"]
            ),
            "recovered_verifier_source_evidence": envelope,
            "recovered_verifier_source_evidence_sha256": (
                journal.recovered_verifier_source_evidence_sha256(
                    envelope
                )
            ),
        }
        self.assert_code(
            "transaction_journal_recovered_verifier_operation_required",
            session.append_event,
            expected_state="staging_tombstone_acked",
            next_state="verifier_output_bound",
            details=copied_details,
            recorded_at_unix=envelope[
                "source_revalidation_receipt_v2"
            ]["revalidated_at_unix"],
        )

        previous = session.latest_record.to_dict()
        forged_value = journal._build_record(
            instance_slug=previous["instance_slug"],
            session_id=previous["session_id"],
            revision=previous["revision"] + 1,
            previous_record_sha256=previous["record_sha256"],
            state="verifier_output_bound",
            recorded_at_unix=previous["recorded_at_unix"],
            control_sha256=previous["control_sha256"],
            handoff_policy_sha256=previous[
                "handoff_policy_sha256"
            ],
            details=plain_details,
        )
        forged = journal.TransactionJournalRecord(forged_value)
        raw = journal._canonical_json(forged.to_dict()) + b"\n"
        descriptor = os.open(
            journal._event_filename(forged),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=session._directory_fd,
        )
        try:
            os.write(descriptor, raw)
            os.fsync(descriptor)
            os.fchmod(descriptor, journal.RECORD_FILE_MODE)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(session._directory_fd)
        session._store.close()
        self.assert_code(
            "transaction_journal_staging_cleanup_continuation_unsafe",
            fixture.fixture.open_store,
        )

        normal_fixture = self._new_fixture()
        normal_store = normal_fixture.fixture.open_store()
        normal = normal_fixture.fixture.reserve(
            normal_store, marker="9"
        )
        normal_fixture.fixture.advance_to_adoption_reconciled(
            normal, result="staging_absent"
        )
        normal.append_event(
            expected_state="adoption_reconciled",
            next_state="staging_tombstone_acked",
            details=(
                normal_fixture.fixture
                .staging_tombstone_acked_details(normal)
            ),
            recorded_at_unix=normal.latest_record.recorded_at_unix,
        )
        self.assert_code(
            "transaction_journal_recovered_verifier_ack_head_state_invalid",
            normal.begin_recovered_verifier_source_evidence,
        )

    def test_material_is_exact_type_pid_session_and_binding_bound(
        self,
    ) -> None:
        fixture = self._new_fixture()
        session = self._acked_session(fixture)
        inputs, _expected_v6 = self._material_inputs(
            fixture, session
        )
        operation = (
            session.begin_recovered_verifier_source_evidence()
        )
        material = operation.mint_material(**inputs)
        for capability in (operation, material):
            with self.assertRaises(TypeError):
                copy.copy(capability)
            with self.assertRaises(TypeError):
                copy.deepcopy(capability)
            with self.assertRaises(TypeError):
                pickle.dumps(capability)
        with self.assertRaises(TypeError):
            journal.RecoveredVerifierSourceEvidenceMaterial(
                _token=object(),
                session=session,
                session_binding=object(),
                operation=operation,
                head_record_sha256=self.digest("head"),
                envelope={},
            )
        with mock.patch.object(
            journal.os,
            "getpid",
            return_value=os.getpid() + 1,
        ):
            self.assert_code(
                (
                    "transaction_journal_recovered_verifier_"
                    "operation_creator_process_mismatch"
                ),
                operation.commit,
                material,
            )

        before_ack = copy.deepcopy(inputs)
        before_ack["verifier_request_v5"]["verified_at_unix"] = (
            session.latest_record.recorded_at_unix - 1
        )
        self.assert_code(
            (
                "transaction_journal_recovered_verifier_"
                "material_effect_precedes_ack"
            ),
            operation.mint_material,
            **before_ack,
        )

        bad_kind = copy.deepcopy(inputs)
        bad_kind["verifier_request_v5"][
            "capture_adoption_result"
        ]["kind"] = adoption_result.NORMAL_ADOPTION_KIND
        self.assert_code(
            "capture_adoption_result_kind_evidence_mismatch",
            operation.mint_material,
            **bad_kind,
        )
        bad_output = copy.deepcopy(inputs)
        bad_output["verifier_output_v4"]["evidence"][
            "capture_plan_sha256"
        ] = self.digest("other-plan")
        self.assert_code(
            (
                "transaction_journal_recovered_verifier_"
                "material_request_output_binding_mismatch"
            ),
            operation.mint_material,
            **bad_output,
        )
        bad_receipt = copy.deepcopy(inputs)
        bad_receipt["source_revalidation_receipt_v2"][
            "capture_adoption_provenance"
        ]["kind"] = adoption_result.NORMAL_ADOPTION_KIND
        self.assert_code(
            "capture_adoption_provenance_kind_schema_mismatch",
            operation.mint_material,
            **bad_receipt,
        )
        bad_lease = copy.deepcopy(inputs)
        bad_lease[
            "post_verifier_recovered_adoption_lease_binding"
        ]["capture_session_id"] = self.digest("other-session")
        self.assert_code(
            (
                "transaction_journal_recovered_verifier_"
                "material_ack_or_result_binding_mismatch"
            ),
            operation.mint_material,
            **bad_lease,
        )

        other_fixture = self._new_fixture()
        other_session = self._acked_session(other_fixture)
        other_operation = (
            other_session
            .begin_recovered_verifier_source_evidence()
        )
        self.assert_code(
            (
                "transaction_journal_recovered_verifier_"
                "material_operation_mismatch"
            ),
            other_operation.commit,
            material,
        )
        other_operation.cancel()
        operation.cancel()

    def test_run_id_is_request_bound_at_mint_and_on_disk_history(
        self,
    ) -> None:
        fixture = self._new_fixture()
        session = self._acked_session(fixture)
        inputs, _expected_v6 = self._material_inputs(
            fixture, session
        )
        operation = (
            session.begin_recovered_verifier_source_evidence()
        )
        hostile = copy.deepcopy(inputs)
        hostile["verifier_output_v4"]["evidence"]["run_id"] = (
            "different-run"
        )
        before = tuple(
            record.record_sha256 for record in session.records
        )
        self.assert_code(
            (
                "transaction_journal_recovered_verifier_"
                "material_request_output_binding_mismatch"
            ),
            operation.mint_material,
            **hostile,
        )
        self.assertEqual(
            tuple(record.record_sha256 for record in session.records),
            before,
        )
        operation.cancel()

        disk_fixture = self._new_fixture()
        disk_session = self._acked_session(disk_fixture)
        self._commit_material(disk_fixture, disk_session)
        head = disk_session.latest_record
        forged = head.to_dict()
        envelope = forged["details"][
            "recovered_verifier_source_evidence"
        ]
        envelope["expected_run_id"] = "different-run"
        forged["details"][
            "recovered_verifier_source_evidence_sha256"
        ] = journal._sha256(journal._canonical_json(envelope))
        forged = journal._build_record(
            instance_slug=forged["instance_slug"],
            session_id=forged["session_id"],
            revision=forged["revision"],
            previous_record_sha256=forged[
                "previous_record_sha256"
            ],
            state=forged["state"],
            recorded_at_unix=forged["recorded_at_unix"],
            control_sha256=forged["control_sha256"],
            handoff_policy_sha256=forged[
                "handoff_policy_sha256"
            ],
            details=forged["details"],
        )
        forged_name = (
            f"{forged['revision']:06d}-{forged['state']}-"
            f"{forged['record_sha256']}.json"
        )
        os.unlink(
            journal._event_filename(head),
            dir_fd=disk_session._directory_fd,
        )
        descriptor = os.open(
            forged_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            journal.RECORD_FILE_MODE,
            dir_fd=disk_session._directory_fd,
        )
        try:
            os.write(
                descriptor,
                journal._canonical_json(forged) + b"\n",
            )
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(disk_session._directory_fd)
        disk_session._store.close()
        self.assert_code(
            (
                "transaction_journal_recovered_verifier_"
                "envelope_expected_run_id_mismatch"
            ),
            disk_fixture.fixture.open_store,
        )

    def test_cancel_finalization_is_exact_idempotent_and_async_safe(
        self,
    ) -> None:
        original_set_state = (
            journal.RecoveredVerifierSourceEvidenceOperation
            ._set_state
        )
        original_release = (
            journal.TransactionJournalSession
            ._release_cancelled_recovered_verifier_operation
        )
        for window in (
            "before-state",
            "after-state",
            "before-release",
            "after-release",
        ):
            with self.subTest(window=window):
                fixture = self._new_fixture()
                session = self._acked_session(fixture)
                operation = (
                    session
                    .begin_recovered_verifier_source_evidence()
                )
                before = tuple(
                    record.record_sha256
                    for record in session.records
                )
                escape = KeyboardInterrupt(window)

                def interrupt_state(
                    selected, expected, replacement
                ):
                    if (
                        window == "before-state"
                        and expected == "open"
                        and replacement == "cancelled"
                    ):
                        raise escape
                    original_set_state(
                        selected, expected, replacement
                    )
                    if (
                        expected == "open"
                        and replacement == "cancelled"
                    ):
                        raise escape

                def interrupt_after_release(
                    selected_session, selected_operation
                ):
                    original_release(
                        selected_session, selected_operation
                    )
                    raise escape

                state_patch = (
                    mock.patch.object(
                        journal
                        .RecoveredVerifierSourceEvidenceOperation,
                        "_set_state",
                        new=interrupt_state,
                    )
                    if window in {"before-state", "after-state"}
                    else contextlib.nullcontext()
                )
                release_patch = (
                    mock.patch.object(
                        journal.TransactionJournalSession,
                        (
                            "_release_cancelled_recovered_"
                            "verifier_operation"
                        ),
                        side_effect=escape,
                    )
                    if window == "before-release"
                    else (
                        mock.patch.object(
                            journal.TransactionJournalSession,
                            (
                                "_release_cancelled_recovered_"
                                "verifier_operation"
                            ),
                            new=interrupt_after_release,
                        )
                        if window == "after-release"
                        else contextlib.nullcontext()
                    )
                )
                with state_patch, release_patch:
                    try:
                        operation.cancel()
                    except BaseException as caught:
                        self.assertIs(caught, escape)
                    else:
                        self.fail("cancel escape was swallowed")

                self.assertEqual(
                    operation.state,
                    (
                        "open"
                        if window == "before-state"
                        else "cancelled"
                    ),
                )
                self.assertEqual(
                    tuple(
                        record.record_sha256
                        for record in session.records
                    ),
                    before,
                )
                operation.cancel()
                self.assertEqual(operation.state, "cancelled")
                replacement = (
                    session
                    .begin_recovered_verifier_source_evidence()
                )
                self.assert_code(
                    (
                        "transaction_journal_recovered_verifier_"
                        "operation_invalid"
                    ),
                    operation.cancel,
                )
                self.assertEqual(replacement.state, "open")
                replacement.cancel()

    def test_durable_candidate_reconciliation_covers_every_projection(
        self,
    ) -> None:
        fixture = self._new_fixture()
        session = self._acked_session(fixture)
        inputs, expected_v6 = self._material_inputs(
            fixture, session
        )
        operation = (
            session.begin_recovered_verifier_source_evidence()
        )
        material = operation.mint_material(**inputs)
        original_commit = (
            journal.TransactionJournalSession._commit_candidate
        )

        def commit_then_report_failure(
            selected_session,
            candidate,
            *,
            fault_hook,
            _lifecycle_authorization=None,
        ):
            original_commit(
                selected_session,
                candidate,
                fault_hook=fault_hook,
                _lifecycle_authorization=(
                    _lifecycle_authorization
                ),
            )
            raise journal.TransactionJournalError(
                "injected_after_candidate_durable"
            )

        with mock.patch.object(
            journal.TransactionJournalSession,
            "_commit_candidate",
            new=commit_then_report_failure,
        ):
            output_clearance = operation.commit(material)
        self.assertEqual(
            output_clearance.head_state, "verifier_output_bound"
        )
        self.assertEqual(
            output_clearance.verified_evidence_v6, expected_v6
        )
        self.assertEqual(operation.state, "committed")
        self.assertFalse(session.recovery_required)

        with mock.patch.object(
            journal.TransactionJournalSession,
            "_commit_candidate",
            new=commit_then_report_failure,
        ):
            started = (
                session.advance_recovered_verifier_source_evidence()
            )
        self.assertEqual(
            started.head_state, "live_revalidation_started"
        )
        with mock.patch.object(
            journal.TransactionJournalSession,
            "_commit_candidate",
            new=commit_then_report_failure,
        ):
            complete = (
                session.advance_recovered_verifier_source_evidence()
            )
        self.assertEqual(
            complete.head_state,
            "live_revalidation_receipt_complete",
        )
        self.assertEqual(complete.verified_evidence_v6, expected_v6)
        self.assertFalse(session.recovery_required)

    def test_absent_candidate_retries_and_divergence_requires_recovery(
        self,
    ) -> None:
        fixture = self._new_fixture()
        session = self._acked_session(fixture)
        inputs, _expected_v6 = self._material_inputs(
            fixture, session
        )
        operation = (
            session.begin_recovered_verifier_source_evidence()
        )
        material = operation.mint_material(**inputs)
        absent = journal.TransactionJournalError(
            "injected_candidate_absent"
        )
        with mock.patch.object(
            journal.TransactionJournalSession,
            "_commit_candidate",
            side_effect=absent,
        ):
            with self.assertRaises(
                journal.TransactionJournalError
            ) as caught:
                operation.commit(material)
        self.assertIs(caught.exception, absent)
        self.assertEqual(session.state, "staging_tombstone_acked")
        self.assertEqual(operation.state, "failed")
        self.assertFalse(session.recovery_required)

        retry = session.begin_recovered_verifier_source_evidence()
        retry_material = retry.mint_material(**inputs)
        retry.commit(retry_material)
        self.assertEqual(session.state, "verifier_output_bound")
        with mock.patch.object(
            journal.TransactionJournalSession,
            "_commit_candidate",
            side_effect=absent,
        ):
            with self.assertRaises(
                journal.TransactionJournalError
            ) as caught:
                session.advance_recovered_verifier_source_evidence()
        self.assertIs(caught.exception, absent)
        self.assertEqual(session.state, "verifier_output_bound")
        self.assertFalse(session.recovery_required)
        session.advance_recovered_verifier_source_evidence()
        self.assertEqual(session.state, "live_revalidation_started")

        ambiguous_fixture = self._new_fixture()
        ambiguous_session = self._acked_session(ambiguous_fixture)
        ambiguous_inputs, _ = self._material_inputs(
            ambiguous_fixture, ambiguous_session
        )
        ambiguous_operation = (
            ambiguous_session
            .begin_recovered_verifier_source_evidence()
        )
        ambiguous_material = ambiguous_operation.mint_material(
            **ambiguous_inputs
        )
        original_scan = journal.TransactionJournalStore._scan_session
        scan_calls = 0

        def divergent_scan(store, *args, **kwargs):
            nonlocal scan_calls
            scan_calls += 1
            if scan_calls == 1:
                return original_scan(store, *args, **kwargs)
            return ()

        with (
            mock.patch.object(
                journal.TransactionJournalSession,
                "_commit_candidate",
                side_effect=journal.TransactionJournalError(
                    "injected_ambiguous_candidate"
                ),
            ),
            mock.patch.object(
                journal.TransactionJournalStore,
                "_scan_session",
                new=divergent_scan,
            ),
        ):
            self.assert_code(
                (
                    "transaction_journal_recovered_verifier_"
                    "commit_ambiguous"
                ),
                ambiguous_operation.commit,
                ambiguous_material,
            )
        self.assertTrue(ambiguous_session.recovery_required)
        self.assertEqual(
            ambiguous_operation.state, "recovery_required"
        )

    def test_preappend_interrupt_preserves_identity_and_releases_old_head(
        self,
    ) -> None:
        original_begin = (
            journal.RecoveredVerifierSourceEvidenceOperation
            ._begin_finalization
        )
        for window in ("before-phase", "after-phase"):
            with self.subTest(window=window):
                fixture = self._new_fixture()
                session = self._acked_session(fixture)
                inputs, _expected_v6 = self._material_inputs(
                    fixture, session
                )
                operation = (
                    session
                    .begin_recovered_verifier_source_evidence()
                )
                material = operation.mint_material(**inputs)
                escape = KeyboardInterrupt(window)

                def interrupt(selected, candidate_sha256):
                    if window == "after-phase":
                        original_begin(
                            selected, candidate_sha256
                        )
                    raise escape

                with mock.patch.object(
                    journal.RecoveredVerifierSourceEvidenceOperation,
                    "_begin_finalization",
                    new=interrupt,
                ):
                    try:
                        operation.commit(material)
                    except BaseException as caught:
                        self.assertIs(caught, escape)
                    else:
                        self.fail("pre-append escape was swallowed")
                self.assertEqual(operation.state, "failed")
                self.assertEqual(
                    session.state, "staging_tombstone_acked"
                )
                replacement = (
                    session
                    .begin_recovered_verifier_source_evidence()
                )
                replacement.cancel()

    def test_finalization_interrupt_windows_resume_without_new_effect(
        self,
    ) -> None:
        original_set_state = (
            journal.RecoveredVerifierSourceEvidenceOperation
            ._set_state
        )
        for window in ("final-state", "reservation-release"):
            with self.subTest(window=window):
                fixture = self._new_fixture()
                session = self._acked_session(fixture)
                inputs, expected_v6 = self._material_inputs(
                    fixture, session
                )
                operation = (
                    session
                    .begin_recovered_verifier_source_evidence()
                )
                material = operation.mint_material(**inputs)
                escape = KeyboardInterrupt(window)

                def interrupt_final_state(
                    selected, expected, replacement
                ):
                    if (
                        expected == "committing"
                        and replacement == "committed"
                    ):
                        raise escape
                    return original_set_state(
                        selected, expected, replacement
                    )

                state_patch = (
                    mock.patch.object(
                        journal
                        .RecoveredVerifierSourceEvidenceOperation,
                        "_set_state",
                        new=interrupt_final_state,
                    )
                    if window == "final-state"
                    else contextlib.nullcontext()
                )
                release_patch = (
                    mock.patch.object(
                        journal.TransactionJournalSession,
                        (
                            "_release_committed_recovered_"
                            "verifier_operation"
                        ),
                        side_effect=escape,
                    )
                    if window == "reservation-release"
                    else contextlib.nullcontext()
                )
                with state_patch, release_patch:
                    try:
                        operation.commit(material)
                    except BaseException as caught:
                        self.assertIs(caught, escape)
                    else:
                        self.fail("finalization escape was swallowed")
                self.assertEqual(
                    session.state, "verifier_output_bound"
                )
                before = len(session.records)
                recovered = (
                    session
                    .recover_recovered_verified_evidence_v6()
                )
                self.assertEqual(len(session.records), before)
                self.assertEqual(
                    recovered.verified_evidence_v6, expected_v6
                )

    def test_pinned_finalization_self_reconciles_exact_successor_only(
        self,
    ) -> None:
        original_set_state = (
            journal.RecoveredVerifierSourceEvidenceOperation
            ._set_state
        )
        for window in ("final-state", "reservation-release"):
            with self.subTest(window=window):
                fixture = self._new_fixture()
                session = self._acked_session(fixture)
                inputs, expected_v6 = self._material_inputs(
                    fixture, session
                )
                operation = (
                    session
                    .begin_recovered_verifier_source_evidence()
                )
                material = operation.mint_material(**inputs)
                escape = KeyboardInterrupt(window)

                def interrupt_final_state(
                    selected, expected, replacement
                ):
                    if (
                        expected == "committing"
                        and replacement == "committed"
                    ):
                        raise escape
                    return original_set_state(
                        selected, expected, replacement
                    )

                state_patch = (
                    mock.patch.object(
                        journal
                        .RecoveredVerifierSourceEvidenceOperation,
                        "_set_state",
                        new=interrupt_final_state,
                    )
                    if window == "final-state"
                    else contextlib.nullcontext()
                )
                release_patch = (
                    mock.patch.object(
                        journal.TransactionJournalSession,
                        (
                            "_release_committed_recovered_"
                            "verifier_operation"
                        ),
                        side_effect=escape,
                    )
                    if window == "reservation-release"
                    else contextlib.nullcontext()
                )
                with (
                    state_patch,
                    release_patch,
                    mock.patch.object(
                        journal.TransactionJournalSession,
                        (
                            "_reconcile_recovered_verifier_"
                            "commit_finalization"
                        ),
                        return_value=None,
                    ),
                ):
                    try:
                        operation.commit(material)
                    except BaseException as caught:
                        self.assertIs(caught, escape)
                    else:
                        self.fail("stale finalization was not injected")

                before = len(session.records)
                recovered = (
                    session
                    .recover_recovered_verified_evidence_v6()
                )
                self.assertEqual(len(session.records), before)
                self.assertEqual(
                    recovered.verified_evidence_v6, expected_v6
                )
                session.advance_recovered_verifier_source_evidence()
                session.advance_recovered_verifier_source_evidence()
                completed = len(session.records)
                self.assertEqual(
                    session.state,
                    "live_revalidation_receipt_complete",
                )
                self.assertEqual(
                    session
                    .advance_recovered_verifier_source_evidence()
                    .verified_evidence_v6,
                    expected_v6,
                )
                self.assertEqual(len(session.records), completed)

    def test_stale_finalization_requires_exact_candidate_and_not_open(
        self,
    ) -> None:
        open_fixture = self._new_fixture()
        open_session = self._acked_session(open_fixture)
        open_operation = (
            open_session.begin_recovered_verifier_source_evidence()
        )
        self.assert_code(
            (
                "transaction_journal_recovered_verifier_"
                "operation_reserved"
            ),
            open_session.recover_recovered_verified_evidence_v6,
        )
        self.assertEqual(open_operation.state, "open")
        open_operation.cancel()

        mismatch_fixture = self._new_fixture()
        mismatch_session = self._acked_session(mismatch_fixture)
        mismatch_inputs, _ = self._material_inputs(
            mismatch_fixture, mismatch_session
        )
        mismatch_operation = (
            mismatch_session
            .begin_recovered_verifier_source_evidence()
        )
        mismatch_material = mismatch_operation.mint_material(
            **mismatch_inputs
        )
        escape = KeyboardInterrupt("pin committed operation")
        with (
            mock.patch.object(
                journal.TransactionJournalSession,
                (
                    "_release_committed_recovered_"
                    "verifier_operation"
                ),
                side_effect=escape,
            ),
            mock.patch.object(
                journal.TransactionJournalSession,
                (
                    "_reconcile_recovered_verifier_"
                    "commit_finalization"
                ),
                return_value=None,
            ),
        ):
            try:
                mismatch_operation.commit(mismatch_material)
            except BaseException as caught:
                self.assertIs(caught, escape)
            else:
                self.fail("committed operation was not pinned")
        original_contents = (
            journal.RecoveredVerifierSourceEvidenceOperation
            ._contents_for_finalization
        )

        def wrong_expected_successor(selected):
            contents = original_contents(selected)
            return (
                *contents[:4],
                self.digest("other-successor"),
                contents[5],
            )

        with mock.patch.object(
            journal.RecoveredVerifierSourceEvidenceOperation,
            "_contents_for_finalization",
            new=wrong_expected_successor,
        ):
            self.assert_code(
                (
                    "transaction_journal_recovered_verifier_"
                    "operation_reserved"
                ),
                (
                    mismatch_session
                    .recover_recovered_verified_evidence_v6
                ),
            )
        self.assertEqual(mismatch_operation.state, "committed")
        mismatch_session.recover_recovered_verified_evidence_v6()

    def test_async_escape_identity_is_preserved_and_never_pins_operation(
        self,
    ) -> None:
        old_fixture = self._new_fixture()
        old_session = self._acked_session(old_fixture)
        old_inputs, _ = self._material_inputs(
            old_fixture, old_session
        )
        old_operation = (
            old_session.begin_recovered_verifier_source_evidence()
        )
        old_material = old_operation.mint_material(**old_inputs)
        old_escape = KeyboardInterrupt("injected_before_candidate")
        with mock.patch.object(
            journal.TransactionJournalSession,
            "_commit_candidate",
            side_effect=old_escape,
        ):
            try:
                old_operation.commit(old_material)
            except BaseException as caught:
                self.assertIs(caught, old_escape)
            else:
                self.fail("async escape was not re-raised")
        self.assertEqual(old_operation.state, "failed")
        self.assertFalse(old_session.recovery_required)
        replacement = (
            old_session.begin_recovered_verifier_source_evidence()
        )
        replacement.cancel()

        durable_fixture = self._new_fixture()
        durable_session = self._acked_session(durable_fixture)
        durable_inputs, expected_v6 = self._material_inputs(
            durable_fixture, durable_session
        )
        durable_operation = (
            durable_session
            .begin_recovered_verifier_source_evidence()
        )
        durable_material = durable_operation.mint_material(
            **durable_inputs
        )
        original_commit = (
            journal.TransactionJournalSession._commit_candidate
        )
        durable_escape = KeyboardInterrupt(
            "injected_after_candidate_durable"
        )

        def commit_then_interrupt(
            selected_session,
            candidate,
            *,
            fault_hook,
            _lifecycle_authorization=None,
        ):
            original_commit(
                selected_session,
                candidate,
                fault_hook=fault_hook,
                _lifecycle_authorization=(
                    _lifecycle_authorization
                ),
            )
            raise durable_escape

        with mock.patch.object(
            journal.TransactionJournalSession,
            "_commit_candidate",
            new=commit_then_interrupt,
        ):
            try:
                durable_operation.commit(durable_material)
            except BaseException as caught:
                self.assertIs(caught, durable_escape)
            else:
                self.fail("durable async escape was swallowed")
        self.assertEqual(
            durable_operation.state, "interrupted_reconciled"
        )
        self.assertEqual(
            durable_session.state, "verifier_output_bound"
        )
        self.assertFalse(durable_session.recovery_required)
        recovered = (
            durable_session.recover_recovered_verified_evidence_v6()
        )
        self.assertEqual(recovered.verified_evidence_v6, expected_v6)

        advance_escape = SystemExit(
            "injected_after_projection_durable"
        )

        def advance_then_interrupt(
            selected_session,
            candidate,
            *,
            fault_hook,
            _lifecycle_authorization=None,
        ):
            original_commit(
                selected_session,
                candidate,
                fault_hook=fault_hook,
                _lifecycle_authorization=(
                    _lifecycle_authorization
                ),
            )
            raise advance_escape

        with mock.patch.object(
            journal.TransactionJournalSession,
            "_commit_candidate",
            new=advance_then_interrupt,
        ):
            try:
                (
                    durable_session
                    .advance_recovered_verifier_source_evidence()
                )
            except BaseException as caught:
                self.assertIs(caught, advance_escape)
            else:
                self.fail("projection async escape was swallowed")
        self.assertEqual(
            durable_session.state, "live_revalidation_started"
        )
        self.assertEqual(
            durable_session
            .recover_recovered_verified_evidence_v6()
            .verified_evidence_v6,
            expected_v6,
        )


if __name__ == "__main__":
    unittest.main()
