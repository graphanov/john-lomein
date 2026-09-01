from __future__ import annotations

import copy
import inspect
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
    john_lomein_persona_qualification_capture_staging as staging,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_transaction_journal as journal,
)
import test_persona_qualification_transaction_journal as _journal_tests  # noqa: E402


class RecoveredAdoptionContinuationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = (
            _journal_tests.PersonaQualificationTransactionJournalTests(
            "test_journal_mints_recovered_adoption_evidence_from_live_head"
        )
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def _append_fixture_state(
        self,
        session: journal.TransactionJournalSession,
        state: str,
    ) -> journal.TransactionJournalRecord:
        protected = {
            "child_running",
            "capture_ready",
            "lifecycle_clearance_intent",
            "lifecycle_scope_empty",
        }
        append = (
            session._append_event_for_history_validation_test
            if state in protected
            else session.append_event
        )
        return append(
            expected_state=session.state,
            next_state=state,
            details=self.fixture.details_for(session, state),
            recorded_at_unix=session.latest_record.revision + 1,
        )

    def _build_real_recovered_head(
        self,
    ) -> tuple[
        journal.TransactionJournalSession,
        Path,
        dict,
    ]:
        store = self.fixture.open_store()
        session = self.fixture.reserve(store)
        shared_root = self.fixture.root / "capture-staging"
        shared_root.mkdir(mode=staging.SHARED_ROOT_MODE)
        shared_root.chmod(staging.SHARED_ROOT_MODE)

        intent = session.append_event(
            expected_state="reserved",
            next_state="staging_create_intent",
            details={
                "staging_leaf_name": (
                    f"session-{session.session_id}"
                ),
                "capture_uid": os.geteuid(),
                "export_gid": os.getegid(),
                "required_device": shared_root.stat().st_dev,
            },
            recorded_at_unix=2,
        )
        staging_lease = staging._create_session_staging_for_test(
            shared_root,
            session_id=session.session_id,
            staging_transaction_intent_sha256=(
                intent.record_sha256
            ),
        )
        self.assertIsInstance(
            staging_lease, staging.CaptureStagingLease
        )
        assert isinstance(
            staging_lease, staging.CaptureStagingLease
        )
        session.append_event(
            expected_state="staging_create_intent",
            next_state="staging_exposed",
            details={
                "staging_exposure_receipt": (
                    staging_lease.exposure_receipt
                ),
                "staging_exposure_receipt_sha256": (
                    staging_lease.exposure_receipt_sha256
                ),
            },
            recorded_at_unix=3,
        )

        staging_lease.record_spawn_intent()
        self._append_fixture_state(session, "child_launch_intent")
        staging_lease.record_spawned()
        self._append_fixture_state(session, "child_running")
        self._append_fixture_state(session, "capture_ready")
        staging_lease.record_ready_bound()
        self._append_fixture_state(
            session, "lifecycle_clearance_intent"
        )
        scope_empty = self._append_fixture_state(
            session, "lifecycle_scope_empty"
        )
        staging_lease.mark_process_scope_dead(
            lifecycle_scope_empty_receipt_sha256=(
                scope_empty.details[
                    "lifecycle_clearance_bundle"
                ]["scope_empty_receipt_sha256"]
            ),
            outer_lifecycle_clearance_record_sha256=(
                scope_empty.record_sha256
            ),
        )
        self._append_fixture_state(session, "adoption_intent")
        terminal = staging_lease.finish_success()
        self.assertEqual(terminal.disposition, "absent")
        pending = session.append_event(
            expected_state="adoption_intent",
            next_state="staging_tombstone_ack_pending",
            details={
                "from_state": "adoption_intent",
                "effect_origin_state": "adoption_intent",
                "terminal_disposition": "absent",
                "terminal_receipt": terminal.terminal_receipt,
                "terminal_receipt_sha256": (
                    terminal.terminal_receipt_sha256
                ),
                "tombstone_sha256": terminal.tombstone_sha256,
                "staging_quarantine_intent_record_sha256": None,
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        adoption_intent = next(
            record
            for record in session.records
            if record.state == "adoption_intent"
        )
        session.append_event(
            expected_state="staging_tombstone_ack_pending",
            next_state="adoption_reconciliation_required",
            details={
                "from_state": "staging_tombstone_ack_pending",
                "adoption_intent_record_sha256": (
                    adoption_intent.record_sha256
                ),
                "terminal_receipt_sha256": (
                    terminal.terminal_receipt_sha256
                ),
                "tombstone_sha256": terminal.tombstone_sha256,
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        reconciled_details = (
            self.fixture.adoption_reconciled_details(
                session, result="recovered_adoption"
            )
        )
        session.append_event(
            expected_state="adoption_reconciliation_required",
            next_state="adoption_reconciled",
            details=reconciled_details,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        return session, shared_root, {
            "pending": pending,
            "terminal": terminal,
            "reconciled_details": reconciled_details,
        }

    def test_context_and_reserved_commit_use_exact_durable_successor(
        self,
    ) -> None:
        session, shared_root, built = (
            self._build_real_recovered_head()
        )
        session._store.close()
        reopened = self.fixture.open_store()
        recovered_sessions = reopened.load_incomplete_sessions()
        self.assertEqual(len(recovered_sessions), 1)
        session = recovered_sessions[0]
        self.assertEqual(
            tuple(
                inspect.signature(
                    session.mint_recovered_adoption_journal_context
                ).parameters
            ),
            (),
        )
        context = (
            session.mint_recovered_adoption_journal_context()
        )
        self.assertIsInstance(
            context, journal.RecoveredAdoptionJournalContext
        )
        pre_binding = context.journal_binding
        self.assertEqual(
            pre_binding["schema_version"],
            journal.RECOVERED_ADOPTION_LEASE_BINDING_V2_SCHEMA,
        )
        self.assertEqual(
            pre_binding["transaction_journal_head_state"],
            "adoption_reconciled",
        )
        self.assertIsNone(
            pre_binding[
                "staging_tombstone_acked_record_sha256"
            ]
        )
        continuation = context.recovered_adoption_continuation
        self.assertEqual(
            continuation[
                "pre_ack_recovered_adoption_lease_binding"
            ],
            pre_binding,
        )
        self.assertEqual(
            journal.normalize_recovered_adoption_continuation(
                continuation
            ),
            continuation,
        )

        direct = self.fixture.staging_tombstone_acked_details(
            session
        )
        direct["recovered_adoption_continuation"] = continuation
        self.fixture.assert_code(
            (
                "transaction_journal_"
                "recovered_adoption_ack_operation_required"
            ),
            session.append_event,
            expected_state="adoption_reconciled",
            next_state="staging_tombstone_acked",
            details=direct,
            recorded_at_unix=session.latest_record.revision + 1,
        )

        operation = (
            session.begin_recovered_adoption_tombstone_ack()
        )
        self.fixture.assert_code(
            (
                "transaction_journal_"
                "installed_capture_staging_control_required"
            ),
            operation.commit,
            shared_root,
        )
        control = (
            staging._open_installed_capture_staging_control_for_test(
                shared_root
            )
        )
        self.assertIsInstance(
            control, staging.InstalledCaptureStagingControl
        )
        descriptor = control._descriptor_number_for_test()
        self.assertFalse(os.get_inheritable(descriptor))
        with mock.patch.object(
            staging,
            "_open_shared_root",
            side_effect=AssertionError(
                "commit must not reopen a caller path"
            ),
        ):
            clearance = operation.commit(control)

        self.assertIsInstance(
            clearance,
            journal.RecoveredAdoptionContinuationClearance,
        )
        committed = clearance.committed_record
        self.assertEqual(committed.state, "staging_tombstone_acked")
        self.assertEqual(session.latest_record.to_dict(), committed.to_dict())
        self.assertEqual(
            clearance.recovered_adoption_continuation,
            continuation,
        )
        self.assertEqual(
            committed.details["terminal_receipt_sha256"],
            built["terminal"].terminal_receipt_sha256,
        )
        self.assertEqual(
            committed.details[
                "outer_ack_pending_record_sha256"
            ],
            built["pending"].record_sha256,
        )
        post_context = (
            session.mint_recovered_adoption_journal_context()
        )
        post_binding = post_context.journal_binding
        self.assertEqual(
            post_binding["transaction_journal_head_state"],
            "staging_tombstone_acked",
        )
        self.assertEqual(
            post_binding[
                "staging_tombstone_acked_record_sha256"
            ],
            committed.record_sha256,
        )
        self.assertEqual(
            post_binding["transaction_journal_head_revision"],
            pre_binding["transaction_journal_head_revision"] + 1,
        )
        with mock.patch.object(
            journal.os,
            "getpid",
            return_value=os.getpid() + 1,
        ):
            self.fixture.assert_code(
                (
                    "transaction_journal_"
                    "recovered_adoption_context_creator_process_mismatch"
                ),
                lambda: post_context.journal_binding,
            )
        self.assertFalse(control.active)
        self.fixture.assert_code(
            (
                "transaction_journal_"
                "recovered_adoption_ack_operation_invalid"
            ),
            operation.commit,
            staging._open_installed_capture_staging_control_for_test(
                shared_root
            ),
        )
        session.append_event(
            expected_state="staging_tombstone_acked",
            next_state="operator_attention",
            details={
                "from_state": "staging_tombstone_acked",
                "reason_code": "post_ack_continuation_not_integrated",
                "incident_sha256": committed.record_sha256,
            },
            recorded_at_unix=committed.recorded_at_unix,
        )
        self.fixture.assert_code(
            (
                "transaction_journal_"
                "recovered_adoption_context_head_state_invalid"
            ),
            session.mint_recovered_adoption_journal_context,
        )
        self.assertEqual(
            clearance.committed_record_sha256,
            committed.record_sha256,
        )

    def test_capabilities_are_nonconstructible_linear_and_inert(
        self,
    ) -> None:
        session, shared_root, _built = (
            self._build_real_recovered_head()
        )
        context = (
            session.mint_recovered_adoption_journal_context()
        )
        operation = (
            session.begin_recovered_adoption_tombstone_ack()
        )
        control = (
            staging._open_installed_capture_staging_control_for_test(
                shared_root
            )
        )
        for capability in (context, operation, control):
            with self.assertRaises(TypeError):
                copy.copy(capability)
            with self.assertRaises(TypeError):
                copy.deepcopy(capability)
            with self.assertRaises(TypeError):
                pickle.dumps(capability)
        with self.assertRaises(TypeError):
            journal.RecoveredAdoptionJournalContext(
                _token=object(),
                session=session,
                session_binding=object(),
                evidence={},
                result={},
                provenance={},
                journal_binding={},
                continuation={},
            )
        with self.assertRaises(TypeError):
            staging.InstalledCaptureStagingControl(
                _token=object(),
                root_fd=-1,
                root_identity_sha256="0" * 64,
                root_stat_sha256="0" * 64,
                device=0,
                identities=object(),
            )
        operation.cancel()
        self.assertEqual(operation.state, "cancelled")
        self.assertTrue(control.active)
        control.close()
        self.assertFalse(control.active)
        self.assertFalse(journal.PRODUCTION_ACTIVATION)
        self.assertFalse(staging.PRODUCTION_ACTIVATION)

    def test_staging_ack_without_outer_candidate_is_idempotently_retryable(
        self,
    ) -> None:
        session, shared_root, _built = (
            self._build_real_recovered_head()
        )
        operation = (
            session.begin_recovered_adoption_tombstone_ack()
        )
        control = (
            staging._open_installed_capture_staging_control_for_test(
                shared_root
            )
        )
        injected = journal.TransactionJournalError(
            "injected_outer_candidate_absent"
        )
        with mock.patch.object(
            journal.TransactionJournalSession,
            "_commit_candidate",
            side_effect=injected,
        ):
            with self.assertRaises(
                journal.TransactionJournalError
            ) as caught:
                operation.commit(control)
        self.assertIs(caught.exception, injected)
        self.assertEqual(session.state, "adoption_reconciled")
        self.assertFalse(session.recovery_required)
        self.assertEqual(operation.state, "failed")

        retry = session.begin_recovered_adoption_tombstone_ack()
        retry_control = (
            staging._open_installed_capture_staging_control_for_test(
                shared_root
            )
        )
        clearance = retry.commit(retry_control)
        self.assertEqual(
            clearance.committed_record.state,
            "staging_tombstone_acked",
        )

    def test_non_domain_staging_escape_cannot_strand_reservation(
        self,
    ) -> None:
        session, shared_root, _built = (
            self._build_real_recovered_head()
        )
        operation = (
            session.begin_recovered_adoption_tombstone_ack()
        )
        control = (
            staging._open_installed_capture_staging_control_for_test(
                shared_root
            )
        )
        injected = KeyboardInterrupt(
            "injected_non_domain_staging_escape"
        )
        with mock.patch.object(
            staging,
            "_acknowledge_terminal_impl",
            side_effect=injected,
        ):
            try:
                operation.commit(control)
            except BaseException as caught:
                self.assertIs(caught, injected)
            else:
                self.fail("non-domain staging escape was not re-raised")
        self.assertEqual(operation.state, "failed")
        self.assertFalse(control.active)
        self.assertEqual(session.state, "adoption_reconciled")
        self.assertFalse(session.recovery_required)

        retry = session.begin_recovered_adoption_tombstone_ack()
        self.assertEqual(retry.state, "open")
        retry.cancel()

    def test_durable_candidate_is_reconciled_before_clearance(
        self,
    ) -> None:
        session, shared_root, _built = (
            self._build_real_recovered_head()
        )
        operation = (
            session.begin_recovered_adoption_tombstone_ack()
        )
        control = (
            staging._open_installed_capture_staging_control_for_test(
                shared_root
            )
        )
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
                "injected_after_outer_candidate_durable"
            )

        with mock.patch.object(
            journal.TransactionJournalSession,
            "_commit_candidate",
            new=commit_then_report_failure,
        ):
            clearance = operation.commit(control)
        self.assertEqual(operation.state, "committed")
        self.assertEqual(
            clearance.committed_record.to_dict(),
            session.latest_record.to_dict(),
        )
        self.assertFalse(session.recovery_required)

    def test_legacy_reconciliation_ack_forbids_recovered_continuation(
        self,
    ) -> None:
        recovered, _shared_root, _built = (
            self._build_real_recovered_head()
        )
        continuation = (
            recovered.mint_recovered_adoption_journal_context()
            .recovered_adoption_continuation
        )

        normal_root = self.fixture.root / "legacy-normal"
        anchor, store_path = self.fixture.make_layout(normal_root)
        store = self.fixture.open_store(store_path, anchor)
        normal = self.fixture.reserve(store, marker="2")
        self.fixture.advance_to_adoption_reconciled(
            normal, result="staging_absent"
        )
        acked = self.fixture.staging_tombstone_acked_details(
            normal
        )
        acked["recovered_adoption_continuation"] = continuation
        self.fixture.assert_code(
            (
                "transaction_journal_"
                "recovered_adoption_continuation_forbidden"
            ),
            normal._append_event_for_history_validation_test,
            expected_state="adoption_reconciled",
            next_state="staging_tombstone_acked",
            details=acked,
            recorded_at_unix=normal.latest_record.revision + 1,
        )


if __name__ == "__main__":
    unittest.main()
