from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
import pickle
import stat
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import test_persona_qualification_adoption_recovery as recovery_tests  # noqa: E402
import test_persona_qualification_recovered_adoption_continuation as continuation_tests  # noqa: E402
import test_persona_qualification_transaction_journal as journal_tests  # noqa: E402
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_adoption_recovery as recovery,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_staging as staging,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_transaction_journal as journal,
)


class PersonaQualificationAdoptionRecoveryV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.journal_fixture = (
            journal_tests.PersonaQualificationTransactionJournalTests(
                "runTest"
            )
        )
        self.journal_fixture.setUp()
        self.addCleanup(self.journal_fixture.doCleanups)
        # The real recovered-continuation builder calls this support fixture
        # through ``self.fixture``.
        self.fixture = self.journal_fixture

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(
            recovery.RecoveredAdoptionRecoveryError
        ) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def _append_fixture_state(
        self,
        session: journal.TransactionJournalSession,
        state: str,
    ) -> journal.TransactionJournalRecord:
        return (
            continuation_tests.RecoveredAdoptionContinuationTests
            ._append_fixture_state(self, session, state)
        )

    def _build_real_recovered_head(
        self,
    ) -> tuple[
        journal.TransactionJournalSession,
        Path,
        dict,
    ]:
        store = self.journal_fixture.open_store()
        session = self.journal_fixture.reserve(store)
        shared_root = (
            self.journal_fixture.root / "capture-staging"
        )
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
                "export_gid": self.object_fixture.export_gid,
                "required_device": shared_root.stat().st_dev,
            },
            recorded_at_unix=2,
        )
        staging_lease = staging._create_impl(
            shared_root,
            session_id=session.session_id,
            staging_transaction_intent_sha256=(
                intent.record_sha256
            ),
            identities=staging._StagingIdentities(
                root_uid=os.geteuid(),
                root_gid=os.getegid(),
                capture_uid=os.geteuid(),
                export_gid=self.object_fixture.export_gid,
            ),
            required_device=None,
            strict_parent_chain=False,
            fault_hook=None,
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
            self.journal_fixture.adoption_reconciled_details(
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

    @staticmethod
    def _canonical_json(value) -> bytes:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")

    @classmethod
    def _object_identity_sha256(
        cls, info: os.stat_result
    ) -> str:
        return hashlib.sha256(
            cls._canonical_json(
                [
                    int(info.st_dev),
                    int(info.st_ino),
                    int(stat.S_IFMT(info.st_mode)),
                ]
            )
        ).hexdigest()

    @classmethod
    def _full_stat_sha256(cls, info: os.stat_result) -> str:
        return hashlib.sha256(
            cls._canonical_json(
                [
                    int(info.st_dev),
                    int(info.st_ino),
                    int(info.st_mode),
                    int(info.st_uid),
                    int(info.st_gid),
                    int(info.st_nlink),
                    int(info.st_size),
                    int(
                        getattr(
                            info,
                            "st_mtime_ns",
                            int(info.st_mtime * 1_000_000_000),
                        )
                    ),
                    int(
                        getattr(
                            info,
                            "st_ctime_ns",
                            int(info.st_ctime * 1_000_000_000),
                        )
                    ),
                ]
            )
        ).hexdigest()

    def _make_object_fixture(self) -> SimpleNamespace:
        owner_uid = os.geteuid()
        verifier_gid = os.getegid()
        if verifier_gid == 0:
            if owner_uid != 0:
                self.skipTest(
                    "unprivileged process has no positive effective group"
                )
            verifier_gid = 1
        export_gid = next(
            (
                group
                for group in os.getgroups()
                if group > 0 and group != verifier_gid
            ),
            None,
        )
        if export_gid is None:
            self.skipTest(
                "recovered v2 staging requires a distinct usable group"
            )
        final_name = "opaque-capture-" + "a" * 32
        final_parent = self.journal_fixture.root / "final-captures"
        capture_root = final_parent / final_name
        nested = capture_root / "nested"
        final_parent.mkdir()
        capture_root.mkdir()
        nested.mkdir()
        root_bytes = b"john-lomein-v2\n"
        nested_bytes = b"recovered-object-v2\n"
        root_file = capture_root / "identity.txt"
        nested_file = nested / "result.bin"
        root_file.write_bytes(root_bytes)
        nested_file.write_bytes(nested_bytes)
        for path in (
            final_parent,
            capture_root,
            nested,
            root_file,
            nested_file,
        ):
            current = path.stat()
            if (
                int(current.st_uid) != owner_uid
                or int(current.st_gid) != verifier_gid
            ):
                os.chown(path, owner_uid, verifier_gid)
        root_file.chmod(recovery.ADOPTED_FILE_MODE)
        nested_file.chmod(recovery.ADOPTED_FILE_MODE)
        nested.chmod(recovery.ADOPTED_DIRECTORY_MODE)
        capture_root.chmod(recovery.ADOPTED_DIRECTORY_MODE)
        final_parent.chmod(recovery.FINAL_PARENT_MODE)

        def make_writable_for_cleanup() -> None:
            if not final_parent.exists():
                return
            for directory, directories, files in os.walk(
                final_parent,
                topdown=True,
                followlinks=False,
            ):
                Path(directory).chmod(0o700)
                for name in directories:
                    (Path(directory) / name).chmod(0o700)
                for name in files:
                    (Path(directory) / name).chmod(0o600)

        self.addCleanup(make_writable_for_cleanup)
        parent_info = final_parent.stat()
        root_info = capture_root.stat()
        records = [
            {"path": "", "type": "directory"},
            {
                "path": "identity.txt",
                "type": "file",
                "size": len(root_bytes),
                "sha256": hashlib.sha256(root_bytes).hexdigest(),
            },
            {"path": "nested", "type": "directory"},
            {
                "path": "nested/result.bin",
                "type": "file",
                "size": len(nested_bytes),
                "sha256": hashlib.sha256(
                    nested_bytes
                ).hexdigest(),
            },
        ]
        limits = {
            "max_files": 10,
            "max_directories": 10,
            "max_bytes": 10_000,
            "max_file_bytes": 1_000,
            "max_depth": 8,
        }
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        parent_fd = os.open(final_parent, flags)
        fixture = SimpleNamespace(
            owner_uid=owner_uid,
            verifier_gid=verifier_gid,
            export_gid=export_gid,
            final_name=final_name,
            final_parent=final_parent,
            capture_root=capture_root,
            root_file=root_file,
            nested_file=nested_file,
            parent_fd=parent_fd,
            parent_identity_sha256=self._object_identity_sha256(
                parent_info
            ),
            filesystem_device=int(parent_info.st_dev),
            object_identity_sha256=self._object_identity_sha256(
                root_info
            ),
            object_stat_sha256=self._full_stat_sha256(root_info),
            object_nlink=int(root_info.st_nlink),
            inventory_sha256=hashlib.sha256(
                self._canonical_json(
                    sorted(records, key=lambda item: item["path"])
                )
            ).hexdigest(),
            file_count=2,
            directory_count=2,
            total_bytes=len(root_bytes) + len(nested_bytes),
            largest_file_bytes=max(
                len(root_bytes), len(nested_bytes)
            ),
            maximum_depth=1,
            limits=limits,
        )

        def close_parent_fd() -> None:
            if fixture.parent_fd >= 0:
                os.close(fixture.parent_fd)
                fixture.parent_fd = -1

        self.addCleanup(close_parent_fd)
        (
            recovery_tests.PersonaQualificationAdoptionRecoveryTests
            .bind_journal_fixture(self, fixture)
        )
        self.object_fixture = fixture
        (
            fixture.session,
            fixture.shared_root,
            fixture.recovered_build,
        ) = self._build_real_recovered_head()
        return fixture

    def _recover(
        self, fixture: SimpleNamespace
    ) -> recovery.RecoveredAdoptedCaptureLeaseV2:
        return recovery._recover_adopted_capture_v2_for_test(
            fixture.session,
            fixture.parent_fd,
            expected_owner_uid=fixture.owner_uid,
            expected_verifier_gid=fixture.verifier_gid,
        )

    @staticmethod
    def _control(
        fixture: SimpleNamespace,
    ) -> staging.InstalledCaptureStagingControl:
        return staging._open_installed_capture_staging_control_impl(
            fixture.shared_root,
            identities=staging._StagingIdentities(
                root_uid=os.geteuid(),
                root_gid=os.getegid(),
                capture_uid=os.geteuid(),
                export_gid=fixture.export_gid,
            ),
            required_device=None,
            strict_parent_chain=False,
        )

    def _commit(
        self,
        fixture: SimpleNamespace,
        lease: recovery.RecoveredAdoptedCaptureLeaseV2,
    ) -> journal.RecoveredAdoptionContinuationClearance:
        return lease.begin_outer_ack().commit(
            self._control(fixture)
        )

    def test_shared_contract_entry_shapes_and_activation_are_inert(
        self,
    ) -> None:
        self.assertEqual(
            recovery.RECOVERED_ADOPTION_LEASE_BINDING_V2_SCHEMA,
            journal.RECOVERED_ADOPTION_LEASE_BINDING_V2_SCHEMA,
        )
        for callable_ in (
            recovery.recover_adopted_capture_v2,
            recovery.recover_adopted_capture_v2_canary,
        ):
            self.assertEqual(
                tuple(inspect.signature(callable_).parameters),
                ("session", "final_parent_fd"),
            )
        seam = inspect.signature(
            recovery._recover_adopted_capture_v2_for_test
        )
        self.assertEqual(
            tuple(seam.parameters),
            (
                "session",
                "final_parent_fd",
                "expected_owner_uid",
                "expected_verifier_gid",
            ),
        )
        self.assertFalse(
            recovery.RECOVERED_LEASE_V2_PRODUCTION_ACTIVATION
        )
        self.assertFalse(
            recovery.RECOVERED_LEASE_V2_CANARY_ACTIVATION
        )
        self.assert_code(
            "adoption_recovery_v2_production_disabled",
            recovery.recover_adopted_capture_v2,
            object(),
            -1,
        )
        self.assert_code(
            "adoption_recovery_v2_canary_disabled",
            recovery.recover_adopted_capture_v2_canary,
            object(),
            -1,
        )

    def test_ack_rebinds_exact_context_without_reopening_final_path(
        self,
    ) -> None:
        fixture = self._make_object_fixture()
        lease = self._recover(fixture)
        self.addCleanup(lambda: lease.close() if lease.active else None)
        self.assertEqual(lease.flow_state, "reconciled")
        pre_ack_binding = lease.recovered_adoption_lease_binding
        self.assertEqual(
            pre_ack_binding["schema_version"],
            journal.RECOVERED_ADOPTION_LEASE_BINDING_V2_SCHEMA,
        )
        self.assertEqual(
            pre_ack_binding["transaction_journal_head_state"],
            "adoption_reconciled",
        )
        self.assertIsNone(
            pre_ack_binding[
                "staging_tombstone_acked_record_sha256"
            ]
        )
        self.assertEqual(
            recovery.normalize_recovered_adoption_lease_binding_v2(
                pre_ack_binding
            ),
            pre_ack_binding,
        )
        self.assertEqual(
            recovery.recovered_adoption_lease_binding_v2_sha256(
                pre_ack_binding
            ),
            journal.recovered_adoption_lease_binding_v2_sha256(
                pre_ack_binding
            ),
        )
        self.assert_code(
            "adoption_recovery_v2_outer_ack_clearance_required",
            lease.pre_verifier_revalidate,
        )
        claims_before = tuple(
            self._canonical_json(value)
            for value in (
                lease.recovered_adoption_evidence,
                lease.capture_adoption_result,
                lease.capture_adoption_provenance,
            )
        )
        digests_before = (
            lease.recovered_adoption_evidence_sha256,
            lease.capture_adoption_result_sha256,
            lease.capture_adoption_provenance_sha256,
        )
        descriptors_before = lease._descriptor_numbers_for_test()
        operation = lease.begin_outer_ack()
        self.assertEqual(
            tuple(inspect.signature(operation.commit).parameters),
            ("control",),
        )
        open_calls: list[object] = []
        real_open = os.open

        def record_open(path, flags, *args, **kwargs):
            open_calls.append(path)
            return real_open(path, flags, *args, **kwargs)

        control = self._control(fixture)
        with (
            mock.patch.object(
                recovery.os, "open", side_effect=record_open
            ),
            mock.patch.object(
                staging,
                "_open_shared_root",
                side_effect=AssertionError(
                    "descriptor-bound ACK must not reopen shared root"
                ),
            ),
        ):
            clearance = operation.commit(control)
        self.assertIsInstance(
            clearance,
            journal.RecoveredAdoptionContinuationClearance,
        )
        self.assertEqual(operation.state, "committed")
        self.assertEqual(lease.flow_state, "acked")
        self.assertEqual(
            lease._descriptor_numbers_for_test(),
            descriptors_before,
        )
        self.assertNotIn(fixture.final_name, open_calls)
        claims_after = tuple(
            self._canonical_json(value)
            for value in (
                lease.recovered_adoption_evidence,
                lease.capture_adoption_result,
                lease.capture_adoption_provenance,
            )
        )
        self.assertEqual(claims_after, claims_before)
        self.assertEqual(
            (
                lease.recovered_adoption_evidence_sha256,
                lease.capture_adoption_result_sha256,
                lease.capture_adoption_provenance_sha256,
            ),
            digests_before,
        )
        pre = lease.pre_verifier_revalidate()
        post = lease.post_verifier_revalidate()
        self.assertEqual(pre, post)
        self.assertEqual(
            pre["transaction_journal_head_state"],
            "staging_tombstone_acked",
        )
        self.assertEqual(
            pre["transaction_journal_head_record_sha256"],
            clearance.committed_record_sha256,
        )
        self.assertEqual(
            pre["staging_tombstone_acked_record_sha256"],
            clearance.committed_record_sha256,
        )
        self.assert_code(
            "adoption_recovery_v2_outer_ack_operation_invalid",
            operation.commit,
            object(),
        )
        self.assert_code(
            "adoption_recovery_v2_outer_ack_operation_invalid",
            operation.cancel,
        )
        lease.close()
        self.assertTrue(fixture.capture_root.is_dir())
        self.assertTrue(fixture.root_file.is_file())

    def test_cancel_is_linear_safe_and_all_capabilities_are_sealed(
        self,
    ) -> None:
        fixture = self._make_object_fixture()
        lease = self._recover(fixture)
        self.addCleanup(lambda: lease.close() if lease.active else None)
        operation = lease.begin_outer_ack()
        for capability in (lease, operation):
            with self.assertRaises(TypeError):
                copy.copy(capability)
            with self.assertRaises(TypeError):
                copy.deepcopy(capability)
            with self.assertRaises(TypeError):
                pickle.dumps(capability)
        with self.assertRaises(TypeError):
            recovery.RecoveredAdoptionOuterAckOperation(
                _token=object(),
                lease=lease,
                journal_operation=object(),
                pre_binding={},
            )
        with self.assertRaises(TypeError):
            recovery.RecoveredAdoptedCaptureLeaseV2(
                _token=object(),
                parent_fd=-1,
                root_fd=-1,
                expected_owner_uid=fixture.owner_uid,
                expected_verifier_gid=fixture.verifier_gid,
                session=fixture.session,
                context=object(),
                evidence={},
                result={},
                provenance={},
                journal_binding={},
                continuation={},
            )
        operation.cancel()
        self.assertEqual(operation.state, "cancelled")
        self.assertEqual(lease.flow_state, "reconciled")
        self.assert_code(
            "adoption_recovery_v2_outer_ack_operation_invalid",
            operation.cancel,
        )
        retry = lease.begin_outer_ack()
        retry.cancel()
        creator_pid = os.getpid()
        with mock.patch.object(
            recovery.os,
            "getpid",
            return_value=creator_pid + 1,
        ):
            self.assertFalse(lease.active)
            self.assert_code(
                "adoption_recovery_v2_lease_creator_process_mismatch",
                lease.begin_outer_ack,
            )

    def _assert_async_cancel_failure(
        self,
        exception: BaseException,
    ) -> None:
        fixture = self._make_object_fixture()
        lease = self._recover(fixture)
        operation = lease.begin_outer_ack()
        with mock.patch.object(
            journal.RecoveredAdoptionTombstoneAckOperation,
            "cancel",
            side_effect=exception,
        ):
            with self.assertRaises(type(exception)) as caught:
                operation.cancel()
        self.assertIs(caught.exception, exception)
        self.assertEqual(operation.state, "failed")
        self.assertEqual(lease.flow_state, "ack_failed")
        self.assert_code(
            "adoption_recovery_v2_outer_ack_clearance_required",
            lease.pre_verifier_revalidate,
        )
        lease.close()

        # The direct journal cancellation fallback released the reservation;
        # a new descriptor lease and a normal cancel/retry remain possible.
        fresh = self._recover(fixture)
        self.addCleanup(lambda: fresh.close() if fresh.active else None)
        retry = fresh.begin_outer_ack()
        retry.cancel()
        self.assertEqual(fresh.flow_state, "reconciled")

    def test_keyboard_interrupt_during_cancel_poison_clears_reservation(
        self,
    ) -> None:
        self._assert_async_cancel_failure(KeyboardInterrupt())

    def test_system_exit_during_cancel_poison_clears_reservation(
        self,
    ) -> None:
        self._assert_async_cancel_failure(SystemExit(17))

    def test_keyboard_interrupt_during_failed_begin_cleanup_clears_reservation(
        self,
    ) -> None:
        fixture = self._make_object_fixture()
        lease = self._recover(fixture)
        injected = RuntimeError("injected wrapper construction failure")
        interrupt = KeyboardInterrupt()
        with (
            mock.patch.object(
                recovery,
                "RecoveredAdoptionOuterAckOperation",
                side_effect=injected,
            ),
            mock.patch.object(
                journal.RecoveredAdoptionTombstoneAckOperation,
                "cancel",
                side_effect=interrupt,
            ),
        ):
            with self.assertRaises(KeyboardInterrupt) as caught:
                lease.begin_outer_ack()
        self.assertIs(caught.exception, interrupt)
        self.assertEqual(lease.flow_state, "ack_failed")
        lease.close()

        fresh = self._recover(fixture)
        self.addCleanup(lambda: fresh.close() if fresh.active else None)
        retry = fresh.begin_outer_ack()
        retry.cancel()
        self.assertEqual(fresh.flow_state, "reconciled")

    def test_system_exit_rejecting_forged_control_clears_reservation(
        self,
    ) -> None:
        fixture = self._make_object_fixture()
        lease = self._recover(fixture)
        operation = lease.begin_outer_ack()
        interrupt = SystemExit(23)
        with mock.patch.object(
            journal.RecoveredAdoptionTombstoneAckOperation,
            "cancel",
            side_effect=interrupt,
        ):
            with self.assertRaises(SystemExit) as caught:
                operation.commit(object())
        self.assertIs(caught.exception, interrupt)
        self.assertEqual(operation.state, "failed")
        self.assertEqual(lease.flow_state, "ack_failed")
        lease.close()

        fresh = self._recover(fixture)
        self.addCleanup(lambda: fresh.close() if fresh.active else None)
        retry = fresh.begin_outer_ack()
        retry.cancel()
        self.assertEqual(fresh.flow_state, "reconciled")

    def test_forged_control_poisoning_never_grants_verifier_authority(
        self,
    ) -> None:
        fixture = self._make_object_fixture()
        lease = self._recover(fixture)
        self.addCleanup(lambda: lease.close() if lease.active else None)
        operation = lease.begin_outer_ack()

        class ForgedControl(
            staging.InstalledCaptureStagingControl
        ):
            pass

        forged = object.__new__(ForgedControl)
        self.assert_code(
            "adoption_recovery_v2_installed_staging_control_required",
            operation.commit,
            forged,
        )
        self.assertEqual(operation.state, "failed")
        self.assertEqual(lease.flow_state, "ack_failed")
        self.assert_code(
            "adoption_recovery_v2_outer_ack_clearance_required",
            lease.pre_verifier_revalidate,
        )
        # The rejected type cancelled the journal reservation.  A fresh,
        # independently recovered descriptor lease remains possible.
        lease.close()
        fresh = self._recover(fixture)
        self.addCleanup(lambda: fresh.close() if fresh.active else None)
        self.assertEqual(fresh.flow_state, "reconciled")

    def test_durable_ack_with_failed_rebind_requires_fresh_recovery(
        self,
    ) -> None:
        fixture = self._make_object_fixture()
        lease = self._recover(fixture)
        operation = lease.begin_outer_ack()
        injected = recovery.RecoveredAdoptionRecoveryError(
            "injected_post_ack_rebind_failure"
        )
        with mock.patch.object(
            recovery.RecoveredAdoptedCaptureLeaseV2,
            "_assert_exact_ack_transition",
            side_effect=injected,
        ):
            with self.assertRaises(
                recovery.RecoveredAdoptionRecoveryError
            ) as caught:
                operation.commit(self._control(fixture))
        self.assertIs(caught.exception, injected)
        self.assertEqual(fixture.session.state, "staging_tombstone_acked")
        self.assertEqual(lease.flow_state, "ack_failed")
        self.assert_code(
            "adoption_recovery_v2_outer_ack_clearance_required",
            lease.pre_verifier_revalidate,
        )
        lease.close()

        fixture.session._store.close()
        reopened = self.journal_fixture.open_store()
        recovered_sessions = reopened.load_incomplete_sessions()
        matching = tuple(
            session
            for session in recovered_sessions
            if session.session_id == fixture.session.session_id
        )
        self.assertEqual(len(matching), 1)
        fixture.session = matching[0]
        fresh = self._recover(fixture)
        self.addCleanup(lambda: fresh.close() if fresh.active else None)
        self.assertEqual(fresh.flow_state, "acked")
        pre = fresh.pre_verifier_revalidate()
        self.assertEqual(pre, fresh.post_verifier_revalidate())

    def test_object_head_and_context_mismatch_fail_closed(
        self,
    ) -> None:
        fixture = self._make_object_fixture()
        lease = self._recover(fixture)
        self.addCleanup(lambda: lease.close() if lease.active else None)
        self._commit(fixture, lease)
        lease.pre_verifier_revalidate()
        fixture.root_file.chmod(0o640)
        self.assert_code(
            "adoption_recovery_file_unsafe",
            lease.post_verifier_revalidate,
        )
        fixture.root_file.chmod(recovery.ADOPTED_FILE_MODE)

        fixture.session.append_event(
            expected_state="staging_tombstone_acked",
            next_state="operator_attention",
            details={
                "from_state": "staging_tombstone_acked",
                "reason_code": "recovered_adoption_review_required",
                "incident_sha256": (
                    fixture.session.latest_record.record_sha256
                ),
            },
            recorded_at_unix=(
                fixture.session.latest_record.recorded_at_unix + 1
            ),
        )
        self.assert_code(
            "transaction_journal_recovered_adoption_context_head_changed",
            lambda: lease.recovered_adoption_evidence,
        )

        other_context = object()
        lease._context = other_context
        self.assert_code(
            "adoption_recovery_v2_journal_context_required",
            lambda: lease.capture_adoption_result,
        )


if __name__ == "__main__":
    unittest.main()
