from __future__ import annotations

import json
import os
import pickle
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture_staging as staging,
)


class PersonaQualificationCaptureStagingTests(unittest.TestCase):
    maxDiff = None

    def fixture(self) -> tuple[tempfile.TemporaryDirectory, Path]:
        temporary = tempfile.TemporaryDirectory()
        shared_root = Path(temporary.name) / "staging"
        shared_root.mkdir(mode=staging.SHARED_ROOT_MODE)
        shared_root.chmod(staging.SHARED_ROOT_MODE)
        return temporary, shared_root

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(staging.CaptureStagingError) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def create(
        self,
        shared_root: Path,
        token: str,
        *,
        transaction_intent_sha256: str | None = None,
        fault_hook=None,
    ) -> (
        staging.CaptureStagingLease
        | staging.CaptureStagingRecoveryOutcome
    ):
        return staging._create_session_staging_for_test(
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256=(
                transaction_intent_sha256
            ),
            fault_hook=fault_hook,
        )

    def assert_outcome(
        self,
        value: object,
        disposition: str,
    ) -> staging.CaptureStagingRecoveryOutcome:
        self.assertIsInstance(
            value,
            staging.CaptureStagingRecoveryOutcome,
        )
        assert isinstance(
            value,
            staging.CaptureStagingRecoveryOutcome,
        )
        self.assertEqual(value.disposition, disposition)
        return value

    def journal(
        self,
        shared_root: Path,
        session_name: str,
    ) -> list[dict[str, object]]:
        path = (
            shared_root
            / staging.TRANSACTIONS_NAMESPACE
            / f"{session_name}.jsonl"
        )
        return [
            json.loads(line)
            for line in path.read_text(encoding="ascii").splitlines()
        ]

    def test_selected_id_and_intent_are_exact_authority(self) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        token = "01" * 32
        intent = "10" * 32

        lease = self.create(
            shared_root,
            token,
            transaction_intent_sha256=intent,
        )
        self.assertIsInstance(lease, staging.CaptureStagingLease)
        assert isinstance(lease, staging.CaptureStagingLease)
        self.assertEqual(lease.session_id, token)
        self.assertEqual(
            lease.staging_transaction_intent_sha256,
            intent,
        )
        transactions = (
            shared_root / staging.TRANSACTIONS_NAMESPACE
        )
        self.assertEqual(
            {
                entry.name
                for entry in transactions.iterdir()
                if entry.name.endswith(".jsonl")
            },
            {f"session-{token}.jsonl"},
        )
        records = self.journal(shared_root, lease.session_name)
        self.assertEqual(
            {
                record["staging_transaction_intent_sha256"]
                for record in records
            },
            {intent},
        )
        self.assert_outcome(lease.finish_success(), "absent")

    def test_invalid_intent_has_no_filesystem_effects(self) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        before = tuple(shared_root.iterdir())

        self.assert_code(
            "capture_staging_transaction_intent_sha256_invalid",
            staging._create_session_staging_for_test,
            shared_root,
            session_id="02" * 32,
            staging_transaction_intent_sha256="not-a-digest",
        )
        self.assertEqual(tuple(shared_root.iterdir()), before)

    def test_exposure_receipt_binds_v3_sequence_and_head(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        token = "03" * 32
        intent = "30" * 32
        lease = self.create(
            shared_root,
            token,
            transaction_intent_sha256=intent,
        )
        self.assertIsInstance(lease, staging.CaptureStagingLease)
        assert isinstance(lease, staging.CaptureStagingLease)

        receipt = lease.exposure_receipt
        records = self.journal(shared_root, lease.session_name)
        exposed = records[3]
        self.assertEqual(
            receipt["schema_version"],
            staging.staging_receipts.STAGING_EXPOSURE_RECEIPT_SCHEMA,
        )
        self.assertEqual(receipt["capture_session_id"], token)
        self.assertEqual(
            receipt["staging_transaction_intent_sha256"],
            intent,
        )
        self.assertEqual(
            receipt["staging_journal_schema"],
            staging.STAGING_JOURNAL_SCHEMA,
        )
        self.assertEqual(receipt["staging_journal_sequence"], 3)
        self.assertEqual(
            receipt["staging_journal_head_sha256"],
            exposed["record_sha256"],
        )
        self.assertEqual(
            lease.exposure_receipt_sha256,
            staging.staging_receipts
            .staging_exposure_receipt_sha256(receipt),
        )
        self.assert_outcome(lease.finish_success(), "absent")

    def test_exact_same_id_recovery_returns_terminal_outcome(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        token = "04" * 32
        intent = "40" * 32
        lease = self.create(
            shared_root,
            token,
            transaction_intent_sha256=intent,
        )
        self.assertIsInstance(lease, staging.CaptureStagingLease)
        assert isinstance(lease, staging.CaptureStagingLease)
        lease._abandon_for_test()

        outcome = self.assert_outcome(
            self.create(
                shared_root,
                token,
                transaction_intent_sha256=intent,
            ),
            "quarantined",
        )
        self.assertEqual(outcome.session_id, token)
        self.assertEqual(
            outcome.staging_transaction_intent_sha256,
            intent,
        )
        journal_path = (
            shared_root
            / staging.TRANSACTIONS_NAMESPACE
            / f"session-{token}.jsonl"
        )
        terminal_raw = journal_path.read_bytes()
        repeated = self.assert_outcome(
            self.create(
                shared_root,
                token,
                transaction_intent_sha256=intent,
            ),
            "quarantined",
        )
        self.assertEqual(
            repeated.terminal_receipt_sha256,
            outcome.terminal_receipt_sha256,
        )
        self.assertEqual(journal_path.read_bytes(), terminal_raw)

    def test_selected_id_rejects_legacy_v2_journal(self) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        bootstrap = self.create(shared_root, "05" * 32)
        self.assertIsInstance(
            bootstrap,
            staging.CaptureStagingLease,
        )
        assert isinstance(bootstrap, staging.CaptureStagingLease)
        self.assert_outcome(bootstrap.finish_success(), "absent")

        token = "06" * 32
        session_name = f"session-{token}"
        legacy_payload = {
            "schema_version": (
                "john-lomein.persona-qualification-"
                "capture-staging-journal.v2"
            ),
            "session_name": session_name,
            "sequence": 0,
            "event": "create_intent",
            "leaf_identity_sha256": None,
            "previous_record_sha256": None,
        }
        legacy_record = dict(legacy_payload)
        legacy_record["record_sha256"] = staging._sha256(
            staging._canonical_json(legacy_payload)
        )
        journal_path = (
            shared_root
            / staging.TRANSACTIONS_NAMESPACE
            / f"{session_name}.jsonl"
        )
        journal_path.write_bytes(
            staging._canonical_json(legacy_record) + b"\n"
        )
        journal_path.chmod(staging.JOURNAL_FILE_MODE)

        self.assert_code(
            "capture_staging_journal_invalid",
            self.create,
            shared_root,
            token,
            transaction_intent_sha256="60" * 32,
        )

    def test_absence_ack_archives_full_journal_idempotently(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        token = "07" * 32
        intent = "70" * 32
        pending = "a7" * 32
        lease = self.create(
            shared_root,
            token,
            transaction_intent_sha256=intent,
        )
        self.assertIsInstance(lease, staging.CaptureStagingLease)
        assert isinstance(lease, staging.CaptureStagingLease)
        terminal = self.assert_outcome(
            lease.finish_success(),
            "absent",
        )
        self.assert_code(
            "capture_staging_ack_"
            "outer_quarantine_intent_unexpected",
            staging._acknowledge_terminal_tombstone_for_test,
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256=intent,
            terminal_receipt=terminal.terminal_receipt,
            outer_ack_pending_record_sha256=pending,
            outer_quarantine_intent_record_sha256="b7" * 32,
        )

        ack = staging._acknowledge_terminal_tombstone_for_test(
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256=intent,
            terminal_receipt=terminal.terminal_receipt,
            outer_ack_pending_record_sha256=pending,
        )
        journal_name = f"session-{token}.jsonl"
        transactions = (
            shared_root / staging.TRANSACTIONS_NAMESPACE
        )
        archived = (
            transactions
            / staging.COMPLETED_NAMESPACE
            / journal_name
        )
        self.assertFalse((transactions / journal_name).exists())
        self.assertTrue(archived.is_file())
        records = [
            json.loads(line)
            for line in archived.read_text(
                encoding="ascii"
            ).splitlines()
        ]
        ack_record = records[-1]
        self.assertEqual(
            ack["journal_storage_disposition"],
            "completed_absence_journal",
        )
        self.assertTrue(ack["transactions_parent_fsynced"])
        self.assertTrue(ack["completed_parent_fsynced"])
        self.assertEqual(
            ack_record["event"],
            staging.staging_receipts.STAGING_TOMBSTONE_ACK_EVENT,
        )
        self.assertEqual(
            ack_record["previous_record_sha256"],
            terminal.terminal_receipt["terminal_record_sha256"],
        )
        self.assertEqual(
            ack_record["outer_ack_pending_record_sha256"],
            pending,
        )
        self.assertEqual(
            ack_record["record_sha256"],
            ack["ack_record_sha256"],
        )
        self.assertEqual(
            ack["ack_journal_identity_sha256"],
            staging._identity_sha256(archived.stat()),
        )
        self.assertEqual(
            ack["ack_journal_readback_sha256"],
            staging._sha256(archived.read_bytes()),
        )
        repeated = (
            staging._acknowledge_terminal_tombstone_for_test(
                shared_root,
                session_id=token,
                staging_transaction_intent_sha256=intent,
                terminal_receipt=terminal.terminal_receipt,
                outer_ack_pending_record_sha256=pending,
            )
        )
        self.assertEqual(repeated, ack)
        recovered = self.assert_outcome(
            self.create(
                shared_root,
                token,
                transaction_intent_sha256=intent,
            ),
            "absent",
        )
        self.assertEqual(
            recovered.terminal_receipt_sha256,
            terminal.terminal_receipt_sha256,
        )

    def test_quarantine_ack_retains_journal_idempotently(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        token = "08" * 32
        intent = "80" * 32
        pending = "a8" * 32
        quarantine_intent = "b8" * 32
        lease = self.create(
            shared_root,
            token,
            transaction_intent_sha256=intent,
        )
        self.assertIsInstance(lease, staging.CaptureStagingLease)
        assert isinstance(lease, staging.CaptureStagingLease)
        (lease.leaf_path / "partial").write_bytes(b"untrusted")
        terminal = self.assert_outcome(
            lease.finish_failure(),
            "quarantined",
        )
        journal_path = (
            shared_root
            / staging.TRANSACTIONS_NAMESPACE
            / f"session-{token}.jsonl"
        )
        before_missing_intent = journal_path.read_bytes()
        self.assert_code(
            "capture_staging_ack_outer_quarantine_intent_missing",
            staging._acknowledge_terminal_tombstone_for_test,
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256=intent,
            terminal_receipt=terminal.terminal_receipt,
            outer_ack_pending_record_sha256=pending,
        )
        self.assertEqual(
            journal_path.read_bytes(),
            before_missing_intent,
        )

        ack = staging._acknowledge_terminal_tombstone_for_test(
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256=intent,
            terminal_receipt=terminal.terminal_receipt,
            outer_ack_pending_record_sha256=pending,
            outer_quarantine_intent_record_sha256=(
                quarantine_intent
            ),
        )
        transactions = (
            shared_root / staging.TRANSACTIONS_NAMESPACE
        )
        journal = transactions / f"session-{token}.jsonl"
        archived = (
            transactions
            / staging.COMPLETED_NAMESPACE
            / journal.name
        )
        self.assertTrue(journal.is_file())
        self.assertFalse(archived.exists())
        self.assertEqual(
            ack["journal_storage_disposition"],
            "retained_quarantine_journal",
        )
        self.assertTrue(ack["transactions_parent_fsynced"])
        self.assertFalse(ack["completed_parent_fsynced"])
        self.assertEqual(
            ack["outer_quarantine_intent_record_sha256"],
            quarantine_intent,
        )
        records = self.journal(
            shared_root,
            f"session-{token}",
        )
        self.assertEqual(
            records[-1][
                "outer_quarantine_intent_record_sha256"
            ],
            quarantine_intent,
        )
        self.assert_code(
            "capture_staging_ack_record_mismatch",
            staging._acknowledge_terminal_tombstone_for_test,
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256=intent,
            terminal_receipt=terminal.terminal_receipt,
            outer_ack_pending_record_sha256=pending,
            outer_quarantine_intent_record_sha256="c8" * 32,
        )
        repeated = (
            staging._acknowledge_terminal_tombstone_for_test(
                shared_root,
                session_id=token,
                staging_transaction_intent_sha256=intent,
                terminal_receipt=terminal.terminal_receipt,
                outer_ack_pending_record_sha256=pending,
                outer_quarantine_intent_record_sha256=(
                    quarantine_intent
                ),
            )
        )
        self.assertEqual(repeated, ack)
        recovered = self.assert_outcome(
            self.create(
                shared_root,
                token,
                transaction_intent_sha256=intent,
            ),
            "quarantined",
        )
        self.assertEqual(
            recovered.terminal_receipt_sha256,
            terminal.terminal_receipt_sha256,
        )

    def test_spawned_ack_requires_persisted_lifecycle_clearance(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        token = "09" * 32
        intent = "90" * 32
        lease = self.create(
            shared_root,
            token,
            transaction_intent_sha256=intent,
        )
        self.assertIsInstance(lease, staging.CaptureStagingLease)
        assert isinstance(lease, staging.CaptureStagingLease)
        lease.record_spawn_intent()
        lease.record_spawned()
        lease._abandon_for_test()
        uncleared = self.assert_outcome(
            self.create(
                shared_root,
                token,
                transaction_intent_sha256=intent,
            ),
            "quarantined",
        )
        self.assertEqual(
            uncleared.terminal_receipt["lifecycle_status"],
            "scope_not_proven",
        )
        self.assert_code(
            "capture_staging_ack_lifecycle_not_cleared",
            staging._acknowledge_terminal_tombstone_for_test,
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256=intent,
            terminal_receipt=uncleared.terminal_receipt,
            outer_ack_pending_record_sha256="a9" * 32,
            outer_quarantine_intent_record_sha256="c9" * 32,
            outer_lifecycle_clearance_record_sha256="b9" * 32,
        )

        second_token = "0a" * 32
        second_intent = "a0" * 32
        scope_receipt = "ba" * 32
        clearance = "ca" * 32
        second = self.create(
            shared_root,
            second_token,
            transaction_intent_sha256=second_intent,
        )
        self.assertIsInstance(second, staging.CaptureStagingLease)
        assert isinstance(second, staging.CaptureStagingLease)
        second.record_spawn_intent()
        second.record_spawned()
        second.mark_process_scope_dead(
            lifecycle_scope_empty_receipt_sha256=scope_receipt,
            outer_lifecycle_clearance_record_sha256=clearance,
        )
        cleared = self.assert_outcome(
            second.finish_success(),
            "absent",
        )
        self.assertEqual(
            cleared.terminal_receipt["lifecycle_status"],
            "scope_empty",
        )
        ack = staging._acknowledge_terminal_tombstone_for_test(
            shared_root,
            session_id=second_token,
            staging_transaction_intent_sha256=second_intent,
            terminal_receipt=cleared.terminal_receipt,
            outer_ack_pending_record_sha256="da" * 32,
            outer_lifecycle_clearance_record_sha256=clearance,
        )
        self.assertEqual(
            ack["outer_lifecycle_clearance_record_sha256"],
            clearance,
        )

    def test_empty_failure_removal_and_crash_recovery_are_live(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        normal = self.create(shared_root, "0b" * 32)
        self.assertIsInstance(normal, staging.CaptureStagingLease)
        assert isinstance(normal, staging.CaptureStagingLease)
        terminal = self.assert_outcome(
            normal.finish_failure(),
            "absent",
        )
        self.assertEqual(
            terminal.terminal_receipt["terminal_event"],
            "quarantine_removed",
        )
        self.assertEqual(
            terminal.terminal_receipt["quarantine_reason_code"],
            "capture_failed",
        )
        normal_intent = (
            terminal.staging_transaction_intent_sha256
        )
        journal_path = (
            shared_root
            / staging.TRANSACTIONS_NAMESPACE
            / f"session-{'0b' * 32}.jsonl"
        )
        before_missing_intent = journal_path.read_bytes()
        self.assert_code(
            "capture_staging_ack_outer_quarantine_intent_missing",
            staging._acknowledge_terminal_tombstone_for_test,
            shared_root,
            session_id="0b" * 32,
            staging_transaction_intent_sha256=normal_intent,
            terminal_receipt=terminal.terminal_receipt,
            outer_ack_pending_record_sha256="db" * 32,
        )
        self.assertEqual(
            journal_path.read_bytes(),
            before_missing_intent,
        )
        quarantine_intent = "eb" * 32
        ack = staging._acknowledge_terminal_tombstone_for_test(
            shared_root,
            session_id="0b" * 32,
            staging_transaction_intent_sha256=normal_intent,
            terminal_receipt=terminal.terminal_receipt,
            outer_ack_pending_record_sha256="db" * 32,
            outer_quarantine_intent_record_sha256=(
                quarantine_intent
            ),
        )
        self.assertEqual(
            ack["outer_quarantine_intent_record_sha256"],
            quarantine_intent,
        )

        for index, phase in enumerate(
            (
                "after_quarantine_remove_intent",
                "after_quarantine_leaf_removed",
            )
        ):
            with self.subTest(phase=phase):
                isolated, isolated_root = self.fixture()
                token = f"{300 + index:064x}"

                def fault(observed: str) -> None:
                    if observed == phase:
                        raise RuntimeError("injected removal fault")

                lease = self.create(
                    isolated_root,
                    token,
                    fault_hook=fault,
                )
                self.assertIsInstance(
                    lease,
                    staging.CaptureStagingLease,
                )
                assert isinstance(lease, staging.CaptureStagingLease)
                with self.assertRaisesRegex(
                    RuntimeError,
                    "injected removal fault",
                ):
                    lease.finish_failure()
                recovered = self.assert_outcome(
                    self.create(isolated_root, token),
                    "absent",
                )
                self.assertIn(
                    recovered.terminal_receipt["terminal_event"],
                    {"quarantine_removed", "startup_absent"},
                )
                isolated.cleanup()

    def test_success_post_rmdir_crash_refsyncs_before_absence(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        token = "0c" * 32

        def fault(observed: str) -> None:
            if observed == "after_success_leaf_removed":
                raise RuntimeError("injected success removal fault")

        lease = self.create(
            shared_root,
            token,
            fault_hook=fault,
        )
        self.assertIsInstance(lease, staging.CaptureStagingLease)
        assert isinstance(lease, staging.CaptureStagingLease)
        with self.assertRaisesRegex(
            RuntimeError,
            "injected success removal fault",
        ):
            lease.finish_success()
        recovered = self.assert_outcome(
            self.create(shared_root, token),
            "absent",
        )
        self.assertEqual(
            recovered.terminal_receipt["terminal_event"],
            "startup_absent",
        )

    def test_startup_quarantine_intent_and_parent_fsync_faults_retry(
        self,
    ) -> None:
        phases = (
            "after_startup_quarantine_intent",
            "after_quarantine_rename",
            "after_quarantine_source_parent_fsync",
            "after_quarantine_destination_parent_fsync",
        )
        for index, phase in enumerate(phases):
            with self.subTest(phase=phase):
                temporary, shared_root = self.fixture()
                token = f"{400 + index:064x}"
                lease = self.create(shared_root, token)
                self.assertIsInstance(
                    lease,
                    staging.CaptureStagingLease,
                )
                assert isinstance(lease, staging.CaptureStagingLease)
                lease._abandon_for_test()

                def fault(observed: str) -> None:
                    if observed == phase:
                        raise RuntimeError(
                            "injected startup quarantine fault"
                        )

                with self.assertRaisesRegex(
                    RuntimeError,
                    "injected startup quarantine fault",
                ):
                    self.create(
                        shared_root,
                        token,
                        fault_hook=fault,
                    )
                recovered = self.assert_outcome(
                    self.create(shared_root, token),
                    "quarantined",
                )
                self.assertEqual(
                    recovered.terminal_receipt["terminal_event"],
                    "startup_quarantined",
                )
                temporary.cleanup()

    def test_absence_ack_fault_windows_return_same_receipt(
        self,
    ) -> None:
        phases = (
            "before_ack_record",
            "after_ack_record_fsync",
            "after_ack_archive_rename",
            "after_ack_transactions_parent_fsync",
            "after_ack_completed_parent_fsync",
            "before_ack_receipt_return",
        )
        for index, phase in enumerate(phases):
            with self.subTest(phase=phase):
                temporary, shared_root = self.fixture()
                token = f"{500 + index:064x}"
                intent = f"{600 + index:064x}"
                pending = f"{700 + index:064x}"
                lease = self.create(
                    shared_root,
                    token,
                    transaction_intent_sha256=intent,
                )
                self.assertIsInstance(
                    lease,
                    staging.CaptureStagingLease,
                )
                assert isinstance(lease, staging.CaptureStagingLease)
                terminal = self.assert_outcome(
                    lease.finish_success(),
                    "absent",
                )

                def fault(observed: str) -> None:
                    if observed == phase:
                        raise RuntimeError("injected ACK fault")

                with self.assertRaisesRegex(
                    RuntimeError,
                    "injected ACK fault",
                ):
                    staging._acknowledge_terminal_tombstone_for_test(
                        shared_root,
                        session_id=token,
                        staging_transaction_intent_sha256=intent,
                        terminal_receipt=terminal.terminal_receipt,
                        outer_ack_pending_record_sha256=pending,
                        fault_hook=fault,
                    )
                recovered = (
                    staging
                    ._acknowledge_terminal_tombstone_for_test(
                        shared_root,
                        session_id=token,
                        staging_transaction_intent_sha256=intent,
                        terminal_receipt=terminal.terminal_receipt,
                        outer_ack_pending_record_sha256=pending,
                    )
                )
                repeated = (
                    staging
                    ._acknowledge_terminal_tombstone_for_test(
                        shared_root,
                        session_id=token,
                        staging_transaction_intent_sha256=intent,
                        terminal_receipt=terminal.terminal_receipt,
                        outer_ack_pending_record_sha256=pending,
                    )
                )
                self.assertEqual(repeated, recovered)
                temporary.cleanup()

    def test_quarantine_ack_fault_windows_and_restart_are_exact(
        self,
    ) -> None:
        phases = (
            "before_ack_record",
            "after_ack_record_fsync",
            "after_ack_transactions_parent_fsync",
            "before_ack_receipt_return",
        )
        for index, phase in enumerate(phases):
            with self.subTest(phase=phase):
                temporary, shared_root = self.fixture()
                token = f"{800 + index:064x}"
                intent = f"{900 + index:064x}"
                pending = f"{1000 + index:064x}"
                quarantine_intent = f"{1100 + index:064x}"
                lease = self.create(
                    shared_root,
                    token,
                    transaction_intent_sha256=intent,
                )
                self.assertIsInstance(
                    lease,
                    staging.CaptureStagingLease,
                )
                assert isinstance(lease, staging.CaptureStagingLease)
                (lease.leaf_path / "partial").write_bytes(b"x")
                terminal = self.assert_outcome(
                    lease.finish_failure(),
                    "quarantined",
                )

                def fault(observed: str) -> None:
                    if observed == phase:
                        raise RuntimeError("injected ACK fault")

                with self.assertRaisesRegex(
                    RuntimeError,
                    "injected ACK fault",
                ):
                    staging._acknowledge_terminal_tombstone_for_test(
                        shared_root,
                        session_id=token,
                        staging_transaction_intent_sha256=intent,
                        terminal_receipt=terminal.terminal_receipt,
                        outer_ack_pending_record_sha256=pending,
                        outer_quarantine_intent_record_sha256=(
                            quarantine_intent
                        ),
                        fault_hook=fault,
                    )
                same_id = self.assert_outcome(
                    self.create(
                        shared_root,
                        token,
                        transaction_intent_sha256=intent,
                    ),
                    "quarantined",
                )
                self.assertEqual(
                    same_id.terminal_receipt_sha256,
                    terminal.terminal_receipt_sha256,
                )
                recovered = (
                    staging
                    ._acknowledge_terminal_tombstone_for_test(
                        shared_root,
                        session_id=token,
                        staging_transaction_intent_sha256=intent,
                        terminal_receipt=terminal.terminal_receipt,
                        outer_ack_pending_record_sha256=pending,
                        outer_quarantine_intent_record_sha256=(
                            quarantine_intent
                        ),
                    )
                )
                repeated = (
                    staging
                    ._acknowledge_terminal_tombstone_for_test(
                        shared_root,
                        session_id=token,
                        staging_transaction_intent_sha256=intent,
                        terminal_receipt=terminal.terminal_receipt,
                        outer_ack_pending_record_sha256=pending,
                        outer_quarantine_intent_record_sha256=(
                            quarantine_intent
                        ),
                    )
                )
                self.assertEqual(repeated, recovered)
                temporary.cleanup()

    def test_recovered_quarantine_receipt_is_acknowledgeable(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        token = "0d" * 32
        intent = "d0" * 32
        lease = self.create(
            shared_root,
            token,
            transaction_intent_sha256=intent,
        )
        self.assertIsInstance(lease, staging.CaptureStagingLease)
        assert isinstance(lease, staging.CaptureStagingLease)
        lease._abandon_for_test()
        terminal = self.assert_outcome(
            self.create(
                shared_root,
                token,
                transaction_intent_sha256=intent,
            ),
            "quarantined",
        )
        self.assertEqual(
            terminal.terminal_receipt["reason_code"],
            "coordinator_restarted",
        )
        ack = staging._acknowledge_terminal_tombstone_for_test(
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256=intent,
            terminal_receipt=terminal.terminal_receipt,
            outer_ack_pending_record_sha256="ed" * 32,
            outer_quarantine_intent_record_sha256="fd" * 32,
        )
        self.assertEqual(
            ack["journal_storage_disposition"],
            "retained_quarantine_journal",
        )

    def test_live_quarantine_reason_survives_post_rename_crash(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        token = "0e" * 32

        def fault(observed: str) -> None:
            if observed == "after_quarantine_rename":
                raise RuntimeError("injected live rename fault")

        lease = self.create(
            shared_root,
            token,
            fault_hook=fault,
        )
        self.assertIsInstance(lease, staging.CaptureStagingLease)
        assert isinstance(lease, staging.CaptureStagingLease)
        (lease.leaf_path / "partial").write_bytes(b"x")
        with self.assertRaisesRegex(
            RuntimeError,
            "injected live rename fault",
        ):
            lease.finish_failure()
        recovered = self.assert_outcome(
            self.create(shared_root, token),
            "quarantined",
        )
        self.assertEqual(
            recovered.terminal_receipt["reason_code"],
            "capture_failed",
        )

    def test_ack_capacity_and_namespace_ambiguity_preflight(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        token = "0f" * 32
        intent = "f0" * 32
        lease = self.create(
            shared_root,
            token,
            transaction_intent_sha256=intent,
        )
        self.assertIsInstance(lease, staging.CaptureStagingLease)
        assert isinstance(lease, staging.CaptureStagingLease)
        terminal = self.assert_outcome(
            lease.finish_success(),
            "absent",
        )
        active = (
            shared_root
            / staging.TRANSACTIONS_NAMESPACE
            / f"session-{token}.jsonl"
        )
        before = active.read_bytes()
        with mock.patch.object(
            staging,
            "MAX_COMPLETED_TOMBSTONES",
            0,
        ):
            self.assert_code(
                "capture_staging_completed_capacity_exceeded",
                staging._acknowledge_terminal_tombstone_for_test,
                shared_root,
                session_id=token,
                staging_transaction_intent_sha256=intent,
                terminal_receipt=terminal.terminal_receipt,
                outer_ack_pending_record_sha256="af" * 32,
            )
        self.assertEqual(active.read_bytes(), before)

        completed = (
            active.parent / staging.COMPLETED_NAMESPACE / active.name
        )
        completed.write_bytes(before)
        completed.chmod(staging.JOURNAL_FILE_MODE)
        self.assert_code(
            "capture_staging_ack_journal_ambiguous",
            staging._acknowledge_terminal_tombstone_for_test,
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256=intent,
            terminal_receipt=terminal.terminal_receipt,
            outer_ack_pending_record_sha256="af" * 32,
        )
        self.assertEqual(active.read_bytes(), before)
        self.assertEqual(completed.read_bytes(), before)

    def test_ack_rejects_missing_wrong_and_conflicting_authority(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        token = "10" * 32
        intent = "01" * 32
        pending = "ab" * 32
        lease = self.create(
            shared_root,
            token,
            transaction_intent_sha256=intent,
        )
        self.assertIsInstance(lease, staging.CaptureStagingLease)
        assert isinstance(lease, staging.CaptureStagingLease)
        terminal = self.assert_outcome(
            lease.finish_success(),
            "absent",
        )
        changed = terminal.terminal_receipt
        changed["tombstone_sha256"] = "cd" * 32
        self.assert_code(
            "capture_staging_ack_terminal_receipt_mismatch",
            staging._acknowledge_terminal_tombstone_for_test,
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256=intent,
            terminal_receipt=changed,
            outer_ack_pending_record_sha256=pending,
        )
        self.assert_code(
            "capture_staging_ack_terminal_binding_invalid",
            staging._acknowledge_terminal_tombstone_for_test,
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256="fe" * 32,
            terminal_receipt=terminal.terminal_receipt,
            outer_ack_pending_record_sha256=pending,
        )
        ack = staging._acknowledge_terminal_tombstone_for_test(
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256=intent,
            terminal_receipt=terminal.terminal_receipt,
            outer_ack_pending_record_sha256=pending,
        )
        self.assert_code(
            "capture_staging_ack_record_mismatch",
            staging._acknowledge_terminal_tombstone_for_test,
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256=intent,
            terminal_receipt=terminal.terminal_receipt,
            outer_ack_pending_record_sha256="bc" * 32,
        )
        self.assertEqual(
            staging._acknowledge_terminal_tombstone_for_test(
                shared_root,
                session_id=token,
                staging_transaction_intent_sha256=intent,
                terminal_receipt=terminal.terminal_receipt,
                outer_ack_pending_record_sha256=pending,
            ),
            ack,
        )

        missing_token = "11" * 32
        missing_lease = self.create(shared_root, missing_token)
        self.assertIsInstance(
            missing_lease,
            staging.CaptureStagingLease,
        )
        assert isinstance(
            missing_lease,
            staging.CaptureStagingLease,
        )
        missing_terminal = self.assert_outcome(
            missing_lease.finish_success(),
            "absent",
        )
        missing_path = (
            shared_root
            / staging.TRANSACTIONS_NAMESPACE
            / f"session-{missing_token}.jsonl"
        )
        missing_path.unlink()
        self.assert_code(
            "capture_staging_ack_journal_missing",
            staging._acknowledge_terminal_tombstone_for_test,
            shared_root,
            session_id=missing_token,
            staging_transaction_intent_sha256=(
                missing_terminal.staging_transaction_intent_sha256
            ),
            terminal_receipt=missing_terminal.terminal_receipt,
            outer_ack_pending_record_sha256="de" * 32,
        )

    def test_torn_active_ack_tail_repairs_but_archive_is_immutable(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        token = "12" * 32
        intent = "21" * 32
        pending = "ef" * 32
        lease = self.create(
            shared_root,
            token,
            transaction_intent_sha256=intent,
        )
        self.assertIsInstance(lease, staging.CaptureStagingLease)
        assert isinstance(lease, staging.CaptureStagingLease)
        terminal = self.assert_outcome(
            lease.finish_success(),
            "absent",
        )
        active = (
            shared_root
            / staging.TRANSACTIONS_NAMESPACE
            / f"session-{token}.jsonl"
        )
        with active.open("ab") as stream:
            stream.write(b'{"event":"outer_tombstone_acknowledged"')
            stream.flush()
            os.fsync(stream.fileno())
        staging._acknowledge_terminal_tombstone_for_test(
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256=intent,
            terminal_receipt=terminal.terminal_receipt,
            outer_ack_pending_record_sha256=pending,
        )
        archived = (
            active.parent / staging.COMPLETED_NAMESPACE / active.name
        )
        with archived.open("ab") as stream:
            stream.write(b'{"event":')
            stream.flush()
            os.fsync(stream.fileno())
        self.assert_code(
            "capture_staging_journal_invalid",
            staging._acknowledge_terminal_tombstone_for_test,
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256=intent,
            terminal_receipt=terminal.terminal_receipt,
            outer_ack_pending_record_sha256=pending,
        )

    def test_root_creates_exact_exclusive_leaf_and_holds_lock(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        token = "1" * 64
        lease = self.create(shared_root, token)
        self.addCleanup(
            lambda: lease.finish_failure() if lease.active else None
        )

        self.assertEqual(lease.session_id, token)
        self.assertEqual(lease.session_name, f"session-{token}")
        self.assertEqual(
            lease.leaf_path,
            shared_root
            / staging.RECOVERY_NAMESPACE
            / f"session-{token}",
        )
        root_info = shared_root.stat()
        recovery_info = (
            shared_root / staging.RECOVERY_NAMESPACE
        ).stat()
        leaf_info = lease.leaf_path.stat()
        self.assertEqual(
            (root_info.st_uid, root_info.st_gid),
            (os.geteuid(), os.getegid()),
        )
        self.assertEqual(
            stat.S_IMODE(root_info.st_mode),
            staging.SHARED_ROOT_MODE,
        )
        self.assertEqual(
            stat.S_IMODE(recovery_info.st_mode),
            staging.RECOVERY_NAMESPACE_MODE,
        )
        self.assertEqual(
            stat.S_IMODE(leaf_info.st_mode),
            staging.EXPOSED_LEAF_MODE,
        )
        self.assertFalse(root_info.st_mode & 0o022)
        descriptor = lease.duplicate_leaf_descriptor()
        try:
            self.assertFalse(os.get_inheritable(descriptor))
            opened = os.fstat(descriptor)
            self.assertEqual(
                (opened.st_dev, opened.st_ino),
                (leaf_info.st_dev, leaf_info.st_ino),
            )
        finally:
            os.close(descriptor)
        with self.assertRaises(TypeError):
            pickle.dumps(lease)

        self.assert_code(
            "capture_staging_session_busy",
            self.create,
            shared_root,
            "2" * 64,
        )
        self.assert_outcome(lease.finish_success(), "absent")
        self.assertFalse(lease.leaf_path.exists() if lease.active else False)

        next_lease = self.create(shared_root, "2" * 64)
        self.assertIsInstance(next_lease, staging.CaptureStagingLease)
        assert isinstance(next_lease, staging.CaptureStagingLease)
        self.assert_outcome(next_lease.finish_success(), "absent")

    def test_journal_orders_identity_before_exposure_and_spawn(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        lease = self.create(shared_root, "3" * 64)
        self.assertIsInstance(lease, staging.CaptureStagingLease)
        assert isinstance(lease, staging.CaptureStagingLease)
        session_name = lease.session_name
        identity = lease.identity_sha256
        lease.record_spawn_intent()
        lease.record_spawned()
        lease.record_ready_bound()
        self.assert_code(
            "capture_staging_ready_transition_invalid",
            lease.record_ready_bound,
        )
        lease.mark_process_scope_dead(
            lifecycle_scope_empty_receipt_sha256="13" * 32,
            outer_lifecycle_clearance_record_sha256="23" * 32,
        )
        self.assert_outcome(lease.finish_success(), "absent")
        journal_path = (
            shared_root
            / staging.TRANSACTIONS_NAMESPACE
            / f"{session_name}.jsonl"
        )
        terminal_raw = journal_path.read_bytes()

        records = [
            json.loads(line)
            for line in terminal_raw.decode("ascii").splitlines()
        ]
        self.assertEqual(
            [record["event"] for record in records],
            [
                "create_intent",
                "leaf_created",
                "staging_exposure_intent",
                "staging_exposed",
                "spawn_intent",
                "spawned",
                "ready_bound",
                "process_scope_dead",
                "cleanup_intent",
                "removed",
            ],
        )
        self.assertIsNone(records[0]["leaf_identity_sha256"])
        identities = {
            record["leaf_identity_sha256"]
            for record in records[1:]
        }
        self.assertEqual(identities, {identity})
        self.assertEqual(
            [record["sequence"] for record in records],
            list(range(len(records))),
        )
        self.assertTrue(journal_path.exists())
        self.assertNotIn(b'"pid"', terminal_raw)
        self.assertNotIn(b'"pgid"', terminal_raw)
        parsed = staging._parse_journal(
            terminal_raw,
            session_name=session_name,
        )
        self.assertEqual(parsed.last_event, "removed")
        self.assertFalse(parsed.torn_tail)

    def test_process_scope_must_be_reaped_before_revocation(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        lease = self.create(shared_root, "4" * 64)
        lease.record_spawn_intent()
        lease.record_spawned()
        self.assert_code(
            "capture_staging_process_scope_not_dead",
            lease.finish_failure,
        )
        self.assertTrue(lease.active)
        lease.mark_process_scope_dead(
            lifecycle_scope_empty_receipt_sha256="14" * 32,
            outer_lifecycle_clearance_record_sha256="24" * 32,
        )
        self.assert_outcome(lease.finish_failure(), "absent")

    def test_nonempty_failure_is_sealed_and_does_not_block_next_run(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        lease = self.create(shared_root, "5" * 64)
        session_name = lease.session_name
        marker = lease.leaf_path / "partial"
        marker.write_text("untrusted", encoding="utf-8")
        self.assert_outcome(lease.finish_failure(), "quarantined")

        quarantined = (
            shared_root
            / staging.QUARANTINE_NAMESPACE
            / staging.QUARANTINE_STAGING_NAMESPACE
            / session_name
        )
        self.assertTrue((quarantined / "partial").is_file())
        info = quarantined.stat()
        self.assertEqual(
            (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)),
            (
                os.geteuid(),
                os.getegid(),
                staging.REVOKED_LEAF_MODE,
            ),
        )
        next_lease = self.create(shared_root, "6" * 64)
        self.assertIsInstance(next_lease, staging.CaptureStagingLease)
        assert isinstance(next_lease, staging.CaptureStagingLease)
        self.assertTrue(next_lease.active)
        self.assert_outcome(next_lease.finish_success(), "absent")
        self.assertTrue(quarantined.is_dir())

    def test_operator_resolution_removes_exact_quarantine_and_journal(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        token = "6" * 64
        intent = "16" * 32
        outer_acked = "26" * 32
        lease = self.create(
            shared_root,
            token,
            transaction_intent_sha256=intent,
        )
        self.assertIsInstance(lease, staging.CaptureStagingLease)
        assert isinstance(lease, staging.CaptureStagingLease)
        session_name = lease.session_name
        identity = lease.identity_sha256
        nested = lease.leaf_path / "partial" / "nested"
        nested.mkdir(parents=True)
        (nested / "untrusted.bin").write_bytes(b"untrusted")
        terminal = self.assert_outcome(
            lease.finish_failure(),
            "quarantined",
        )
        staging._acknowledge_terminal_tombstone_for_test(
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256=intent,
            terminal_receipt=terminal.terminal_receipt,
            outer_ack_pending_record_sha256="36" * 32,
            outer_quarantine_intent_record_sha256="46" * 32,
        )

        quarantine = (
            shared_root
            / staging.QUARANTINE_NAMESPACE
            / staging.QUARANTINE_STAGING_NAMESPACE
            / session_name
        )
        journal = (
            shared_root
            / staging.TRANSACTIONS_NAMESPACE
            / f"{session_name}.jsonl"
        )
        self.assertTrue(quarantine.is_dir())
        self.assertTrue(journal.is_file())
        self.assert_code(
            "capture_staging_operator_identity_mismatch",
            staging._resolve_quarantined_session_for_test,
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256=intent,
            outer_staging_tombstone_acked_record_sha256=outer_acked,
            expected_identity_sha256="f" * 64,
        )
        self.assertTrue(quarantine.is_dir())

        self.assertEqual(
            staging._resolve_quarantined_session_for_test(
                shared_root,
                session_id=token,
                staging_transaction_intent_sha256=intent,
                outer_staging_tombstone_acked_record_sha256=(
                    outer_acked
                ),
                expected_identity_sha256=identity,
            ),
            "removed",
        )
        self.assertFalse(quarantine.exists())
        self.assertFalse(journal.exists())
        archived = (
            shared_root
            / staging.TRANSACTIONS_NAMESPACE
            / staging.COMPLETED_NAMESPACE
            / f"{session_name}.jsonl"
        )
        self.assertTrue(archived.is_file())
        self.assertEqual(
            staging._resolve_quarantined_session_for_test(
                shared_root,
                session_id=token,
                staging_transaction_intent_sha256=intent,
                outer_staging_tombstone_acked_record_sha256=(
                    outer_acked
                ),
                expected_identity_sha256=identity,
            ),
            "removed",
        )
        next_lease = self.create(shared_root, "7" * 64)
        self.assertIsInstance(next_lease, staging.CaptureStagingLease)
        assert isinstance(next_lease, staging.CaptureStagingLease)
        self.assert_outcome(next_lease.finish_success(), "absent")

    def test_operator_resolution_rejects_unsafe_entry_types_and_hardlinks(
        self,
    ) -> None:
        for index, kind in enumerate(("symlink", "fifo", "hardlink")):
            with self.subTest(kind=kind):
                temporary, shared_root = self.fixture()
                token = f"{index + 30:064x}"
                intent = f"{index + 130:064x}"
                lease = self.create(
                    shared_root,
                    token,
                    transaction_intent_sha256=intent,
                )
                self.assertIsInstance(
                    lease,
                    staging.CaptureStagingLease,
                )
                assert isinstance(lease, staging.CaptureStagingLease)
                identity = lease.identity_sha256
                unsafe = lease.leaf_path / "unsafe"
                if kind == "symlink":
                    unsafe.symlink_to(shared_root)
                elif kind == "fifo":
                    os.mkfifo(unsafe)
                else:
                    original = lease.leaf_path / "original"
                    original.write_bytes(b"linked")
                    os.link(original, unsafe)
                terminal = self.assert_outcome(
                    lease.finish_failure(),
                    "quarantined",
                )
                staging._acknowledge_terminal_tombstone_for_test(
                    shared_root,
                    session_id=token,
                    staging_transaction_intent_sha256=intent,
                    terminal_receipt=terminal.terminal_receipt,
                    outer_ack_pending_record_sha256=(
                        f"{index + 230:064x}"
                    ),
                    outer_quarantine_intent_record_sha256=(
                        f"{index + 330:064x}"
                    ),
                )
                journal = (
                    shared_root
                    / staging.TRANSACTIONS_NAMESPACE
                    / f"session-{token}.jsonl"
                )
                before = journal.read_bytes()
                self.assert_code(
                    (
                        "capture_staging_operator_remove_"
                        + (
                            "file_unsafe"
                            if kind == "hardlink"
                            else "entry_type_unsafe"
                        )
                    ),
                    staging._resolve_quarantined_session_for_test,
                    shared_root,
                    session_id=token,
                    staging_transaction_intent_sha256=intent,
                    outer_staging_tombstone_acked_record_sha256=(
                        f"{index + 330:064x}"
                    ),
                    expected_identity_sha256=identity,
                )
                self.assertEqual(journal.read_bytes(), before)
                temporary.cleanup()

    def test_operator_resolution_faults_are_retryable_or_restart_safe(
        self,
    ) -> None:
        phases = (
            "after_operator_resolution_intent",
            "after_operator_contents_removed",
            "after_operator_quarantine_removed_before_parent_fsync",
            "after_operator_quarantine_removed",
            "after_operator_removed_record",
            "after_operator_archive_rename",
            "after_operator_transactions_parent_fsync",
            "after_operator_completed_parent_fsync",
        )
        for index, phase in enumerate(phases):
            with self.subTest(phase=phase):
                temporary, shared_root = self.fixture()
                token = f"{index + 40:064x}"
                intent = f"{index + 140:064x}"
                outer_acked = f"{index + 240:064x}"
                lease = self.create(
                    shared_root,
                    token,
                    transaction_intent_sha256=intent,
                )
                self.assertIsInstance(
                    lease,
                    staging.CaptureStagingLease,
                )
                assert isinstance(lease, staging.CaptureStagingLease)
                identity = lease.identity_sha256
                (lease.leaf_path / "partial").write_bytes(b"x")
                terminal = self.assert_outcome(
                    lease.finish_failure(),
                    "quarantined",
                )
                staging._acknowledge_terminal_tombstone_for_test(
                    shared_root,
                    session_id=token,
                    staging_transaction_intent_sha256=intent,
                    terminal_receipt=terminal.terminal_receipt,
                    outer_ack_pending_record_sha256=(
                        f"{index + 340:064x}"
                    ),
                    outer_quarantine_intent_record_sha256=(
                        f"{index + 440:064x}"
                    ),
                )

                def fault(observed: str) -> None:
                    if observed == phase:
                        raise RuntimeError("injected resolution fault")

                with self.assertRaisesRegex(
                    RuntimeError,
                    "injected resolution fault",
                ):
                    staging._resolve_quarantined_session_for_test(
                        shared_root,
                        session_id=token,
                        staging_transaction_intent_sha256=intent,
                        outer_staging_tombstone_acked_record_sha256=(
                            outer_acked
                        ),
                        expected_identity_sha256=identity,
                        fault_hook=fault,
                    )
                self.assertEqual(
                    staging._resolve_quarantined_session_for_test(
                        shared_root,
                        session_id=token,
                        staging_transaction_intent_sha256=intent,
                        outer_staging_tombstone_acked_record_sha256=(
                            outer_acked
                        ),
                        expected_identity_sha256=identity,
                    ),
                    "removed",
                )
                self.assertEqual(
                    staging._resolve_quarantined_session_for_test(
                        shared_root,
                        session_id=token,
                        staging_transaction_intent_sha256=intent,
                        outer_staging_tombstone_acked_record_sha256=(
                            outer_acked
                        ),
                        expected_identity_sha256=identity,
                    ),
                    "removed",
                )
                archived = (
                    shared_root
                    / staging.TRANSACTIONS_NAMESPACE
                    / staging.COMPLETED_NAMESPACE
                    / f"session-{token}.jsonl"
                )
                events = [
                    json.loads(line)["event"]
                    for line in archived.read_text(
                        encoding="ascii"
                    ).splitlines()
                ]
                self.assertEqual(
                    events.count("operator_resolution_intent"),
                    1,
                )
                self.assertEqual(events.count("operator_removed"), 1)
                temporary.cleanup()

    def test_operator_resolution_requires_ack_intent_and_capacity(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        token = "4a" * 32
        intent = "5a" * 32
        outer_acked = "6a" * 32
        lease = self.create(
            shared_root,
            token,
            transaction_intent_sha256=intent,
        )
        self.assertIsInstance(lease, staging.CaptureStagingLease)
        assert isinstance(lease, staging.CaptureStagingLease)
        identity = lease.identity_sha256
        (lease.leaf_path / "partial").write_bytes(b"x")
        terminal = self.assert_outcome(
            lease.finish_failure(),
            "quarantined",
        )
        self.assert_code(
            "capture_staging_operator_ack_required",
            staging._resolve_quarantined_session_for_test,
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256=intent,
            outer_staging_tombstone_acked_record_sha256=outer_acked,
            expected_identity_sha256=identity,
        )
        staging._acknowledge_terminal_tombstone_for_test(
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256=intent,
            terminal_receipt=terminal.terminal_receipt,
            outer_ack_pending_record_sha256="7a" * 32,
            outer_quarantine_intent_record_sha256="8a" * 32,
        )
        journal = (
            shared_root
            / staging.TRANSACTIONS_NAMESPACE
            / f"session-{token}.jsonl"
        )
        quarantine = (
            shared_root
            / staging.QUARANTINE_NAMESPACE
            / staging.QUARANTINE_STAGING_NAMESPACE
            / f"session-{token}"
        )
        before_journal = journal.read_bytes()
        before_marker = (quarantine / "partial").read_bytes()
        self.assert_code(
            "capture_staging_session_transaction_intent_conflict",
            staging._resolve_quarantined_session_for_test,
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256="8a" * 32,
            outer_staging_tombstone_acked_record_sha256=outer_acked,
            expected_identity_sha256=identity,
        )
        with mock.patch.object(
            staging,
            "MAX_COMPLETED_TOMBSTONES",
            0,
        ):
            self.assert_code(
                "capture_staging_completed_capacity_exceeded",
                staging._resolve_quarantined_session_for_test,
                shared_root,
                session_id=token,
                staging_transaction_intent_sha256=intent,
                outer_staging_tombstone_acked_record_sha256=(
                    outer_acked
                ),
                expected_identity_sha256=identity,
            )
        self.assertEqual(journal.read_bytes(), before_journal)
        self.assertEqual(
            (quarantine / "partial").read_bytes(),
            before_marker,
        )

        def stop_after_intent(observed: str) -> None:
            if observed == "after_operator_resolution_intent":
                raise RuntimeError("stop after disposal intent")

        with self.assertRaisesRegex(
            RuntimeError,
            "stop after disposal intent",
        ):
            staging._resolve_quarantined_session_for_test(
                shared_root,
                session_id=token,
                staging_transaction_intent_sha256=intent,
                outer_staging_tombstone_acked_record_sha256=(
                    outer_acked
                ),
                expected_identity_sha256=identity,
                fault_hook=stop_after_intent,
            )
        self.assert_code(
            "capture_staging_operator_outer_acked_conflict",
            staging._resolve_quarantined_session_for_test,
            shared_root,
            session_id=token,
            staging_transaction_intent_sha256=intent,
            outer_staging_tombstone_acked_record_sha256="9a" * 32,
            expected_identity_sha256=identity,
        )
        self.assertEqual(
            staging._resolve_quarantined_session_for_test(
                shared_root,
                session_id=token,
                staging_transaction_intent_sha256=intent,
                outer_staging_tombstone_acked_record_sha256=(
                    outer_acked
                ),
                expected_identity_sha256=identity,
            ),
            "removed",
        )
        archived = (
            shared_root
            / staging.TRANSACTIONS_NAMESPACE
            / staging.COMPLETED_NAMESPACE
            / f"session-{token}.jsonl"
        )
        records = [
            json.loads(line)
            for line in archived.read_text(
                encoding="ascii"
            ).splitlines()
        ]
        disposal = next(
            record
            for record in records
            if record["event"] == "operator_resolution_intent"
        )
        ack_record = next(
            record
            for record in records
            if record["event"]
            == staging.staging_receipts.STAGING_TOMBSTONE_ACK_EVENT
        )
        self.assertEqual(
            disposal[
                "outer_staging_tombstone_acked_record_sha256"
            ],
            outer_acked,
        )
        self.assertEqual(
            disposal["previous_record_sha256"],
            ack_record["record_sha256"],
        )
        self.assertEqual(
            disposal["outer_ack_pending_record_sha256"],
            ack_record["outer_ack_pending_record_sha256"],
        )

    def test_sigkill_recovery_quarantines_without_signalling_saved_ids(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        lease = self.create(shared_root, "7" * 64)
        session_name = lease.session_name
        lease.record_spawn_intent()
        lease.record_spawned()
        (lease.leaf_path / "partial").write_text(
            "untrusted",
            encoding="utf-8",
        )
        lease._abandon_for_test()

        with (
            mock.patch.object(staging.os, "kill") as kill,
            mock.patch.object(staging.os, "killpg") as killpg,
        ):
            recovered = self.create(shared_root, "7" * 64)
        kill.assert_not_called()
        killpg.assert_not_called()
        self.assert_outcome(recovered, "quarantined")
        quarantined = (
            shared_root
            / staging.QUARANTINE_NAMESPACE
            / staging.QUARANTINE_STAGING_NAMESPACE
            / session_name
        )
        self.assertTrue(quarantined.is_dir())
        self.assertEqual(
            stat.S_IMODE(quarantined.stat().st_mode),
            staging.REVOKED_LEAF_MODE,
        )

    def test_torn_final_journal_tail_is_repaired_but_full_corruption_fails(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        lease = self.create(shared_root, "8" * 64)
        session_name = lease.session_name
        lease._abandon_for_test()
        journal_path = (
            shared_root
            / staging.TRANSACTIONS_NAMESPACE
            / f"{session_name}.jsonl"
        )
        durable_prefix = journal_path.read_bytes()
        with journal_path.open("ab") as stream:
            stream.write(b'{"event":')
            stream.flush()
            os.fsync(stream.fileno())

        recovered_outcome = self.create(shared_root, "8" * 64)
        self.assert_outcome(recovered_outcome, "quarantined")
        repaired = journal_path.read_bytes()
        self.assertTrue(repaired.startswith(durable_prefix))
        self.assertTrue(repaired.endswith(b"\n"))
        state = staging._parse_journal(
            repaired,
            session_name=session_name,
        )
        self.assertEqual(state.last_event, "startup_quarantined")
        self.assertFalse(state.torn_tail)

        second = self.create(shared_root, "a" * 64)
        self.assertIsInstance(second, staging.CaptureStagingLease)
        assert isinstance(second, staging.CaptureStagingLease)
        second_name = second.session_name
        second._abandon_for_test()
        second_journal = (
            shared_root
            / staging.TRANSACTIONS_NAMESPACE
            / f"{second_name}.jsonl"
        )
        with second_journal.open("ab") as stream:
            stream.write(b"{}\n")
            stream.flush()
            os.fsync(stream.fileno())
        self.assert_code(
            "capture_staging_journal_invalid",
            self.create,
            shared_root,
            "a" * 64,
        )

    def test_selected_creation_never_globally_sweeps_journals(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        bootstrap = self.create(shared_root, "c" * 64)
        self.assertIsInstance(bootstrap, staging.CaptureStagingLease)
        assert isinstance(bootstrap, staging.CaptureStagingLease)
        self.assert_outcome(bootstrap.finish_success(), "absent")
        transactions = (
            shared_root / staging.TRANSACTIONS_NAMESPACE
        )
        session_name = f"session-{100:064x}"
        orphan = transactions / f"{session_name}.jsonl"
        descriptor = os.open(
            orphan,
            os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL,
            staging.JOURNAL_FILE_MODE,
        )
        try:
            os.set_inheritable(descriptor, False)
            staging._append_record(
                descriptor,
                session_name=session_name,
                sequence=0,
                event="create_intent",
                identity_sha256=None,
                staging_transaction_intent_sha256="ac" * 32,
            )
        finally:
            os.close(descriptor)
        before = orphan.read_bytes()
        next_lease = self.create(shared_root, "d" * 64)
        self.assertIsInstance(next_lease, staging.CaptureStagingLease)
        assert isinstance(next_lease, staging.CaptureStagingLease)
        self.assertEqual(orphan.read_bytes(), before)
        self.assert_outcome(next_lease.finish_success(), "absent")
        self.assert_code(
            "capture_staging_global_recovery_disabled",
            staging._recover_namespaces,
            recovery_fd=-1,
            quarantine_fd=-1,
            transactions_fd=-1,
            identities=staging._StagingIdentities(
                root_uid=os.geteuid(),
                root_gid=os.getegid(),
                capture_uid=os.geteuid(),
                export_gid=os.getegid(),
            ),
            device=0,
        )

    def test_pre_ack_terminal_journal_cannot_be_retired(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        token = f"{200:064x}"
        lease = self.create(shared_root, token)
        self.assertIsInstance(lease, staging.CaptureStagingLease)
        assert isinstance(lease, staging.CaptureStagingLease)
        self.assert_outcome(lease.finish_success(), "absent")
        recovery_fd = os.open(
            shared_root / staging.RECOVERY_NAMESPACE,
            os.O_RDONLY | os.O_DIRECTORY,
        )
        quarantine_fd = os.open(
            shared_root
            / staging.QUARANTINE_NAMESPACE
            / staging.QUARANTINE_STAGING_NAMESPACE,
            os.O_RDONLY | os.O_DIRECTORY,
        )
        transactions_fd = os.open(
            shared_root / staging.TRANSACTIONS_NAMESPACE,
            os.O_RDONLY | os.O_DIRECTORY,
        )
        journal_fd = os.open(
            f"session-{token}.jsonl",
            os.O_RDWR,
            dir_fd=transactions_fd,
        )
        try:
            self.assert_code(
                "capture_staging_journal_not_terminal",
                staging._retire_terminal_journal,
                recovery_fd=recovery_fd,
                quarantine_fd=quarantine_fd,
                transactions_fd=transactions_fd,
                session_name=f"session-{token}",
                journal_fd=journal_fd,
            )
        finally:
            os.close(journal_fd)
            os.close(transactions_fd)
            os.close(quarantine_fd)
            os.close(recovery_fd)

    def test_create_phase_faults_release_lock_and_allow_next_run(
        self,
    ) -> None:
        phases = (
            "after_create_intent",
            "after_leaf_created",
            "after_leaf_identity_journaled",
            "after_exposure_intent",
            "after_staging_exposed",
        )
        for index, phase in enumerate(phases):
            temporary, shared_root = self.fixture()
            with self.subTest(phase=phase):
                calls: list[str] = []

                def fault(observed: str) -> None:
                    calls.append(observed)
                    if observed == phase:
                        raise RuntimeError("injected phase fault")

                with self.assertRaises(RuntimeError):
                    self.create(
                        shared_root,
                        f"{index + 10:064x}",
                        fault_hook=fault,
                    )
                self.assertIn(phase, calls)
                next_lease = self.create(
                    shared_root,
                    f"{index + 20:064x}",
                )
                self.assertIsInstance(
                    next_lease,
                    staging.CaptureStagingLease,
                )
                assert isinstance(
                    next_lease,
                    staging.CaptureStagingLease,
                )
                self.assert_outcome(
                    next_lease.finish_success(),
                    "absent",
                )
            temporary.cleanup()

    def test_recovery_rejects_name_and_inode_substitution(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        lease = self.create(shared_root, "9" * 64)
        leaf = lease.leaf_path
        lease._abandon_for_test()
        leaf.rmdir()
        leaf.mkdir(mode=staging.EXPOSED_LEAF_MODE)
        leaf.chmod(staging.EXPOSED_LEAF_MODE)
        self.assert_code(
            "capture_staging_recovery_leaf_identity_mismatch",
            self.create,
            shared_root,
            "9" * 64,
        )

        leaf.rmdir()
        recovery = shared_root / staging.RECOVERY_NAMESPACE
        (recovery / "foreign").mkdir()
        unrelated = self.create(shared_root, "b" * 64)
        self.assertIsInstance(
            unrelated,
            staging.CaptureStagingLease,
        )
        assert isinstance(unrelated, staging.CaptureStagingLease)
        self.assert_outcome(unrelated.finish_success(), "absent")

    def test_recovery_rejects_symlink_and_quarantine_mode_drift(
        self,
    ) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        lease = self.create(shared_root, "c" * 64)
        leaf = lease.leaf_path
        lease._abandon_for_test()
        leaf.rmdir()
        leaf.symlink_to(shared_root)
        self.assert_code(
            "capture_staging_recovery_leaf_unreadable",
            self.create,
            shared_root,
            "c" * 64,
        )
        leaf.unlink()

        second = self.create(shared_root, "e" * 64)
        session_name = second.session_name
        (second.leaf_path / "partial").write_text(
            "x",
            encoding="utf-8",
        )
        self.assert_outcome(second.finish_failure(), "quarantined")
        quarantined = (
            shared_root
            / staging.QUARANTINE_NAMESPACE
            / staging.QUARANTINE_STAGING_NAMESPACE
            / session_name
        )
        quarantined.chmod(0o777)
        self.assert_code(
            "capture_staging_quarantine_leaf_unsafe",
            self.create,
            shared_root,
            "e" * 64,
        )

    def test_public_creation_requires_real_root(self) -> None:
        temporary, shared_root = self.fixture()
        self.addCleanup(temporary.cleanup)
        with (
            mock.patch.object(staging.os, "getuid", return_value=501),
            mock.patch.object(staging.os, "geteuid", return_value=0),
        ):
            self.assert_code(
                "capture_staging_requires_root",
                staging.create_session_staging,
                shared_root,
                session_id="1" * 64,
                staging_transaction_intent_sha256="2" * 64,
                capture_uid=502,
                export_gid=503,
            )
            self.assert_code(
                "capture_staging_operator_resolution_requires_root",
                staging.resolve_quarantined_session,
                shared_root,
                session_id="1" * 64,
                staging_transaction_intent_sha256="3" * 64,
                outer_staging_tombstone_acked_record_sha256=(
                    "4" * 64
                ),
                expected_identity_sha256="2" * 64,
            )
        self.assertIs(staging.PRODUCTION_ACTIVATION, False)


if __name__ == "__main__":
    unittest.main()
