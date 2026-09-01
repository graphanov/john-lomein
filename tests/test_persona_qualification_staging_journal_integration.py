from __future__ import annotations

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
    john_lomein_persona_qualification_capture_staging as staging,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_transaction_journal as journal,
)


class PersonaQualificationStagingJournalIntegrationTests(
    unittest.TestCase
):
    """Exercise the real staging producer against the outer journal."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

        self.shared_root = self.root / "capture-staging"
        self.shared_root.mkdir(mode=staging.SHARED_ROOT_MODE)
        self.shared_root.chmod(staging.SHARED_ROOT_MODE)

        self.anchor = self.root / "outer" / "data"
        self.store_path = self.anchor / "state" / "transactions"
        self.store_path.mkdir(parents=True, mode=0o700)
        self.anchor.chmod(0o700)
        self.store_path.parent.chmod(0o700)
        self.store_path.chmod(0o700)
        (self.store_path / ".completed").mkdir(mode=0o700)
        (self.store_path / ".lock").touch(mode=0o600)

        self.store = journal._open_transaction_store_for_test(
            self.store_path,
            self.anchor,
        )
        self.addCleanup(
            lambda: self.store.close() if self.store.active else None
        )

    def digest(self, label: str) -> str:
        return hashlib.sha256(label.encode("ascii")).hexdigest()

    def begin_staging_session(
        self,
        session_id: str,
    ) -> tuple[
        journal.TransactionJournalSession,
        journal.TransactionJournalRecord,
        staging.CaptureStagingLease,
    ]:
        session = self.store._reserve_session_for_test(
            instance_slug="john-test",
            control_sha256=self.digest("control"),
            handoff_policy_sha256=self.digest("handoff"),
            recorded_at_unix=1,
            session_id=session_id,
        )
        intent = session.append_event(
            expected_state="reserved",
            next_state="staging_create_intent",
            details={
                "staging_leaf_name": f"session-{session_id}",
                "capture_uid": os.geteuid(),
                "export_gid": os.getegid(),
                "required_device": self.shared_root.stat().st_dev,
            },
            recorded_at_unix=2,
        )

        lease = staging._create_session_staging_for_test(
            self.shared_root,
            session_id=session_id,
            staging_transaction_intent_sha256=intent.record_sha256,
        )
        self.assertIsInstance(lease, staging.CaptureStagingLease)
        assert isinstance(lease, staging.CaptureStagingLease)
        exposure_receipt = lease.exposure_receipt
        session.append_event(
            expected_state="staging_create_intent",
            next_state="staging_exposed",
            details={
                "staging_exposure_receipt": exposure_receipt,
                "staging_exposure_receipt_sha256": (
                    lease.exposure_receipt_sha256
                ),
            },
            recorded_at_unix=3,
        )
        return session, intent, lease

    def test_real_absence_ack_is_accepted_by_outer_journal(
        self,
    ) -> None:
        session_id = "1" * 64
        session, intent, lease = self.begin_staging_session(
            session_id
        )

        terminal = lease.finish_success()
        self.assertEqual(terminal.disposition, "absent")
        pending = session.append_event(
            expected_state="staging_exposed",
            next_state="staging_tombstone_ack_pending",
            details={
                "from_state": "staging_exposed",
                "effect_origin_state": "staging_exposed",
                "terminal_disposition": terminal.disposition,
                "terminal_receipt": terminal.terminal_receipt,
                "terminal_receipt_sha256": (
                    terminal.terminal_receipt_sha256
                ),
                "tombstone_sha256": terminal.tombstone_sha256,
                "staging_quarantine_intent_record_sha256": None,
            },
            recorded_at_unix=4,
        )

        acknowledgement = (
            staging._acknowledge_terminal_tombstone_for_test(
                self.shared_root,
                session_id=session_id,
                staging_transaction_intent_sha256=(
                    intent.record_sha256
                ),
                terminal_receipt=terminal.terminal_receipt,
                outer_ack_pending_record_sha256=(
                    pending.record_sha256
                ),
            )
        )
        completed_journal = (
            self.shared_root
            / staging.TRANSACTIONS_NAMESPACE
            / staging.COMPLETED_NAMESPACE
            / f"session-{session_id}.jsonl"
        )
        ack_journal_raw = completed_journal.read_bytes()
        ack_records = [
            json.loads(line)
            for line in ack_journal_raw.decode("ascii").splitlines()
        ]
        self.assertEqual(
            acknowledgement["ack_record_sha256"],
            ack_records[-1]["record_sha256"],
        )
        self.assertEqual(
            acknowledgement["ack_sequence"],
            ack_records[-1]["sequence"],
        )
        self.assertEqual(
            acknowledgement["ack_previous_record_sha256"],
            ack_records[-1]["previous_record_sha256"],
        )
        self.assertEqual(
            acknowledgement["ack_journal_readback_sha256"],
            hashlib.sha256(ack_journal_raw).hexdigest(),
        )
        self.assertEqual(
            acknowledgement["ack_journal_identity_sha256"],
            staging._identity_sha256(completed_journal.stat()),
        )
        acknowledgement_sha256 = (
            journal.staging_tombstone_ack_receipt_sha256(
                acknowledgement
            )
        )
        session.append_event(
            expected_state="staging_tombstone_ack_pending",
            next_state="staging_tombstone_acked",
            details={
                "from_state": "staging_tombstone_ack_pending",
                "terminal_disposition": "absent",
                "terminal_receipt_sha256": (
                    terminal.terminal_receipt_sha256
                ),
                "tombstone_sha256": terminal.tombstone_sha256,
                "outer_ack_pending_record_sha256": (
                    pending.record_sha256
                ),
                "tombstone_ack_receipt": acknowledgement,
                "tombstone_ack_receipt_sha256": (
                    acknowledgement_sha256
                ),
                "adoption_reconciliation_record_sha256": None,
                "adoption_reconciliation_receipt_sha256": None,
            },
            recorded_at_unix=5,
        )
        session.append_event(
            expected_state="staging_tombstone_acked",
            next_state="staging_absent_cleanup_complete",
            details={
                "from_state": "staging_tombstone_acked",
                "terminal_disposition": "absent",
                "terminal_receipt_sha256": (
                    terminal.terminal_receipt_sha256
                ),
                "tombstone_ack_receipt_sha256": (
                    acknowledgement_sha256
                ),
            },
            recorded_at_unix=6,
        )

        self.assertTrue(completed_journal.is_file())
        self.assertFalse(
            (
                self.shared_root
                / staging.TRANSACTIONS_NAMESPACE
                / f"session-{session_id}.jsonl"
            ).exists()
        )
        self.assertEqual(
            session.state, "staging_absent_cleanup_complete"
        )

    def test_real_empty_failure_satisfies_outer_quarantine_intent(
        self,
    ) -> None:
        session_id = "2" * 64
        session, _, lease = self.begin_staging_session(session_id)
        quarantine_intent = session.append_event(
            expected_state="staging_exposed",
            next_state="quarantine_pending",
            details={
                "from_state": "staging_exposed",
                "namespace": "staging",
                "quarantine_name": f"session-{session_id}",
                "object_identity_sha256": lease.identity_sha256,
                "reason_code": "capture_failed",
                "lifecycle_status": "not_applicable",
                "empty_leaf_policy": "remove_and_fsync",
            },
            recorded_at_unix=4,
        )

        terminal = lease.finish_failure()
        self.assertEqual(terminal.disposition, "absent")
        self.assertEqual(
            terminal.terminal_receipt["terminal_event"],
            "quarantine_removed",
        )
        session.append_event(
            expected_state="quarantine_pending",
            next_state="staging_tombstone_ack_pending",
            details={
                "from_state": "quarantine_pending",
                "effect_origin_state": "staging_exposed",
                "terminal_disposition": "absent",
                "terminal_receipt": terminal.terminal_receipt,
                "terminal_receipt_sha256": (
                    terminal.terminal_receipt_sha256
                ),
                "tombstone_sha256": terminal.tombstone_sha256,
                "staging_quarantine_intent_record_sha256": (
                    quarantine_intent.record_sha256
                ),
            },
            recorded_at_unix=5,
        )
        self.assertEqual(
            session.state, "staging_tombstone_ack_pending"
        )


if __name__ == "__main__":
    unittest.main()
