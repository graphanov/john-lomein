from __future__ import annotations

import hashlib
import json
import sys
import unittest
from collections import OrderedDict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (
    john_lomein_persona_qualification_capture_staging_receipts as receipts,
)


class PersonaQualificationCaptureStagingReceiptTests(
    unittest.TestCase
):
    session_id = "1" * 64

    def digest(self, label: str) -> str:
        return hashlib.sha256(label.encode("ascii")).hexdigest()

    def exposure(self) -> dict:
        return {
            "schema_version": receipts.STAGING_EXPOSURE_RECEIPT_SCHEMA,
            "status": receipts.STAGING_EXPOSURE_STATUS,
            "capture_session_id": self.session_id,
            "staging_leaf_name": f"session-{self.session_id}",
            "staging_transaction_intent_sha256": self.digest("intent"),
            "staging_leaf_identity_sha256": self.digest("leaf"),
            "capture_uid": 501,
            "export_gid": 502,
            "staging_leaf_mode": 0o700,
            "filesystem_device": 42,
            "shared_root_identity_sha256": self.digest("shared-root"),
            "recovery_namespace_identity_sha256": self.digest("recovery"),
            "quarantine_namespace_identity_sha256": self.digest(
                "quarantine"
            ),
            "transactions_namespace_identity_sha256": self.digest(
                "transactions"
            ),
            "staging_journal_schema": (
                receipts.CAPTURE_STAGING_JOURNAL_SCHEMA
            ),
            "staging_journal_sequence": 3,
            "staging_journal_head_sha256": self.digest("journal-head"),
        }

    def common_terminal(self) -> dict:
        return {
            "capture_session_id": self.session_id,
            "staging_leaf_name": f"session-{self.session_id}",
            "staging_transaction_intent_sha256": self.digest("intent"),
            "staging_leaf_identity_sha256": self.digest("leaf"),
            "filesystem_device": 42,
            "shared_root_identity_sha256": self.digest("shared-root"),
            "recovery_namespace_identity_sha256": self.digest("recovery"),
            "quarantine_namespace_identity_sha256": self.digest(
                "quarantine"
            ),
            "transactions_namespace_identity_sha256": self.digest(
                "transactions"
            ),
            "staging_journal_schema": (
                receipts.CAPTURE_STAGING_JOURNAL_SCHEMA
            ),
            "inspection_lock_epoch_sha256": self.digest("lock-epoch"),
            "terminal_event": "startup_absent",
            "terminal_sequence": 5,
            "terminal_record_sha256": self.digest("terminal-record"),
            "tombstone_sha256": self.digest("tombstone"),
        }

    def absence(self) -> dict:
        return {
            "schema_version": receipts.STAGING_ABSENCE_RECEIPT_SCHEMA,
            "status": receipts.STAGING_ABSENCE_STATUS,
            **self.common_terminal(),
            "quarantine_reason_code": None,
            "lifecycle_status": "not_applicable",
            "lifecycle_scope_empty_receipt_sha256": None,
        }

    def quarantine(self) -> dict:
        common = self.common_terminal()
        common["terminal_event"] = "startup_quarantined"
        return {
            "schema_version": receipts.STAGING_QUARANTINE_RECEIPT_SCHEMA,
            "status": receipts.STAGING_QUARANTINE_STATUS,
            **common,
            "quarantine_namespace": "staging",
            "quarantine_name": f"session-{self.session_id}",
            "quarantined_stat_sha256": self.digest("quarantined-stat"),
            "reason_code": "coordinator_restarted",
            "lifecycle_status": "scope_not_proven",
            "lifecycle_scope_empty_receipt_sha256": None,
            "rename_primitive": "renameat2_noreplace",
            "rename_noreplace": True,
            "parents_fsynced": True,
        }

    def acknowledgement(self) -> dict:
        return {
            "schema_version": (
                receipts.STAGING_TOMBSTONE_ACK_RECEIPT_SCHEMA
            ),
            "status": receipts.STAGING_TOMBSTONE_ACK_STATUS,
            "capture_session_id": self.session_id,
            "staging_transaction_intent_sha256": self.digest("intent"),
            "terminal_receipt_sha256": self.digest("terminal-receipt"),
            "tombstone_sha256": self.digest("tombstone"),
            "outer_ack_pending_record_sha256": self.digest(
                "outer-ack-pending"
            ),
            "outer_quarantine_intent_record_sha256": None,
            "outer_lifecycle_clearance_record_sha256": None,
            "terminal_disposition": "absent",
            "staging_journal_schema": (
                receipts.CAPTURE_STAGING_JOURNAL_SCHEMA
            ),
            "ack_event": receipts.STAGING_TOMBSTONE_ACK_EVENT,
            "ack_sequence": 6,
            "ack_previous_record_sha256": self.digest(
                "terminal-record"
            ),
            "ack_record_sha256": self.digest("ack-record"),
            "inspection_lock_epoch_sha256": self.digest("lock-epoch"),
            "journal_storage_disposition": (
                "completed_absence_journal"
            ),
            "ack_journal_identity_sha256": self.digest(
                "ack-journal-identity"
            ),
            "ack_journal_readback_sha256": self.digest(
                "ack-journal-readback"
            ),
            "transactions_parent_fsynced": True,
            "completed_parent_fsynced": True,
        }

    def assert_rejected(self, function, value: dict) -> None:
        with self.assertRaises(receipts.CaptureStagingReceiptError):
            function(value)

    def independent_digest(self, value: dict) -> str:
        raw = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        return hashlib.sha256(raw).hexdigest()

    def test_exposure_receipt_is_exact_canonical_and_deterministic(
        self,
    ) -> None:
        value = self.exposure()
        normalized = receipts.normalize_staging_exposure_receipt(value)
        self.assertEqual(normalized, value)
        self.assertEqual(
            set(normalized),
            receipts.STAGING_EXPOSURE_RECEIPT_FIELDS,
        )
        expected = self.independent_digest(normalized)
        self.assertEqual(
            receipts.staging_exposure_receipt_sha256(value),
            expected,
        )
        reversed_value = OrderedDict(reversed(tuple(value.items())))
        self.assertEqual(
            receipts.staging_exposure_receipt_sha256(reversed_value),
            expected,
        )

    def test_exposure_receipt_rejects_every_hostile_binding_mutation(
        self,
    ) -> None:
        mutations = {
            "schema_version": "wrong.schema",
            "status": "exposed",
            "capture_session_id": "A" * 64,
            "staging_leaf_name": "session-" + "2" * 64,
            "staging_transaction_intent_sha256": "not-a-digest",
            "staging_leaf_identity_sha256": None,
            "capture_uid": True,
            "export_gid": 0,
            "staging_leaf_mode": 0o755,
            "staging_journal_sequence": 4,
            "filesystem_device": -1,
            "shared_root_identity_sha256": None,
            "recovery_namespace_identity_sha256": "0" * 63,
            "quarantine_namespace_identity_sha256": "A" * 64,
            "transactions_namespace_identity_sha256": 1,
            "staging_journal_schema": (
                "john-lomein.persona-qualification-"
                "capture-staging-journal.v2"
            ),
            "staging_journal_head_sha256": "f" * 63,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                changed = self.exposure()
                changed[field] = replacement
                self.assert_rejected(
                    receipts.normalize_staging_exposure_receipt,
                    changed,
                )
        for field in tuple(self.exposure()):
            with self.subTest(missing=field):
                changed = self.exposure()
                del changed[field]
                self.assert_rejected(
                    receipts.normalize_staging_exposure_receipt,
                    changed,
                )
        for forbidden in ("path", "pid", "pgid", "created_at_unix"):
            with self.subTest(extra=forbidden):
                changed = self.exposure()
                changed[forbidden] = "/secret" if forbidden == "path" else 1
                self.assert_rejected(
                    receipts.normalize_staging_exposure_receipt,
                    changed,
                )

    def test_absence_receipt_enforces_nullable_identity_and_namespaces(
        self,
    ) -> None:
        without_identity = self.absence()
        without_identity["staging_leaf_identity_sha256"] = None
        normalized = receipts.normalize_staging_absence_receipt(
            without_identity
        )
        self.assertIsNone(normalized["staging_leaf_identity_sha256"])
        self.assertEqual(
            receipts.staging_absence_receipt_sha256(without_identity),
            self.independent_digest(normalized),
        )

        mutations = {
            "schema_version": "wrong.schema",
            "status": "absent",
            "capture_session_id": "2" * 63,
            "staging_leaf_name": "session-" + "2" * 64,
            "staging_transaction_intent_sha256": "x" * 64,
            "staging_leaf_identity_sha256": 7,
            "filesystem_device": True,
            "shared_root_identity_sha256": None,
            "recovery_namespace_identity_sha256": "0" * 63,
            "quarantine_namespace_identity_sha256": "A" * 64,
            "transactions_namespace_identity_sha256": "",
            "staging_journal_schema": "wrong.schema",
            "terminal_event": "quarantined",
            "terminal_sequence": -1,
            "terminal_record_sha256": None,
            "tombstone_sha256": "not-a-digest",
            "quarantine_reason_code": "Capture-Failed",
            "inspection_lock_epoch_sha256": 1,
            "lifecycle_status": "dead",
            "lifecycle_scope_empty_receipt_sha256": "bad",
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                changed = self.absence()
                changed[field] = replacement
                self.assert_rejected(
                    receipts.normalize_staging_absence_receipt,
                    changed,
                )
        removed_without_identity = self.absence()
        removed_without_identity["terminal_event"] = "removed"
        removed_without_identity["staging_leaf_identity_sha256"] = None
        self.assert_rejected(
            receipts.normalize_staging_absence_receipt,
            removed_without_identity,
        )
        quarantine_removed = self.absence()
        quarantine_removed["terminal_event"] = "quarantine_removed"
        quarantine_removed["quarantine_reason_code"] = "capture_failed"
        receipts.normalize_staging_absence_receipt(
            quarantine_removed
        )
        missing_reason = dict(quarantine_removed)
        missing_reason["quarantine_reason_code"] = None
        self.assert_rejected(
            receipts.normalize_staging_absence_receipt,
            missing_reason,
        )
        ordinary_with_reason = self.absence()
        ordinary_with_reason["terminal_event"] = "removed"
        ordinary_with_reason["quarantine_reason_code"] = (
            "capture_failed"
        )
        self.assert_rejected(
            receipts.normalize_staging_absence_receipt,
            ordinary_with_reason,
        )

    def test_quarantine_receipt_binds_exact_object_and_effect_proofs(
        self,
    ) -> None:
        value = self.quarantine()
        normalized = receipts.normalize_staging_quarantine_receipt(
            value
        )
        self.assertEqual(normalized, value)
        self.assertEqual(
            receipts.staging_quarantine_receipt_sha256(value),
            self.independent_digest(normalized),
        )

        mutations = {
            "schema_version": "wrong.schema",
            "status": "quarantined",
            "capture_session_id": "2" * 64,
            "staging_leaf_name": "session-" + "2" * 64,
            "staging_transaction_intent_sha256": None,
            "staging_leaf_identity_sha256": None,
            "filesystem_device": -1,
            "shared_root_identity_sha256": "z" * 64,
            "recovery_namespace_identity_sha256": None,
            "quarantine_namespace_identity_sha256": "f" * 63,
            "transactions_namespace_identity_sha256": 1,
            "staging_journal_schema": "wrong.schema",
            "inspection_lock_epoch_sha256": "",
            "quarantine_namespace": "adopted",
            "quarantine_name": "session-" + "2" * 64,
            "quarantined_stat_sha256": None,
            "reason_code": "Coordinator-Restarted",
            "lifecycle_status": "dead",
            "rename_primitive": "rename",
            "rename_noreplace": 1,
            "parents_fsynced": False,
            "terminal_event": "startup_absent",
            "terminal_sequence": True,
            "terminal_record_sha256": "0" * 65,
            "tombstone_sha256": None,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                changed = self.quarantine()
                changed[field] = replacement
                self.assert_rejected(
                    receipts.normalize_staging_quarantine_receipt,
                    changed,
                )

    def test_quarantine_lifecycle_receipt_null_convention_is_exact(
        self,
    ) -> None:
        scope_empty = self.quarantine()
        scope_empty["lifecycle_status"] = "scope_empty"
        scope_empty["lifecycle_scope_empty_receipt_sha256"] = self.digest(
            "scope-empty"
        )
        receipts.normalize_staging_quarantine_receipt(scope_empty)

        missing = dict(scope_empty)
        missing["lifecycle_scope_empty_receipt_sha256"] = None
        self.assert_rejected(
            receipts.normalize_staging_quarantine_receipt,
            missing,
        )

        unexpected = self.quarantine()
        unexpected["lifecycle_scope_empty_receipt_sha256"] = self.digest(
            "scope-empty"
        )
        self.assert_rejected(
            receipts.normalize_staging_quarantine_receipt,
            unexpected,
        )

    def test_acknowledgement_is_strict_deterministic_and_path_free(
        self,
    ) -> None:
        value = self.acknowledgement()
        normalized = (
            receipts.normalize_staging_tombstone_ack_receipt(value)
        )
        self.assertEqual(normalized, value)
        self.assertEqual(
            receipts.staging_tombstone_ack_receipt_sha256(value),
            self.independent_digest(normalized),
        )
        quarantined = dict(value)
        quarantined["terminal_disposition"] = "quarantined"
        quarantined["outer_quarantine_intent_record_sha256"] = (
            self.digest("outer-quarantine-intent")
        )
        quarantined["journal_storage_disposition"] = (
            "retained_quarantine_journal"
        )
        quarantined["completed_parent_fsynced"] = False
        receipts.normalize_staging_tombstone_ack_receipt(quarantined)
        missing_quarantine_intent = dict(quarantined)
        missing_quarantine_intent[
            "outer_quarantine_intent_record_sha256"
        ] = None
        self.assert_rejected(
            receipts.normalize_staging_tombstone_ack_receipt,
            missing_quarantine_intent,
        )
        quarantine_derived_absence = dict(value)
        quarantine_derived_absence[
            "outer_quarantine_intent_record_sha256"
        ] = self.digest("outer-quarantine-intent")
        receipts.normalize_staging_tombstone_ack_receipt(
            quarantine_derived_absence
        )

        mutations = {
            "schema_version": "wrong.schema",
            "status": "acked",
            "capture_session_id": "1" * 63,
            "staging_transaction_intent_sha256": None,
            "terminal_receipt_sha256": "g" * 64,
            "tombstone_sha256": 1,
            "outer_ack_pending_record_sha256": "f" * 65,
            "outer_quarantine_intent_record_sha256": "bad",
            "outer_lifecycle_clearance_record_sha256": "bad",
            "terminal_disposition": "removed",
            "staging_journal_schema": "wrong.schema",
            "ack_event": "acknowledged",
            "ack_sequence": True,
            "ack_previous_record_sha256": None,
            "ack_record_sha256": "0" * 63,
            "inspection_lock_epoch_sha256": 1,
            "journal_storage_disposition": "retired",
            "ack_journal_identity_sha256": "",
            "ack_journal_readback_sha256": "A" * 64,
            "transactions_parent_fsynced": False,
            "completed_parent_fsynced": False,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                changed = self.acknowledgement()
                changed[field] = replacement
                self.assert_rejected(
                    receipts.normalize_staging_tombstone_ack_receipt,
                    changed,
                )
        for forbidden in (
            "path",
            "pid",
            "pgid",
            "acknowledged_at_unix",
        ):
            with self.subTest(extra=forbidden):
                changed = self.acknowledgement()
                changed[forbidden] = 1
                self.assert_rejected(
                    receipts.normalize_staging_tombstone_ack_receipt,
                    changed,
                )

    def test_nfc_and_exact_type_guards_reject_lookalikes(self) -> None:
        quarantine = self.quarantine()
        quarantine["reason_code"] = "caf" + "e\u0301"
        self.assert_rejected(
            receipts.normalize_staging_quarantine_receipt,
            quarantine,
        )

        absence = self.absence()
        absence["terminal_event"] = True
        self.assert_rejected(
            receipts.normalize_staging_absence_receipt,
            absence,
        )

    def test_every_schema_rejects_missing_and_forbidden_fields(
        self,
    ) -> None:
        cases = (
            (
                self.exposure,
                receipts.normalize_staging_exposure_receipt,
            ),
            (
                self.absence,
                receipts.normalize_staging_absence_receipt,
            ),
            (
                self.quarantine,
                receipts.normalize_staging_quarantine_receipt,
            ),
            (
                self.acknowledgement,
                receipts.normalize_staging_tombstone_ack_receipt,
            ),
        )
        forbidden = {
            "path": "/private/secret",
            "pid": 123,
            "pgid": 123,
            "recorded_at_unix": 1,
        }
        for factory, normalizer in cases:
            value = factory()
            for field in tuple(value):
                with self.subTest(
                    schema=value["schema_version"],
                    missing=field,
                ):
                    changed = dict(value)
                    del changed[field]
                    self.assert_rejected(normalizer, changed)
            for field, selected in forbidden.items():
                with self.subTest(
                    schema=value["schema_version"],
                    forbidden=field,
                ):
                    changed = dict(value)
                    changed[field] = selected
                    self.assert_rejected(normalizer, changed)

    def test_public_surface_is_explicit(self) -> None:
        exported = set(receipts.__all__)
        for name in (
            "normalize_staging_exposure_receipt",
            "staging_exposure_receipt_sha256",
            "normalize_staging_absence_receipt",
            "staging_absence_receipt_sha256",
            "normalize_staging_quarantine_receipt",
            "staging_quarantine_receipt_sha256",
            "normalize_staging_tombstone_ack_receipt",
            "staging_tombstone_ack_receipt_sha256",
        ):
            self.assertIn(name, exported)

    def test_canonical_hash_vectors_are_stable(self) -> None:
        vectors = (
            (
                receipts.staging_exposure_receipt_sha256,
                self.exposure(),
                (
                    "0c71939a3a480c33f0ba2979d7f6d08d"
                    "d5f45d1aecfdface1afa2de0d8497901"
                ),
            ),
            (
                receipts.staging_absence_receipt_sha256,
                self.absence(),
                (
                    "9fa4c3bef979a30bd7181870e6f125e2"
                    "c833e6f7490b3f4c47a56003fdd1a42e"
                ),
            ),
            (
                receipts.staging_quarantine_receipt_sha256,
                self.quarantine(),
                (
                    "00b49bee69d1ed0af9ed351dace4ece5"
                    "a4f02fb9bd8fe47fbeb00210f81f2ba3"
                ),
            ),
            (
                receipts.staging_tombstone_ack_receipt_sha256,
                self.acknowledgement(),
                (
                    "0249a5cc909c5f2ee53aea4a305856aaf"
                    "50343094551b8d2e1bfcf9eca776112"
                ),
            ),
        )
        for function, value, expected in vectors:
            with self.subTest(function=function.__name__):
                self.assertEqual(function(value), expected)


if __name__ == "__main__":
    unittest.main()
