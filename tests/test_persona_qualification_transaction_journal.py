from __future__ import annotations

import copy
import ctypes
import hashlib
import inspect
import json
import os
import pickle
import shutil
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (
    john_lomein_persona_qualification_transaction_journal as journal,
)
from qualification_attestor import (
    john_lomein_persona_qualification_lifecycle_receipts as lifecycle,
)
from qualification_attestor import (
    john_lomein_persona_qualification_adoption_reconciliation
    as adoption_reconciliation,
)
from qualification_attestor import (
    john_lomein_persona_qualification_recovered_adoption_evidence
    as recovered_adoption_evidence,
)


class SimulatedCrash(RuntimeError):
    pass


class PersonaQualificationTransactionJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.anchor, self.store_path = self.make_layout(self.root)
        self.stores: list[journal.TransactionJournalStore] = []
        self.addCleanup(self.close_stores)

    def close_stores(self) -> None:
        for store in reversed(self.stores):
            if store.active:
                store.close()

    def make_layout(self, root: Path) -> tuple[Path, Path]:
        anchor = root / "data"
        state = anchor / "state"
        store_path = state / "transactions"
        store_path.mkdir(parents=True, mode=0o700)
        anchor.chmod(0o700)
        state.chmod(0o700)
        store_path.chmod(0o700)
        completed_path = store_path / ".completed"
        completed_path.mkdir(mode=0o700)
        completed_path.chmod(0o700)
        lock_path = store_path / ".lock"
        lock_path.touch(mode=0o600)
        lock_path.chmod(0o600)
        return anchor, store_path

    def open_store(
        self,
        store_path: Path | None = None,
        anchor: Path | None = None,
    ) -> journal.TransactionJournalStore:
        store = journal._open_transaction_store_for_test(
            self.store_path if store_path is None else store_path,
            self.anchor if anchor is None else anchor,
        )
        self.stores.append(store)
        return store

    def digest(self, label: str) -> str:
        return hashlib.sha256(label.encode("ascii")).hexdigest()

    def reserve(
        self,
        store: journal.TransactionJournalStore,
        *,
        marker: str = "1",
        fault_hook=None,
    ) -> journal.TransactionJournalSession:
        return store._reserve_session_for_test(
            instance_slug="john-test",
            control_sha256=self.digest("control"),
            handoff_policy_sha256=self.digest("handoff"),
            recorded_at_unix=1,
            session_id=marker * 64,
            fault_hook=fault_hook,
        )

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(journal.TransactionJournalError) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def set_test_xattr(
        self,
        path: Path,
    ) -> tuple[ctypes.CDLL, bytes]:
        libc = ctypes.CDLL(None, use_errno=True)
        name = (
            b"com.john-lomein.test"
            if sys.platform == "darwin"
            else b"user.john-lomein-test"
        )
        value = ctypes.create_string_buffer(b"1")
        if sys.platform == "darwin":
            if not hasattr(libc, "setxattr"):
                self.skipTest("xattrs are not supported")
            libc.setxattr.argtypes = [
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_uint32,
                ctypes.c_int,
            ]
            result = libc.setxattr(
                os.fsencode(path),
                name,
                value,
                1,
                0,
                0,
            )
        elif sys.platform.startswith("linux"):
            if not hasattr(libc, "setxattr"):
                self.skipTest("xattrs are not supported")
            libc.setxattr.argtypes = [
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_int,
            ]
            result = libc.setxattr(
                os.fsencode(path),
                name,
                value,
                1,
                0,
            )
        else:
            self.skipTest("xattrs are not supported")
        if result != 0:
            self.skipTest("filesystem does not support test xattrs")
        return libc, name

    def remove_test_xattr(
        self,
        libc: ctypes.CDLL,
        path: Path,
        name: bytes,
    ) -> None:
        if sys.platform == "darwin":
            libc.removexattr.argtypes = [
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_int,
            ]
            libc.removexattr(os.fsencode(path), name, 0)
        else:
            libc.removexattr.argtypes = [
                ctypes.c_char_p,
                ctypes.c_char_p,
            ]
            libc.removexattr(os.fsencode(path), name)

    def lifecycle_activation_receipt(self) -> dict:
        return {
            "schema_version": lifecycle.ACTIVATION_RECEIPT_SCHEMA,
            "status": lifecycle.ACTIVATION_STATUS,
            "system": "Linux",
            "lifecycle_backend": lifecycle.LIFECYCLE_BACKEND,
            "lifecycle_provider": "linux_cgroup_v2",
            "supervisor_policy_sha256": self.digest(
                "supervisor-policy"
            ),
            "supervisor_bundle_sha256": self.digest(
                "supervisor-bundle"
            ),
            "helper_activation_policy_sha256": self.digest("helper"),
            "lifecycle_canary_sha256": self.digest(
                "lifecycle-canary"
            ),
            "host_boot_measurement": "linux_boot_id",
            "host_boot_id_sha256": self.digest("host-boot"),
            "assertions": {
                name: True for name in lifecycle.ACTIVATION_ASSERTIONS
            },
            "production_activation": False,
        }

    def lifecycle_scope_started_receipt(
        self,
        session: journal.TransactionJournalSession,
    ) -> dict:
        activation = self.lifecycle_activation_receipt()
        staging_intent = next(
            record
            for record in session.records
            if record.state == "staging_create_intent"
        )
        exposure = next(
            record
            for record in session.records
            if record.state == "staging_exposed"
        )
        launch = next(
            record
            for record in session.records
            if record.state == "child_launch_intent"
        )
        return {
            "schema_version": lifecycle.SCOPE_STARTED_RECEIPT_SCHEMA,
            "status": lifecycle.SCOPE_STARTED_STATUS,
            "capture_session_id": session.session_id,
            "lifecycle_backend": lifecycle.LIFECYCLE_BACKEND,
            "lifecycle_provider": "linux_cgroup_v2",
            "lifecycle_scope_id": (
                f"jlq-{lifecycle.LIFECYCLE_BACKEND}-"
                f"{session.session_id}"
            ),
            "scope_incarnation_id": self.digest(
                f"scope-incarnation-{session.session_id}"
            ),
            "supervisor_epoch_id": self.digest("supervisor-epoch"),
            "host_boot_id_sha256": self.digest("host-boot"),
            "staging_transaction_intent_sha256": (
                staging_intent.record_sha256
            ),
            "staging_exposure_receipt_sha256": exposure.details[
                "staging_exposure_receipt_sha256"
            ],
            "child_launch_intent_record_sha256": (
                launch.record_sha256
            ),
            "handoff_policy_sha256": self.digest("handoff"),
            "helper_activation_policy_sha256": self.digest("helper"),
            "capture_uid": staging_intent.details["capture_uid"],
            "export_gid": staging_intent.details["export_gid"],
            "lifecycle_activation_receipt_sha256": (
                lifecycle.activation_receipt_sha256(activation)
            ),
        }

    def lifecycle_clearance_intent_details(
        self,
        session: journal.TransactionJournalSession,
    ) -> dict:
        effect = session.latest_record
        if effect.state == "operator_attention":
            effect = session.records[-2]
        start_digest = None
        if effect.state != "child_launch_intent":
            started = next(
                record
                for record in session.records
                if record.state == "child_running"
            )
            start_digest = started.details[
                "lifecycle_scope_started_receipt_sha256"
            ]
        return {
            "effect_origin_state": effect.state,
            "effect_origin_record_revision": effect.revision,
            "effect_origin_record_sha256": effect.record_sha256,
            "scope_started_receipt_sha256": start_digest,
            "clearance_mode": (
                "wait_clean_then_terminate_on_deadline"
                if effect.state == "capture_ready"
                else "terminate_and_clear"
            ),
            "lifecycle_operation_binding": self.lifecycle_operation_binding(
                session,
                operation="prepare_clearance",
                successor_state="lifecycle_clearance_intent",
            ),
        }

    def lifecycle_operation_binding(
        self,
        session: journal.TransactionJournalSession,
        *,
        operation: str,
        successor_state: str,
        outcome: str = "success",
        error_code: str | None = None,
    ) -> dict:
        base = session.latest_record
        local = operation == "prepare_clearance"
        capture_event = successor_state == "capture_ready"
        await_clearance = (
            operation == "await_capture_event"
            and successor_state == "lifecycle_clearance_intent"
        )
        event = (
            "capture_ready"
            if capture_event
            else ("child_exited" if await_clearance else None)
        )
        ledger_head = None
        if local and "lifecycle_operation_binding" in base.details:
            ledger_head = base.details[
                "lifecycle_operation_binding"
            ]["supervisor_ledger_head_sha256"]
        elif not local:
            ledger_head = self.digest(
                f"ledger-{operation}-{base.revision}"
            )
        return {
            "schema_version": (
                journal.LIFECYCLE_OPERATION_BINDING_SCHEMA
            ),
            "operation": operation,
            "base_record_revision": base.revision,
            "base_record_sha256": base.record_sha256,
            "request_sha256": (
                None
                if local
                else self.digest(
                    f"supervisor-request-{operation}-{base.revision}"
                )
            ),
            "response_sha256": (
                None
                if local
                else self.digest(
                    f"supervisor-response-{operation}-{base.revision}"
                )
            ),
            "outcome": "local_intent" if local else outcome,
            "error_code": error_code,
            "result_sha256": (
                self.digest(
                    f"supervisor-result-{operation}-{base.revision}"
                )
                if outcome == "success" and not local
                else None
            ),
            "supervisor_ledger_head_sha256": ledger_head,
            "supervisor_event_sequence": (
                base.revision if event is not None else None
            ),
            "supervisor_event": event,
            "supervisor_event_record_sha256": (
                self.digest(f"supervisor-event-{base.revision}")
                if event is not None
                else None
            ),
            "supervisor_event_evidence_sha256": None,
        }

    def lifecycle_clearance_bundle(
        self,
        session: journal.TransactionJournalSession,
        *,
        disposition: str = "clean_exit",
        late_discovered_start: bool = False,
    ) -> dict:
        activation = self.lifecycle_activation_receipt()
        activation_digest = lifecycle.activation_receipt_sha256(
            activation
        )
        clearance_record = next(
            record
            for record in reversed(session.records)
            if record.state == "lifecycle_clearance_intent"
        )
        clearance = clearance_record.details
        launch = next(
            record
            for record in session.records
            if record.state == "child_launch_intent"
        )
        running = next(
            (
                record
                for record in session.records
                if record.state == "child_running"
            ),
            None,
        )
        include_start = disposition not in {
            "never_started",
            "never_started_after_reboot",
        } and (running is not None or late_discovered_start)
        started = (
            (
                running.details["lifecycle_scope_started_receipt"]
                if running is not None
                else self.lifecycle_scope_started_receipt(session)
            )
            if include_start
            else None
        )
        started_digest = (
            lifecycle.scope_started_receipt_sha256(started)
            if started is not None
            else None
        )
        scope_incarnation = (
            started["scope_incarnation_id"]
            if started is not None
            else self.digest(f"scope-incarnation-{session.session_id}")
        )
        start_epoch = (
            started["supervisor_epoch_id"]
            if started is not None
            else None
        )
        start_boot = (
            started["host_boot_id_sha256"]
            if started is not None
            else None
        )
        clearance_epoch = (
            start_epoch
            if disposition in {"clean_exit", "abnormal_exit"}
            else self.digest("clearance-supervisor-epoch")
        )
        scope_id = (
            f"jlq-{lifecycle.LIFECYCLE_BACKEND}-"
            f"{session.session_id}"
        )
        intent = {
            "schema_version": (
                lifecycle.CLEARANCE_INTENT_RECEIPT_SCHEMA
            ),
            "status": lifecycle.CLEARANCE_INTENT_STATUS,
            "capture_session_id": session.session_id,
            "lifecycle_backend": lifecycle.LIFECYCLE_BACKEND,
            "lifecycle_provider": "linux_cgroup_v2",
            "lifecycle_scope_id": scope_id,
            "scope_incarnation_id": scope_incarnation,
            "lifecycle_activation_receipt_sha256": activation_digest,
            "child_launch_intent_record_sha256": launch.record_sha256,
            "effect_origin_state": clearance["effect_origin_state"],
            "effect_origin_record_sha256": clearance[
                "effect_origin_record_sha256"
            ],
            "scope_started_receipt_sha256": clearance[
                "scope_started_receipt_sha256"
            ],
            "clearance_mode": clearance["clearance_mode"],
            "outer_clearance_intent_record_sha256": (
                clearance_record.record_sha256
            ),
        }
        intent_digest = lifecycle.clearance_intent_receipt_sha256(
            intent
        )
        process_observed = disposition in {
            "clean_exit",
            "abnormal_exit",
            "forced_termination",
        }
        clearance_boot = (
            self.digest("host-boot-after-reboot")
            if disposition
            in {"host_reboot", "never_started_after_reboot"}
            else (
                start_boot
                if start_boot is not None
                else self.digest("host-boot")
            )
        )
        basis = {
            "never_started": "supervisor_ledger_no_effect",
            "never_started_after_reboot": "host_boot_epoch_changed",
            "host_reboot": "host_boot_epoch_changed",
        }.get(
            disposition,
            "linux_cgroup_kill_populated_zero",
        )
        empty = {
            "schema_version": lifecycle.SCOPE_EMPTY_RECEIPT_SCHEMA,
            "status": lifecycle.SCOPE_EMPTY_STATUS,
            "capture_session_id": session.session_id,
            "lifecycle_backend": lifecycle.LIFECYCLE_BACKEND,
            "lifecycle_provider": "linux_cgroup_v2",
            "lifecycle_scope_id": scope_id,
            "scope_incarnation_id": scope_incarnation,
            "lifecycle_activation_receipt_sha256": activation_digest,
            "child_launch_intent_record_sha256": launch.record_sha256,
            "effect_origin_state": clearance["effect_origin_state"],
            "effect_origin_record_sha256": clearance[
                "effect_origin_record_sha256"
            ],
            "scope_started_receipt_sha256": started_digest,
            "clearance_intent_receipt_sha256": intent_digest,
            "outer_clearance_intent_record_sha256": (
                clearance_record.record_sha256
            ),
            "clearance_mode": clearance["clearance_mode"],
            "start_supervisor_epoch_id": start_epoch,
            "clearance_supervisor_epoch_id": clearance_epoch,
            "start_host_boot_id_sha256": start_boot,
            "clearance_host_boot_id_sha256": clearance_boot,
            "clearance_basis": basis,
            "completion_disposition": disposition,
            "stderr_bytes": 0 if process_observed else None,
            "stderr_sha256": (
                lifecycle.EMPTY_SHA256 if process_observed else None
            ),
            "adoption_eligible": (
                disposition == "clean_exit"
                and clearance["effect_origin_state"] == "capture_ready"
            ),
        }
        bundle = {
            "schema_version": lifecycle.CLEARANCE_BUNDLE_SCHEMA,
            "status": lifecycle.CLEARANCE_BUNDLE_STATUS,
            "activation_receipt": activation,
            "activation_receipt_sha256": activation_digest,
            "scope_started_receipt": started,
            "scope_started_receipt_sha256": started_digest,
            "clearance_intent_receipt": intent,
            "clearance_intent_receipt_sha256": intent_digest,
            "scope_empty_receipt": empty,
            "scope_empty_receipt_sha256": (
                lifecycle.scope_empty_receipt_sha256(empty)
            ),
        }
        return lifecycle.normalize_clearance_bundle(bundle)

    def rehash_lifecycle_clearance_bundle(
        self,
        bundle: dict,
    ) -> dict:
        activation_digest = lifecycle.activation_receipt_sha256(
            bundle["activation_receipt"]
        )
        bundle["activation_receipt_sha256"] = activation_digest
        started = bundle["scope_started_receipt"]
        started_digest = (
            lifecycle.scope_started_receipt_sha256(started)
            if started is not None
            else None
        )
        bundle["scope_started_receipt_sha256"] = started_digest
        intent = bundle["clearance_intent_receipt"]
        intent_digest = lifecycle.clearance_intent_receipt_sha256(
            intent
        )
        bundle["clearance_intent_receipt_sha256"] = intent_digest
        empty = bundle["scope_empty_receipt"]
        empty["clearance_intent_receipt_sha256"] = intent_digest
        bundle["scope_empty_receipt_sha256"] = (
            lifecycle.scope_empty_receipt_sha256(empty)
        )
        return lifecycle.normalize_clearance_bundle(bundle)

    def begin_adoption_reconciliation(
        self,
        session: journal.TransactionJournalSession,
        *,
        disposition: str,
    ) -> journal.TransactionJournalRecord:
        if disposition == "quarantined":
            scope_receipt_sha256 = next(
                record.details["lifecycle_clearance_bundle"][
                    "scope_empty_receipt_sha256"
                ]
                for record in session.records
                if record.state == "lifecycle_scope_empty"
            )
            session.append_event(
                expected_state="adoption_intent",
                next_state="quarantine_pending",
                details={
                    "from_state": "adoption_intent",
                    "namespace": "staging",
                    "quarantine_name": (
                        "session-" + session.session_id
                    ),
                    "object_identity_sha256": self.digest("leaf"),
                    "reason_code": "coordinator_restarted",
                    "lifecycle_status": "scope_empty",
                    "lifecycle_scope_empty_receipt_sha256": (
                        scope_receipt_sha256
                    ),
                    "empty_leaf_policy": "remove_and_fsync",
                },
                recorded_at_unix=session.latest_record.revision + 1,
            )
        pending = self.staging_tombstone_pending_details(
            session,
            disposition=disposition,
            origin="adoption_intent",
        )
        session.append_event(
            expected_state=session.state,
            next_state="staging_tombstone_ack_pending",
            details=pending,
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
                "terminal_receipt_sha256": pending[
                    "terminal_receipt_sha256"
                ],
                "tombstone_sha256": pending["tombstone_sha256"],
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        return next(
            record
            for record in session.records
            if record.state == "staging_tombstone_ack_pending"
        )

    def adoption_reconciliation_receipt(
        self,
        session: journal.TransactionJournalSession,
        *,
        result: str,
    ) -> dict:
        pending = next(
            record
            for record in session.records
            if record.state == "staging_tombstone_ack_pending"
        )
        terminal = pending.details["terminal_receipt"]
        adoption_intent_record = next(
            record
            for record in session.records
            if record.state == "adoption_intent"
        )
        intent = adoption_intent_record.details
        staging_intent = next(
            record
            for record in session.records
            if record.state == "staging_create_intent"
        )
        scope_empty = next(
            record.details["lifecycle_clearance_bundle"]
            for record in session.records
            if record.state == "lifecycle_scope_empty"
        )
        exact_final = result == "recovered_adoption"
        mismatched_final = result == "operator_attention"
        observed_final = exact_final or mismatched_final
        quarantined = result == "staging_quarantined"
        receipt = {
            "schema_version": (
                adoption_reconciliation
                .ADOPTION_RECONCILIATION_RECEIPT_SCHEMA
            ),
            "status": (
                adoption_reconciliation
                .ADOPTION_RECONCILIATION_STATUS
            ),
            "result": result,
            "capture_session_id": session.session_id,
            "adoption_intent_record_sha256": (
                adoption_intent_record.record_sha256
            ),
            "adoption_policy_sha256": intent[
                "adoption_policy_sha256"
            ],
            "lifecycle_scope_empty_receipt_sha256": scope_empty[
                "scope_empty_receipt_sha256"
            ],
            "staging_transaction_intent_sha256": (
                staging_intent.record_sha256
            ),
            "staging_terminal_receipt_sha256": pending.details[
                "terminal_receipt_sha256"
            ],
            "staging_tombstone_sha256": pending.details[
                "tombstone_sha256"
            ],
            "staging_terminal_disposition": pending.details[
                "terminal_disposition"
            ],
            "staging_leaf_identity_sha256": terminal[
                "staging_leaf_identity_sha256"
            ],
            "staging_inspection_lock_epoch_sha256": terminal[
                "inspection_lock_epoch_sha256"
            ],
            "shared_root_identity_sha256": terminal[
                "shared_root_identity_sha256"
            ],
            "recovery_namespace_identity_sha256": terminal[
                "recovery_namespace_identity_sha256"
            ],
            "quarantine_namespace_identity_sha256": terminal[
                "quarantine_namespace_identity_sha256"
            ],
            "transactions_namespace_identity_sha256": terminal[
                "transactions_namespace_identity_sha256"
            ],
            "final_parent_identity_sha256": intent[
                "final_parent_identity_sha256"
            ],
            "final_parent_filesystem_device": intent[
                "final_parent_filesystem_device"
            ],
            "dual_parent_lock_epoch_sha256": self.digest(
                "dual-parent-lock"
            ),
            "final_name": intent["final_name"],
            "expected_object_identity_sha256": intent[
                "capture_object_identity_sha256"
            ],
            "expected_verifier_gid": intent["verifier_gid"],
            "adoption_limits": intent["limits"],
            "final_observation": (
                "exact_present"
                if exact_final
                else (
                    "identity_mismatch"
                    if mismatched_final
                    else "absent"
                )
            ),
            "final_object_identity_sha256": (
                intent["capture_object_identity_sha256"]
                if exact_final
                else (
                    self.digest("replacement-final-object")
                    if mismatched_final
                    else None
                )
            ),
            "final_object_stat_sha256": (
                self.digest("reconciled-final-stat")
                if observed_final
                else None
            ),
            "final_content_inventory_sha256": (
                self.digest("reconciled-inventory")
                if exact_final
                else None
            ),
            "final_file_count": 2 if exact_final else None,
            "final_directory_count": 3 if exact_final else None,
            "final_total_bytes": 120 if exact_final else None,
            "final_largest_file_bytes": 80 if exact_final else None,
            "final_maximum_depth": 2 if exact_final else None,
            "final_object_owner_uid": (
                0 if observed_final else None
            ),
            "final_object_group_gid": (
                intent["verifier_gid"] if observed_final else None
            ),
            "final_object_mode": (
                adoption_reconciliation.ADOPTED_DIRECTORY_MODE
                if observed_final
                else None
            ),
            "final_object_nlink": 2 if observed_final else None,
            "staging_observation": (
                "exact_quarantine" if quarantined else "absent"
            ),
            "staging_observed_leaf_identity_sha256": (
                terminal["staging_leaf_identity_sha256"]
                if quarantined
                else None
            ),
            "staging_terminal_quarantine_name": (
                terminal["quarantine_name"] if quarantined else None
            ),
            "staging_terminal_quarantine_reason_code": (
                terminal["reason_code"] if quarantined else None
            ),
            "staging_terminal_quarantined_stat_sha256": (
                terminal["quarantined_stat_sha256"]
                if quarantined
                else None
            ),
            "staging_observed_quarantined_stat_sha256": (
                terminal["quarantined_stat_sha256"]
                if quarantined
                else None
            ),
            "final_parent_fsynced": True,
            "staging_parents_fsynced": True,
            "observations_rechecked_under_lock": True,
        }
        return (
            adoption_reconciliation
            .normalize_adoption_reconciliation_receipt(receipt)
        )

    def adoption_reconciled_details(
        self,
        session: journal.TransactionJournalSession,
        *,
        result: str,
    ) -> dict:
        required = next(
            record
            for record in session.records
            if record.state == "adoption_reconciliation_required"
        )
        receipt = self.adoption_reconciliation_receipt(
            session, result=result
        )
        return {
            "adoption_reconciliation_required_record_sha256": (
                required.record_sha256
            ),
            "adoption_reconciliation_receipt": receipt,
            "adoption_reconciliation_receipt_sha256": (
                adoption_reconciliation
                .adoption_reconciliation_receipt_sha256(receipt)
            ),
        }

    def advance_to_adoption_reconciled(
        self,
        session: journal.TransactionJournalSession,
        *,
        result: str,
    ) -> dict:
        self.advance_to(session, "adoption_intent")
        self.begin_adoption_reconciliation(
            session, disposition="absent"
        )
        reconciled = self.adoption_reconciled_details(
            session, result=result
        )
        session.append_event(
            expected_state="adoption_reconciliation_required",
            next_state="adoption_reconciled",
            details=reconciled,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        return reconciled

    def details_for(
        self,
        session: journal.TransactionJournalSession,
        state: str,
    ) -> dict:
        session_id = session.session_id
        staging_name = f"session-{session_id}"
        final_name = "opaque-capture-" + "a" * 32
        attestation_binding = {
            "transaction_binding_sha256": self.digest(
                "transaction-binding"
            ),
            "fresh_evidence_sha256": self.digest("fresh-evidence"),
            "requested_attestation_evidence_sha256": self.digest(
                "requested-evidence"
            ),
            "authoritative_attestation_evidence_sha256": self.digest(
                "authoritative-evidence"
            ),
            "requested_run_id": "run-1",
            "requested_chain_sequence": 3,
            "requested_attestation_sha256": self.digest(
                "requested-attestation"
            ),
            "authoritative_run_id": "run-1",
            "authoritative_chain_sequence": 3,
            "authoritative_attestation_sha256": self.digest(
                "authoritative-attestation"
            ),
            "attestor_config_sha256": self.digest("attestor-config"),
            "public_key_sha256": self.digest("public-key"),
            "operator_policy_sha256": self.digest("operator-policy"),
            "projection_policy_sha256": self.digest(
                "projection-policy"
            ),
        }
        if state == "staging_create_intent":
            return {
                "staging_leaf_name": staging_name,
                "capture_uid": 501,
                "export_gid": 502,
                "required_device": 42,
            }
        if state == "staging_exposed":
            intent = next(
                record
                for record in session.records
                if record.state == "staging_create_intent"
            )
            receipt = {
                "schema_version": (
                    journal.STAGING_EXPOSURE_RECEIPT_SCHEMA
                ),
                "status": journal.STAGING_EXPOSURE_STATUS,
                "capture_session_id": session_id,
                "staging_leaf_name": staging_name,
                "staging_leaf_identity_sha256": self.digest("leaf"),
                "capture_uid": intent.details["capture_uid"],
                "export_gid": intent.details["export_gid"],
                "staging_leaf_mode": (
                    journal.STAGING_EXPOSED_LEAF_MODE
                ),
                "filesystem_device": intent.details[
                    "required_device"
                ],
                "shared_root_identity_sha256": self.digest(
                    "shared-root"
                ),
                "recovery_namespace_identity_sha256": self.digest(
                    "recovery-namespace"
                ),
                "quarantine_namespace_identity_sha256": self.digest(
                    "quarantine-namespace"
                ),
                "transactions_namespace_identity_sha256": self.digest(
                    "transactions-namespace"
                ),
                "staging_journal_schema": (
                    journal.CAPTURE_STAGING_JOURNAL_SCHEMA
                ),
                "staging_journal_sequence": 3,
                "staging_journal_head_sha256": self.digest(
                    "staging-journal-head"
                ),
                "staging_transaction_intent_sha256": (
                    intent.record_sha256
                ),
            }
            return {
                "staging_exposure_receipt": receipt,
                "staging_exposure_receipt_sha256": (
                    journal.staging_exposure_receipt_sha256(receipt)
                ),
            }
        if state == "child_launch_intent":
            receipt = self.lifecycle_activation_receipt()
            return {
                "lifecycle_activation_receipt": receipt,
                "lifecycle_activation_receipt_sha256": (
                    lifecycle.activation_receipt_sha256(receipt)
                ),
            }
        if state == "child_running":
            receipt = self.lifecycle_scope_started_receipt(session)
            return {
                "lifecycle_scope_started_receipt": receipt,
                "lifecycle_scope_started_receipt_sha256": (
                    lifecycle.scope_started_receipt_sha256(receipt)
                ),
                "lifecycle_operation_binding": (
                    self.lifecycle_operation_binding(
                        session,
                        operation="start_scope",
                        successor_state="child_running",
                    )
                ),
            }
        if state == "capture_ready":
            details = {
                "provisional_name": "opaque-capture-" + "a" * 32,
                "capture_object_identity_sha256": self.digest("object"),
                "capture_selection_sha256": self.digest("selection"),
                "capture_plan_sha256": self.digest("plan"),
                "capture_manifest_sha256": self.digest("manifest"),
                "capture_boundary_policy_sha256": self.digest("boundary"),
                "helper_activation_policy_sha256": self.digest("helper"),
                "request_sha256": self.digest("request"),
            }
            binding = self.lifecycle_operation_binding(
                session,
                operation="await_capture_event",
                successor_state="capture_ready",
            )
            binding["supervisor_event_evidence_sha256"] = (
                journal._capture_event_evidence_sha256(details)
            )
            return {
                **details,
                "lifecycle_operation_binding": binding,
            }
        if state == "lifecycle_clearance_intent":
            return self.lifecycle_clearance_intent_details(session)
        if state == "lifecycle_scope_empty":
            bundle = self.lifecycle_clearance_bundle(session)
            return {
                "lifecycle_clearance_bundle": bundle,
                "lifecycle_clearance_bundle_sha256": (
                    lifecycle.clearance_bundle_sha256(bundle)
                ),
                "lifecycle_operation_binding": (
                    self.lifecycle_operation_binding(
                        session,
                        operation="request_clearance",
                        successor_state="lifecycle_scope_empty",
                    )
                ),
            }
        if state == "adoption_intent":
            return {
                "adoption_policy_sha256": self.digest("adoption-policy"),
                "provisional_name": "opaque-capture-" + "a" * 32,
                "final_name": final_name,
                "final_parent_identity_sha256": self.digest(
                    "final-parent"
                ),
                "final_parent_filesystem_device": next(
                    record
                    for record in session.records
                    if record.state == "staging_create_intent"
                ).details["required_device"],
                "capture_object_identity_sha256": self.digest("object"),
                "verifier_gid": 503,
                "limits": {
                    "max_files": 10,
                    "max_directories": 10,
                    "max_bytes": 10_000,
                    "max_file_bytes": 1_000,
                    "max_depth": 8,
                },
            }
        if state == "adopted":
            return {
                "adoption_policy_sha256": self.digest("adoption-policy"),
                "adoption_receipt_sha256": self.digest(
                    "adoption-receipt"
                ),
                "final_name": final_name,
                "final_parent_identity_sha256": self.digest(
                    "final-parent"
                ),
                "final_parent_filesystem_device": next(
                    record
                    for record in session.records
                    if record.state == "staging_create_intent"
                ).details["required_device"],
                "capture_object_identity_sha256": self.digest("object"),
                "adopted_stat_sha256": self.digest("adopted-stat"),
                "content_inventory_sha256": self.digest("inventory"),
            }
        if state in {
            "verifier_output_bound",
            "live_revalidation_started",
        }:
            return {
                "verifier_output_sha256": self.digest("verifier-output")
            }
        if state == "live_revalidation_receipt_complete":
            return {
                "verifier_output_sha256": self.digest("verifier-output"),
                "source_revalidation_receipt_sha256": self.digest(
                    "source-revalidation"
                ),
            }
        if state == "signing_intent":
            return {
                "transaction_binding_sha256": self.digest(
                    "transaction-binding"
                ),
                "fresh_evidence_sha256": self.digest("fresh-evidence"),
                "requested_run_id": "run-1",
                "expected_next_chain_sequence": 3,
                "predecessor_head_sha256": self.digest("predecessor"),
                "predecessor_attestation_sha256": self.digest(
                    "predecessor-attestation"
                ),
                "updated_at_unix": 1_000,
                "attestor_config_sha256": self.digest(
                    "attestor-config"
                ),
                "attestor_key_id": "key-1",
                "public_key_sha256": self.digest("public-key"),
                "operator_policy_sha256": self.digest(
                    "operator-policy"
                ),
                "projection_policy_sha256": self.digest(
                    "projection-policy"
                ),
            }
        if state == "attestation_archive_durable_head_pending":
            return {
                **attestation_binding,
                "attestation_archive_receipt_sha256": self.digest(
                    "archive-receipt"
                ),
            }
        if state == (
            "attestation_head_committed_trust_projection_pending"
        ):
            return {
                **attestation_binding,
                "attestation_archive_receipt_sha256": self.digest(
                    "archive-receipt"
                ),
                "authoritative_head_sha256": self.digest(
                    "authoritative-head"
                ),
                "head_commit_receipt_sha256": self.digest(
                    "head-receipt"
                ),
                "trust_projection_sha256": self.digest("projection"),
                "projection_generated_at_unix": 1_001,
            }
        if state == "full_publication_committed_cleanup_required":
            return {
                **attestation_binding,
                "attestation_archive_receipt_sha256": self.digest(
                    "archive-receipt"
                ),
                "authoritative_head_sha256": self.digest(
                    "authoritative-head"
                ),
                "head_commit_receipt_sha256": self.digest(
                    "head-receipt"
                ),
                "trust_projection_sha256": self.digest("projection"),
                "trust_projection_receipt_sha256": self.digest(
                    "projection-receipt"
                ),
                "projection_generated_at_unix": 1_001,
                "adoption_receipt_sha256": self.digest(
                    "adoption-receipt"
                ),
                "final_name": final_name,
                "capture_object_identity_sha256": self.digest("object"),
                "cleanup_phase": "name_bound",
            }
        if state == "committed_cleanup_pending":
            commit = next(
                record
                for record in session.records
                if record.state
                == "full_publication_committed_cleanup_required"
            )
            return {
                "commit_record_sha256": commit.record_sha256,
                "cleanup_phase": "name_bound",
                "cleanup_error_code": "cleanup_failed",
            }
        if state == "cleanup_complete":
            commit = next(
                record
                for record in session.records
                if record.state
                == "full_publication_committed_cleanup_required"
            )
            return {
                "commit_record_sha256": commit.record_sha256,
                "trust_projection_sha256": self.digest("projection"),
                "cleanup_result": "removed_and_fsynced",
            }
        raise AssertionError(f"no test details for {state}")

    def staging_terminal_receipt(
        self,
        session: journal.TransactionJournalSession,
        *,
        disposition: str,
        origin: str,
        lifecycle_status: str | None = None,
        scope_receipt_sha256: str | None = None,
    ) -> dict:
        quarantine_intent = None
        if session.state == "quarantine_pending":
            quarantine_intent = session.latest_record
        elif (
            session.state == "operator_attention"
            and session.latest_record.details["from_state"]
            == "quarantine_pending"
        ):
            quarantine_intent = session.records[-2]
        intent_record = next(
            record
            for record in session.records
            if record.state == "staging_create_intent"
        )
        exposure_record = next(
            (
                record
                for record in session.records
                if record.state == "staging_exposed"
            ),
            None,
        )
        if lifecycle_status is None:
            if origin in {
                "staging_create_intent",
                "staging_exposed",
            }:
                lifecycle_status = "not_applicable"
            elif any(
                record.state == "lifecycle_scope_empty"
                for record in session.records
            ):
                lifecycle_status = "scope_empty"
                scope_receipt_sha256 = next(
                    record
                    for record in session.records
                    if record.state == "lifecycle_scope_empty"
                ).details["lifecycle_clearance_bundle"][
                    "scope_empty_receipt_sha256"
                ]
            else:
                lifecycle_status = "scope_not_proven"
        leaf_identity = (
            None
            if origin == "staging_create_intent"
            and disposition == "absent"
            else (
                exposure_record.details[
                    "staging_exposure_receipt"
                ]["staging_leaf_identity_sha256"]
                if exposure_record is not None
                else self.digest("leaf")
            )
        )
        common = {
            "capture_session_id": session.session_id,
            "staging_leaf_name": "session-" + session.session_id,
            "staging_transaction_intent_sha256": (
                intent_record.record_sha256
            ),
            "staging_leaf_identity_sha256": leaf_identity,
            "filesystem_device": intent_record.details[
                "required_device"
            ],
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
            "staging_journal_schema": (
                journal.CAPTURE_STAGING_JOURNAL_SCHEMA
            ),
            "inspection_lock_epoch_sha256": self.digest("lock-epoch"),
            "lifecycle_status": lifecycle_status,
            "lifecycle_scope_empty_receipt_sha256": (
                scope_receipt_sha256
            ),
            "terminal_sequence": (
                journal.STAGING_EXPOSURE_JOURNAL_SEQUENCE + 3
                if exposure_record is not None
                else 3
            ),
            "terminal_record_sha256": self.digest("terminal-record"),
            "tombstone_sha256": self.digest("terminal-tombstone"),
        }
        if disposition == "absent":
            return {
                "schema_version": (
                    journal.STAGING_ABSENCE_RECEIPT_SCHEMA
                ),
                "status": journal.STAGING_ABSENCE_STATUS,
                **common,
                "terminal_event": (
                    "startup_absent"
                    if origin == "staging_create_intent"
                    else (
                        "quarantine_removed"
                        if quarantine_intent is not None
                        else "removed"
                    )
                ),
                "quarantine_reason_code": (
                    None
                    if quarantine_intent is None
                    else quarantine_intent.details["reason_code"]
                ),
            }
        if disposition != "quarantined":
            raise AssertionError("unsupported terminal disposition")
        return {
            "schema_version": (
                journal.STAGING_QUARANTINE_RECEIPT_SCHEMA
            ),
            "status": journal.STAGING_QUARANTINE_STATUS,
            **common,
            "quarantine_namespace": "staging",
            "quarantine_name": "session-" + session.session_id,
            "quarantined_stat_sha256": self.digest(
                "quarantined-stat"
            ),
            "reason_code": "coordinator_restarted",
            "rename_primitive": "renameat2_noreplace",
            "rename_noreplace": True,
            "parents_fsynced": True,
            "terminal_event": "startup_quarantined",
        }

    def staging_tombstone_pending_details(
        self,
        session: journal.TransactionJournalSession,
        *,
        disposition: str,
        origin: str,
        lifecycle_status: str | None = None,
        scope_receipt_sha256: str | None = None,
    ) -> dict:
        receipt = self.staging_terminal_receipt(
            session,
            disposition=disposition,
            origin=origin,
            lifecycle_status=lifecycle_status,
            scope_receipt_sha256=scope_receipt_sha256,
        )
        digest_function = (
            journal.staging_absence_receipt_sha256
            if disposition == "absent"
            else journal.staging_quarantine_receipt_sha256
        )
        quarantine_intent_record_sha256 = None
        if session.state == "quarantine_pending":
            quarantine_intent_record_sha256 = (
                session.latest_record.record_sha256
            )
        elif (
            session.state == "operator_attention"
            and session.latest_record.details["from_state"]
            == "quarantine_pending"
        ):
            quarantine_intent_record_sha256 = session.records[
                -2
            ].record_sha256
        return {
            "from_state": session.state,
            "effect_origin_state": origin,
            "terminal_disposition": disposition,
            "terminal_receipt": receipt,
            "terminal_receipt_sha256": digest_function(receipt),
            "tombstone_sha256": receipt["tombstone_sha256"],
            "staging_quarantine_intent_record_sha256": (
                quarantine_intent_record_sha256
            ),
        }

    def staging_tombstone_acked_details(
        self,
        session: journal.TransactionJournalSession,
    ) -> dict:
        pending = next(
            record
            for record in session.records
            if record.state == "staging_tombstone_ack_pending"
        )
        terminal_receipt = pending.details["terminal_receipt"]
        disposition = pending.details["terminal_disposition"]
        reconciliation_record = next(
            (
                record
                for record in reversed(session.records)
                if record.state == "adoption_reconciled"
            ),
            None,
        )
        lifecycle_clearance_record_sha256 = None
        if terminal_receipt["lifecycle_status"] == "scope_empty":
            lifecycle_clearance_record_sha256 = next(
                record.record_sha256
                for record in session.records
                if record.state == "lifecycle_scope_empty"
            )
        acknowledgement = {
            "schema_version": (
                journal.STAGING_TOMBSTONE_ACK_RECEIPT_SCHEMA
            ),
            "status": journal.STAGING_TOMBSTONE_ACK_STATUS,
            "capture_session_id": session.session_id,
            "staging_transaction_intent_sha256": next(
                record
                for record in session.records
                if record.state == "staging_create_intent"
            ).record_sha256,
            "terminal_receipt_sha256": pending.details[
                "terminal_receipt_sha256"
            ],
            "tombstone_sha256": pending.details[
                "tombstone_sha256"
            ],
            "outer_ack_pending_record_sha256": pending.record_sha256,
            "outer_quarantine_intent_record_sha256": pending.details[
                "staging_quarantine_intent_record_sha256"
            ],
            "outer_lifecycle_clearance_record_sha256": (
                lifecycle_clearance_record_sha256
            ),
            "terminal_disposition": disposition,
            "staging_journal_schema": (
                journal.CAPTURE_STAGING_JOURNAL_SCHEMA
            ),
            "ack_event": "outer_tombstone_acknowledged",
            "ack_sequence": terminal_receipt["terminal_sequence"] + 1,
            "ack_previous_record_sha256": terminal_receipt[
                "terminal_record_sha256"
            ],
            "ack_record_sha256": self.digest("ack-record"),
            "inspection_lock_epoch_sha256": terminal_receipt[
                "inspection_lock_epoch_sha256"
            ],
            "journal_storage_disposition": (
                "completed_absence_journal"
                if disposition == "absent"
                else "retained_quarantine_journal"
            ),
            "ack_journal_identity_sha256": self.digest(
                "ack-journal-identity"
            ),
            "ack_journal_readback_sha256": self.digest(
                "ack-journal-readback"
            ),
            "transactions_parent_fsynced": True,
            "completed_parent_fsynced": disposition == "absent",
        }
        return {
            "from_state": session.state,
            "terminal_disposition": pending.details[
                "terminal_disposition"
            ],
            "terminal_receipt_sha256": pending.details[
                "terminal_receipt_sha256"
            ],
            "tombstone_sha256": pending.details[
                "tombstone_sha256"
            ],
            "outer_ack_pending_record_sha256": pending.record_sha256,
            "adoption_reconciliation_record_sha256": (
                None
                if reconciliation_record is None
                else reconciliation_record.record_sha256
            ),
            "adoption_reconciliation_receipt_sha256": (
                None
                if reconciliation_record is None
                else reconciliation_record.details[
                    "adoption_reconciliation_receipt_sha256"
                ]
            ),
            "tombstone_ack_receipt": acknowledgement,
            "tombstone_ack_receipt_sha256": (
                journal.staging_tombstone_ack_receipt_sha256(
                    acknowledgement
                )
            ),
        }

    def complete_staging_tombstone_handshake(
        self,
        session: journal.TransactionJournalSession,
        *,
        disposition: str,
        origin: str,
    ) -> None:
        pending = self.staging_tombstone_pending_details(
            session,
            disposition=disposition,
            origin=origin,
        )
        session.append_event(
            expected_state=session.state,
            next_state="staging_tombstone_ack_pending",
            details=pending,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        acked = self.staging_tombstone_acked_details(session)
        session.append_event(
            expected_state="staging_tombstone_ack_pending",
            next_state="staging_tombstone_acked",
            details=acked,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session.append_event(
            expected_state="staging_tombstone_acked",
            next_state=(
                "staging_absent_cleanup_complete"
                if disposition == "absent"
                else "staging_quarantined_cleanup_complete"
            ),
            details={
                "from_state": "staging_tombstone_acked",
                "terminal_disposition": disposition,
                "terminal_receipt_sha256": pending[
                    "terminal_receipt_sha256"
                ],
                "tombstone_ack_receipt_sha256": acked[
                    "tombstone_ack_receipt_sha256"
                ],
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )

    def advance_to(
        self,
        session: journal.TransactionJournalSession,
        target: str,
    ) -> None:
        path = [
            "staging_create_intent",
            "staging_exposed",
            "child_launch_intent",
            "child_running",
            "capture_ready",
            "lifecycle_clearance_intent",
            "lifecycle_scope_empty",
            "adoption_intent",
            "adopted",
            "verifier_output_bound",
            "live_revalidation_started",
            "live_revalidation_receipt_complete",
            "signing_intent",
            "attestation_archive_durable_head_pending",
            "attestation_head_committed_trust_projection_pending",
            "full_publication_committed_cleanup_required",
            "cleanup_complete",
        ]
        for state in path:
            previous = session.state
            append = (
                session._append_event_for_history_validation_test
                if state
                in {
                    "child_running",
                    "capture_ready",
                    "lifecycle_clearance_intent",
                    "lifecycle_scope_empty",
                }
                else session.append_event
            )
            append(
                expected_state=previous,
                next_state=state,
                details=self.details_for(session, state),
                recorded_at_unix=session.latest_record.revision + 1,
            )
            if state == target:
                return
            if state == "adopted":
                pending = self.staging_tombstone_pending_details(
                    session,
                    disposition="absent",
                    origin="adopted",
                )
                session.append_event(
                    expected_state="adopted",
                    next_state="staging_tombstone_ack_pending",
                    details=pending,
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )
                session.append_event(
                    expected_state="staging_tombstone_ack_pending",
                    next_state="staging_tombstone_acked",
                    details=self.staging_tombstone_acked_details(
                        session
                    ),
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )
        raise AssertionError(f"target state {target!r} not reached")

    def test_lifecycle_operation_lease_exact_commit_and_capabilities(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "child_launch_intent")
        snapshot = session.live_snapshot()
        direct_details = self.details_for(
            session, "child_running"
        )
        direct_candidate = session._prepare_candidate(
            next_state="child_running",
            details=direct_details,
            recorded_at_unix=5,
            _lifecycle_authorization=(
                journal._HISTORY_VALIDATION_TEST_TOKEN
            ),
        )
        self.assert_code(
            "transaction_journal_lifecycle_operation_permit_required",
            session._commit_candidate,
            direct_candidate,
            fault_hook=None,
        )
        self.assert_code(
            "transaction_journal_lifecycle_operation_permit_required",
            session._prepare_candidate,
            next_state="child_running",
            details=direct_details,
            recorded_at_unix=5,
        )
        lease = session._begin_lifecycle_operation_for_client(
            operation="start_scope",
            snapshot=snapshot,
        )
        self.assertEqual(lease.operation, "start_scope")
        self.assertEqual(
            lease.base_record_sha256,
            snapshot.head_record_sha256,
        )
        for callable_ in (
            lambda: copy.copy(lease),
            lambda: copy.deepcopy(lease),
            lambda: pickle.dumps(lease),
        ):
            with self.assertRaises(TypeError):
                callable_()
        with self.assertRaises(TypeError):
            journal.TransactionJournalOperationLease(
                _token=object(),
                session=session,
                session_binding=object(),
                operation="start_scope",
                base_revision=snapshot.revision,
                base_record_sha256=snapshot.head_record_sha256,
            )
        self.assert_code(
            "transaction_journal_lifecycle_operation_already_reserved",
            session._begin_lifecycle_operation_for_client,
            operation="start_scope",
            snapshot=snapshot,
        )

        running = self.details_for(session, "child_running")
        binding = running.pop("lifecycle_operation_binding")
        lease.mark_dispatched(binding["request_sha256"])
        self.assert_code(
            "transaction_journal_lifecycle_operation_already_reserved",
            session.append_event,
            expected_state="child_launch_intent",
            next_state="child_running",
            details={
                **running,
                "lifecycle_operation_binding": binding,
            },
            recorded_at_unix=5,
        )
        permit = lease.mint_successor_permit(
            next_state="child_running",
            details=running,
            lifecycle_operation_binding=binding,
            recorded_at_unix=5,
        )
        self.assertEqual(permit.state, "child_running")
        for callable_ in (
            lambda: copy.copy(permit),
            lambda: copy.deepcopy(permit),
            lambda: pickle.dumps(permit),
        ):
            with self.assertRaises(TypeError):
                callable_()
        with self.assertRaises(TypeError):
            journal.TransactionJournalOuterSuccessorPermit(
                _token=object(),
                session=session,
                session_binding=object(),
                lease=lease,
                candidate=session.latest_record,
            )

        other_root = self.root / "permit-other"
        other_anchor, other_store_path = self.make_layout(other_root)
        other_store = self.open_store(other_store_path, other_anchor)
        other_session = self.reserve(other_store, marker="2")
        self.assert_code(
            (
                "transaction_journal_"
                "outer_successor_permit_session_mismatch"
            ),
            other_session._commit_outer_successor_permit,
            permit,
        )
        committed = permit.commit()
        self.assertEqual(committed.state, "child_running")
        self.assertEqual(committed.record_sha256, permit.record_sha256)
        self.assertEqual(
            session.live_snapshot().head_record_sha256,
            committed.record_sha256,
        )
        self.assert_code(
            "transaction_journal_outer_successor_permit_spent",
            permit.commit,
        )

    def test_lifecycle_operation_cancel_no_effect_and_recovery_barrier(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "child_launch_intent")
        snapshot = session.live_snapshot()
        cancelled = session._begin_lifecycle_operation_for_client(
            operation="start_scope",
            snapshot=snapshot,
        )
        cancelled.cancel_before_dispatch()
        self.assertEqual(cancelled.state, "cancelled")
        self.assertEqual(session.live_snapshot().revision, snapshot.revision)

        no_effect = session._begin_lifecycle_operation_for_client(
            operation="start_scope",
            snapshot=session.live_snapshot(),
        )
        binding = self.lifecycle_operation_binding(
            session,
            operation="start_scope",
            successor_state="operator_attention",
            outcome="no_effect",
            error_code="scope_start_rejected",
        )
        no_effect.mark_dispatched(binding["request_sha256"])
        no_effect.complete_no_effect(binding)
        self.assertEqual(no_effect.state, "no_effect_complete")
        self.assertEqual(session.live_snapshot().revision, snapshot.revision)

        abandoned = session._begin_lifecycle_operation_for_client(
            operation="start_scope",
            snapshot=session.live_snapshot(),
        )
        abandoned.mark_dispatched(self.digest("abandoned-request"))
        abandoned.require_recovery()
        self.assertTrue(session.recovery_required)
        self.assert_code(
            "transaction_journal_lifecycle_recovery_required",
            session.append_event,
            expected_state="child_launch_intent",
            next_state="operator_attention",
            details={
                "from_state": "child_launch_intent",
                "reason_code": "should_not_append",
                "incident_sha256": self.digest("incident"),
            },
            recorded_at_unix=5,
        )
        self.assert_code(
            "transaction_journal_lifecycle_recovery_required",
            session._begin_lifecycle_operation_for_client,
            operation="start_scope",
            snapshot=session.live_snapshot(),
        )
        recovery = session._begin_lifecycle_operation_for_client(
            operation="recover_scope",
            snapshot=session.live_snapshot(),
        )
        recovery.cancel_before_dispatch()
        self.assertTrue(session.recovery_required)

    def test_lifecycle_operation_reload_is_recovery_first(self) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "child_launch_intent")
        store.close()
        reopened = self.open_store()
        loaded = reopened.load_incomplete_sessions()
        self.assertEqual(len(loaded), 1)
        recovered = loaded[0]
        self.assertTrue(recovered.recovery_required)
        self.assert_code(
            "transaction_journal_lifecycle_recovery_required",
            recovered._begin_lifecycle_operation_for_client,
            operation="start_scope",
            snapshot=recovered.live_snapshot(),
        )
        lease = recovered._begin_lifecycle_operation_for_client(
            operation="recover_scope",
            snapshot=recovered.live_snapshot(),
        )
        lease.cancel_before_dispatch()

    def test_lifecycle_operation_permit_stale_head_and_commit_readback(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "child_launch_intent")
        lease = session._begin_lifecycle_operation_for_client(
            operation="start_scope",
            snapshot=session.live_snapshot(),
        )
        running = self.details_for(session, "child_running")
        binding = running.pop("lifecycle_operation_binding")
        lease.mark_dispatched(binding["request_sha256"])
        permit = lease.mint_successor_permit(
            next_state="child_running",
            details=running,
            lifecycle_operation_binding=binding,
            recorded_at_unix=5,
        )
        original_rename = journal._exclusive_rename

        def committed_then_interrupted(*args, **kwargs):
            original_rename(*args, **kwargs)
            raise SimulatedCrash("after noreplace commit")

        with mock.patch.object(
            journal,
            "_exclusive_rename",
            side_effect=committed_then_interrupted,
        ):
            committed = permit.commit()
        self.assertEqual(committed.state, "child_running")
        self.assertEqual(session.state, "child_running")
        self.assertFalse(session.recovery_required)

        second_root = self.root / "stale-permit"
        anchor, store_path = self.make_layout(second_root)
        second_store = self.open_store(store_path, anchor)
        stale_session = self.reserve(second_store, marker="3")
        self.advance_to(stale_session, "child_launch_intent")
        stale_lease = (
            stale_session._begin_lifecycle_operation_for_client(
                operation="start_scope",
                snapshot=stale_session.live_snapshot(),
            )
        )
        stale_running = self.details_for(
            stale_session, "child_running"
        )
        stale_binding = stale_running.pop(
            "lifecycle_operation_binding"
        )
        stale_lease.mark_dispatched(
            stale_binding["request_sha256"]
        )
        stale_permit = stale_lease.mint_successor_permit(
            next_state="child_running",
            details=stale_running,
            lifecycle_operation_binding=stale_binding,
            recorded_at_unix=5,
        )
        attention_binding = self.lifecycle_operation_binding(
            stale_session,
            operation="recover_scope",
            successor_state="operator_attention",
            outcome="attention",
            error_code="concurrent_history_change",
        )
        stale_session._append(
            next_state="operator_attention",
            details={
                "from_state": "child_launch_intent",
                "reason_code": "concurrent_history_change",
                "incident_sha256": (
                    journal.lifecycle_operation_binding_sha256(
                        attention_binding
                    )
                ),
                "lifecycle_operation_binding": attention_binding,
            },
            recorded_at_unix=5,
            fault_hook=None,
            _lifecycle_authorization=(
                journal._HISTORY_VALIDATION_TEST_TOKEN
            ),
        )
        self.assert_code(
            "transaction_journal_outer_successor_permit_stale_head",
            stale_permit.commit,
        )
        self.assertTrue(stale_session.recovery_required)

    def test_lifecycle_capture_event_evidence_substitution_rejected(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "child_running")
        ready = self.details_for(session, "capture_ready")
        ready["lifecycle_operation_binding"][
            "supervisor_event_evidence_sha256"
        ] = self.digest("substituted-evidence")
        self.assert_code(
            (
                "transaction_journal_"
                "lifecycle_operation_event_evidence_changed"
            ),
            session._append_event_for_history_validation_test,
            expected_state="child_running",
            next_state="capture_ready",
            details=ready,
            recorded_at_unix=6,
        )

    def test_same_head_threads_and_store_reservation_are_serialized(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        outcomes: list[str] = []
        barrier = threading.Barrier(2)

        def append_attention(marker: str) -> None:
            barrier.wait()
            try:
                session.append_event(
                    expected_state="reserved",
                    next_state="operator_attention",
                    details={
                        "from_state": "reserved",
                        "reason_code": f"thread_{marker}",
                        "incident_sha256": self.digest(
                            f"thread-{marker}"
                        ),
                    },
                    recorded_at_unix=2,
                )
                outcomes.append("committed")
            except journal.TransactionJournalError as exc:
                outcomes.append(exc.code)

        threads = [
            threading.Thread(target=append_attention, args=(marker,))
            for marker in ("one", "two")
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertCountEqual(
            outcomes,
            [
                "committed",
                "transaction_journal_expected_state_mismatch",
            ],
        )
        self.assertEqual(len(session.records), 2)
        self.assertEqual(session.latest_record.revision, 2)

        other_root = self.root / "reservation-race"
        anchor, store_path = self.make_layout(other_root)
        race_store = self.open_store(store_path, anchor)
        reserve_outcomes: list[str] = []
        reserve_barrier = threading.Barrier(2)

        def reserve_same() -> None:
            reserve_barrier.wait()
            try:
                race_store._reserve_session_for_test(
                    instance_slug="john-test",
                    control_sha256=self.digest("control"),
                    handoff_policy_sha256=self.digest("handoff"),
                    recorded_at_unix=1,
                    session_id="4" * 64,
                )
                reserve_outcomes.append("committed")
            except journal.TransactionJournalError as exc:
                reserve_outcomes.append(exc.code)

        reserve_threads = [
            threading.Thread(target=reserve_same) for _ in range(2)
        ]
        for thread in reserve_threads:
            thread.start()
        for thread in reserve_threads:
            thread.join()
        self.assertEqual(reserve_outcomes.count("committed"), 1)
        self.assertEqual(len(reserve_outcomes), 2)

    def test_store_and_session_reject_creator_process_drift(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        with mock.patch.object(
            journal.os,
            "getpid",
            return_value=os.getpid() + 1,
        ):
            self.assert_code(
                (
                    "transaction_journal_"
                    "session_creator_process_mismatch"
                ),
                lambda: session.records,
            )
            self.assert_code(
                (
                    "transaction_journal_"
                    "store_creator_process_mismatch"
                ),
                lambda: store.store_path,
            )

    def test_production_open_is_root_only_and_activation_stays_false(
        self,
    ) -> None:
        self.assertFalse(journal.PRODUCTION_ACTIVATION)
        with mock.patch.object(journal.os, "geteuid", return_value=501):
            self.assert_code(
                "transaction_journal_requires_root",
                journal.open_transaction_store,
                self.store_path,
                self.anchor,
            )

    def test_store_lock_is_exclusive_and_leases_are_not_serializable(
        self,
    ) -> None:
        first = self.open_store()
        self.assert_code(
            "transaction_journal_store_busy",
            journal._open_transaction_store_for_test,
            self.store_path,
            self.anchor,
        )
        session = self.reserve(first)
        with self.assertRaises(TypeError):
            pickle.dumps(first)
        with self.assertRaises(TypeError):
            pickle.dumps(session)

    def test_reservation_is_canonical_bound_and_durable(self) -> None:
        store = self.open_store()
        session = self.reserve(store)
        record = session.latest_record.to_dict()
        self.assertEqual(
            journal.JOURNAL_RECORD_SCHEMA,
            (
                "john-lomein.persona-qualification-"
                "transaction-journal.v5"
            ),
        )
        self.assertEqual(
            record["schema_version"],
            journal.JOURNAL_RECORD_SCHEMA,
        )
        self.assertEqual(record["revision"], 1)
        self.assertEqual(record["state"], "reserved")
        self.assertEqual(
            record["previous_record_sha256"],
            journal.ZERO_SHA256,
        )
        self.assertEqual(record["details"], {})
        session_path = self.store_path / ("session-" + "1" * 64)
        self.assertEqual(
            stat.S_IMODE(session_path.stat().st_mode),
            journal.SESSION_DIRECTORY_MODE,
        )
        event_paths = list(session_path.glob("*.json"))
        self.assertEqual(len(event_paths), 1)
        event_path = event_paths[0]
        self.assertEqual(
            stat.S_IMODE(event_path.stat().st_mode),
            journal.RECORD_FILE_MODE,
        )
        self.assertEqual(event_path.stat().st_nlink, 1)
        raw = event_path.read_bytes()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(
            json.dumps(
                json.loads(raw),
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n",
            raw,
        )
        payload = dict(record)
        observed = payload.pop("record_sha256")
        self.assertEqual(
            observed,
            hashlib.sha256(
                json.dumps(
                    payload,
                    allow_nan=False,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")
            ).hexdigest(),
        )

    def test_capture_ready_binds_real_adopted_name_and_rejects_drift(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "lifecycle_scope_empty")
        adoption = self.details_for(session, "adoption_intent")
        self.assertEqual(
            adoption["final_name"],
            adoption["provisional_name"],
        )
        changed = dict(adoption)
        changed["final_name"] = "opaque-capture-" + "b" * 32
        self.assert_code(
            "transaction_journal_final_name_binding_changed",
            session.append_event,
            expected_state="lifecycle_scope_empty",
            next_state="adoption_intent",
            details=changed,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session.append_event(
            expected_state="lifecycle_scope_empty",
            next_state="adoption_intent",
            details=adoption,
            recorded_at_unix=session.latest_record.revision + 1,
        )

    def test_adoption_binds_final_parent_identity_and_device(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "lifecycle_scope_empty")
        intent = self.details_for(session, "adoption_intent")
        wrong_device = {
            **intent,
            "final_parent_filesystem_device": (
                intent["final_parent_filesystem_device"] + 1
            ),
        }
        self.assert_code(
            (
                "transaction_journal_"
                "adoption_final_parent_device_mismatch"
            ),
            session.append_event,
            expected_state="lifecycle_scope_empty",
            next_state="adoption_intent",
            details=wrong_device,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session.append_event(
            expected_state="lifecycle_scope_empty",
            next_state="adoption_intent",
            details=intent,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        adopted = self.details_for(session, "adopted")
        changed_identity = {
            **adopted,
            "final_parent_identity_sha256": self.digest(
                "replacement-final-parent"
            ),
        }
        self.assert_code(
            (
                "transaction_journal_"
                "adoption_final_parent_identity_changed"
            ),
            session.append_event,
            expected_state="adoption_intent",
            next_state="adopted",
            details=changed_identity,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        changed_device = {
            **adopted,
            "final_parent_filesystem_device": (
                adopted["final_parent_filesystem_device"] + 1
            ),
        }
        self.assert_code(
            (
                "transaction_journal_"
                "adoption_final_parent_device_changed"
            ),
            session.append_event,
            expected_state="adoption_intent",
            next_state="adopted",
            details=changed_device,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session.append_event(
            expected_state="adoption_intent",
            next_state="adopted",
            details=adopted,
            recorded_at_unix=session.latest_record.revision + 1,
        )

    def test_adoption_intent_enforces_shared_name_and_limit_caps(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "lifecycle_scope_empty")
        valid = self.details_for(session, "adoption_intent")
        for final_name in (
            "opaque-capture-" + "a" * 31,
            "opaque-capture-" + "A" * 32,
            "capture-" + "a" * 32,
        ):
            with self.subTest(final_name=final_name):
                self.assert_code(
                    "transaction_journal_final_name_invalid",
                    session.append_event,
                    expected_state="lifecycle_scope_empty",
                    next_state="adoption_intent",
                    details={
                        **valid,
                        "final_name": final_name,
                    },
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )
        caps = {
            "max_files": (
                4_097,
                "transaction_journal_max_files_invalid",
            ),
            "max_directories": (
                4_097,
                "transaction_journal_max_directories_invalid",
            ),
            "max_bytes": (
                128 * 1024 * 1024 + 1,
                "transaction_journal_max_bytes_invalid",
            ),
            "max_file_bytes": (
                16 * 1024 * 1024 + 1,
                "transaction_journal_max_file_bytes_invalid",
            ),
            "max_depth": (
                65,
                "transaction_journal_max_depth_invalid",
            ),
        }
        for field, (replacement, code) in caps.items():
            with self.subTest(limit=field):
                self.assert_code(
                    code,
                    session.append_event,
                    expected_state="lifecycle_scope_empty",
                    next_state="adoption_intent",
                    details={
                        **valid,
                        "limits": {
                            **valid["limits"],
                            field: replacement,
                        },
                    },
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )
        session.append_event(
            expected_state="lifecycle_scope_empty",
            next_state="adoption_intent",
            details=valid,
            recorded_at_unix=session.latest_record.revision + 1,
        )

    def test_pre_activation_legacy_records_are_explicitly_rejected(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        for version in ("v1", "v2", "v3"):
            with self.subTest(version=version):
                old_shape = session.latest_record.to_dict()
                old_shape["schema_version"] = (
                    "john-lomein.persona-qualification-"
                    f"transaction-journal.{version}"
                )
                self.assert_code(
                    "transaction_journal_record_schema_unsupported",
                    journal.TransactionJournalRecord,
                    old_shape,
                )

    def test_staging_create_absence_receipt_terminates_and_unblocks(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store, marker="1")
        session.append_event(
            expected_state="reserved",
            next_state="staging_create_intent",
            details=self.details_for(
                session, "staging_create_intent"
            ),
            recorded_at_unix=2,
        )
        pending = self.staging_tombstone_pending_details(
            session,
            disposition="absent",
            origin="staging_create_intent",
        )
        wrong_schema = {
            **pending,
            "terminal_receipt": {
                **pending["terminal_receipt"],
                "schema_version": "wrong.schema",
            },
        }
        self.assert_code(
            "capture_staging_absence_receipt_schema_invalid",
            session.append_event,
            expected_state="staging_create_intent",
            next_state="staging_tombstone_ack_pending",
            details=wrong_schema,
            recorded_at_unix=3,
        )
        wrong_digest = {
            **pending,
            "terminal_receipt_sha256": self.digest("wrong-receipt"),
        }
        self.assert_code(
            (
                "transaction_journal_"
                "staging_terminal_receipt_digest_mismatch"
            ),
            session.append_event,
            expected_state="staging_create_intent",
            next_state="staging_tombstone_ack_pending",
            details=wrong_digest,
            recorded_at_unix=3,
        )
        session.append_event(
            expected_state="staging_create_intent",
            next_state="staging_tombstone_ack_pending",
            details=pending,
            recorded_at_unix=3,
        )
        self.assert_code(
            "transaction_journal_incomplete_session_exists",
            self.reserve,
            store,
            marker="2",
        )
        acked = self.staging_tombstone_acked_details(session)
        session.append_event(
            expected_state="staging_tombstone_ack_pending",
            next_state="staging_tombstone_acked",
            details=acked,
            recorded_at_unix=4,
        )
        self.assert_code(
            "transaction_journal_incomplete_session_exists",
            self.reserve,
            store,
            marker="2",
        )
        session.append_event(
            expected_state="staging_tombstone_acked",
            next_state="staging_absent_cleanup_complete",
            details={
                "from_state": "staging_tombstone_acked",
                "terminal_disposition": "absent",
                "terminal_receipt_sha256": pending[
                    "terminal_receipt_sha256"
                ],
                "tombstone_ack_receipt_sha256": acked[
                    "tombstone_ack_receipt_sha256"
                ],
            },
            recorded_at_unix=5,
        )
        replacement = self.reserve(store, marker="2")
        self.assertEqual(replacement.state, "reserved")
        self.assertTrue(
            (
                self.store_path
                / ".completed"
                / ("session-" + "1" * 64)
            ).is_dir()
        )

    def test_full_state_machine_loads_only_unresolved_sessions(self) -> None:
        store = self.open_store()
        completed = self.reserve(store, marker="1")
        self.advance_to(completed, "cleanup_complete")
        unresolved = self.reserve(store, marker="2")
        self.assertFalse(
            (self.store_path / ("session-" + "1" * 64)).exists()
        )
        self.assertTrue(
            (
                self.store_path
                / ".completed"
                / ("session-" + "1" * 64)
            ).is_dir()
        )
        unresolved.append_event(
            expected_state="reserved",
            next_state="operator_attention",
            details={
                "from_state": "reserved",
                "reason_code": "operator_review_required",
                "incident_sha256": self.digest("incident"),
            },
            recorded_at_unix=2,
        )
        store.close()

        reopened = self.open_store()
        loaded = reopened.load_incomplete_sessions()
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].session_id, "2" * 64)
        self.assertEqual(loaded[0].state, "operator_attention")

    def test_one_incomplete_session_blocks_another_reservation(self) -> None:
        store = self.open_store()
        self.reserve(store, marker="1")
        self.assert_code(
            "transaction_journal_incomplete_session_exists",
            self.reserve,
            store,
            marker="2",
        )

    def test_publication_boundaries_are_exact_and_keyless(self) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(
            session,
            "attestation_archive_durable_head_pending",
        )
        archived = session.latest_record.details
        self.assertNotEqual(
            archived["fresh_evidence_sha256"],
            archived["requested_attestation_evidence_sha256"],
        )
        self.assertNotEqual(
            archived["requested_attestation_sha256"],
            archived["authoritative_attestation_sha256"],
        )
        head_details = self.details_for(
            session,
            "attestation_head_committed_trust_projection_pending",
        )
        head_details["operator_policy_sha256"] = self.digest(
            "different-operator-policy"
        )
        self.assert_code(
            "transaction_journal_head_binding_changed",
            session.append_event,
            expected_state=(
                "attestation_archive_durable_head_pending"
            ),
            next_state=(
                "attestation_head_committed_"
                "trust_projection_pending"
            ),
            details=head_details,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session.append_event(
            expected_state=(
                "attestation_archive_durable_head_pending"
            ),
            next_state=(
                "attestation_head_committed_"
                "trust_projection_pending"
            ),
            details=self.details_for(
                session,
                (
                    "attestation_head_committed_"
                    "trust_projection_pending"
                ),
            ),
            recorded_at_unix=session.latest_record.revision + 1,
        )
        store.close()
        reopened = self.open_store()
        loaded = reopened.load_incomplete_sessions()
        self.assertEqual(len(loaded), 1)
        self.assertEqual(
            loaded[0].state,
            "attestation_head_committed_trust_projection_pending",
        )

        forbidden = {
            "private_key",
            "private_key_loader",
            "signer",
            "verifier",
            "publisher",
            "pid",
            "pgid",
        }
        public_callables = [
            journal.open_transaction_store,
            journal.TransactionJournalStore.reserve_session,
            journal.TransactionJournalStore.load_incomplete_sessions,
            journal.TransactionJournalSession.append_event,
            journal.TransactionJournalSession.begin_capture_recording,
            journal.CaptureTransactionRecorder.record_staging_exposed,
            journal.CaptureTransactionRecorder.record_child_launch_intent,
            journal.CaptureTransactionRecorder.record_child_running,
            journal.CaptureTransactionRecorder.record_capture_ready,
            (
                journal.CaptureTransactionRecorder
                .record_lifecycle_clearance_intent
            ),
            journal.CaptureTransactionRecorder.record_lifecycle_scope_empty,
            journal.CaptureTransactionRecorder.record_adoption_intent,
            journal.CaptureTransactionRecorder.record_adopted,
        ]
        for callable_ in public_callables:
            self.assertTrue(
                forbidden.isdisjoint(
                    inspect.signature(callable_).parameters
                )
            )

    def test_post_sign_durable_states_cannot_be_quarantined(self) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(
            session,
            "attestation_archive_durable_head_pending",
        )

        def assert_quarantine_rejected() -> None:
            scope_receipt = next(
                record.details["lifecycle_clearance_bundle"][
                    "scope_empty_receipt_sha256"
                ]
                for record in session.records
                if record.state == "lifecycle_scope_empty"
            )
            for next_state in ("quarantine_pending", "quarantined"):
                with self.subTest(
                    previous=session.state,
                    next_state=next_state,
                ):
                    details = {
                        "from_state": session.state,
                        "namespace": "adopted",
                        "quarantine_name": (
                            "opaque-capture-" + "a" * 32
                        ),
                        "object_identity_sha256": self.digest(
                            "object"
                        ),
                        "reason_code": "publication_incomplete",
                        "lifecycle_status": "scope_empty",
                        "lifecycle_scope_empty_receipt_sha256": (
                            scope_receipt
                        ),
                    }
                    if next_state == "quarantine_pending":
                        details["empty_leaf_policy"] = (
                            "remove_and_fsync"
                        )
                    self.assert_code(
                        "transaction_journal_transition_invalid",
                        session.append_event,
                        expected_state=session.state,
                        next_state=next_state,
                        details=details,
                        recorded_at_unix=(
                            session.latest_record.revision + 1
                        ),
                    )

        assert_quarantine_rejected()
        session.append_event(
            expected_state=session.state,
            next_state=(
                "attestation_head_committed_"
                "trust_projection_pending"
            ),
            details=self.details_for(
                session,
                (
                    "attestation_head_committed_"
                    "trust_projection_pending"
                ),
            ),
            recorded_at_unix=session.latest_record.revision + 1,
        )
        assert_quarantine_rejected()

    def test_post_sign_operator_attention_must_reconcile_publication(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(
            session,
            "attestation_archive_durable_head_pending",
        )
        attention = session.append_event(
            expected_state=session.state,
            next_state="operator_attention",
            details={
                "from_state": session.state,
                "reason_code": "head_repair_failed",
                "incident_sha256": self.digest("head-incident"),
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        self.assert_code(
            "transaction_journal_operator_resolution_unsafe",
            session.append_event,
            expected_state="operator_attention",
            next_state="operator_resolved",
            details={
                "operator_attention_record_sha256": (
                    attention.record_sha256
                ),
                "resolution_code": "manual_override",
                "resolution_receipt_sha256": self.digest(
                    "opaque-resolution"
                ),
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session.append_event(
            expected_state="operator_attention",
            next_state=(
                "attestation_head_committed_"
                "trust_projection_pending"
            ),
            details=self.details_for(
                session,
                (
                    "attestation_head_committed_"
                    "trust_projection_pending"
                ),
            ),
            recorded_at_unix=session.latest_record.revision + 1,
        )
        self.assertEqual(
            session.state,
            "attestation_head_committed_trust_projection_pending",
        )

    def test_operator_resolution_unblocks_and_archives_session(self) -> None:
        store = self.open_store()
        session = self.reserve(store, marker="1")
        attention = session.append_event(
            expected_state="reserved",
            next_state="operator_attention",
            details={
                "from_state": "reserved",
                "reason_code": "operator_review_required",
                "incident_sha256": self.digest("incident"),
            },
            recorded_at_unix=2,
        )
        self.assert_code(
            "transaction_journal_incomplete_session_exists",
            self.reserve,
            store,
            marker="2",
        )
        session.append_event(
            expected_state="operator_attention",
            next_state="operator_resolved",
            details={
                "operator_attention_record_sha256": (
                    attention.record_sha256
                ),
                "resolution_code": "incident_resolved",
                "resolution_receipt_sha256": self.digest(
                    "resolution"
                ),
            },
            recorded_at_unix=3,
        )
        replacement = self.reserve(store, marker="2")
        self.assertEqual(replacement.state, "reserved")
        self.assertTrue(
            (
                self.store_path
                / ".completed"
                / ("session-" + "1" * 64)
            ).is_dir()
        )

    def test_quarantine_requires_scope_proof_and_exact_object(self) -> None:
        store = self.open_store()
        session = self.reserve(store, marker="1")
        self.advance_to(session, "staging_exposed")
        pending = {
            "from_state": "staging_exposed",
            "namespace": "staging",
            "quarantine_name": "session-" + "1" * 64,
            "object_identity_sha256": self.digest("leaf"),
            "reason_code": "coordinator_restarted",
            "lifecycle_status": "not_applicable",
            "empty_leaf_policy": "remove_and_fsync",
        }
        session.append_event(
            expected_state="staging_exposed",
            next_state="quarantine_pending",
            details=pending,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        self.assert_code(
            "transaction_journal_incomplete_session_exists",
            self.reserve,
            store,
            marker="2",
        )
        mismatched = {
            **pending,
            "from_state": "quarantine_pending",
            "object_identity_sha256": self.digest("replacement-object"),
            "lifecycle_status": "not_applicable",
        }
        mismatched.pop("empty_leaf_policy")
        self.assert_code(
            "transaction_journal_quarantine_binding_changed",
            session.append_event,
            expected_state="quarantine_pending",
            next_state="quarantined",
            details=mismatched,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        terminal = {
            **pending,
            "from_state": "quarantine_pending",
            "lifecycle_status": "not_applicable",
        }
        terminal.pop("empty_leaf_policy")
        self.assert_code(
            "transaction_journal_staging_quarantine_ack_required",
            session.append_event,
            expected_state="quarantine_pending",
            next_state="quarantined",
            details=terminal,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        self.complete_staging_tombstone_handshake(
            session,
            disposition="quarantined",
            origin="staging_exposed",
        )
        replacement = self.reserve(store, marker="2")
        self.assertEqual(replacement.state, "reserved")

    def test_staging_quarantine_intent_is_exactly_bound(self) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "staging_exposed")
        session.append_event(
            expected_state="staging_exposed",
            next_state="quarantine_pending",
            details={
                "from_state": "staging_exposed",
                "namespace": "staging",
                "quarantine_name": "session-" + session.session_id,
                "object_identity_sha256": self.digest("leaf"),
                "reason_code": "coordinator_restarted",
                "lifecycle_status": "not_applicable",
                "empty_leaf_policy": "remove_and_fsync",
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        quarantine_intent = session.latest_record
        session.append_event(
            expected_state="quarantine_pending",
            next_state="operator_attention",
            details={
                "from_state": "quarantine_pending",
                "reason_code": "quarantine_retry_required",
                "incident_sha256": self.digest("quarantine-retry"),
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        valid = self.staging_tombstone_pending_details(
            session,
            disposition="quarantined",
            origin="staging_exposed",
        )

        wrong_intent = copy.deepcopy(valid)
        wrong_intent[
            "staging_quarantine_intent_record_sha256"
        ] = self.digest("wrong-quarantine-intent")
        self.assert_code(
            "transaction_journal_staging_quarantine_effect_binding_changed",
            session.append_event,
            expected_state="operator_attention",
            next_state="staging_tombstone_ack_pending",
            details=wrong_intent,
            recorded_at_unix=session.latest_record.revision + 1,
        )

        wrong_reason = copy.deepcopy(valid)
        wrong_reason["terminal_receipt"]["reason_code"] = (
            "different_quarantine_reason"
        )
        wrong_reason["terminal_receipt_sha256"] = (
            journal.staging_quarantine_receipt_sha256(
                wrong_reason["terminal_receipt"]
            )
        )
        self.assert_code(
            "transaction_journal_staging_quarantine_effect_binding_changed",
            session.append_event,
            expected_state="operator_attention",
            next_state="staging_tombstone_ack_pending",
            details=wrong_reason,
            recorded_at_unix=session.latest_record.revision + 1,
        )

        self.assertEqual(
            valid["staging_quarantine_intent_record_sha256"],
            quarantine_intent.record_sha256,
        )
        session.append_event(
            expected_state="operator_attention",
            next_state="staging_tombstone_ack_pending",
            details=valid,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        self.assertEqual(
            session.state, "staging_tombstone_ack_pending"
        )

    def test_quarantine_effect_cannot_bypass_outer_intent_or_ack(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "staging_exposed")

        removed_without_intent = self.staging_tombstone_pending_details(
            session,
            disposition="absent",
            origin="staging_exposed",
        )
        removed_without_intent["terminal_receipt"][
            "terminal_event"
        ] = "quarantine_removed"
        removed_without_intent["terminal_receipt"][
            "quarantine_reason_code"
        ] = "capture_failed"
        removed_without_intent["terminal_receipt_sha256"] = (
            journal.staging_absence_receipt_sha256(
                removed_without_intent["terminal_receipt"]
            )
        )
        self.assert_code(
            (
                "transaction_journal_"
                "staging_quarantine_intent_missing"
            ),
            session.append_event,
            expected_state="staging_exposed",
            next_state="staging_tombstone_ack_pending",
            details=removed_without_intent,
            recorded_at_unix=session.latest_record.revision + 1,
        )

        quarantine_without_intent = (
            self.staging_tombstone_pending_details(
                session,
                disposition="quarantined",
                origin="staging_exposed",
            )
        )
        self.assert_code(
            (
                "transaction_journal_"
                "staging_quarantine_intent_missing"
            ),
            session.append_event,
            expected_state="staging_exposed",
            next_state="staging_tombstone_ack_pending",
            details=quarantine_without_intent,
            recorded_at_unix=session.latest_record.revision + 1,
        )

        session.append_event(
            expected_state="staging_exposed",
            next_state="quarantine_pending",
            details={
                "from_state": "staging_exposed",
                "namespace": "staging",
                "quarantine_name": "session-" + session.session_id,
                "object_identity_sha256": self.digest("leaf"),
                "reason_code": "capture_failed",
                "lifecycle_status": "not_applicable",
                "empty_leaf_policy": "remove_and_fsync",
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        pending = self.staging_tombstone_pending_details(
            session,
            disposition="absent",
            origin="staging_exposed",
        )
        session.append_event(
            expected_state="quarantine_pending",
            next_state="staging_tombstone_ack_pending",
            details=pending,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        wrong_ack = self.staging_tombstone_acked_details(session)
        wrong_ack["tombstone_ack_receipt"][
            "outer_quarantine_intent_record_sha256"
        ] = self.digest("other-quarantine-intent")
        wrong_ack["tombstone_ack_receipt_sha256"] = (
            journal.staging_tombstone_ack_receipt_sha256(
                wrong_ack["tombstone_ack_receipt"]
            )
        )
        self.assert_code(
            (
                "transaction_journal_"
                "staging_tombstone_ack_receipt_binding_changed"
            ),
            session.append_event,
            expected_state="staging_tombstone_ack_pending",
            next_state="staging_tombstone_acked",
            details=wrong_ack,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        valid_ack = self.staging_tombstone_acked_details(session)
        session.append_event(
            expected_state="staging_tombstone_ack_pending",
            next_state="staging_tombstone_acked",
            details=valid_ack,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session.append_event(
            expected_state="staging_tombstone_acked",
            next_state="staging_absent_cleanup_complete",
            details={
                "from_state": "staging_tombstone_acked",
                "terminal_disposition": "absent",
                "terminal_receipt_sha256": pending[
                    "terminal_receipt_sha256"
                ],
                "tombstone_ack_receipt_sha256": valid_ack[
                    "tombstone_ack_receipt_sha256"
                ],
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )

    def test_empty_staging_quarantine_intent_accepts_exact_absence(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "staging_exposed")
        session.append_event(
            expected_state="staging_exposed",
            next_state="quarantine_pending",
            details={
                "from_state": "staging_exposed",
                "namespace": "staging",
                "quarantine_name": "session-" + session.session_id,
                "object_identity_sha256": self.digest("leaf"),
                "reason_code": "capture_failed",
                "lifecycle_status": "not_applicable",
                "empty_leaf_policy": "remove_and_fsync",
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        valid = self.staging_tombstone_pending_details(
            session,
            disposition="absent",
            origin="staging_exposed",
        )
        valid["terminal_receipt"]["terminal_event"] = (
            "quarantine_removed"
        )
        valid["terminal_receipt_sha256"] = (
            journal.staging_absence_receipt_sha256(
                valid["terminal_receipt"]
            )
        )

        wrong_event = copy.deepcopy(valid)
        wrong_event["terminal_receipt"]["terminal_event"] = "removed"
        wrong_event["terminal_receipt"][
            "quarantine_reason_code"
        ] = None
        wrong_event["terminal_receipt_sha256"] = (
            journal.staging_absence_receipt_sha256(
                wrong_event["terminal_receipt"]
            )
        )
        self.assert_code(
            "transaction_journal_staging_quarantine_effect_binding_changed",
            session.append_event,
            expected_state="quarantine_pending",
            next_state="staging_tombstone_ack_pending",
            details=wrong_event,
            recorded_at_unix=session.latest_record.revision + 1,
        )

        session.append_event(
            expected_state="quarantine_pending",
            next_state="staging_tombstone_ack_pending",
            details=valid,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        acked = self.staging_tombstone_acked_details(session)
        session.append_event(
            expected_state="staging_tombstone_ack_pending",
            next_state="staging_tombstone_acked",
            details=acked,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session.append_event(
            expected_state="staging_tombstone_acked",
            next_state="staging_absent_cleanup_complete",
            details={
                "from_state": "staging_tombstone_acked",
                "terminal_disposition": "absent",
                "terminal_receipt_sha256": valid[
                    "terminal_receipt_sha256"
                ],
                "tombstone_ack_receipt_sha256": acked[
                    "tombstone_ack_receipt_sha256"
                ],
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )

    def test_staging_terminal_binds_every_exposed_namespace(self) -> None:
        namespace_fields = (
            "shared_root_identity_sha256",
            "recovery_namespace_identity_sha256",
            "quarantine_namespace_identity_sha256",
            "transactions_namespace_identity_sha256",
        )
        for index, field in enumerate(namespace_fields, start=1):
            with self.subTest(field=field):
                layout_root = self.root / f"namespace-{index}"
                anchor, store_path = self.make_layout(layout_root)
                store = self.open_store(store_path, anchor)
                session = self.reserve(store)
                self.advance_to(session, "staging_exposed")
                changed = self.staging_tombstone_pending_details(
                    session,
                    disposition="absent",
                    origin="staging_exposed",
                )
                changed["terminal_receipt"][field] = self.digest(
                    f"wrong-{field}"
                )
                changed["terminal_receipt_sha256"] = (
                    journal.staging_absence_receipt_sha256(
                        changed["terminal_receipt"]
                    )
                )
                self.assert_code(
                    (
                        "transaction_journal_"
                        "staging_terminal_receipt_identity_changed"
                    ),
                    session.append_event,
                    expected_state="staging_exposed",
                    next_state="staging_tombstone_ack_pending",
                    details=changed,
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )

    def test_intent_effect_identities_and_lifecycle_are_bound(self) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "staging_create_intent")
        changed_exposure = self.details_for(
            session, "staging_exposed"
        )
        changed_receipt = dict(
            changed_exposure["staging_exposure_receipt"]
        )
        changed_receipt["capture_uid"] = 999
        changed_exposure["staging_exposure_receipt"] = changed_receipt
        changed_exposure["staging_exposure_receipt_sha256"] = (
            journal.staging_exposure_receipt_sha256(changed_receipt)
        )
        self.assert_code(
            "transaction_journal_staging_exposure_binding_changed",
            session.append_event,
            expected_state="staging_create_intent",
            next_state="staging_exposed",
            details=changed_exposure,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session.append_event(
            expected_state="staging_create_intent",
            next_state="staging_exposed",
            details=self.details_for(session, "staging_exposed"),
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session.append_event(
            expected_state="staging_exposed",
            next_state="child_launch_intent",
            details=self.details_for(session, "child_launch_intent"),
            recorded_at_unix=session.latest_record.revision + 1,
        )
        changed_scope = self.details_for(session, "child_running")
        changed_scope["lifecycle_scope_started_receipt"][
            "lifecycle_provider"
        ] = "systemd_transient_scope"
        changed_scope["lifecycle_scope_started_receipt_sha256"] = (
            lifecycle.scope_started_receipt_sha256(
                changed_scope["lifecycle_scope_started_receipt"]
            )
        )
        self.assert_code(
            (
                "transaction_journal_"
                "lifecycle_scope_started_binding_changed"
            ),
            session.append_event,
            expected_state="child_launch_intent",
            next_state="child_running",
            details=changed_scope,
            recorded_at_unix=session.latest_record.revision + 1,
        )

    def test_lifecycle_v5_rejects_bare_hashes_and_start_drift(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "staging_exposed")
        launch = self.details_for(session, "child_launch_intent")
        wrong_activation_digest = {
            **launch,
            "lifecycle_activation_receipt_sha256": self.digest(
                "wrong-activation-wrapper"
            ),
        }
        self.assert_code(
            (
                "transaction_journal_"
                "lifecycle_activation_receipt_digest_mismatch"
            ),
            session.append_event,
            expected_state="staging_exposed",
            next_state="child_launch_intent",
            details=wrong_activation_digest,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session.append_event(
            expected_state="staging_exposed",
            next_state="child_launch_intent",
            details=launch,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        self.assert_code(
            "transaction_journal_child_running_details_invalid",
            session.append_event,
            expected_state="child_launch_intent",
            next_state="child_running",
            details={
                "lifecycle_scope_id": (
                    f"jlq-{lifecycle.LIFECYCLE_BACKEND}-"
                    f"{session.session_id}"
                ),
                "lifecycle_scope_receipt_sha256": self.digest(
                    "legacy-bare-start"
                ),
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        valid = self.details_for(session, "child_running")
        mutations = {
            "staging_transaction_intent_sha256": self.digest(
                "other-staging-intent"
            ),
            "child_launch_intent_record_sha256": self.digest(
                "other-launch-intent"
            ),
            "handoff_policy_sha256": self.digest(
                "other-handoff-policy"
            ),
            "host_boot_id_sha256": self.digest(
                "other-start-host-boot"
            ),
        }
        for field, replacement in mutations.items():
            with self.subTest(start_binding=field):
                changed = copy.deepcopy(valid)
                changed["lifecycle_scope_started_receipt"][
                    field
                ] = replacement
                changed[
                    "lifecycle_scope_started_receipt_sha256"
                ] = lifecycle.scope_started_receipt_sha256(
                    changed["lifecycle_scope_started_receipt"]
                )
                self.assert_code(
                    (
                        "transaction_journal_"
                        "lifecycle_scope_started_binding_changed"
                    ),
                    session.append_event,
                    expected_state="child_launch_intent",
                    next_state="child_running",
                    details=changed,
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )
        session._append_event_for_history_validation_test(
            expected_state="child_launch_intent",
            next_state="child_running",
            details=valid,
            recorded_at_unix=session.latest_record.revision + 1,
        )

    def test_lifecycle_clearance_bundle_is_exactly_cross_bound(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "lifecycle_clearance_intent")

        wrong_wrapper = self.details_for(
            session, "lifecycle_scope_empty"
        )
        wrong_wrapper["lifecycle_clearance_bundle_sha256"] = (
            self.digest("wrong-clearance-bundle-wrapper")
        )
        self.assert_code(
            (
                "transaction_journal_"
                "lifecycle_clearance_bundle_digest_mismatch"
            ),
            session.append_event,
            expected_state="lifecycle_clearance_intent",
            next_state="lifecycle_scope_empty",
            details=wrong_wrapper,
            recorded_at_unix=session.latest_record.revision + 1,
        )

        wrong_outer = copy.deepcopy(
            self.details_for(
                session, "lifecycle_scope_empty"
            )["lifecycle_clearance_bundle"]
        )
        other_outer = self.digest("other-outer-clearance-intent")
        wrong_outer["clearance_intent_receipt"][
            "outer_clearance_intent_record_sha256"
        ] = other_outer
        wrong_outer["scope_empty_receipt"][
            "outer_clearance_intent_record_sha256"
        ] = other_outer
        wrong_outer = self.rehash_lifecycle_clearance_bundle(
            wrong_outer
        )
        self.assert_code(
            (
                "transaction_journal_"
                "lifecycle_clearance_binding_changed"
            ),
            session.append_event,
            expected_state="lifecycle_clearance_intent",
            next_state="lifecycle_scope_empty",
            details={
                "lifecycle_clearance_bundle": wrong_outer,
                "lifecycle_clearance_bundle_sha256": (
                    lifecycle.clearance_bundle_sha256(wrong_outer)
                ),
                "lifecycle_operation_binding": (
                    self.lifecycle_operation_binding(
                        session,
                        operation="request_clearance",
                        successor_state="lifecycle_scope_empty",
                    )
                ),
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )

        wrong_activation = copy.deepcopy(
            self.details_for(
                session, "lifecycle_scope_empty"
            )["lifecycle_clearance_bundle"]
        )
        other_helper = self.digest("other-helper-policy")
        wrong_activation["activation_receipt"][
            "helper_activation_policy_sha256"
        ] = other_helper
        other_activation_digest = lifecycle.activation_receipt_sha256(
            wrong_activation["activation_receipt"]
        )
        wrong_activation["scope_started_receipt"][
            "helper_activation_policy_sha256"
        ] = other_helper
        wrong_activation["scope_started_receipt"][
            "lifecycle_activation_receipt_sha256"
        ] = other_activation_digest
        other_start_digest = lifecycle.scope_started_receipt_sha256(
            wrong_activation["scope_started_receipt"]
        )
        wrong_activation["clearance_intent_receipt"][
            "lifecycle_activation_receipt_sha256"
        ] = other_activation_digest
        wrong_activation["clearance_intent_receipt"][
            "scope_started_receipt_sha256"
        ] = other_start_digest
        wrong_activation["scope_empty_receipt"][
            "lifecycle_activation_receipt_sha256"
        ] = other_activation_digest
        wrong_activation["scope_empty_receipt"][
            "scope_started_receipt_sha256"
        ] = other_start_digest
        wrong_activation = self.rehash_lifecycle_clearance_bundle(
            wrong_activation
        )
        self.assert_code(
            (
                "transaction_journal_"
                "lifecycle_activation_binding_changed"
            ),
            session.append_event,
            expected_state="lifecycle_clearance_intent",
            next_state="lifecycle_scope_empty",
            details={
                "lifecycle_clearance_bundle": wrong_activation,
                "lifecycle_clearance_bundle_sha256": (
                    lifecycle.clearance_bundle_sha256(
                        wrong_activation
                    )
                ),
                "lifecycle_operation_binding": (
                    self.lifecycle_operation_binding(
                        session,
                        operation="request_clearance",
                        successor_state="lifecycle_scope_empty",
                    )
                ),
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )

    def test_never_started_bundle_cannot_rebind_outer_session(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "child_launch_intent")
        session._append_event_for_history_validation_test(
            expected_state="child_launch_intent",
            next_state="lifecycle_clearance_intent",
            details=self.details_for(
                session, "lifecycle_clearance_intent"
            ),
            recorded_at_unix=session.latest_record.revision + 1,
        )
        bundle = self.lifecycle_clearance_bundle(
            session, disposition="never_started"
        )
        rebound_session = "2" * 64
        rebound_scope = (
            f"jlq-{lifecycle.LIFECYCLE_BACKEND}-"
            f"{rebound_session}"
        )
        rebound_incarnation = self.digest(
            "rebound-scope-incarnation"
        )
        for receipt_name in (
            "clearance_intent_receipt",
            "scope_empty_receipt",
        ):
            receipt = bundle[receipt_name]
            receipt["capture_session_id"] = rebound_session
            receipt["lifecycle_scope_id"] = rebound_scope
            receipt["scope_incarnation_id"] = (
                rebound_incarnation
            )
        bundle = self.rehash_lifecycle_clearance_bundle(bundle)
        self.assert_code(
            "transaction_journal_lifecycle_scope_binding_changed",
            session.append_event,
            expected_state="lifecycle_clearance_intent",
            next_state="lifecycle_scope_empty",
            details={
                "lifecycle_clearance_bundle": bundle,
                "lifecycle_clearance_bundle_sha256": (
                    lifecycle.clearance_bundle_sha256(bundle)
                ),
                "lifecycle_operation_binding": (
                    self.lifecycle_operation_binding(
                        session,
                        operation="request_clearance",
                        successor_state="lifecycle_scope_empty",
                    )
                ),
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )

    def test_lifecycle_clearance_recovers_through_exact_attention(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "child_running")
        first_attention_binding = self.lifecycle_operation_binding(
            session,
            operation="recover_scope",
            successor_state="operator_attention",
            outcome="attention",
            error_code="capture_runner_uncertain",
        )
        session._append_event_for_history_validation_test(
            expected_state="child_running",
            next_state="operator_attention",
            details={
                "from_state": "child_running",
                "reason_code": "capture_runner_uncertain",
                "incident_sha256": (
                    journal.lifecycle_operation_binding_sha256(
                        first_attention_binding
                    )
                ),
                "lifecycle_operation_binding": (
                    first_attention_binding
                ),
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        clearance = self.details_for(
            session, "lifecycle_clearance_intent"
        )
        changed = {
            **clearance,
            "effect_origin_record_sha256": self.digest(
                "unrelated-running-record"
            ),
        }
        self.assert_code(
            (
                "transaction_journal_"
                "lifecycle_clearance_effect_origin_changed"
            ),
            session.append_event,
            expected_state="operator_attention",
            next_state="lifecycle_clearance_intent",
            details=changed,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session._append_event_for_history_validation_test(
            expected_state="operator_attention",
            next_state="lifecycle_clearance_intent",
            details=clearance,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        second_attention_binding = self.lifecycle_operation_binding(
            session,
            operation="recover_scope",
            successor_state="operator_attention",
            outcome="attention",
            error_code="clearance_retry_required",
        )
        session._append_event_for_history_validation_test(
            expected_state="lifecycle_clearance_intent",
            next_state="operator_attention",
            details={
                "from_state": "lifecycle_clearance_intent",
                "reason_code": "clearance_retry_required",
                "incident_sha256": (
                    journal.lifecycle_operation_binding_sha256(
                        second_attention_binding
                    )
                ),
                "lifecycle_operation_binding": (
                    second_attention_binding
                ),
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        recovered_scope_empty = self.details_for(
            session, "lifecycle_scope_empty"
        )
        recovered_scope_empty["lifecycle_operation_binding"] = (
            self.lifecycle_operation_binding(
                session,
                operation="recover_scope",
                successor_state="lifecycle_scope_empty",
            )
        )
        session._append_event_for_history_validation_test(
            expected_state="operator_attention",
            next_state="lifecycle_scope_empty",
            details=recovered_scope_empty,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        self.complete_staging_tombstone_handshake(
            session,
            disposition="absent",
            origin="child_running",
        )

    def test_late_discovered_start_is_cleanup_only(self) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "child_launch_intent")
        session._append_event_for_history_validation_test(
            expected_state="child_launch_intent",
            next_state="lifecycle_clearance_intent",
            details=self.details_for(
                session, "lifecycle_clearance_intent"
            ),
            recorded_at_unix=session.latest_record.revision + 1,
        )
        bundle = self.lifecycle_clearance_bundle(
            session,
            disposition="forced_termination",
            late_discovered_start=True,
        )
        self.assertIsNone(
            bundle["clearance_intent_receipt"][
                "scope_started_receipt_sha256"
            ]
        )
        self.assertIsNotNone(bundle["scope_started_receipt"])
        session._append_event_for_history_validation_test(
            expected_state="lifecycle_clearance_intent",
            next_state="lifecycle_scope_empty",
            details={
                "lifecycle_clearance_bundle": bundle,
                "lifecycle_clearance_bundle_sha256": (
                    lifecycle.clearance_bundle_sha256(bundle)
                ),
                "lifecycle_operation_binding": (
                    self.lifecycle_operation_binding(
                        session,
                        operation="request_clearance",
                        successor_state="lifecycle_scope_empty",
                    )
                ),
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        self.assert_code(
            "transaction_journal_lifecycle_adoption_forbidden",
            session.append_event,
            expected_state="lifecycle_scope_empty",
            next_state="adoption_intent",
            details=self.details_for(session, "adoption_intent"),
            recorded_at_unix=session.latest_record.revision + 1,
        )
        self.complete_staging_tombstone_handshake(
            session,
            disposition="absent",
            origin="child_launch_intent",
        )
        self.assertEqual(
            session.state, "staging_absent_cleanup_complete"
        )

    def test_never_started_and_reboot_clearance_are_cleanup_only(
        self,
    ) -> None:
        cases = (
            ("never_started", "child_launch_intent"),
            ("host_reboot", "capture_ready"),
        )
        for index, (disposition, origin) in enumerate(
            cases, start=1
        ):
            with self.subTest(disposition=disposition):
                case_root = self.root / f"noneligible-{index}"
                anchor, store_path = self.make_layout(case_root)
                store = self.open_store(store_path, anchor)
                session = self.reserve(
                    store, marker=str(index + 1)
                )
                self.advance_to(session, origin)
                session._append_event_for_history_validation_test(
                    expected_state=origin,
                    next_state="lifecycle_clearance_intent",
                    details=self.details_for(
                        session, "lifecycle_clearance_intent"
                    ),
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )
                bundle = self.lifecycle_clearance_bundle(
                    session,
                    disposition=disposition,
                )
                session._append_event_for_history_validation_test(
                    expected_state="lifecycle_clearance_intent",
                    next_state="lifecycle_scope_empty",
                    details={
                        "lifecycle_clearance_bundle": bundle,
                        "lifecycle_clearance_bundle_sha256": (
                            lifecycle.clearance_bundle_sha256(bundle)
                        ),
                        "lifecycle_operation_binding": (
                            self.lifecycle_operation_binding(
                                session,
                                operation="request_clearance",
                                successor_state=(
                                    "lifecycle_scope_empty"
                                ),
                            )
                        ),
                    },
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )
                self.assertFalse(
                    bundle["scope_empty_receipt"][
                        "adoption_eligible"
                    ]
                )
                self.assert_code(
                    (
                        "transaction_journal_"
                        "lifecycle_adoption_forbidden"
                    ),
                    session.append_event,
                    expected_state="lifecycle_scope_empty",
                    next_state="adoption_intent",
                    details=self.details_for(
                        session, "adoption_intent"
                    ),
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )
                self.complete_staging_tombstone_handshake(
                    session,
                    disposition="absent",
                    origin=origin,
                )
                self.assertEqual(
                    session.state,
                    "staging_absent_cleanup_complete",
                )

    def test_staging_exposure_receipt_rejects_cross_ledger_drift(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "staging_create_intent")
        valid = self.details_for(session, "staging_exposed")

        binding_mutations = {
            "session_and_name": {
                "capture_session_id": "2" * 64,
                "staging_leaf_name": "session-" + "2" * 64,
            },
            "intent": {
                "staging_transaction_intent_sha256": self.digest(
                    "other-intent"
                )
            },
            "export_gid": {"export_gid": 999},
            "device": {"filesystem_device": 999},
        }
        for label, mutation in binding_mutations.items():
            with self.subTest(binding=label):
                details = {
                    "staging_exposure_receipt": {
                        **valid["staging_exposure_receipt"],
                        **mutation,
                    },
                    "staging_exposure_receipt_sha256": "",
                }
                details["staging_exposure_receipt_sha256"] = (
                    journal.staging_exposure_receipt_sha256(
                        details["staging_exposure_receipt"]
                    )
                )
                self.assert_code(
                    (
                        "transaction_journal_"
                        "staging_exposure_binding_changed"
                    ),
                    session.append_event,
                    expected_state="staging_create_intent",
                    next_state="staging_exposed",
                    details=details,
                    recorded_at_unix=3,
                )

        normalizer_mutations = {
            "schema": (
                {"schema_version": "wrong.schema"},
                (
                    "capture_staging_"
                    "exposure_receipt_schema_invalid"
                ),
            ),
            "status": (
                {"status": "wrong"},
                (
                    "capture_staging_"
                    "exposure_receipt_status_invalid"
                ),
            ),
            "mode": (
                {"staging_leaf_mode": 0o777},
                (
                    "capture_staging_exposure_receipt_"
                    "staging_leaf_mode_invalid"
                ),
            ),
            "journal_head": (
                {"staging_journal_head_sha256": "bad"},
                (
                    "capture_staging_exposure_receipt_"
                    "journal_head_sha256_invalid"
                ),
            ),
        }
        for label, (mutation, code) in normalizer_mutations.items():
            with self.subTest(normalizer=label):
                receipt = {
                    **valid["staging_exposure_receipt"],
                    **mutation,
                }
                self.assert_code(
                    code,
                    journal.normalize_staging_exposure_receipt,
                    receipt,
                )

        for label, receipt in (
            (
                "missing",
                {
                    key: value
                    for key, value in valid[
                        "staging_exposure_receipt"
                    ].items()
                    if key != "staging_journal_head_sha256"
                },
            ),
            (
                "extra",
                {
                    **valid["staging_exposure_receipt"],
                    "pid": 123,
                },
            ),
        ):
            with self.subTest(fields=label):
                self.assert_code(
                    (
                        "capture_staging_"
                        "exposure_receipt_fields_invalid"
                    ),
                    journal.normalize_staging_exposure_receipt,
                    receipt,
                )

        wrong_wrapper = {
            **valid,
            "staging_exposure_receipt_sha256": self.digest(
                "wrong-wrapper"
            ),
        }
        self.assert_code(
            (
                "transaction_journal_"
                "staging_exposure_receipt_digest_mismatch"
            ),
            session.append_event,
            expected_state="staging_create_intent",
            next_state="staging_exposed",
            details=wrong_wrapper,
            recorded_at_unix=3,
        )
        session.append_event(
            expected_state="staging_create_intent",
            next_state="staging_exposed",
            details=valid,
            recorded_at_unix=3,
        )

    def test_capture_recorder_is_narrow_bound_and_nonserializable(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        final_parent = self.root / "capture-recorder-final"
        final_parent.mkdir()
        final_parent_fd = os.open(
            final_parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
        self.addCleanup(os.close, final_parent_fd)
        os.set_inheritable(final_parent_fd, False)
        for label, bad_fd, code in (
            (
                "boolean",
                True,
                "transaction_journal_final_parent_fd_invalid",
            ),
            (
                "negative",
                -1,
                "transaction_journal_final_parent_fd_invalid",
            ),
        ):
            with self.subTest(final_parent_fd=label):
                self.assert_code(
                    code,
                    session.begin_capture_recording,
                    capture_uid=501,
                    export_gid=502,
                    retained_final_parent_fd=bad_fd,
                    handoff_policy_sha256=self.digest("handoff"),
                    recorded_at_unix=2,
                )
                self.assertEqual(session.state, "reserved")
                self.assertEqual(len(session.records), 1)

        closed_fd = os.dup(final_parent_fd)
        os.close(closed_fd)
        self.assert_code(
            "transaction_journal_final_parent_fd_unreadable",
            session.begin_capture_recording,
            capture_uid=501,
            export_gid=502,
            retained_final_parent_fd=closed_fd,
            handoff_policy_sha256=self.digest("handoff"),
            recorded_at_unix=2,
        )
        regular_path = self.root / "not-a-final-directory"
        regular_path.write_bytes(b"x")
        regular_fd = os.open(
            regular_path, os.O_RDONLY | os.O_CLOEXEC
        )
        self.addCleanup(os.close, regular_fd)
        self.assert_code(
            "transaction_journal_final_parent_fd_unsafe",
            session.begin_capture_recording,
            capture_uid=501,
            export_gid=502,
            retained_final_parent_fd=regular_fd,
            handoff_policy_sha256=self.digest("handoff"),
            recorded_at_unix=2,
        )
        inheritable_fd = os.dup(final_parent_fd)
        self.addCleanup(os.close, inheritable_fd)
        os.set_inheritable(inheritable_fd, True)
        self.assert_code(
            "transaction_journal_final_parent_fd_unsafe",
            session.begin_capture_recording,
            capture_uid=501,
            export_gid=502,
            retained_final_parent_fd=inheritable_fd,
            handoff_policy_sha256=self.digest("handoff"),
            recorded_at_unix=2,
        )
        self.assertEqual(session.state, "reserved")
        self.assertEqual(len(session.records), 1)
        self.assert_code(
            "transaction_journal_handoff_policy_mismatch",
            session.begin_capture_recording,
            capture_uid=501,
            export_gid=502,
            retained_final_parent_fd=final_parent_fd,
            handoff_policy_sha256=self.digest("wrong-handoff"),
            recorded_at_unix=2,
        )
        self.assertEqual(session.state, "reserved")
        self.assertEqual(len(session.records), 1)
        recorder = session.begin_capture_recording(
            capture_uid=501,
            export_gid=502,
            retained_final_parent_fd=final_parent_fd,
            handoff_policy_sha256=self.digest("handoff"),
            recorded_at_unix=2,
        )
        self.assert_code(
            "transaction_journal_expected_state_mismatch",
            session.begin_capture_recording,
            capture_uid=501,
            export_gid=502,
            retained_final_parent_fd=final_parent_fd,
            handoff_policy_sha256=self.digest("handoff"),
            recorded_at_unix=3,
        )
        self.assertEqual(len(session.records), 2)
        self.assertEqual(recorder.capture_session_id, session.session_id)
        self.assertEqual(
            recorder.staging_leaf_name,
            "session-" + session.session_id,
        )
        self.assertEqual(
            recorder.staging_transaction_intent_sha256,
            session.latest_record.record_sha256,
        )
        self.assertEqual(recorder.capture_uid, 501)
        self.assertEqual(recorder.export_gid, 502)
        self.assertEqual(
            recorder.required_device,
            os.fstat(final_parent_fd).st_dev,
        )
        self.assertFalse(hasattr(recorder, "append_event"))
        self.assertFalse(hasattr(recorder, "complete_signing"))
        self.assertFalse(hasattr(recorder, "publish"))
        with self.assertRaises(TypeError):
            pickle.dumps(recorder)
        with self.assertRaises(TypeError):
            journal.CaptureTransactionRecorder(
                _token=object(),
                session=session,
                intent=session.latest_record,
            )

        exposure = self.details_for(session, "staging_exposed")
        recorder.record_staging_exposed(
            exposure["staging_exposure_receipt"],
            receipt_sha256=exposure[
                "staging_exposure_receipt_sha256"
            ],
            recorded_at_unix=3,
        )
        launch = self.details_for(session, "child_launch_intent")
        recorder.record_child_launch_intent(
            launch["lifecycle_activation_receipt"],
            activation_receipt_sha256=launch[
                "lifecycle_activation_receipt_sha256"
            ],
            recorded_at_unix=4,
        )
        running = self.details_for(session, "child_running")
        active_lease = (
            session._begin_lifecycle_operation_for_client(
                operation="start_scope",
                snapshot=session.live_snapshot(),
            )
        )
        self.assert_code(
            "transaction_journal_lifecycle_operation_permit_required",
            recorder.record_child_running,
            running["lifecycle_scope_started_receipt"],
            scope_started_receipt_sha256=running[
                "lifecycle_scope_started_receipt_sha256"
            ],
            recorded_at_unix=5,
        )
        self.assert_code(
            "transaction_journal_lifecycle_operation_already_reserved",
            session.append_event,
            expected_state="child_launch_intent",
            next_state="child_running",
            details=running,
            recorded_at_unix=5,
        )
        active_lease.cancel_before_dispatch()
        self.assert_code(
            "transaction_journal_lifecycle_operation_permit_required",
            recorder.record_child_running,
            running["lifecycle_scope_started_receipt"],
            scope_started_receipt_sha256=running[
                "lifecycle_scope_started_receipt_sha256"
            ],
            recorded_at_unix=5,
        )
        session._append_event_for_history_validation_test(
            expected_state="child_launch_intent",
            next_state="child_running",
            details=running,
            recorded_at_unix=5,
        )
        ready = self.details_for(session, "capture_ready")
        self.assert_code(
            "transaction_journal_lifecycle_operation_permit_required",
            recorder.record_capture_ready,
            ready,
            recorded_at_unix=6,
        )
        session._append_event_for_history_validation_test(
            expected_state="child_running",
            next_state="capture_ready",
            details=ready,
            recorded_at_unix=6,
        )
        clearance = self.details_for(
            session, "lifecycle_clearance_intent"
        )
        recorder.record_lifecycle_clearance_intent(
            effect_origin_state=clearance["effect_origin_state"],
            effect_origin_record_sha256=clearance[
                "effect_origin_record_sha256"
            ],
            scope_started_receipt_sha256=clearance[
                "scope_started_receipt_sha256"
            ],
            clearance_mode=clearance["clearance_mode"],
            recorded_at_unix=7,
        )
        scope_empty = self.details_for(
            session, "lifecycle_scope_empty"
        )
        self.assert_code(
            "transaction_journal_lifecycle_operation_permit_required",
            recorder.record_lifecycle_scope_empty,
            scope_empty["lifecycle_clearance_bundle"],
            clearance_bundle_sha256=scope_empty[
                "lifecycle_clearance_bundle_sha256"
            ],
            recorded_at_unix=8,
        )
        session._append_event_for_history_validation_test(
            expected_state="lifecycle_clearance_intent",
            next_state="lifecycle_scope_empty",
            details=scope_empty,
            recorded_at_unix=8,
        )
        recorder.record_adoption_intent(
            self.details_for(session, "adoption_intent"),
            recorded_at_unix=9,
        )
        recorder.record_adopted(
            self.details_for(session, "adopted"),
            recorded_at_unix=10,
        )
        self.assertEqual(session.state, "adopted")

    def test_capture_recorder_is_not_regranted_after_restart(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        final_parent = self.root / "capture-restart-final"
        final_parent.mkdir()
        final_parent_fd = os.open(
            final_parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
        self.addCleanup(os.close, final_parent_fd)
        session.begin_capture_recording(
            capture_uid=501,
            export_gid=502,
            retained_final_parent_fd=final_parent_fd,
            handoff_policy_sha256=self.digest("handoff"),
            recorded_at_unix=2,
        )
        store.close()

        reopened = self.open_store()
        loaded = reopened.load_incomplete_sessions()
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].state, "staging_create_intent")
        self.assertFalse(
            hasattr(loaded[0], "resume_capture_recording")
        )

    def test_live_child_cannot_enter_tombstone_handshake_before_clearance(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "child_running")
        pending = self.staging_tombstone_pending_details(
            session,
            disposition="quarantined",
            origin="child_running",
            lifecycle_status="scope_not_proven",
        )
        self.assert_code(
            "transaction_journal_transition_invalid",
            session.append_event,
            expected_state="child_running",
            next_state="staging_tombstone_ack_pending",
            details=pending,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        self.assertEqual(session.state, "child_running")

    def test_adopted_requires_acked_absence_before_verifier(self) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "adopted")
        self.assert_code(
            "transaction_journal_transition_invalid",
            session.append_event,
            expected_state="adopted",
            next_state="verifier_output_bound",
            details=self.details_for(session, "verifier_output_bound"),
            recorded_at_unix=session.latest_record.revision + 1,
        )
        pending = self.staging_tombstone_pending_details(
            session,
            disposition="absent",
            origin="adopted",
        )
        pending["terminal_receipt"]["terminal_event"] = "startup_absent"
        pending["terminal_receipt_sha256"] = (
            journal.staging_absence_receipt_sha256(
                pending["terminal_receipt"]
            )
        )
        session.append_event(
            expected_state="adopted",
            next_state="staging_tombstone_ack_pending",
            details=pending,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session.append_event(
            expected_state="staging_tombstone_ack_pending",
            next_state="staging_tombstone_acked",
            details=self.staging_tombstone_acked_details(session),
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session.append_event(
            expected_state="staging_tombstone_acked",
            next_state="verifier_output_bound",
            details=self.details_for(session, "verifier_output_bound"),
            recorded_at_unix=session.latest_record.revision + 1,
        )
        self.assertEqual(session.state, "verifier_output_bound")

    def test_adopted_staging_quarantine_cannot_continue_to_verifier(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "adopted")
        scope_receipt_sha256 = next(
            record.details["lifecycle_clearance_bundle"][
                "scope_empty_receipt_sha256"
            ]
            for record in session.records
            if record.state == "lifecycle_scope_empty"
        )
        session.append_event(
            expected_state="adopted",
            next_state="quarantine_pending",
            details={
                "from_state": "adopted",
                "namespace": "staging",
                "quarantine_name": "session-" + session.session_id,
                "object_identity_sha256": self.digest("leaf"),
                "reason_code": "coordinator_restarted",
                "lifecycle_status": "scope_empty",
                "lifecycle_scope_empty_receipt_sha256": (
                    scope_receipt_sha256
                ),
                "empty_leaf_policy": "remove_and_fsync",
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        pending = self.staging_tombstone_pending_details(
            session,
            disposition="quarantined",
            origin="adopted",
        )
        session.append_event(
            expected_state="quarantine_pending",
            next_state="staging_tombstone_ack_pending",
            details=pending,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session.append_event(
            expected_state="staging_tombstone_ack_pending",
            next_state="staging_tombstone_acked",
            details=self.staging_tombstone_acked_details(session),
            recorded_at_unix=session.latest_record.revision + 1,
        )
        self.assert_code(
            "transaction_journal_staging_cleanup_continuation_unsafe",
            session.append_event,
            expected_state="staging_tombstone_acked",
            next_state="verifier_output_bound",
            details=self.details_for(session, "verifier_output_bound"),
            recorded_at_unix=session.latest_record.revision + 1,
        )
        self.assertEqual(session.state, "staging_tombstone_acked")

    def test_adoption_intent_tombstone_requires_reconciliation(self) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "adoption_intent")
        pending = self.staging_tombstone_pending_details(
            session,
            disposition="absent",
            origin="adoption_intent",
        )
        session.append_event(
            expected_state="adoption_intent",
            next_state="staging_tombstone_ack_pending",
            details=pending,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        acked = self.staging_tombstone_acked_details(session)
        self.assert_code(
            "transaction_journal_adoption_reconciliation_required",
            session.append_event,
            expected_state="staging_tombstone_ack_pending",
            next_state="staging_tombstone_acked",
            details=acked,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        adoption_intent = next(
            record
            for record in session.records
            if record.state == "adoption_intent"
        )
        session.append_event(
            expected_state="staging_tombstone_ack_pending",
            next_state="operator_attention",
            details={
                "from_state": "staging_tombstone_ack_pending",
                "reason_code": "adoption_inspection_failed",
                "incident_sha256": self.digest(
                    "adoption-inspection-failure"
                ),
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session.append_event(
            expected_state="operator_attention",
            next_state="adoption_reconciliation_required",
            details={
                "from_state": "operator_attention",
                "adoption_intent_record_sha256": (
                    adoption_intent.record_sha256
                ),
                "terminal_receipt_sha256": pending[
                    "terminal_receipt_sha256"
                ],
                "tombstone_sha256": pending["tombstone_sha256"],
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        self.assertEqual(
            session.state, "adoption_reconciliation_required"
        )

    def test_repeated_attention_resolves_against_exact_predecessor(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "adopted")
        pending = self.staging_tombstone_pending_details(
            session,
            disposition="absent",
            origin="adopted",
        )
        session.append_event(
            expected_state="adopted",
            next_state="staging_tombstone_ack_pending",
            details=pending,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session.append_event(
            expected_state="staging_tombstone_ack_pending",
            next_state="operator_attention",
            details={
                "from_state": "staging_tombstone_ack_pending",
                "reason_code": "ack_retry_required",
                "incident_sha256": self.digest("ack-retry"),
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session.append_event(
            expected_state="operator_attention",
            next_state="staging_tombstone_acked",
            details=self.staging_tombstone_acked_details(session),
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session.append_event(
            expected_state="staging_tombstone_acked",
            next_state="verifier_output_bound",
            details=self.details_for(session, "verifier_output_bound"),
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session.append_event(
            expected_state="verifier_output_bound",
            next_state="operator_attention",
            details={
                "from_state": "verifier_output_bound",
                "reason_code": "verifier_failed",
                "incident_sha256": self.digest("verifier-failure"),
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        scope_receipt = next(
            record.details["lifecycle_clearance_bundle"][
                "scope_empty_receipt_sha256"
            ]
            for record in session.records
            if record.state == "lifecycle_scope_empty"
        )
        session.append_event(
            expected_state="operator_attention",
            next_state="quarantined",
            details={
                "from_state": "operator_attention",
                "namespace": "adopted",
                "quarantine_name": "opaque-capture-" + "a" * 32,
                "object_identity_sha256": self.digest("object"),
                "reason_code": "verifier_failed",
                "lifecycle_status": "scope_empty",
                "lifecycle_scope_empty_receipt_sha256": (
                    scope_receipt
                ),
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        self.assertEqual(session.state, "quarantined")

    def test_adoption_intent_direct_reconciliation_is_exactly_bound(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "adoption_intent")
        pending = self.staging_tombstone_pending_details(
            session,
            disposition="absent",
            origin="adoption_intent",
        )
        session.append_event(
            expected_state="adoption_intent",
            next_state="staging_tombstone_ack_pending",
            details=pending,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        adoption_intent = next(
            record
            for record in session.records
            if record.state == "adoption_intent"
        )
        valid = {
            "from_state": "staging_tombstone_ack_pending",
            "adoption_intent_record_sha256": (
                adoption_intent.record_sha256
            ),
            "terminal_receipt_sha256": pending[
                "terminal_receipt_sha256"
            ],
            "tombstone_sha256": pending["tombstone_sha256"],
        }
        mutations = {
            "from_state": "operator_attention",
            "adoption_intent_record_sha256": self.digest(
                "wrong-adoption-intent"
            ),
            "terminal_receipt_sha256": self.digest(
                "wrong-terminal-receipt"
            ),
            "tombstone_sha256": self.digest("wrong-tombstone"),
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                with self.assertRaises(
                    journal.TransactionJournalError
                ):
                    session.append_event(
                        expected_state=(
                            "staging_tombstone_ack_pending"
                        ),
                        next_state="adoption_reconciliation_required",
                        details={**valid, field: replacement},
                        recorded_at_unix=(
                            session.latest_record.revision + 1
                        ),
                    )
                self.assertEqual(
                    session.state, "staging_tombstone_ack_pending"
                )
        session.append_event(
            expected_state="staging_tombstone_ack_pending",
            next_state="adoption_reconciliation_required",
            details=valid,
            recorded_at_unix=session.latest_record.revision + 1,
        )

    def test_adoption_reconciliation_receipt_binds_all_durable_history(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "adoption_intent")
        self.begin_adoption_reconciliation(
            session, disposition="absent"
        )
        valid = self.adoption_reconciled_details(
            session, result="staging_absent"
        )

        wrong_wrapper = {
            **valid,
            "adoption_reconciliation_receipt_sha256": self.digest(
                "wrong-reconciliation-wrapper"
            ),
        }
        self.assert_code(
            (
                "transaction_journal_"
                "adoption_reconciliation_receipt_digest_mismatch"
            ),
            session.append_event,
            expected_state="adoption_reconciliation_required",
            next_state="adoption_reconciled",
            details=wrong_wrapper,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        wrong_required = {
            **valid,
            "adoption_reconciliation_required_record_sha256": (
                self.digest("wrong-reconciliation-required")
            ),
        }
        self.assert_code(
            (
                "transaction_journal_"
                "adoption_reconciliation_required_record_changed"
            ),
            session.append_event,
            expected_state="adoption_reconciliation_required",
            next_state="adoption_reconciled",
            details=wrong_required,
            recorded_at_unix=session.latest_record.revision + 1,
        )

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
            "expected_object_identity_sha256",
        )
        mutations: dict[str, object] = {
            field: (
                "2" * 64
                if field == "capture_session_id"
                else self.digest(f"wrong-{field}")
            )
            for field in digest_fields
        }
        mutations.update(
            {
                "final_parent_filesystem_device": 43,
                "final_name": "opaque-capture-" + "b" * 32,
                "expected_verifier_gid": 504,
                "adoption_limits": {
                    **valid[
                        "adoption_reconciliation_receipt"
                    ]["adoption_limits"],
                    "max_files": 11,
                },
            }
        )
        for field, replacement in mutations.items():
            with self.subTest(receipt_binding=field):
                receipt = copy.deepcopy(
                    valid["adoption_reconciliation_receipt"]
                )
                receipt[field] = replacement
                receipt = (
                    adoption_reconciliation
                    .normalize_adoption_reconciliation_receipt(
                        receipt
                    )
                )
                changed = {
                    **valid,
                    "adoption_reconciliation_receipt": receipt,
                    "adoption_reconciliation_receipt_sha256": (
                        adoption_reconciliation
                        .adoption_reconciliation_receipt_sha256(
                            receipt
                        )
                    ),
                }
                self.assert_code(
                    (
                        "transaction_journal_"
                        "adoption_reconciliation_"
                        "receipt_binding_changed"
                    ),
                    session.append_event,
                    expected_state=(
                        "adoption_reconciliation_required"
                    ),
                    next_state="adoption_reconciled",
                    details=changed,
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )

        disposition_changed = copy.deepcopy(
            valid["adoption_reconciliation_receipt"]
        )
        disposition_changed.update(
            {
                "result": "staging_quarantined",
                "staging_terminal_disposition": "quarantined",
                "staging_observation": "exact_quarantine",
                "staging_observed_leaf_identity_sha256": (
                    disposition_changed[
                        "staging_leaf_identity_sha256"
                    ]
                ),
                "staging_terminal_quarantine_name": (
                    "session-" + session.session_id
                ),
                "staging_terminal_quarantine_reason_code": (
                    "coordinator_restarted"
                ),
                "staging_terminal_quarantined_stat_sha256": (
                    self.digest("fabricated-quarantined-stat")
                ),
                "staging_observed_quarantined_stat_sha256": (
                    self.digest("fabricated-quarantined-stat")
                ),
            }
        )
        disposition_changed = (
            adoption_reconciliation
            .normalize_adoption_reconciliation_receipt(
                disposition_changed
            )
        )
        self.assert_code(
            (
                "transaction_journal_"
                "adoption_reconciliation_receipt_binding_changed"
            ),
            session.append_event,
            expected_state="adoption_reconciliation_required",
            next_state="adoption_reconciled",
            details={
                **valid,
                "adoption_reconciliation_receipt": (
                    disposition_changed
                ),
                "adoption_reconciliation_receipt_sha256": (
                    adoption_reconciliation
                    .adoption_reconciliation_receipt_sha256(
                        disposition_changed
                    )
                ),
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        session.append_event(
            expected_state="adoption_reconciliation_required",
            next_state="adoption_reconciled",
            details=valid,
            recorded_at_unix=session.latest_record.revision + 1,
        )

    def test_reconciliation_cleanup_results_require_bound_ack(
        self,
    ) -> None:
        cases = (
            ("absent", "staging_absent"),
            ("quarantined", "staging_quarantined"),
        )
        for index, (disposition, result) in enumerate(
            cases, start=1
        ):
            with self.subTest(result=result):
                case_root = self.root / f"reconciled-cleanup-{index}"
                anchor, store_path = self.make_layout(case_root)
                store = self.open_store(store_path, anchor)
                session = self.reserve(
                    store, marker=str(index + 4)
                )
                self.advance_to(session, "adoption_intent")
                pending = self.begin_adoption_reconciliation(
                    session, disposition=disposition
                )
                reconciled = self.adoption_reconciled_details(
                    session, result=result
                )
                if result == "staging_quarantined":
                    quarantine_mutations = (
                        (
                            "reason",
                            {
                                (
                                    "staging_terminal_"
                                    "quarantine_reason_code"
                                ): "different_quarantine_reason",
                            },
                        ),
                        (
                            "stat",
                            {
                                (
                                    "staging_terminal_"
                                    "quarantined_stat_sha256"
                                ): self.digest(
                                    "different-quarantine-stat"
                                ),
                                (
                                    "staging_observed_"
                                    "quarantined_stat_sha256"
                                ): self.digest(
                                    "different-quarantine-stat"
                                ),
                            },
                        ),
                        (
                            "name_and_session",
                            {
                                "capture_session_id": "a" * 64,
                                (
                                    "staging_terminal_"
                                    "quarantine_name"
                                ): "session-" + "a" * 64,
                            },
                        ),
                    )
                    for label, mutation in quarantine_mutations:
                        with self.subTest(
                            result=result,
                            quarantine_binding=label,
                        ):
                            receipt = copy.deepcopy(
                                reconciled[
                                    "adoption_reconciliation_receipt"
                                ]
                            )
                            receipt.update(mutation)
                            receipt = (
                                adoption_reconciliation
                                .normalize_adoption_reconciliation_receipt(
                                    receipt
                                )
                            )
                            changed = {
                                **reconciled,
                                (
                                    "adoption_reconciliation_"
                                    "receipt"
                                ): receipt,
                                (
                                    "adoption_reconciliation_"
                                    "receipt_sha256"
                                ): (
                                    adoption_reconciliation
                                    .adoption_reconciliation_receipt_sha256(
                                        receipt
                                    )
                                ),
                            }
                            self.assert_code(
                                (
                                    "transaction_journal_"
                                    "adoption_reconciliation_"
                                    "receipt_binding_changed"
                                ),
                                session.append_event,
                                expected_state=(
                                    "adoption_reconciliation_required"
                                ),
                                next_state="adoption_reconciled",
                                details=changed,
                                recorded_at_unix=(
                                    session.latest_record.revision
                                    + 1
                                ),
                            )
                session.append_event(
                    expected_state=(
                        "adoption_reconciliation_required"
                    ),
                    next_state="adoption_reconciled",
                    details=reconciled,
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )
                self.assert_code(
                    "transaction_journal_transition_invalid",
                    session.append_event,
                    expected_state="adoption_reconciled",
                    next_state="verifier_output_bound",
                    details=self.details_for(
                        session, "verifier_output_bound"
                    ),
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )
                acked = self.staging_tombstone_acked_details(
                    session
                )
                changed_ack = {
                    **acked,
                    "adoption_reconciliation_record_sha256": (
                        self.digest("wrong-reconciled-record")
                    ),
                }
                self.assert_code(
                    (
                        "transaction_journal_"
                        "staging_tombstone_ack_binding_changed"
                    ),
                    session.append_event,
                    expected_state="adoption_reconciled",
                    next_state="staging_tombstone_acked",
                    details=changed_ack,
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )
                session.append_event(
                    expected_state="adoption_reconciled",
                    next_state="staging_tombstone_acked",
                    details=acked,
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )
                completion_state = (
                    "staging_absent_cleanup_complete"
                    if disposition == "absent"
                    else "staging_quarantined_cleanup_complete"
                )
                session.append_event(
                    expected_state="staging_tombstone_acked",
                    next_state=completion_state,
                    details={
                        "from_state": "staging_tombstone_acked",
                        "terminal_disposition": disposition,
                        "terminal_receipt_sha256": pending.details[
                            "terminal_receipt_sha256"
                        ],
                        "tombstone_ack_receipt_sha256": acked[
                            "tombstone_ack_receipt_sha256"
                        ],
                    },
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )
                self.assertEqual(session.state, completion_state)

    def test_journal_mints_recovered_adoption_evidence_from_live_head(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        reconciled = self.advance_to_adoption_reconciled(
            session, result="recovered_adoption"
        )
        expected_head_sha256 = session.latest_record.record_sha256
        store.close()

        reopened = self.open_store()
        recovered_sessions = reopened.load_incomplete_sessions()
        self.assertEqual(len(recovered_sessions), 1)
        recovered_session = recovered_sessions[0]
        self.assertEqual(
            tuple(
                inspect.signature(
                    recovered_session
                    .mint_recovered_adoption_evidence
                ).parameters
            ),
            (),
        )

        evidence = (
            recovered_session.mint_recovered_adoption_evidence()
        )
        self.assertEqual(
            recovered_adoption_evidence
            .normalize_recovered_adoption_evidence(evidence),
            evidence,
        )
        self.assertEqual(
            evidence["adoption_reconciliation_record_sha256"],
            expected_head_sha256,
        )
        self.assertEqual(
            evidence["adoption_reconciliation_receipt_sha256"],
            reconciled[
                "adoption_reconciliation_receipt_sha256"
            ],
        )
        self.assertEqual(
            evidence["reconciliation_result"],
            "recovered_adoption",
        )
        self.assertRegex(
            recovered_adoption_evidence
            .recovered_adoption_evidence_sha256(evidence),
            r"^[0-9a-f]{64}$",
        )
        self.assertFalse(journal.PRODUCTION_ACTIVATION)
        self.assertFalse(
            recovered_adoption_evidence.PRODUCTION_ACTIVATION
        )
        with self.assertRaises(TypeError):
            recovered_session.mint_recovered_adoption_evidence(
                recovered_session.records
            )

    def test_recovered_adoption_mint_rejects_wrong_head_and_result(
        self,
    ) -> None:
        store = self.open_store()
        reserved = self.reserve(store)
        self.assert_code(
            (
                "transaction_journal_"
                "recovered_adoption_evidence_head_state_invalid"
            ),
            reserved.mint_recovered_adoption_evidence,
        )

        result_root = self.root / "wrong-result"
        result_anchor, result_store_path = self.make_layout(
            result_root
        )
        result_store = self.open_store(
            result_store_path, result_anchor
        )
        wrong_result = self.reserve(result_store, marker="2")
        self.advance_to_adoption_reconciled(
            wrong_result, result="operator_attention"
        )
        self.assert_code(
            (
                "transaction_journal_"
                "recovered_adoption_evidence_result_invalid"
            ),
            wrong_result.mint_recovered_adoption_evidence,
        )

        post_head_root = self.root / "post-reconciliation-head"
        post_anchor, post_store_path = self.make_layout(
            post_head_root
        )
        post_store = self.open_store(post_store_path, post_anchor)
        post_head = self.reserve(post_store, marker="3")
        reconciled = self.advance_to_adoption_reconciled(
            post_head, result="recovered_adoption"
        )
        post_head.append_event(
            expected_state="adoption_reconciled",
            next_state="operator_attention",
            details={
                "from_state": "adoption_reconciled",
                "reason_code": (
                    "recovered_adoption_evidence_required"
                ),
                "incident_sha256": reconciled[
                    "adoption_reconciliation_receipt_sha256"
                ],
            },
            recorded_at_unix=post_head.latest_record.revision + 1,
        )
        self.assert_code(
            (
                "transaction_journal_"
                "recovered_adoption_evidence_head_state_invalid"
            ),
            post_head.mint_recovered_adoption_evidence,
        )

    def test_recovered_adoption_mint_enforces_barriers_and_rescan(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to_adoption_reconciled(
            session, result="recovered_adoption"
        )

        session._active_operation_lease = object()
        self.assert_code(
            (
                "transaction_journal_"
                "recovered_adoption_evidence_operation_reserved"
            ),
            session.mint_recovered_adoption_evidence,
        )
        session._active_operation_lease = None

        session._recovery_required = True
        self.assert_code(
            "transaction_journal_lifecycle_recovery_required",
            session.mint_recovered_adoption_evidence,
        )
        session._recovery_required = False

        live_records = session._records
        session._records = live_records[:-1]
        self.assert_code(
            "transaction_journal_live_snapshot_session_changed",
            session.mint_recovered_adoption_evidence,
        )
        session._records = live_records
        self.assertEqual(
            session.mint_recovered_adoption_evidence()[
                "reconciliation_result"
            ],
            "recovered_adoption",
        )

    def test_recovered_adoption_mint_serializes_head_change(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        reconciled = self.advance_to_adoption_reconciled(
            session, result="recovered_adoption"
        )
        binder_entered = threading.Event()
        release_binder = threading.Event()
        append_started = threading.Event()
        append_finished = threading.Event()
        results: list[dict] = []
        failures: list[BaseException] = []
        original_binder = (
            recovered_adoption_evidence
            .bind_recovered_adoption_evidence
        )

        def blocking_binder(**kwargs):
            binder_entered.set()
            if not release_binder.wait(timeout=2):
                raise AssertionError("test binder release timed out")
            return original_binder(**kwargs)

        def mint() -> None:
            try:
                results.append(
                    session.mint_recovered_adoption_evidence()
                )
            except BaseException as exc:
                failures.append(exc)

        def append_attention() -> None:
            append_started.set()
            try:
                session.append_event(
                    expected_state="adoption_reconciled",
                    next_state="operator_attention",
                    details={
                        "from_state": "adoption_reconciled",
                        "reason_code": (
                            "recovered_adoption_evidence_required"
                        ),
                        "incident_sha256": reconciled[
                            (
                                "adoption_reconciliation_"
                                "receipt_sha256"
                            )
                        ],
                    },
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )
            except BaseException as exc:
                failures.append(exc)
            finally:
                append_finished.set()

        with mock.patch.object(
            recovered_adoption_evidence,
            "bind_recovered_adoption_evidence",
            side_effect=blocking_binder,
        ):
            mint_thread = threading.Thread(target=mint)
            mint_thread.start()
            self.assertTrue(binder_entered.wait(timeout=2))
            append_thread = threading.Thread(target=append_attention)
            append_thread.start()
            self.assertTrue(append_started.wait(timeout=2))
            self.assertFalse(append_finished.wait(timeout=0.05))
            release_binder.set()
            mint_thread.join(timeout=2)
            append_thread.join(timeout=2)

        self.assertFalse(mint_thread.is_alive())
        self.assertFalse(append_thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(results), 1)
        self.assertEqual(
            results[0]["adoption_reconciliation_record_sha256"],
            session.records[-2].record_sha256,
        )
        self.assertEqual(session.state, "operator_attention")

    def test_recovered_and_attention_reconciliation_are_isolated(
        self,
    ) -> None:
        for index, result in enumerate(
            ("recovered_adoption", "operator_attention"),
            start=1,
        ):
            with self.subTest(result=result):
                case_root = self.root / f"reconciled-attention-{index}"
                anchor, store_path = self.make_layout(case_root)
                store = self.open_store(store_path, anchor)
                session = self.reserve(
                    store, marker=str(index + 6)
                )
                self.advance_to(session, "adoption_intent")
                self.begin_adoption_reconciliation(
                    session, disposition="absent"
                )
                reconciled = self.adoption_reconciled_details(
                    session, result=result
                )
                session.append_event(
                    expected_state=(
                        "adoption_reconciliation_required"
                    ),
                    next_state="adoption_reconciled",
                    details=reconciled,
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )
                self.assertNotIn(
                    "adopted",
                    {record.state for record in session.records},
                )
                acked = self.staging_tombstone_acked_details(
                    session
                )
                self.assert_code(
                    (
                        "transaction_journal_"
                        "adoption_reconciliation_cleanup_unsafe"
                    ),
                    session.append_event,
                    expected_state="adoption_reconciled",
                    next_state="staging_tombstone_acked",
                    details=acked,
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )
                for forbidden_state in (
                    "adopted",
                    "verifier_output_bound",
                ):
                    self.assert_code(
                        "transaction_journal_transition_invalid",
                        session.append_event,
                        expected_state="adoption_reconciled",
                        next_state=forbidden_state,
                        details=self.details_for(
                            session, forbidden_state
                        ),
                        recorded_at_unix=(
                            session.latest_record.revision + 1
                        ),
                    )
                wrong_attention = {
                    "from_state": "adoption_reconciled",
                    "reason_code": (
                        "recovered_adoption_evidence_required"
                    ),
                    "incident_sha256": self.digest(
                        "wrong-reconciliation-incident"
                    ),
                }
                self.assert_code(
                    (
                        "transaction_journal_"
                        "adoption_reconciliation_"
                        "attention_binding_changed"
                    ),
                    session.append_event,
                    expected_state="adoption_reconciled",
                    next_state="operator_attention",
                    details=wrong_attention,
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )
                session.append_event(
                    expected_state="adoption_reconciled",
                    next_state="operator_attention",
                    details={
                        **wrong_attention,
                        "incident_sha256": reconciled[
                            "adoption_reconciliation_receipt_sha256"
                        ],
                    },
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )
                self.assertEqual(
                    session.state, "operator_attention"
                )

    def test_reconciliation_retry_and_restart_preserve_exact_chain(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "adoption_intent")
        pending = self.begin_adoption_reconciliation(
            session, disposition="absent"
        )
        session.append_event(
            expected_state="adoption_reconciliation_required",
            next_state="operator_attention",
            details={
                "from_state": "adoption_reconciliation_required",
                "reason_code": "reconciliation_retry_required",
                "incident_sha256": self.digest(
                    "reconciliation-retry"
                ),
            },
            recorded_at_unix=session.latest_record.revision + 1,
        )
        reconciled = self.adoption_reconciled_details(
            session, result="staging_absent"
        )
        session.append_event(
            expected_state="operator_attention",
            next_state="adoption_reconciled",
            details=reconciled,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        store.close()

        reopened = self.open_store()
        loaded = reopened.load_incomplete_sessions()
        self.assertEqual(len(loaded), 1)
        recovered = loaded[0]
        self.assertEqual(recovered.state, "adoption_reconciled")
        self.assertEqual(
            recovered.latest_record.details[
                "adoption_reconciliation_receipt_sha256"
            ],
            reconciled[
                "adoption_reconciliation_receipt_sha256"
            ],
        )
        acked = self.staging_tombstone_acked_details(recovered)
        recovered.append_event(
            expected_state="adoption_reconciled",
            next_state="staging_tombstone_acked",
            details=acked,
            recorded_at_unix=recovered.latest_record.revision + 1,
        )
        recovered.append_event(
            expected_state="staging_tombstone_acked",
            next_state="staging_absent_cleanup_complete",
            details={
                "from_state": "staging_tombstone_acked",
                "terminal_disposition": "absent",
                "terminal_receipt_sha256": pending.details[
                    "terminal_receipt_sha256"
                ],
                "tombstone_ack_receipt_sha256": acked[
                    "tombstone_ack_receipt_sha256"
                ],
            },
            recorded_at_unix=recovered.latest_record.revision + 1,
        )

    def test_tombstone_ack_rejects_every_cross_ledger_drift(self) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "staging_create_intent")
        pending = self.staging_tombstone_pending_details(
            session,
            disposition="absent",
            origin="staging_create_intent",
        )
        session.append_event(
            expected_state="staging_create_intent",
            next_state="staging_tombstone_ack_pending",
            details=pending,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        valid = self.staging_tombstone_acked_details(session)
        mutations = {
            "outer_terminal_receipt": lambda value: value.__setitem__(
                "terminal_receipt_sha256", self.digest("wrong-terminal")
            ),
            "outer_tombstone": lambda value: value.__setitem__(
                "tombstone_sha256", self.digest("wrong-tombstone")
            ),
            "outer_pending": lambda value: value.__setitem__(
                "outer_ack_pending_record_sha256",
                self.digest("wrong-pending"),
            ),
            "outer_reconciliation_record": lambda value: (
                value.__setitem__(
                    "adoption_reconciliation_record_sha256",
                    self.digest("unexpected-reconciliation-record"),
                )
            ),
            "outer_reconciliation_receipt": lambda value: (
                value.__setitem__(
                    "adoption_reconciliation_receipt_sha256",
                    self.digest("unexpected-reconciliation-receipt"),
                )
            ),
            "ack_session": lambda value: value[
                "tombstone_ack_receipt"
            ].__setitem__("capture_session_id", "2" * 64),
            "ack_intent": lambda value: value[
                "tombstone_ack_receipt"
            ].__setitem__(
                "staging_transaction_intent_sha256",
                self.digest("wrong-intent"),
            ),
            "ack_terminal": lambda value: value[
                "tombstone_ack_receipt"
            ].__setitem__(
                "terminal_receipt_sha256",
                self.digest("wrong-terminal"),
            ),
            "ack_tombstone": lambda value: value[
                "tombstone_ack_receipt"
            ].__setitem__(
                "tombstone_sha256", self.digest("wrong-tombstone")
            ),
            "ack_pending": lambda value: value[
                "tombstone_ack_receipt"
            ].__setitem__(
                "outer_ack_pending_record_sha256",
                self.digest("wrong-pending"),
            ),
            "ack_sequence": lambda value: value[
                "tombstone_ack_receipt"
            ].__setitem__(
                "ack_sequence",
                value["tombstone_ack_receipt"]["ack_sequence"] + 1,
            ),
            "ack_previous": lambda value: value[
                "tombstone_ack_receipt"
            ].__setitem__(
                "ack_previous_record_sha256",
                self.digest("wrong-ack-previous"),
            ),
            "ack_lock_epoch": lambda value: value[
                "tombstone_ack_receipt"
            ].__setitem__(
                "inspection_lock_epoch_sha256",
                self.digest("wrong-lock-epoch"),
            ),
            "ack_lifecycle_clearance": lambda value: value[
                "tombstone_ack_receipt"
            ].__setitem__(
                "outer_lifecycle_clearance_record_sha256",
                self.digest("unexpected-lifecycle-clearance"),
            ),
            "ack_disposition": lambda value: value[
                "tombstone_ack_receipt"
            ].update(
                {
                    "terminal_disposition": "quarantined",
                    "journal_storage_disposition": (
                        "retained_quarantine_journal"
                    ),
                    "outer_quarantine_intent_record_sha256": (
                        self.digest("unexpected-quarantine-intent")
                    ),
                    "completed_parent_fsynced": False,
                }
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(field=label):
                changed = copy.deepcopy(valid)
                mutate(changed)
                if label.startswith("ack_"):
                    changed["tombstone_ack_receipt_sha256"] = (
                        journal.staging_tombstone_ack_receipt_sha256(
                            changed["tombstone_ack_receipt"]
                        )
                    )
                with self.assertRaises(
                    journal.TransactionJournalError
                ):
                    session.append_event(
                        expected_state=(
                            "staging_tombstone_ack_pending"
                        ),
                        next_state="staging_tombstone_acked",
                        details=changed,
                        recorded_at_unix=(
                            session.latest_record.revision + 1
                        ),
                    )
                self.assertEqual(
                    session.state, "staging_tombstone_ack_pending"
                )

    def test_scope_empty_ack_binds_exact_clearance_record(self) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(session, "adopted")
        pending = self.staging_tombstone_pending_details(
            session,
            disposition="absent",
            origin="adopted",
        )
        session.append_event(
            expected_state="adopted",
            next_state="staging_tombstone_ack_pending",
            details=pending,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        valid = self.staging_tombstone_acked_details(session)
        for label, replacement in (
            ("missing", None),
            ("wrong", self.digest("wrong-clearance-record")),
        ):
            with self.subTest(clearance=label):
                changed = copy.deepcopy(valid)
                changed["tombstone_ack_receipt"][
                    "outer_lifecycle_clearance_record_sha256"
                ] = replacement
                changed["tombstone_ack_receipt_sha256"] = (
                    journal.staging_tombstone_ack_receipt_sha256(
                        changed["tombstone_ack_receipt"]
                    )
                )
                self.assert_code(
                    (
                        "transaction_journal_"
                        "staging_tombstone_ack_receipt_binding_changed"
                    ),
                    session.append_event,
                    expected_state=(
                        "staging_tombstone_ack_pending"
                    ),
                    next_state="staging_tombstone_acked",
                    details=changed,
                    recorded_at_unix=(
                        session.latest_record.revision + 1
                    ),
                )

    def test_capacity_rejects_before_creating_a_session(self) -> None:
        store = self.open_store()
        with mock.patch.object(
            journal,
            "MAX_SESSION_DIRECTORIES",
            0,
        ):
            self.assert_code(
                "transaction_journal_session_capacity_exceeded",
                self.reserve,
                store,
                marker="1",
            )
        self.assertEqual(
            [
                path.name
                for path in self.store_path.iterdir()
                if path.name.startswith("session-")
            ],
            [],
        )

    def test_invalid_transition_clock_and_pid_fields_fail_before_write(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.assert_code(
            "transaction_journal_transition_invalid",
            session.append_event,
            expected_state="reserved",
            next_state="child_launch_intent",
            details={
                "lifecycle_activation_receipt": (
                    self.lifecycle_activation_receipt()
                ),
                "lifecycle_activation_receipt_sha256": (
                    lifecycle.activation_receipt_sha256(
                        self.lifecycle_activation_receipt()
                    )
                ),
            },
            recorded_at_unix=2,
        )
        self.advance_to(session, "staging_exposed")
        details = self.details_for(session, "child_launch_intent")
        details["pid"] = 123
        self.assert_code(
            "transaction_journal_child_launch_intent_details_invalid",
            session.append_event,
            expected_state="staging_exposed",
            next_state="child_launch_intent",
            details=details,
            recorded_at_unix=6,
        )
        details.pop("pid")
        details = {
            "lifecycle_backend": "launchd",
            "lifecycle_scope_id": (
                f"jlq-launchd-{session.session_id}"
            ),
            "lifecycle_scope_receipt_sha256": self.digest("bare"),
        }
        self.assert_code(
            "transaction_journal_child_launch_intent_details_invalid",
            session.append_event,
            expected_state="staging_exposed",
            next_state="child_launch_intent",
            details=details,
            recorded_at_unix=6,
        )
        details = self.details_for(session, "child_launch_intent")
        self.assert_code(
            "transaction_journal_clock_rollback",
            session.append_event,
            expected_state="staging_exposed",
            next_state="child_launch_intent",
            details=details,
            recorded_at_unix=1,
        )
        self.assertEqual(session.state, "staging_exposed")

    def test_append_faults_recover_to_old_or_complete_new_record(
        self,
    ) -> None:
        phases = [
            "after_temp_open",
            "after_temp_write",
            "after_temp_file_fsync",
            "after_temp_chmod",
            "after_temp_metadata_fsync",
            "after_noreplace_commit",
            "after_session_directory_fsync",
        ]
        committed_phases = {
            "after_noreplace_commit",
            "after_session_directory_fsync",
        }
        for index, phase in enumerate(phases, start=1):
            with self.subTest(phase=phase):
                case_root = self.root / f"append-{index}"
                anchor, store_path = self.make_layout(case_root)
                store = journal._open_transaction_store_for_test(
                    store_path, anchor
                )
                session = self.reserve(store, marker="a")

                def fault(observed: str) -> None:
                    if observed == phase:
                        raise SimulatedCrash(phase)

                with self.assertRaises(SimulatedCrash):
                    session._append_event_for_test(
                        expected_state="reserved",
                        next_state="staging_create_intent",
                        details=self.details_for(
                            session, "staging_create_intent"
                        ),
                        recorded_at_unix=2,
                        fault_hook=fault,
                    )
                store.close()
                reopened = journal._open_transaction_store_for_test(
                    store_path, anchor
                )
                loaded = reopened.load_incomplete_sessions()
                self.assertEqual(len(loaded), 1)
                self.assertEqual(
                    loaded[0].state,
                    (
                        "staging_create_intent"
                        if phase in committed_phases
                        else "reserved"
                    ),
                )
                session_path = store_path / ("session-" + "a" * 64)
                self.assertEqual(
                    list(session_path.glob(".tmp-*")),
                    [],
                )
                reopened.close()

    def test_reservation_faults_remove_empty_or_load_committed_session(
        self,
    ) -> None:
        phases = [
            "after_session_mkdir",
            "after_new_session_directory_fsync",
            "after_store_directory_fsync",
            "after_temp_open",
            "after_temp_write",
            "after_temp_file_fsync",
            "after_temp_chmod",
            "after_temp_metadata_fsync",
            "after_noreplace_commit",
            "after_session_directory_fsync",
        ]
        committed_phases = {
            "after_noreplace_commit",
            "after_session_directory_fsync",
        }
        for index, phase in enumerate(phases, start=1):
            with self.subTest(phase=phase):
                case_root = self.root / f"reserve-{index}"
                anchor, store_path = self.make_layout(case_root)
                store = journal._open_transaction_store_for_test(
                    store_path, anchor
                )

                def fault(observed: str) -> None:
                    if observed == phase:
                        raise SimulatedCrash(phase)

                with self.assertRaises(SimulatedCrash):
                    self.reserve(
                        store,
                        marker="b",
                        fault_hook=fault,
                    )
                store.close()
                reopened = journal._open_transaction_store_for_test(
                    store_path, anchor
                )
                loaded = reopened.load_incomplete_sessions()
                if phase in committed_phases:
                    self.assertEqual(len(loaded), 1)
                    self.assertEqual(loaded[0].state, "reserved")
                else:
                    self.assertEqual(loaded, ())
                    self.assertFalse(
                        (
                            store_path / ("session-" + "b" * 64)
                        ).exists()
                    )
                reopened.close()

    def test_valid_stale_temp_is_removed_and_fsynced(self) -> None:
        store = self.open_store()
        session = self.reserve(store)
        session_path = self.store_path / ("session-" + "1" * 64)
        stale = session_path / (".tmp-" + "c" * 32)
        stale.write_bytes(b"partial")
        stale.chmod(journal.TEMP_FILE_MODE)
        store.close()

        reopened = self.open_store()
        loaded = reopened.load_incomplete_sessions()
        self.assertEqual(len(loaded), 1)
        self.assertFalse(stale.exists())

    def test_unsafe_stale_temp_fails_closed(self) -> None:
        store = self.open_store()
        self.reserve(store)
        session_path = self.store_path / ("session-" + "1" * 64)
        target = self.root / "target"
        target.write_bytes(b"do-not-touch")
        stale = session_path / (".tmp-" + "c" * 32)
        stale.symlink_to(target)
        store.close()

        self.assert_code(
            "transaction_journal_stale_temp_unsafe",
            journal._open_transaction_store_for_test,
            self.store_path,
            self.anchor,
        )
        self.assertEqual(target.read_bytes(), b"do-not-touch")

    def test_record_mode_content_name_and_hardlink_tampering_fail_closed(
        self,
    ) -> None:
        tamper_kinds = ["mode", "content", "name", "hardlink"]
        for index, kind in enumerate(tamper_kinds, start=1):
            with self.subTest(kind=kind):
                case_root = self.root / f"tamper-{index}"
                anchor, store_path = self.make_layout(case_root)
                store = journal._open_transaction_store_for_test(
                    store_path, anchor
                )
                session = self.reserve(store, marker="d")
                session_path = store_path / ("session-" + "d" * 64)
                event = next(session_path.glob("*.json"))
                store.close()
                if kind == "mode":
                    event.chmod(0o600)
                    expected = "transaction_journal_record_unsafe"
                elif kind == "content":
                    event.chmod(0o600)
                    raw = event.read_bytes()
                    event.write_bytes(raw.replace(b"john-test", b"john-tost"))
                    event.chmod(0o400)
                    expected = (
                        "transaction_journal_record_digest_mismatch"
                    )
                elif kind == "name":
                    pieces = event.name.split("-")
                    pieces[-1] = self.digest("wrong-name") + ".json"
                    event.rename(event.with_name("-".join(pieces)))
                    expected = (
                        "transaction_journal_record_filename_mismatch"
                    )
                else:
                    os.link(
                        event,
                        session_path / (".tmp-" + "e" * 32),
                    )
                    expected = "transaction_journal_record_unsafe"
                self.assert_code(
                    expected,
                    journal._open_transaction_store_for_test,
                    store_path,
                    anchor,
                )

    def test_store_and_session_namespace_tampering_fail_closed(self) -> None:
        store = self.open_store()
        self.reserve(store)
        session_path = self.store_path / ("session-" + "1" * 64)
        store.close()
        (session_path / "surprise").write_bytes(b"x")
        self.assert_code(
            "transaction_journal_session_entry_invalid",
            journal._open_transaction_store_for_test,
            self.store_path,
            self.anchor,
        )

    def test_completed_archive_is_bounded_and_fully_revalidated(self) -> None:
        store = self.open_store()
        completed = self.reserve(store, marker="1")
        self.advance_to(completed, "cleanup_complete")
        self.reserve(store, marker="2")
        archived = (
            self.store_path
            / ".completed"
            / ("session-" + "1" * 64)
        )
        event = next(archived.glob("*.json"))
        store.close()
        event.chmod(0o600)
        self.assert_code(
            "transaction_journal_record_unsafe",
            journal._open_transaction_store_for_test,
            self.store_path,
            self.anchor,
        )

        case_root = self.root / "archive-capacity"
        anchor, store_path = self.make_layout(case_root)
        capacity_store = journal._open_transaction_store_for_test(
            store_path, anchor
        )
        terminal = self.reserve(capacity_store, marker="3")
        self.advance_to(terminal, "cleanup_complete")
        with mock.patch.object(
            journal,
            "MAX_COMPLETED_SESSION_DIRECTORIES",
            0,
        ):
            self.assert_code(
                "transaction_journal_completed_archive_capacity_exceeded",
                self.reserve,
                capacity_store,
                marker="4",
            )
        self.assertTrue(
            (store_path / ("session-" + "3" * 64)).is_dir()
        )
        self.assertFalse(
            (store_path / ("session-" + "4" * 64)).exists()
        )
        capacity_store.close()

        admission_root = self.root / "archive-admission"
        admission_anchor, admission_store_path = self.make_layout(
            admission_root
        )
        admission_store = journal._open_transaction_store_for_test(
            admission_store_path,
            admission_anchor,
        )
        historical = self.reserve(admission_store, marker="5")
        self.advance_to(historical, "cleanup_complete")
        admission_store.close()
        historical_path = (
            admission_store_path / ("session-" + "5" * 64)
        )
        historical_path.rename(
            admission_store_path / ".completed" / historical_path.name
        )
        with mock.patch.object(
            journal,
            "MAX_COMPLETED_SESSION_DIRECTORIES",
            1,
        ):
            reopened = journal._open_transaction_store_for_test(
                admission_store_path,
                admission_anchor,
            )
            self.assert_code(
                "transaction_journal_completed_archive_admission_closed",
                self.reserve,
                reopened,
                marker="6",
            )
            reopened.close()
        self.assertFalse(
            (
                admission_store_path / ("session-" + "6" * 64)
            ).exists()
        )

    def test_completed_archive_destination_collision_fails_closed(
        self,
    ) -> None:
        store = self.open_store()
        completed = self.reserve(store, marker="1")
        self.advance_to(completed, "cleanup_complete")
        source = self.store_path / ("session-" + "1" * 64)
        destination = self.store_path / ".completed" / source.name
        shutil.copytree(source, destination)
        self.assert_code(
            "transaction_journal_archive_destination_exists",
            self.reserve,
            store,
            marker="2",
        )
        self.assertTrue(source.is_dir())
        self.assertFalse(
            (self.store_path / ("session-" + "2" * 64)).exists()
        )

    def test_extended_attribute_is_rejected_when_supported(self) -> None:
        libc, name = self.set_test_xattr(self.store_path)
        self.addCleanup(
            self.remove_test_xattr,
            libc,
            self.store_path,
            name,
        )
        self.assert_code(
            "transaction_journal_store_extended_metadata_unsupported",
            journal._open_transaction_store_for_test,
            self.store_path,
            self.anchor,
        )

    def test_same_filesystem_check_is_fail_closed(self) -> None:
        original = journal._validate_directory
        calls = 0

        def different_devices(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                return SimpleNamespace(st_dev=1)
            if calls == 2:
                return SimpleNamespace(st_dev=2)
            return original(*args, **kwargs)

        with mock.patch.object(
            journal,
            "_validate_directory",
            side_effect=different_devices,
        ):
            self.assert_code(
                "transaction_journal_cross_device_forbidden",
                journal._open_transaction_store_for_test,
                self.store_path,
                self.anchor,
            )

    def test_event_and_record_byte_limits_fail_before_commit(self) -> None:
        store = self.open_store()
        session = self.reserve(store)
        with mock.patch.object(
            journal, "MAX_EVENTS_PER_SESSION", 1
        ):
            self.assert_code(
                "transaction_journal_event_limit_exceeded",
                session.append_event,
                expected_state="reserved",
                next_state="staging_create_intent",
                details=self.details_for(
                    session, "staging_create_intent"
                ),
                recorded_at_unix=2,
            )
        self.advance_to(session, "staging_create_intent")
        with mock.patch.object(journal, "MAX_RECORD_BYTES", 1_200):
            self.assert_code(
                "transaction_journal_record_too_large",
                session.append_event,
                expected_state="staging_create_intent",
                next_state="staging_exposed",
                details=self.details_for(session, "staging_exposed"),
                recorded_at_unix=session.latest_record.revision + 1,
            )
        self.assertEqual(session.state, "staging_create_intent")

    def test_cleanup_pending_is_bounded_and_phase_monotonic(self) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(
            session,
            "full_publication_committed_cleanup_required",
        )
        pending = self.details_for(
            session, "committed_cleanup_pending"
        )
        session.append_event(
            expected_state="full_publication_committed_cleanup_required",
            next_state="committed_cleanup_pending",
            details=pending,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        duplicate = self.details_for(
            session, "committed_cleanup_pending"
        )
        self.assert_code(
            "transaction_journal_cleanup_phase_not_advanced",
            session.append_event,
            expected_state="committed_cleanup_pending",
            next_state="committed_cleanup_pending",
            details=duplicate,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        advanced = self.details_for(
            session, "committed_cleanup_pending"
        )
        advanced["cleanup_phase"] = "parent_fsync_only"
        session.append_event(
            expected_state="committed_cleanup_pending",
            next_state="committed_cleanup_pending",
            details=advanced,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        self.assert_code(
            "transaction_journal_cleanup_pending_exhausted",
            session.append_event,
            expected_state="committed_cleanup_pending",
            next_state="committed_cleanup_pending",
            details=advanced,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        complete = self.details_for(session, "cleanup_complete")
        complete["cleanup_result"] = "parent_fsynced"
        session.append_event(
            expected_state="committed_cleanup_pending",
            next_state="cleanup_complete",
            details=complete,
            recorded_at_unix=session.latest_record.revision + 1,
        )

    def test_cleanup_result_must_prove_the_recorded_phase(self) -> None:
        store = self.open_store()
        session = self.reserve(store)
        self.advance_to(
            session,
            "full_publication_committed_cleanup_required",
        )
        invalid = self.details_for(session, "cleanup_complete")
        invalid["cleanup_result"] = "parent_fsynced"
        self.assert_code(
            "transaction_journal_cleanup_result_phase_mismatch",
            session.append_event,
            expected_state=(
                "full_publication_committed_cleanup_required"
            ),
            next_state="cleanup_complete",
            details=invalid,
            recorded_at_unix=session.latest_record.revision + 1,
        )
        valid = self.details_for(session, "cleanup_complete")
        session.append_event(
            expected_state=(
                "full_publication_committed_cleanup_required"
            ),
            next_state="cleanup_complete",
            details=valid,
            recorded_at_unix=session.latest_record.revision + 1,
        )

    def test_live_snapshot_is_exact_immutable_and_path_free(self) -> None:
        store = self.open_store()
        session = self.reserve(store)
        snapshot = session.live_snapshot()
        session_path = self.store_path / (
            "session-" + session.session_id
        )
        session_info = session_path.stat()

        self.assertIs(
            type(snapshot),
            journal.TransactionJournalLiveSnapshot,
        )
        self.assertEqual(snapshot.instance_slug, "john-test")
        self.assertEqual(snapshot.session_id, session.session_id)
        self.assertEqual(snapshot.state, "reserved")
        self.assertEqual(snapshot.revision, 1)
        self.assertEqual(
            snapshot.head_record_sha256,
            session.latest_record.record_sha256,
        )
        self.assertEqual(
            snapshot.record_sha256s,
            tuple(
                record.record_sha256 for record in session.records
            ),
        )
        self.assertEqual(
            tuple(
                record.to_dict() for record in snapshot.records
            ),
            tuple(
                record.to_dict() for record in session.records
            ),
        )
        self.assertEqual(
            snapshot.descriptor_device,
            int(session_info.st_dev),
        )
        self.assertEqual(
            snapshot.descriptor_inode,
            int(session_info.st_ino),
        )
        self.assertIsNone(
            session.assert_live_snapshot_current(snapshot)
        )
        for forbidden in (
            "append_event",
            "begin_capture_recording",
            "close",
            "directory_name",
            "path",
            "pid",
            "command",
            "session",
            "store",
        ):
            self.assertFalse(hasattr(snapshot, forbidden))
        with self.assertRaises(TypeError):
            snapshot.state = "operator_attention"
        with self.assertRaises(TypeError):
            del snapshot.state
        with self.assertRaises(TypeError):
            pickle.dumps(snapshot)
        with self.assertRaises(TypeError):
            journal.TransactionJournalLiveSnapshot(
                _token=object(),
                session_binding=object(),
                records=session.records,
                descriptor_device=int(session_info.st_dev),
                descriptor_inode=int(session_info.st_ino),
            )

    def test_live_snapshot_rejects_stale_and_internally_tampered_values(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        stale = session.live_snapshot()
        details = self.details_for(
            session, "staging_create_intent"
        )
        session.append_event(
            expected_state="reserved",
            next_state="staging_create_intent",
            details=details,
            recorded_at_unix=2,
        )
        self.assert_code(
            "transaction_journal_live_snapshot_stale",
            session.assert_live_snapshot_current,
            stale,
        )

        tampered = session.live_snapshot()
        object.__setattr__(
            tampered,
            (
                "_TransactionJournalLiveSnapshot"
                "__canonical"
            ),
            b"{}",
        )
        self.assert_code(
            "transaction_journal_live_snapshot_stale",
            session.assert_live_snapshot_current,
            tampered,
        )
        self.assert_code(
            "transaction_journal_live_snapshot_fields_invalid",
            lambda: tampered.state,
        )

    def test_live_snapshot_rejects_closed_duck_and_swapped_sessions(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        snapshot = session.live_snapshot()

        class DuckSession:
            active = True

        self.assert_code(
            "transaction_journal_live_snapshot_session_required",
            journal.TransactionJournalSession.live_snapshot,
            DuckSession(),
        )
        self.assert_code(
            "transaction_journal_live_snapshot_required",
            session.assert_live_snapshot_current,
            SimpleNamespace(
                instance_slug=snapshot.instance_slug,
                session_id=snapshot.session_id,
                state=snapshot.state,
                revision=snapshot.revision,
                head_record_sha256=(
                    snapshot.head_record_sha256
                ),
                record_sha256s=snapshot.record_sha256s,
                records=snapshot.records,
                descriptor_device=snapshot.descriptor_device,
                descriptor_inode=snapshot.descriptor_inode,
            ),
        )

        other_root = self.root / "other-store"
        other_anchor, other_store_path = self.make_layout(other_root)
        other_store = self.open_store(
            store_path=other_store_path,
            anchor=other_anchor,
        )
        other_session = self.reserve(other_store, marker="2")
        self.assert_code(
            "transaction_journal_live_snapshot_session_mismatch",
            other_session.assert_live_snapshot_current,
            snapshot,
        )

        session.close()
        self.assert_code(
            "transaction_journal_session_closed",
            session.live_snapshot,
        )
        self.assert_code(
            "transaction_journal_session_closed",
            session.assert_live_snapshot_current,
            snapshot,
        )

    def test_live_snapshot_rescan_detects_disk_and_namespace_tampering(
        self,
    ) -> None:
        store = self.open_store()
        session = self.reserve(store)
        session_path = self.store_path / (
            "session-" + session.session_id
        )
        event = next(session_path.glob("*.json"))
        event.chmod(0o600)
        self.assert_code(
            "transaction_journal_record_unsafe",
            session.live_snapshot,
        )
        event.chmod(0o400)
        snapshot = session.live_snapshot()

        displaced = self.store_path / (
            "displaced-" + session.session_id
        )
        session_path.rename(displaced)
        session_path.mkdir(mode=0o700)
        session_path.chmod(0o700)
        self.assert_code(
            (
                "transaction_journal_live_snapshot_"
                "directory_inode_mismatch"
            ),
            session.live_snapshot,
        )
        self.assert_code(
            (
                "transaction_journal_live_snapshot_"
                "directory_inode_mismatch"
            ),
            session.assert_live_snapshot_current,
            snapshot,
        )


if __name__ == "__main__":
    unittest.main()
