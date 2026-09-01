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
    john_lomein_persona_qualification_adoption_reconciliation
    as reconciliation,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_recovered_adoption_evidence
    as recovered,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_lifecycle_supervisor_protocol
    as lifecycle_protocol,
)


class NormalizedRecord:
    """Test stand-in for the future journal v5 immutable record wrapper."""

    def __init__(self, value: dict) -> None:
        self._value = copy.deepcopy(value)

    def to_dict(self) -> dict:
        return copy.deepcopy(self._value)


class PersonaQualificationRecoveredAdoptionEvidenceTests(
    unittest.TestCase
):
    def digest(self, label: str) -> str:
        return hashlib.sha256(label.encode("ascii")).hexdigest()

    def canonical(self, value: object) -> bytes:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")

    def lifecycle_operation_binding(
        self,
        *,
        base: NormalizedRecord,
        operation: str,
        capture_ready_details: dict | None = None,
    ) -> dict:
        base_value = base.to_dict()
        capture_event = capture_ready_details is not None
        return {
            "schema_version": (
                recovered.LIFECYCLE_OPERATION_BINDING_SCHEMA
            ),
            "operation": operation,
            "base_record_revision": base_value["revision"],
            "base_record_sha256": base_value["record_sha256"],
            "request_sha256": self.digest(
                f"{operation}-request-{base_value['revision']}"
            ),
            "response_sha256": self.digest(
                f"{operation}-response-{base_value['revision']}"
            ),
            "outcome": "success",
            "error_code": None,
            "result_sha256": self.digest(
                f"{operation}-result-{base_value['revision']}"
            ),
            "supervisor_ledger_head_sha256": self.digest(
                f"{operation}-ledger-head-{base_value['revision']}"
            ),
            "supervisor_event_sequence": (
                base_value["revision"] if capture_event else None
            ),
            "supervisor_event": (
                "capture_ready" if capture_event else None
            ),
            "supervisor_event_record_sha256": (
                self.digest(
                    f"{operation}-event-{base_value['revision']}"
                )
                if capture_event
                else None
            ),
            "supervisor_event_evidence_sha256": (
                lifecycle_protocol.capture_event_evidence_sha256(
                    capture_ready_details
                )
                if capture_event
                else None
            ),
        }

    def append_record(
        self,
        records: list[NormalizedRecord],
        *,
        state: str,
        details: dict,
        schema: str = recovered.TRANSACTION_JOURNAL_SCHEMA,
    ) -> NormalizedRecord:
        revision = len(records) + 1
        previous = (
            recovered.ZERO_SHA256
            if not records
            else records[-1].to_dict()["record_sha256"]
        )
        payload = {
            "schema_version": schema,
            "instance_slug": "john-test",
            "session_id": "1" * 64,
            "revision": revision,
            "previous_record_sha256": previous,
            "state": state,
            "recorded_at_unix": revision,
            "control_sha256": self.digest("control"),
            "handoff_policy_sha256": self.digest("handoff"),
            "details": copy.deepcopy(details),
        }
        record = NormalizedRecord(
            {
                **payload,
                "record_sha256": hashlib.sha256(
                    self.canonical(payload)
                ).hexdigest(),
            }
        )
        records.append(record)
        return record

    def rechain(self, values: list[dict]) -> list[NormalizedRecord]:
        records: list[NormalizedRecord] = []
        previous = recovered.ZERO_SHA256
        for revision, source in enumerate(values, start=1):
            payload = {
                key: copy.deepcopy(value)
                for key, value in source.items()
                if key != "record_sha256"
            }
            payload["revision"] = revision
            payload["previous_record_sha256"] = previous
            record = {
                **payload,
                "record_sha256": hashlib.sha256(
                    self.canonical(payload)
                ).hexdigest(),
            }
            records.append(NormalizedRecord(record))
            previous = record["record_sha256"]
        return records

    def repair_record_hash_references(
        self,
        records: list[NormalizedRecord],
        *,
        repair_lifecycle_bindings: bool = True,
    ) -> tuple[list[NormalizedRecord], dict]:
        values = [record.to_dict() for record in records]
        records = self.rechain(values)
        if repair_lifecycle_bindings:
            for _ in range(2):
                values = [record.to_dict() for record in records]
                for index, value in enumerate(values):
                    if value["state"] not in {
                        "capture_ready",
                        "lifecycle_scope_empty",
                    }:
                        continue
                    binding = value["details"].get(
                        "lifecycle_operation_binding"
                    )
                    if not isinstance(binding, dict):
                        continue
                    binding["base_record_revision"] = values[
                        index - 1
                    ]["revision"]
                    binding["base_record_sha256"] = values[
                        index - 1
                    ]["record_sha256"]
                    if value["state"] == "capture_ready":
                        capture_evidence = {
                            field: value["details"][field]
                            for field in (
                                "provisional_name",
                                "capture_object_identity_sha256",
                                "capture_selection_sha256",
                                "capture_plan_sha256",
                                "capture_manifest_sha256",
                                "capture_boundary_policy_sha256",
                                "helper_activation_policy_sha256",
                                "request_sha256",
                            )
                        }
                        binding[
                            "supervisor_event_evidence_sha256"
                        ] = (
                            lifecycle_protocol
                            .capture_event_evidence_sha256(
                                capture_evidence
                            )
                        )
                records = self.rechain(values)
        values = [record.to_dict() for record in records]

        by_state = {value["state"]: value for value in values}
        receipt = copy.deepcopy(
            by_state["adoption_reconciled"]["details"][
                "adoption_reconciliation_receipt"
            ]
        )
        receipt["staging_transaction_intent_sha256"] = by_state[
            "staging_create_intent"
        ]["record_sha256"]
        receipt["adoption_intent_record_sha256"] = by_state[
            "adoption_intent"
        ]["record_sha256"]
        receipt = (
            reconciliation.normalize_adoption_reconciliation_receipt(
                receipt
            )
        )
        by_state["adoption_reconciliation_required"]["details"][
            "adoption_intent_record_sha256"
        ] = by_state["adoption_intent"]["record_sha256"]
        by_state["adoption_reconciled"]["details"][
            "adoption_reconciliation_receipt"
        ] = receipt
        by_state["adoption_reconciled"]["details"][
            "adoption_reconciliation_receipt_sha256"
        ] = reconciliation.adoption_reconciliation_receipt_sha256(
            receipt
        )

        records = self.rechain(values)
        values = [record.to_dict() for record in records]
        by_state = {value["state"]: value for value in values}
        by_state["adoption_reconciled"]["details"][
            "adoption_reconciliation_required_record_sha256"
        ] = by_state["adoption_reconciliation_required"][
            "record_sha256"
        ]
        records = self.rechain(values)
        return records, receipt

    def reconciliation_receipt(
        self,
        *,
        staging_intent_sha256: str,
        adoption_intent_sha256: str,
        scope_empty_receipt_sha256: str,
        adoption_policy_sha256: str,
        final_parent_identity_sha256: str,
        final_parent_filesystem_device: int,
        final_name: str,
        object_identity_sha256: str,
        verifier_gid: int,
        limits: dict,
        terminal_receipt_sha256: str,
        tombstone_sha256: str,
    ) -> dict:
        value = {
            "schema_version": (
                reconciliation.ADOPTION_RECONCILIATION_RECEIPT_SCHEMA
            ),
            "status": reconciliation.ADOPTION_RECONCILIATION_STATUS,
            "result": "recovered_adoption",
            "capture_session_id": "1" * 64,
            "adoption_intent_record_sha256": adoption_intent_sha256,
            "adoption_policy_sha256": adoption_policy_sha256,
            "lifecycle_scope_empty_receipt_sha256": (
                scope_empty_receipt_sha256
            ),
            "staging_transaction_intent_sha256": (
                staging_intent_sha256
            ),
            "staging_terminal_receipt_sha256": (
                terminal_receipt_sha256
            ),
            "staging_tombstone_sha256": tombstone_sha256,
            "staging_terminal_disposition": "absent",
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
            "final_parent_identity_sha256": (
                final_parent_identity_sha256
            ),
            "final_parent_filesystem_device": (
                final_parent_filesystem_device
            ),
            "dual_parent_lock_epoch_sha256": self.digest(
                "dual-parent-lock"
            ),
            "final_name": final_name,
            "expected_object_identity_sha256": object_identity_sha256,
            "expected_verifier_gid": verifier_gid,
            "adoption_limits": copy.deepcopy(limits),
            "final_observation": "exact_present",
            "final_object_identity_sha256": object_identity_sha256,
            "final_object_stat_sha256": self.digest("final-stat"),
            "final_content_inventory_sha256": self.digest("inventory"),
            "final_file_count": 2,
            "final_directory_count": 3,
            "final_total_bytes": 120,
            "final_largest_file_bytes": 80,
            "final_maximum_depth": 2,
            "final_object_owner_uid": 0,
            "final_object_group_gid": verifier_gid,
            "final_object_mode": reconciliation.ADOPTED_DIRECTORY_MODE,
            "final_object_nlink": 2,
            "staging_observation": "absent",
            "staging_observed_leaf_identity_sha256": None,
            "staging_terminal_quarantine_name": None,
            "staging_terminal_quarantine_reason_code": None,
            "staging_terminal_quarantined_stat_sha256": None,
            "staging_observed_quarantined_stat_sha256": None,
            "final_parent_fsynced": True,
            "staging_parents_fsynced": True,
            "observations_rechecked_under_lock": True,
        }
        return reconciliation.normalize_adoption_reconciliation_receipt(
            value
        )

    def bound_fixture(
        self,
    ) -> tuple[list[NormalizedRecord], dict, dict]:
        records: list[NormalizedRecord] = []
        self.append_record(records, state="reserved", details={})
        staging = self.append_record(
            records,
            state="staging_create_intent",
            details={
                "staging_leaf_name": "session-" + "1" * 64,
                "capture_uid": 501,
                "export_gid": 502,
                "required_device": 42,
            },
        )
        self.append_record(records, state="staging_exposed", details={})
        self.append_record(
            records, state="child_launch_intent", details={}
        )
        running = self.append_record(
            records, state="child_running", details={}
        )
        object_identity = self.digest("object")
        provisional_name = "opaque-capture-" + "a" * 32
        capture_details = {
            "provisional_name": provisional_name,
            "capture_object_identity_sha256": object_identity,
            "capture_selection_sha256": self.digest("selection"),
            "capture_plan_sha256": self.digest("plan"),
            "capture_manifest_sha256": self.digest("manifest"),
            "capture_boundary_policy_sha256": self.digest("boundary"),
            "helper_activation_policy_sha256": self.digest("helper"),
            "request_sha256": self.digest("request"),
        }
        capture = self.append_record(
            records,
            state="capture_ready",
            details={
                **capture_details,
                "lifecycle_operation_binding": (
                    self.lifecycle_operation_binding(
                        base=running,
                        operation="await_capture_event",
                        capture_ready_details=capture_details,
                    )
                ),
            },
        )
        clearance_intent = self.append_record(
            records, state="lifecycle_clearance_intent", details={}
        )
        scope_receipt = self.digest("scope-empty")
        scope = self.append_record(
            records,
            state="lifecycle_scope_empty",
            details={
                "lifecycle_clearance_bundle": {
                    "scope_empty_receipt_sha256": scope_receipt
                },
                "lifecycle_clearance_bundle_sha256": self.digest(
                    "scope-bundle"
                ),
                "lifecycle_operation_binding": (
                    self.lifecycle_operation_binding(
                        base=clearance_intent,
                        operation="request_clearance",
                    )
                ),
            },
        )
        limits = {
            "max_files": 32,
            "max_directories": 32,
            "max_bytes": 1024 * 1024,
            "max_file_bytes": 256 * 1024,
            "max_depth": 16,
        }
        adoption_policy = self.digest("adoption-policy")
        final_parent = self.digest("final-parent")
        adoption = self.append_record(
            records,
            state="adoption_intent",
            details={
                "adoption_policy_sha256": adoption_policy,
                "provisional_name": provisional_name,
                "final_name": provisional_name,
                "final_parent_identity_sha256": final_parent,
                "final_parent_filesystem_device": 42,
                "capture_object_identity_sha256": object_identity,
                "verifier_gid": 503,
                "limits": copy.deepcopy(limits),
            },
        )
        self.append_record(
            records,
            state="staging_tombstone_ack_pending",
            details={},
        )
        terminal_receipt = self.digest("terminal-receipt")
        tombstone = self.digest("tombstone")
        required = self.append_record(
            records,
            state="adoption_reconciliation_required",
            details={
                "from_state": "staging_tombstone_ack_pending",
                "adoption_intent_record_sha256": adoption.to_dict()[
                    "record_sha256"
                ],
                "terminal_receipt_sha256": terminal_receipt,
                "tombstone_sha256": tombstone,
            },
        )
        receipt = self.reconciliation_receipt(
            staging_intent_sha256=staging.to_dict()["record_sha256"],
            adoption_intent_sha256=adoption.to_dict()["record_sha256"],
            scope_empty_receipt_sha256=scope_receipt,
            adoption_policy_sha256=adoption_policy,
            final_parent_identity_sha256=final_parent,
            final_parent_filesystem_device=42,
            final_name=provisional_name,
            object_identity_sha256=object_identity,
            verifier_gid=503,
            limits=limits,
            terminal_receipt_sha256=terminal_receipt,
            tombstone_sha256=tombstone,
        )
        self.append_record(
            records,
            state="adoption_reconciled",
            details={
                (
                    "adoption_reconciliation_"
                    "required_record_sha256"
                ): required.to_dict()["record_sha256"],
                "adoption_reconciliation_receipt": receipt,
                "adoption_reconciliation_receipt_sha256": (
                    reconciliation
                    .adoption_reconciliation_receipt_sha256(receipt)
                ),
            },
        )
        evidence = recovered.bind_recovered_adoption_evidence(
            validated_history=self.validated_history(records),
            adoption_reconciliation_receipt=receipt,
        )
        self.assertEqual(
            evidence["capture_ready_record_sha256"],
            capture.to_dict()["record_sha256"],
        )
        self.assertEqual(
            evidence["lifecycle_scope_empty_record_sha256"],
            scope.to_dict()["record_sha256"],
        )
        return records, receipt, evidence

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(
            recovered.RecoveredAdoptionEvidenceError
        ) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def validated_history(
        self,
        records: list[NormalizedRecord],
    ) -> recovered.ValidatedRecoveredAdoptionHistoryV5:
        return (
            recovered
            ._mint_validated_recovered_adoption_history_v5_for_test(
                records
            )
        )

    def test_binding_is_canonical_path_free_and_sidecar_only(
        self,
    ) -> None:
        _, _, evidence = self.bound_fixture()
        self.assertEqual(
            recovered.normalize_recovered_adoption_evidence(evidence),
            evidence,
        )
        self.assertEqual(
            recovered.recovered_adoption_evidence_sha256(
                dict(reversed(tuple(evidence.items())))
            ),
            recovered.recovered_adoption_evidence_sha256(evidence),
        )
        encoded = json.dumps(evidence, sort_keys=True)
        for forbidden in (
            "path",
            "child_pid",
            "child_exit_status",
            "child_stderr",
            "provisional_stat",
            "adopted_at_unix",
            "rename_primitive",
            "rename_noreplace",
            "capture_adoption_receipt",
            '"adoption_reconciliation_receipt"',
            "/private/",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertFalse(recovered.PRODUCTION_ACTIVATION)

    def test_fixed_schemas_states_and_durability_cannot_drift(
        self,
    ) -> None:
        _, _, evidence = self.bound_fixture()
        mutations = {
            "schema_version": "wrong",
            "status": "adopted",
            "transaction_journal_schema": (
                "john-lomein.persona-qualification-"
                "transaction-journal.v4"
            ),
            "adoption_reconciliation_receipt_schema": "wrong",
            "reconciliation_result": "operator_attention",
            "final_observation": "absent",
            "staging_observation": "exact_quarantine",
            "staging_terminal_disposition": "quarantined",
            "final_parent_fsynced": False,
            "staging_parents_fsynced": False,
            "observations_rechecked_under_lock": False,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(evidence)
                changed[field] = replacement
                with self.assertRaises(
                    recovered.RecoveredAdoptionEvidenceError
                ):
                    recovered.normalize_recovered_adoption_evidence(
                        changed
                    )

    def test_every_digest_is_nonzero_and_exact(self) -> None:
        _, _, evidence = self.bound_fixture()
        digest_fields = (
            "capture_session_id",
            *sorted(
                field
                for field in (
                    recovered.RECOVERED_ADOPTION_EVIDENCE_FIELDS
                )
                if field.endswith("_sha256")
            ),
        )
        self.assertGreater(len(digest_fields), 20)
        for field in digest_fields:
            for replacement in (None, "not-a-digest", recovered.ZERO_SHA256):
                with self.subTest(field=field, replacement=replacement):
                    changed = copy.deepcopy(evidence)
                    changed[field] = replacement
                    self.assert_code(
                        f"recovered_adoption_{field}_invalid",
                        recovered.normalize_recovered_adoption_evidence,
                        changed,
                    )

    def test_fields_are_exact_and_normal_only_claims_are_rejected(
        self,
    ) -> None:
        _, _, evidence = self.bound_fixture()
        missing = copy.deepcopy(evidence)
        missing.pop("dual_parent_lock_epoch_sha256")
        self.assert_code(
            "recovered_adoption_evidence_fields_invalid",
            recovered.normalize_recovered_adoption_evidence,
            missing,
        )
        for field in (
            "capture_adoption_receipt_sha256",
            "provisional_stat_sha256",
            "child_pid",
            "rename_primitive",
            "adopted_at_unix",
            "adoption_reconciliation_receipt",
        ):
            with self.subTest(field=field):
                extra = copy.deepcopy(evidence)
                extra[field] = self.digest(field)
                self.assert_code(
                    "recovered_adoption_evidence_fields_invalid",
                    recovered.normalize_recovered_adoption_evidence,
                    extra,
                )

    def test_identity_mode_group_and_inventory_are_strict(self) -> None:
        _, _, evidence = self.bound_fixture()
        mutations = {
            "capture_uid": True,
            "capture_export_gid": 503,
            "final_object_owner_uid": 501,
            "final_object_group_gid": 504,
            "final_object_mode": 0o770,
            "final_object_nlink": 0,
            "reconciled_file_count": 33,
            "reconciled_directory_count": 2,
            "reconciled_total_bytes": 1024 * 1024 + 1,
            "reconciled_largest_file_bytes": 121,
            "reconciled_maximum_depth": 17,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(evidence)
                changed[field] = replacement
                with self.assertRaises(
                    recovered.RecoveredAdoptionEvidenceError
                ):
                    recovered.normalize_recovered_adoption_evidence(
                        changed
                    )

    def test_binder_requires_v5_validated_history_capability(
        self,
    ) -> None:
        records, receipt, _ = self.bound_fixture()
        self.assert_code(
            (
                "recovered_adoption_"
                "validated_history_capability_required"
            ),
            recovered.bind_recovered_adoption_evidence,
            validated_history=records,
            adoption_reconciliation_receipt=receipt,
        )
        with self.assertRaises(TypeError):
            recovered.ValidatedRecoveredAdoptionHistoryV5(records)

        class HostileFakeHistory:
            def _records_for_binding(self, **_kwargs):
                return tuple(
                    record.to_dict() for record in records
                )

        self.assert_code(
            (
                "recovered_adoption_"
                "validated_history_capability_required"
            ),
            recovered.bind_recovered_adoption_evidence,
            validated_history=HostileFakeHistory(),
            adoption_reconciliation_receipt=receipt,
        )

        forged = object.__new__(
            recovered.ValidatedRecoveredAdoptionHistoryV5
        )
        object.__setattr__(forged, "_canonical_records", (b"{}",))
        self.assert_code(
            (
                "recovered_adoption_"
                "validated_history_capability_invalid"
            ),
            recovered.bind_recovered_adoption_evidence,
            validated_history=forged,
            adoption_reconciliation_receipt=receipt,
        )

        v4 = copy.deepcopy(records[0].to_dict())
        v4["schema_version"] = (
            "john-lomein.persona-qualification-transaction-journal.v4"
        )
        v4_payload = {
            key: value
            for key, value in v4.items()
            if key != "record_sha256"
        }
        v4["record_sha256"] = hashlib.sha256(
            self.canonical(v4_payload)
        ).hexdigest()
        self.assert_code(
            "recovered_adoption_transaction_journal_schema_invalid",
            (
                recovered
                ._mint_validated_recovered_adoption_history_v5_for_test
            ),
            [
                NormalizedRecord(v4),
                *records[1:],
            ],
        )

    def test_test_mint_rejects_tampered_record_and_chain(self) -> None:
        records, _, _ = self.bound_fixture()
        tampered = [
            NormalizedRecord(record.to_dict()) for record in records
        ]
        changed = tampered[5].to_dict()
        changed["details"]["capture_selection_sha256"] = self.digest(
            "changed"
        )
        tampered[5] = NormalizedRecord(changed)
        self.assert_code(
            "recovered_adoption_journal_record_digest_mismatch",
            (
                recovered
                ._mint_validated_recovered_adoption_history_v5_for_test
            ),
            tampered,
        )

        broken = [
            NormalizedRecord(record.to_dict()) for record in records
        ]
        changed = broken[1].to_dict()
        changed["previous_record_sha256"] = self.digest("wrong")
        payload = {
            key: value
            for key, value in changed.items()
            if key != "record_sha256"
        }
        changed["record_sha256"] = hashlib.sha256(
            self.canonical(payload)
        ).hexdigest()
        broken[1] = NormalizedRecord(changed)
        self.assert_code(
            "recovered_adoption_journal_previous_digest_mismatch",
            (
                recovered
                ._mint_validated_recovered_adoption_history_v5_for_test
            ),
            broken,
        )

    def test_lifecycle_operation_detail_and_binding_fields_are_exact(
        self,
    ) -> None:
        cases = (
            (
                "capture_missing_binding",
                "capture_ready",
                lambda details: details.pop(
                    "lifecycle_operation_binding"
                ),
                (
                    "recovered_adoption_journal_"
                    "capture_ready_details_invalid"
                ),
            ),
            (
                "scope_missing_binding",
                "lifecycle_scope_empty",
                lambda details: details.pop(
                    "lifecycle_operation_binding"
                ),
                (
                    "recovered_adoption_journal_"
                    "lifecycle_scope_empty_details_invalid"
                ),
            ),
            (
                "capture_extra_detail",
                "capture_ready",
                lambda details: details.__setitem__(
                    "unexpected", self.digest("unexpected")
                ),
                (
                    "recovered_adoption_journal_"
                    "capture_ready_details_invalid"
                ),
            ),
            (
                "scope_extra_detail",
                "lifecycle_scope_empty",
                lambda details: details.__setitem__(
                    "unexpected", self.digest("unexpected")
                ),
                (
                    "recovered_adoption_journal_"
                    "lifecycle_scope_empty_details_invalid"
                ),
            ),
            (
                "capture_missing_binding_field",
                "capture_ready",
                lambda details: details[
                    "lifecycle_operation_binding"
                ].pop("response_sha256"),
                (
                    "recovered_adoption_journal_capture_ready_"
                    "lifecycle_operation_binding_fields_invalid"
                ),
            ),
            (
                "scope_missing_binding_field",
                "lifecycle_scope_empty",
                lambda details: details[
                    "lifecycle_operation_binding"
                ].pop("response_sha256"),
                (
                    "recovered_adoption_journal_"
                    "lifecycle_scope_empty_"
                    "lifecycle_operation_binding_fields_invalid"
                ),
            ),
            (
                "capture_extra_binding_field",
                "capture_ready",
                lambda details: details[
                    "lifecycle_operation_binding"
                ].__setitem__("unexpected", None),
                (
                    "recovered_adoption_journal_capture_ready_"
                    "lifecycle_operation_binding_fields_invalid"
                ),
            ),
            (
                "scope_extra_binding_field",
                "lifecycle_scope_empty",
                lambda details: details[
                    "lifecycle_operation_binding"
                ].__setitem__("unexpected", None),
                (
                    "recovered_adoption_journal_"
                    "lifecycle_scope_empty_"
                    "lifecycle_operation_binding_fields_invalid"
                ),
            ),
        )
        for label, state, mutate, code in cases:
            with self.subTest(case=label):
                records, _, _ = self.bound_fixture()
                values = [record.to_dict() for record in records]
                selected = next(
                    value
                    for value in values
                    if value["state"] == state
                )
                mutate(selected["details"])
                repaired, receipt = (
                    self.repair_record_hash_references(
                        [
                            NormalizedRecord(value)
                            for value in values
                        ],
                        repair_lifecycle_bindings=False,
                    )
                )
                self.assert_code(
                    code,
                    recovered.bind_recovered_adoption_evidence,
                    validated_history=self.validated_history(
                        repaired
                    ),
                    adoption_reconciliation_receipt=receipt,
                )

    def test_lifecycle_operation_bindings_cannot_be_substituted(
        self,
    ) -> None:
        for target_state, source_state in (
            ("capture_ready", "lifecycle_scope_empty"),
            ("lifecycle_scope_empty", "capture_ready"),
        ):
            with self.subTest(
                target=target_state, source=source_state
            ):
                records, _, _ = self.bound_fixture()
                values = [record.to_dict() for record in records]
                by_state = {
                    value["state"]: value for value in values
                }
                by_state[target_state]["details"][
                    "lifecycle_operation_binding"
                ] = copy.deepcopy(
                    by_state[source_state]["details"][
                        "lifecycle_operation_binding"
                    ]
                )
                repaired, receipt = (
                    self.repair_record_hash_references(
                        [
                            NormalizedRecord(value)
                            for value in values
                        ],
                        repair_lifecycle_bindings=False,
                    )
                )
                self.assert_code(
                    (
                        f"recovered_adoption_journal_{target_state}_"
                        "lifecycle_operation_invalid"
                    ),
                    recovered.bind_recovered_adoption_evidence,
                    validated_history=self.validated_history(
                        repaired
                    ),
                    adoption_reconciliation_receipt=receipt,
                )

    def test_capture_ready_binding_is_exact_and_evidence_bound(
        self,
    ) -> None:
        cases = (
            (
                "operation",
                "start_scope",
                (
                    "recovered_adoption_journal_capture_ready_"
                    "lifecycle_operation_invalid"
                ),
            ),
            (
                "outcome",
                "no_effect",
                (
                    "recovered_adoption_journal_capture_ready_"
                    "lifecycle_operation_success_invalid"
                ),
            ),
            (
                "supervisor_ledger_head_sha256",
                None,
                (
                    "recovered_adoption_capture_ready_"
                    "lifecycle_operation_"
                    "supervisor_ledger_head_sha256_invalid"
                ),
            ),
            (
                "supervisor_event",
                "child_exited",
                (
                    "recovered_adoption_journal_capture_ready_"
                    "lifecycle_operation_event_invalid"
                ),
            ),
            (
                "supervisor_event_record_sha256",
                None,
                (
                    "recovered_adoption_capture_ready_"
                    "lifecycle_operation_"
                    "supervisor_event_record_sha256_invalid"
                ),
            ),
            (
                "supervisor_event_evidence_sha256",
                self.digest("substituted-capture-evidence"),
                (
                    "recovered_adoption_journal_capture_ready_"
                    "event_evidence_mismatch"
                ),
            ),
            (
                "base_record_revision",
                1,
                (
                    "recovered_adoption_journal_capture_ready_"
                    "lifecycle_operation_base_mismatch"
                ),
            ),
        )
        for field, replacement, code in cases:
            with self.subTest(field=field):
                records, _, _ = self.bound_fixture()
                values = [record.to_dict() for record in records]
                capture = next(
                    value
                    for value in values
                    if value["state"] == "capture_ready"
                )
                capture["details"]["lifecycle_operation_binding"][
                    field
                ] = replacement
                repaired, receipt = (
                    self.repair_record_hash_references(
                        [
                            NormalizedRecord(value)
                            for value in values
                        ],
                        repair_lifecycle_bindings=False,
                    )
                )
                self.assert_code(
                    code,
                    recovered.bind_recovered_adoption_evidence,
                    validated_history=self.validated_history(
                        repaired
                    ),
                    adoption_reconciliation_receipt=receipt,
                )

    def test_scope_empty_binding_is_exact_and_settled(
        self,
    ) -> None:
        cases = (
            (
                "operation",
                "await_capture_event",
                (
                    "recovered_adoption_journal_"
                    "lifecycle_scope_empty_"
                    "lifecycle_operation_invalid"
                ),
            ),
            (
                "outcome",
                "attention",
                (
                    "recovered_adoption_journal_"
                    "lifecycle_scope_empty_"
                    "lifecycle_operation_success_invalid"
                ),
            ),
            (
                "result_sha256",
                None,
                (
                    "recovered_adoption_lifecycle_scope_empty_"
                    "lifecycle_operation_result_sha256_invalid"
                ),
            ),
            (
                "supervisor_ledger_head_sha256",
                None,
                (
                    "recovered_adoption_lifecycle_scope_empty_"
                    "lifecycle_operation_"
                    "supervisor_ledger_head_sha256_invalid"
                ),
            ),
            (
                "supervisor_event",
                "capture_ready",
                (
                    "recovered_adoption_journal_"
                    "lifecycle_scope_empty_"
                    "lifecycle_operation_settled_head_invalid"
                ),
            ),
            (
                "base_record_sha256",
                self.digest("substituted-base"),
                (
                    "recovered_adoption_journal_"
                    "lifecycle_scope_empty_"
                    "lifecycle_operation_base_mismatch"
                ),
            ),
        )
        for field, replacement, code in cases:
            with self.subTest(field=field):
                records, _, _ = self.bound_fixture()
                values = [record.to_dict() for record in records]
                scope = next(
                    value
                    for value in values
                    if value["state"] == "lifecycle_scope_empty"
                )
                scope["details"]["lifecycle_operation_binding"][
                    field
                ] = replacement
                repaired, receipt = (
                    self.repair_record_hash_references(
                        [
                            NormalizedRecord(value)
                            for value in values
                        ],
                        repair_lifecycle_bindings=False,
                    )
                )
                self.assert_code(
                    code,
                    recovered.bind_recovered_adoption_evidence,
                    validated_history=self.validated_history(
                        repaired
                    ),
                    adoption_reconciliation_receipt=receipt,
                )

    def test_recovered_success_bindings_are_accepted(self) -> None:
        records, _, _ = self.bound_fixture()
        values = [record.to_dict() for record in records]
        for state in ("capture_ready", "lifecycle_scope_empty"):
            selected = next(
                value for value in values if value["state"] == state
            )
            selected["details"]["lifecycle_operation_binding"][
                "operation"
            ] = "recover_scope"
        repaired, receipt = self.repair_record_hash_references(
            [NormalizedRecord(value) for value in values]
        )
        evidence = recovered.bind_recovered_adoption_evidence(
            validated_history=self.validated_history(repaired),
            adoption_reconciliation_receipt=receipt,
        )
        self.assertEqual(
            evidence["status"], recovered.RECOVERED_ADOPTION_STATUS
        )

    def test_binder_rechecks_every_cross_record_provenance_join(
        self,
    ) -> None:
        cases = (
            (
                "capture_object",
                "capture_ready",
                "capture_object_identity_sha256",
                self.digest("replacement-object"),
                (
                    "recovered_adoption_"
                    "capture_object_identity_sha256_mismatch"
                ),
            ),
            (
                "scope_receipt",
                "lifecycle_scope_empty",
                "scope_empty_receipt_sha256",
                self.digest("replacement-scope"),
                (
                    "recovered_adoption_reconciliation_"
                    "lifecycle_scope_empty_receipt_sha256_mismatch"
                ),
            ),
            (
                "filesystem_device",
                "staging_create_intent",
                "required_device",
                43,
                (
                    "recovered_adoption_"
                    "staging_final_filesystem_device_mismatch"
                ),
            ),
            (
                "terminal_receipt",
                "adoption_reconciliation_required",
                "terminal_receipt_sha256",
                self.digest("replacement-terminal"),
                (
                    "recovered_adoption_reconciliation_"
                    "staging_terminal_receipt_sha256_mismatch"
                ),
            ),
        )
        for label, state, field, replacement, code in cases:
            with self.subTest(join=label):
                records, _, _ = self.bound_fixture()
                values = [
                    record.to_dict() for record in records
                ]
                selected = next(
                    value
                    for value in values
                    if value["state"] == state
                )
                if label == "scope_receipt":
                    selected["details"][
                        "lifecycle_clearance_bundle"
                    ][field] = replacement
                else:
                    selected["details"][field] = replacement
                repaired, receipt = (
                    self.repair_record_hash_references(
                        [
                            NormalizedRecord(value)
                            for value in values
                        ]
                    )
                )
                self.assert_code(
                    code,
                    recovered.bind_recovered_adoption_evidence,
                    validated_history=self.validated_history(
                        repaired
                    ),
                    adoption_reconciliation_receipt=receipt,
                )

    def test_sidecar_must_be_exact_receipt_embedded_by_journal(
        self,
    ) -> None:
        records, receipt, _ = self.bound_fixture()
        changed = copy.deepcopy(receipt)
        changed["dual_parent_lock_epoch_sha256"] = self.digest(
            "different-lock"
        )
        changed = (
            reconciliation.normalize_adoption_reconciliation_receipt(
                changed
            )
        )
        self.assert_code(
            "recovered_adoption_reconciliation_receipt_sidecar_mismatch",
            recovered.bind_recovered_adoption_evidence,
            validated_history=self.validated_history(records),
            adoption_reconciliation_receipt=changed,
        )

    def test_non_recovered_receipt_cannot_bind(self) -> None:
        records, receipt, _ = self.bound_fixture()
        changed = copy.deepcopy(receipt)
        changed.update(
            {
                "result": "staging_absent",
                "final_observation": "absent",
                "final_object_identity_sha256": None,
                "final_object_stat_sha256": None,
                "final_content_inventory_sha256": None,
                "final_file_count": None,
                "final_directory_count": None,
                "final_total_bytes": None,
                "final_largest_file_bytes": None,
                "final_maximum_depth": None,
                "final_object_owner_uid": None,
                "final_object_group_gid": None,
                "final_object_mode": None,
                "final_object_nlink": None,
            }
        )
        changed = (
            reconciliation.normalize_adoption_reconciliation_receipt(
                changed
            )
        )
        self.assert_code(
            "recovered_adoption_reconciliation_receipt_sidecar_mismatch",
            recovered.bind_recovered_adoption_evidence,
            validated_history=self.validated_history(records),
            adoption_reconciliation_receipt=changed,
        )

    def test_hash_vector_is_stable(self) -> None:
        _, _, evidence = self.bound_fixture()
        self.assertEqual(
            recovered.recovered_adoption_evidence_sha256(evidence),
            "71f0376958ebdc631a7681ddb19b4a9172431edf455f0322f68dc6363134fe3d",
        )


if __name__ == "__main__":
    unittest.main()
