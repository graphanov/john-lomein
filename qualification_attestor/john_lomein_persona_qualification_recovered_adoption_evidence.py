"""Pure contract for evidence recovered after an interrupted adoption.

Normal capture-adoption receipts contain facts observed by the live adoption
operation (for example the rename primitive, child status, and adoption
time).  A crash-time reconciler cannot reconstruct those facts honestly.
This module therefore defines a separate, path-free evidence kind whose
claims come only from a canonical transaction-journal chain and a
dual-parent reconciliation receipt.

The module owns no path, descriptor, lock, process, signer, or publication
authority.  ``bind_recovered_adoption_evidence`` accepts a nominal history
capability that the v5 journal must mint only after its complete transition
grammar has passed.  The dormant production mint is owned by the
descriptor-bound v5 journal session.  The binder still rechecks every
evidence-relevant provenance field, so the v5 record schema alone must not
be treated as sufficient authority for this evidence.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any

from qualification_attestor import (
    john_lomein_persona_qualification_adoption_reconciliation
    as adoption_reconciliation,
)


PRODUCTION_ACTIVATION = False

RECOVERED_ADOPTION_EVIDENCE_SCHEMA = (
    "john-lomein.persona-qualification-recovered-adoption-evidence.v1"
)
RECOVERED_ADOPTION_STATUS = "recovered_adoption"
TRANSACTION_JOURNAL_SCHEMA = (
    "john-lomein.persona-qualification-transaction-journal.v5"
)
LIFECYCLE_OPERATION_BINDING_SCHEMA = (
    "john-lomein.persona-qualification-lifecycle-operation-binding.v1"
)
LIFECYCLE_CAPTURE_EVENT_EVIDENCE_SCHEMA = (
    "john-lomein.persona-qualification-lifecycle-"
    "capture-event-evidence.v1"
)
ADOPTION_RECONCILIATION_RECEIPT_SCHEMA = (
    adoption_reconciliation.ADOPTION_RECONCILIATION_RECEIPT_SCHEMA
)
ADOPTED_DIRECTORY_MODE = adoption_reconciliation.ADOPTED_DIRECTORY_MODE

ZERO_SHA256 = "0" * 64
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FINAL_NAME_RE = re.compile(r"^opaque-capture-[0-9a-f]{32}$")
SLUG_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$"
)
STATE_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")

MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_IDENTITY = (1 << 31) - 1
MAX_FILESYSTEM_DEVICE = (1 << 63) - 1
MAX_CAPTURE_FILES = adoption_reconciliation.MAX_CAPTURE_FILES
MAX_CAPTURE_DIRECTORIES = (
    adoption_reconciliation.MAX_CAPTURE_DIRECTORIES
)
MAX_CAPTURE_BYTES = adoption_reconciliation.MAX_CAPTURE_BYTES
MAX_CAPTURE_FILE_BYTES = (
    adoption_reconciliation.MAX_CAPTURE_FILE_BYTES
)
MAX_CAPTURE_DEPTH = adoption_reconciliation.MAX_CAPTURE_DEPTH

ADOPTION_LIMIT_FIELDS = adoption_reconciliation.ADOPTION_LIMIT_FIELDS

RECOVERED_ADOPTION_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "transaction_journal_schema",
        "adoption_reconciliation_receipt_schema",
        "instance_slug",
        "capture_session_id",
        "staging_transaction_intent_record_sha256",
        "capture_ready_record_sha256",
        "lifecycle_scope_empty_record_sha256",
        "lifecycle_scope_empty_receipt_sha256",
        "adoption_intent_record_sha256",
        "adoption_reconciliation_required_record_sha256",
        "adoption_reconciliation_record_sha256",
        "adoption_reconciliation_receipt_sha256",
        "capture_uid",
        "capture_export_gid",
        "final_object_owner_uid",
        "verifier_gid",
        "final_object_group_gid",
        "capture_adoption_policy_sha256",
        "capture_selection_sha256",
        "capture_plan_sha256",
        "capture_manifest_sha256",
        "capture_request_sha256",
        "capture_boundary_policy_sha256",
        "helper_activation_policy_sha256",
        "final_name",
        "final_parent_identity_sha256",
        "final_parent_filesystem_device",
        "capture_object_identity_sha256",
        "adoption_limits",
        "reconciliation_result",
        "final_observation",
        "staging_observation",
        "staging_terminal_disposition",
        "reconciled_final_object_stat_sha256",
        "reconciled_content_inventory_sha256",
        "reconciled_file_count",
        "reconciled_directory_count",
        "reconciled_total_bytes",
        "reconciled_largest_file_bytes",
        "reconciled_maximum_depth",
        "final_object_mode",
        "final_object_nlink",
        "staging_terminal_receipt_sha256",
        "staging_tombstone_sha256",
        "dual_parent_lock_epoch_sha256",
        "final_parent_fsynced",
        "staging_parents_fsynced",
        "observations_rechecked_under_lock",
    }
)

_RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "instance_slug",
        "session_id",
        "revision",
        "previous_record_sha256",
        "state",
        "recorded_at_unix",
        "control_sha256",
        "handoff_policy_sha256",
        "details",
        "record_sha256",
    }
)

_LIFECYCLE_OPERATION_BINDING_FIELDS = frozenset(
    {
        "schema_version",
        "operation",
        "base_record_revision",
        "base_record_sha256",
        "request_sha256",
        "response_sha256",
        "outcome",
        "error_code",
        "result_sha256",
        "supervisor_ledger_head_sha256",
        "supervisor_event_sequence",
        "supervisor_event",
        "supervisor_event_record_sha256",
        "supervisor_event_evidence_sha256",
    }
)
_CAPTURE_READY_EVIDENCE_FIELDS = frozenset(
    {
        "provisional_name",
        "capture_object_identity_sha256",
        "capture_selection_sha256",
        "capture_plan_sha256",
        "capture_manifest_sha256",
        "capture_boundary_policy_sha256",
        "helper_activation_policy_sha256",
        "request_sha256",
    }
)
_SELECTED_DETAIL_FIELDS = {
    "staging_create_intent": frozenset(
        {
            "staging_leaf_name",
            "capture_uid",
            "export_gid",
            "required_device",
        }
    ),
    "capture_ready": frozenset(
        {
            "provisional_name",
            "capture_object_identity_sha256",
            "capture_selection_sha256",
            "capture_plan_sha256",
            "capture_manifest_sha256",
            "capture_boundary_policy_sha256",
            "helper_activation_policy_sha256",
            "request_sha256",
            "lifecycle_operation_binding",
        }
    ),
    "lifecycle_scope_empty": frozenset(
        {
            "lifecycle_clearance_bundle",
            "lifecycle_clearance_bundle_sha256",
            "lifecycle_operation_binding",
        }
    ),
    "adoption_intent": frozenset(
        {
            "adoption_policy_sha256",
            "provisional_name",
            "final_name",
            "final_parent_identity_sha256",
            "final_parent_filesystem_device",
            "capture_object_identity_sha256",
            "verifier_gid",
            "limits",
        }
    ),
    "adoption_reconciliation_required": frozenset(
        {
            "from_state",
            "adoption_intent_record_sha256",
            "terminal_receipt_sha256",
            "tombstone_sha256",
        }
    ),
    "adoption_reconciled": frozenset(
        {
            "adoption_reconciliation_required_record_sha256",
            "adoption_reconciliation_receipt",
            "adoption_reconciliation_receipt_sha256",
        }
    ),
}

_REQUIRED_STATES = (
    "staging_create_intent",
    "capture_ready",
    "lifecycle_scope_empty",
    "adoption_intent",
    "staging_tombstone_ack_pending",
    "adoption_reconciliation_required",
    "adoption_reconciled",
)

_HISTORY_CAPABILITY_TOKEN = object()


class RecoveredAdoptionEvidenceError(ValueError):
    """Stable public-safe rejection from the pure evidence boundary."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _error(code: str) -> RecoveredAdoptionEvidenceError:
    return RecoveredAdoptionEvidenceError(code)


class ValidatedRecoveredAdoptionHistoryV5:
    """Nominal result of journal-v5 full-history validation.

    The class is not public-authority by itself: same-process Python
    introspection can bypass nominal guards.  It only prevents accidental
    binding from caller-authored mappings.  Production authority must come
    from the isolated root journal, which will own the real mint path.
    """

    __slots__ = ("_canonical_records",)

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError(
            "ValidatedRecoveredAdoptionHistoryV5 cannot be "
            "constructed directly"
        )

    @classmethod
    def _mint(
        cls,
        *,
        _token: object,
        records: tuple[dict[str, Any], ...],
    ) -> ValidatedRecoveredAdoptionHistoryV5:
        if _token is not _HISTORY_CAPABILITY_TOKEN:
            raise TypeError(
                "ValidatedRecoveredAdoptionHistoryV5 mint denied"
            )
        instance = object.__new__(cls)
        instance._canonical_records = tuple(
            _canonical_json(record) for record in records
        )
        return instance

    def _records_for_binding(
        self,
        *,
        _token: object,
    ) -> tuple[dict[str, Any], ...]:
        if _token is not _HISTORY_CAPABILITY_TOKEN:
            raise TypeError(
                "ValidatedRecoveredAdoptionHistoryV5 read denied"
            )
        records: list[dict[str, Any]] = []
        for raw in self._canonical_records:
            value = json.loads(raw.decode("ascii"))
            if not isinstance(value, dict):
                raise AssertionError(
                    "canonical recovered-adoption history record "
                    "is not an object"
                )
            records.append(value)
        return tuple(records)


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise _error("recovered_adoption_json_invalid") from exc


def _strict_mapping(
    value: Any,
    fields: frozenset[str],
    *,
    code: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise _error(code)
    return {field: value[field] for field in fields}


def _digest(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not SHA256_RE.fullmatch(value)
        or value == ZERO_SHA256
    ):
        raise _error(f"recovered_adoption_{field}_invalid")
    return value


def _integer(
    value: Any,
    *,
    field: str,
    minimum: int = 0,
    maximum: int = MAX_SAFE_INTEGER,
) -> int:
    if (
        type(value) is not int
        or not minimum <= value <= maximum
    ):
        raise _error(f"recovered_adoption_{field}_invalid")
    return value


def _text(
    value: Any,
    *,
    field: str,
    expression: re.Pattern[str],
) -> str:
    if (
        not isinstance(value, str)
        or unicodedata.normalize("NFC", value) != value
        or not expression.fullmatch(value)
    ):
        raise _error(f"recovered_adoption_{field}_invalid")
    return value


def _adoption_limits(value: Any) -> dict[str, int]:
    selected = _strict_mapping(
        value,
        ADOPTION_LIMIT_FIELDS,
        code="recovered_adoption_adoption_limits_invalid",
    )
    limits = {
        "max_files": _integer(
            selected["max_files"],
            field="adoption_limits_max_files",
            minimum=1,
            maximum=MAX_CAPTURE_FILES,
        ),
        "max_directories": _integer(
            selected["max_directories"],
            field="adoption_limits_max_directories",
            minimum=1,
            maximum=MAX_CAPTURE_DIRECTORIES,
        ),
        "max_bytes": _integer(
            selected["max_bytes"],
            field="adoption_limits_max_bytes",
            minimum=1,
            maximum=MAX_CAPTURE_BYTES,
        ),
        "max_file_bytes": _integer(
            selected["max_file_bytes"],
            field="adoption_limits_max_file_bytes",
            minimum=1,
            maximum=MAX_CAPTURE_FILE_BYTES,
        ),
        "max_depth": _integer(
            selected["max_depth"],
            field="adoption_limits_max_depth",
            minimum=1,
            maximum=MAX_CAPTURE_DEPTH,
        ),
    }
    if limits["max_file_bytes"] > limits["max_bytes"]:
        raise _error(
            "recovered_adoption_adoption_file_limit_exceeds_total"
        )
    return limits


def normalize_recovered_adoption_evidence(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Return one exact canonical recovered-adoption evidence object."""

    selected = _strict_mapping(
        value,
        RECOVERED_ADOPTION_EVIDENCE_FIELDS,
        code="recovered_adoption_evidence_fields_invalid",
    )
    if selected["schema_version"] != RECOVERED_ADOPTION_EVIDENCE_SCHEMA:
        raise _error("recovered_adoption_evidence_schema_invalid")
    if selected["status"] != RECOVERED_ADOPTION_STATUS:
        raise _error("recovered_adoption_status_invalid")
    if selected["transaction_journal_schema"] != TRANSACTION_JOURNAL_SCHEMA:
        raise _error(
            "recovered_adoption_transaction_journal_schema_invalid"
        )
    if (
        selected["adoption_reconciliation_receipt_schema"]
        != ADOPTION_RECONCILIATION_RECEIPT_SCHEMA
    ):
        raise _error(
            "recovered_adoption_reconciliation_receipt_schema_invalid"
        )
    if selected["reconciliation_result"] != RECOVERED_ADOPTION_STATUS:
        raise _error("recovered_adoption_reconciliation_result_invalid")
    if selected["final_observation"] != "exact_present":
        raise _error("recovered_adoption_final_observation_invalid")
    if selected["staging_observation"] != "absent":
        raise _error("recovered_adoption_staging_observation_invalid")
    if selected["staging_terminal_disposition"] != "absent":
        raise _error(
            "recovered_adoption_staging_terminal_disposition_invalid"
        )

    instance_slug = _text(
        selected["instance_slug"],
        field="instance_slug",
        expression=SLUG_RE,
    )
    final_name = _text(
        selected["final_name"],
        field="final_name",
        expression=FINAL_NAME_RE,
    )
    limits = _adoption_limits(selected["adoption_limits"])

    capture_uid = _integer(
        selected["capture_uid"],
        field="capture_uid",
        minimum=1,
        maximum=MAX_IDENTITY,
    )
    capture_export_gid = _integer(
        selected["capture_export_gid"],
        field="capture_export_gid",
        minimum=1,
        maximum=MAX_IDENTITY,
    )
    final_owner = _integer(
        selected["final_object_owner_uid"],
        field="final_object_owner_uid",
        maximum=MAX_IDENTITY,
    )
    verifier_gid = _integer(
        selected["verifier_gid"],
        field="verifier_gid",
        minimum=1,
        maximum=MAX_IDENTITY,
    )
    final_group = _integer(
        selected["final_object_group_gid"],
        field="final_object_group_gid",
        minimum=1,
        maximum=MAX_IDENTITY,
    )
    if capture_export_gid == verifier_gid:
        raise _error("recovered_adoption_group_separation_missing")
    if final_owner != 0:
        raise _error("recovered_adoption_final_object_owner_invalid")
    if final_group != verifier_gid:
        raise _error("recovered_adoption_final_object_group_invalid")

    final_device = _integer(
        selected["final_parent_filesystem_device"],
        field="final_parent_filesystem_device",
        maximum=MAX_FILESYSTEM_DEVICE,
    )
    file_count = _integer(
        selected["reconciled_file_count"],
        field="reconciled_file_count",
        maximum=MAX_CAPTURE_FILES,
    )
    directory_count = _integer(
        selected["reconciled_directory_count"],
        field="reconciled_directory_count",
        minimum=1,
        maximum=MAX_CAPTURE_DIRECTORIES,
    )
    total_bytes = _integer(
        selected["reconciled_total_bytes"],
        field="reconciled_total_bytes",
        maximum=MAX_CAPTURE_BYTES,
    )
    largest_file = _integer(
        selected["reconciled_largest_file_bytes"],
        field="reconciled_largest_file_bytes",
        maximum=MAX_CAPTURE_FILE_BYTES,
    )
    maximum_depth = _integer(
        selected["reconciled_maximum_depth"],
        field="reconciled_maximum_depth",
        maximum=MAX_CAPTURE_DEPTH,
    )
    final_mode = _integer(
        selected["final_object_mode"],
        field="final_object_mode",
        maximum=0o7777,
    )
    final_nlink = _integer(
        selected["final_object_nlink"],
        field="final_object_nlink",
        minimum=1,
        maximum=MAX_IDENTITY,
    )
    if final_mode != ADOPTED_DIRECTORY_MODE:
        raise _error("recovered_adoption_final_object_mode_invalid")
    if (
        file_count > limits["max_files"]
        or directory_count > limits["max_directories"]
        or total_bytes > limits["max_bytes"]
        or largest_file > limits["max_file_bytes"]
        or largest_file > total_bytes
        or maximum_depth > limits["max_depth"]
        or maximum_depth >= directory_count
        or (total_bytes > 0 and largest_file == 0)
        or (
            file_count == 0
            and (total_bytes != 0 or largest_file != 0)
        )
    ):
        raise _error(
            "recovered_adoption_reconciled_inventory_invalid"
        )

    for field in (
        "final_parent_fsynced",
        "staging_parents_fsynced",
        "observations_rechecked_under_lock",
    ):
        if selected[field] is not True:
            raise _error(f"recovered_adoption_{field}_invalid")

    normalized = {
        "schema_version": RECOVERED_ADOPTION_EVIDENCE_SCHEMA,
        "status": RECOVERED_ADOPTION_STATUS,
        "transaction_journal_schema": TRANSACTION_JOURNAL_SCHEMA,
        "adoption_reconciliation_receipt_schema": (
            ADOPTION_RECONCILIATION_RECEIPT_SCHEMA
        ),
        "instance_slug": instance_slug,
        "capture_uid": capture_uid,
        "capture_export_gid": capture_export_gid,
        "final_object_owner_uid": 0,
        "verifier_gid": verifier_gid,
        "final_object_group_gid": final_group,
        "final_name": final_name,
        "final_parent_filesystem_device": final_device,
        "adoption_limits": limits,
        "reconciliation_result": RECOVERED_ADOPTION_STATUS,
        "final_observation": "exact_present",
        "staging_observation": "absent",
        "staging_terminal_disposition": "absent",
        "reconciled_file_count": file_count,
        "reconciled_directory_count": directory_count,
        "reconciled_total_bytes": total_bytes,
        "reconciled_largest_file_bytes": largest_file,
        "reconciled_maximum_depth": maximum_depth,
        "final_object_mode": ADOPTED_DIRECTORY_MODE,
        "final_object_nlink": final_nlink,
        "final_parent_fsynced": True,
        "staging_parents_fsynced": True,
        "observations_rechecked_under_lock": True,
    }
    for field in (
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
    ):
        normalized[field] = _digest(selected[field], field=field)
    return normalized


def recovered_adoption_evidence_sha256(
    value: Mapping[str, Any],
) -> str:
    """Digest one canonical recovered-adoption evidence object."""

    return hashlib.sha256(
        _canonical_json(normalize_recovered_adoption_evidence(value))
    ).hexdigest()


def _record_from_wrapper(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        raise _error(
            "recovered_adoption_journal_record_wrapper_required"
        )
    to_dict = getattr(value, "to_dict", None)
    if not callable(to_dict):
        raise _error(
            "recovered_adoption_journal_record_wrapper_required"
        )
    try:
        raw = to_dict()
    except Exception as exc:
        raise _error(
            "recovered_adoption_journal_record_wrapper_invalid"
        ) from exc
    return _normalize_record_value(raw)


def _normalize_record_value(raw: Any) -> dict[str, Any]:
    selected = _strict_mapping(
        raw,
        _RECORD_FIELDS,
        code="recovered_adoption_journal_record_fields_invalid",
    )
    if selected["schema_version"] != TRANSACTION_JOURNAL_SCHEMA:
        raise _error(
            "recovered_adoption_transaction_journal_schema_invalid"
        )
    instance_slug = _text(
        selected["instance_slug"],
        field="journal_instance_slug",
        expression=SLUG_RE,
    )
    session_id = _digest(
        selected["session_id"],
        field="journal_session_id",
    )
    revision = _integer(
        selected["revision"],
        field="journal_revision",
        minimum=1,
        maximum=32,
    )
    previous_digest = selected["previous_record_sha256"]
    if (
        not isinstance(previous_digest, str)
        or not SHA256_RE.fullmatch(previous_digest)
    ):
        raise _error(
            "recovered_adoption_journal_previous_record_sha256_invalid"
        )
    state = _text(
        selected["state"],
        field="journal_state",
        expression=STATE_RE,
    )
    recorded_at = _integer(
        selected["recorded_at_unix"],
        field="journal_recorded_at_unix",
        minimum=1,
    )
    control_digest = _digest(
        selected["control_sha256"],
        field="journal_control_sha256",
    )
    handoff_digest = _digest(
        selected["handoff_policy_sha256"],
        field="journal_handoff_policy_sha256",
    )
    if not isinstance(selected["details"], Mapping):
        raise _error("recovered_adoption_journal_details_invalid")
    details = dict(selected["details"])
    record_digest = _digest(
        selected["record_sha256"],
        field="journal_record_sha256",
    )
    normalized_without_digest = {
        "schema_version": TRANSACTION_JOURNAL_SCHEMA,
        "instance_slug": instance_slug,
        "session_id": session_id,
        "revision": revision,
        "previous_record_sha256": previous_digest,
        "state": state,
        "recorded_at_unix": recorded_at,
        "control_sha256": control_digest,
        "handoff_policy_sha256": handoff_digest,
        "details": details,
    }
    expected_digest = hashlib.sha256(
        _canonical_json(normalized_without_digest)
    ).hexdigest()
    if not hmac.compare_digest(record_digest, expected_digest):
        raise _error(
            "recovered_adoption_journal_record_digest_mismatch"
        )
    return {
        **normalized_without_digest,
        "record_sha256": record_digest,
    }


def _normalize_journal_history(
    values: Sequence[Any],
) -> tuple[dict[str, Any], ...]:
    if (
        isinstance(values, (str, bytes, bytearray))
        or not isinstance(values, Sequence)
        or not 1 <= len(values) <= 32
    ):
        raise _error("recovered_adoption_journal_history_invalid")
    records = tuple(_record_from_wrapper(value) for value in values)
    return _validate_journal_history_records(records)


def _validate_journal_history_records(
    records: tuple[dict[str, Any], ...],
) -> tuple[dict[str, Any], ...]:
    if not 1 <= len(records) <= 32:
        raise _error("recovered_adoption_journal_history_invalid")
    first = records[0]
    if first["state"] != "reserved":
        raise _error("recovered_adoption_journal_origin_invalid")
    constants = {
        field: first[field]
        for field in (
            "instance_slug",
            "session_id",
            "control_sha256",
            "handoff_policy_sha256",
        )
    }
    previous: dict[str, Any] | None = None
    for expected_revision, record in enumerate(records, start=1):
        if record["revision"] != expected_revision:
            raise _error("recovered_adoption_journal_revision_gap")
        if any(record[field] != value for field, value in constants.items()):
            raise _error("recovered_adoption_journal_binding_changed")
        if previous is None:
            if record["previous_record_sha256"] != ZERO_SHA256:
                raise _error(
                    "recovered_adoption_journal_previous_digest_mismatch"
                )
        else:
            if record["previous_record_sha256"] != previous[
                "record_sha256"
            ]:
                raise _error(
                    "recovered_adoption_journal_previous_digest_mismatch"
                )
            if record["recorded_at_unix"] < previous["recorded_at_unix"]:
                raise _error("recovered_adoption_journal_clock_rollback")
        previous = record
    if records[-1]["state"] != "adoption_reconciled":
        raise _error("recovered_adoption_journal_head_state_invalid")
    if any(record["state"] == "adopted" for record in records):
        raise _error("recovered_adoption_normal_adoption_claim_present")
    return records


def _mint_validated_recovered_adoption_history_v5(
    records: tuple[dict[str, Any], ...],
) -> ValidatedRecoveredAdoptionHistoryV5:
    """Construct the nominal capability from journal-validated records.

    This private helper owns no validation authority.  The production caller
    is the descriptor-bound journal session after its locked live rescan and
    complete transition-grammar validation.  The separate test seam below
    performs the pure module's intentionally narrower normalization first.
    """

    if (
        type(records) is not tuple
        or not records
        or any(type(record) is not dict for record in records)
    ):
        raise _error(
            "recovered_adoption_validated_journal_records_invalid"
        )
    return ValidatedRecoveredAdoptionHistoryV5._mint(
        _token=_HISTORY_CAPABILITY_TOKEN,
        records=records,
    )


def _mint_validated_recovered_adoption_history_v5_for_test(
    journal_records: Sequence[Any],
) -> ValidatedRecoveredAdoptionHistoryV5:
    """Test-only nominal mint; it is not production journal authority."""

    records = _normalize_journal_history(journal_records)
    return _mint_validated_recovered_adoption_history_v5(records)


def _unique_state(
    records: tuple[dict[str, Any], ...],
    state: str,
) -> tuple[int, dict[str, Any]]:
    matches = tuple(
        (index, record)
        for index, record in enumerate(records)
        if record["state"] == state
    )
    if len(matches) != 1:
        raise _error(
            f"recovered_adoption_journal_{state}_record_invalid"
        )
    return matches[0]


def _selected_details(
    record: Mapping[str, Any],
    state: str,
) -> dict[str, Any]:
    return _strict_mapping(
        record["details"],
        _SELECTED_DETAIL_FIELDS[state],
        code=f"recovered_adoption_journal_{state}_details_invalid",
    )


def _validated_lifecycle_operation_binding(
    *,
    record: Mapping[str, Any],
    immediate_base: Mapping[str, Any],
    permitted_operations: frozenset[str],
    capture_ready_details: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Revalidate one evidence-relevant journal-v5 operation binding."""

    state = record["state"]
    selected = _strict_mapping(
        record["details"]["lifecycle_operation_binding"],
        _LIFECYCLE_OPERATION_BINDING_FIELDS,
        code=(
            f"recovered_adoption_journal_{state}_"
            "lifecycle_operation_binding_fields_invalid"
        ),
    )
    if (
        selected["schema_version"]
        != LIFECYCLE_OPERATION_BINDING_SCHEMA
    ):
        raise _error(
            f"recovered_adoption_journal_{state}_"
            "lifecycle_operation_binding_schema_invalid"
        )
    if selected["operation"] not in permitted_operations:
        raise _error(
            f"recovered_adoption_journal_{state}_"
            "lifecycle_operation_invalid"
        )
    base_revision = _integer(
        selected["base_record_revision"],
        field=f"{state}_lifecycle_operation_base_record_revision",
        minimum=1,
        maximum=32,
    )
    base_digest = _digest(
        selected["base_record_sha256"],
        field=f"{state}_lifecycle_operation_base_record_sha256",
    )
    if (
        base_revision != immediate_base["revision"]
        or base_digest != immediate_base["record_sha256"]
    ):
        raise _error(
            f"recovered_adoption_journal_{state}_"
            "lifecycle_operation_base_mismatch"
        )
    if (
        selected["outcome"] != "success"
        or selected["error_code"] is not None
    ):
        raise _error(
            f"recovered_adoption_journal_{state}_"
            "lifecycle_operation_success_invalid"
        )
    for field in (
        "request_sha256",
        "response_sha256",
        "result_sha256",
        "supervisor_ledger_head_sha256",
    ):
        _digest(
            selected[field],
            field=f"{state}_lifecycle_operation_{field}",
        )

    if capture_ready_details is None:
        if any(
            selected[field] is not None
            for field in (
                "supervisor_event_sequence",
                "supervisor_event",
                "supervisor_event_record_sha256",
                "supervisor_event_evidence_sha256",
            )
        ):
            raise _error(
                f"recovered_adoption_journal_{state}_"
                "lifecycle_operation_settled_head_invalid"
            )
        return selected

    _integer(
        selected["supervisor_event_sequence"],
        field=f"{state}_lifecycle_operation_supervisor_event_sequence",
        minimum=1,
    )
    if selected["supervisor_event"] != "capture_ready":
        raise _error(
            f"recovered_adoption_journal_{state}_"
            "lifecycle_operation_event_invalid"
        )
    _digest(
        selected["supervisor_event_record_sha256"],
        field=(
            f"{state}_lifecycle_operation_"
            "supervisor_event_record_sha256"
        ),
    )
    observed_evidence_digest = _digest(
        selected["supervisor_event_evidence_sha256"],
        field=(
            f"{state}_lifecycle_operation_"
            "supervisor_event_evidence_sha256"
        ),
    )
    exact_capture_evidence = {
        field: capture_ready_details[field]
        for field in _CAPTURE_READY_EVIDENCE_FIELDS
    }
    expected_evidence_digest = hashlib.sha256(
        _canonical_json(
            {
                "schema_version": (
                    LIFECYCLE_CAPTURE_EVENT_EVIDENCE_SCHEMA
                ),
                "capture_ready": exact_capture_evidence,
            }
        )
    ).hexdigest()
    if not hmac.compare_digest(
        observed_evidence_digest, expected_evidence_digest
    ):
        raise _error(
            "recovered_adoption_journal_capture_ready_"
            "event_evidence_mismatch"
        )
    return selected


def _immediate_base(
    records: tuple[dict[str, Any], ...],
    record: Mapping[str, Any],
) -> dict[str, Any]:
    index = record["revision"] - 1
    if (
        index <= 0
        or index >= len(records)
        or records[index] is not record
    ):
        raise _error(
            f"recovered_adoption_journal_{record['state']}_"
            "lifecycle_operation_base_missing"
        )
    return records[index - 1]


def _assert_equal(
    observed: Any,
    expected: Any,
    *,
    field: str,
) -> None:
    if observed != expected:
        raise _error(f"recovered_adoption_{field}_mismatch")


def bind_recovered_adoption_evidence(
    *,
    validated_history: ValidatedRecoveredAdoptionHistoryV5,
    adoption_reconciliation_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Derive evidence only from a v5 journal chain and its sidecar receipt.

    The full reconciliation receipt remains a sidecar: the returned evidence
    binds its canonical digest but never embeds it.  In production,
    ``validated_history`` can be obtained only through the descriptor-bound
    journal session's locked, zero-input mint.
    """

    if type(validated_history) is not ValidatedRecoveredAdoptionHistoryV5:
        raise _error(
            "recovered_adoption_validated_history_capability_required"
        )
    try:
        stored_records = validated_history._records_for_binding(
            _token=_HISTORY_CAPABILITY_TOKEN
        )
        records = _validate_journal_history_records(
            tuple(
                _normalize_record_value(record)
                for record in stored_records
            )
        )
    except (
        AssertionError,
        AttributeError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise _error(
            "recovered_adoption_validated_history_capability_invalid"
        ) from exc
    try:
        receipt = (
            adoption_reconciliation
            .normalize_adoption_reconciliation_receipt(
                adoption_reconciliation_receipt
            )
        )
        receipt_digest = (
            adoption_reconciliation
            .adoption_reconciliation_receipt_sha256(receipt)
        )
    except adoption_reconciliation.AdoptionReconciliationError as exc:
        raise _error(
            f"recovered_adoption_{exc.code}"
        ) from exc

    selected_records: dict[str, dict[str, Any]] = {}
    positions: list[int] = []
    for state in _REQUIRED_STATES:
        position, record = _unique_state(records, state)
        positions.append(position)
        selected_records[state] = record
    if positions != sorted(positions) or len(set(positions)) != len(positions):
        raise _error("recovered_adoption_journal_state_order_invalid")

    staging_intent = selected_records["staging_create_intent"]
    capture_ready = selected_records["capture_ready"]
    scope_empty = selected_records["lifecycle_scope_empty"]
    adoption_intent = selected_records["adoption_intent"]
    reconciliation_required = selected_records[
        "adoption_reconciliation_required"
    ]
    reconciled = selected_records["adoption_reconciled"]

    staging_details = _selected_details(
        staging_intent, "staging_create_intent"
    )
    capture_details = _selected_details(capture_ready, "capture_ready")
    scope_details = _selected_details(
        scope_empty, "lifecycle_scope_empty"
    )
    adoption_details = _selected_details(
        adoption_intent, "adoption_intent"
    )
    required_details = _selected_details(
        reconciliation_required,
        "adoption_reconciliation_required",
    )
    reconciled_details = _selected_details(
        reconciled, "adoption_reconciled"
    )

    _validated_lifecycle_operation_binding(
        record=capture_ready,
        immediate_base=_immediate_base(records, capture_ready),
        permitted_operations=frozenset(
            {"await_capture_event", "recover_scope"}
        ),
        capture_ready_details=capture_details,
    )
    _validated_lifecycle_operation_binding(
        record=scope_empty,
        immediate_base=_immediate_base(records, scope_empty),
        permitted_operations=frozenset(
            {"request_clearance", "recover_scope"}
        ),
        capture_ready_details=None,
    )

    if required_details["from_state"] != "staging_tombstone_ack_pending":
        raise _error(
            "recovered_adoption_reconciliation_required_origin_invalid"
        )
    _assert_equal(
        required_details["adoption_intent_record_sha256"],
        adoption_intent["record_sha256"],
        field="required_adoption_intent_record_sha256",
    )
    _assert_equal(
        reconciled_details[
            "adoption_reconciliation_required_record_sha256"
        ],
        reconciliation_required["record_sha256"],
        field="reconciled_required_record_sha256",
    )
    embedded_receipt = reconciled_details[
        "adoption_reconciliation_receipt"
    ]
    try:
        normalized_embedded = (
            adoption_reconciliation
            .normalize_adoption_reconciliation_receipt(
                embedded_receipt
            )
        )
        embedded_digest = (
            adoption_reconciliation
            .adoption_reconciliation_receipt_sha256(
                normalized_embedded
            )
        )
    except adoption_reconciliation.AdoptionReconciliationError as exc:
        raise _error(
            f"recovered_adoption_{exc.code}"
        ) from exc
    _assert_equal(
        reconciled_details[
            "adoption_reconciliation_receipt_sha256"
        ],
        embedded_digest,
        field="journal_reconciliation_receipt_sha256",
    )
    _assert_equal(
        normalized_embedded,
        receipt,
        field="reconciliation_receipt_sidecar",
    )
    _assert_equal(
        receipt_digest,
        embedded_digest,
        field="reconciliation_receipt_sha256",
    )

    bundle = scope_details["lifecycle_clearance_bundle"]
    if not isinstance(bundle, Mapping):
        raise _error(
            "recovered_adoption_lifecycle_clearance_bundle_invalid"
        )
    scope_receipt_digest = _digest(
        bundle.get("scope_empty_receipt_sha256"),
        field="lifecycle_scope_empty_receipt_sha256",
    )
    limits = _adoption_limits(adoption_details["limits"])

    expected_receipt_fields = {
        "capture_session_id": records[0]["session_id"],
        "adoption_intent_record_sha256": adoption_intent[
            "record_sha256"
        ],
        "adoption_policy_sha256": adoption_details[
            "adoption_policy_sha256"
        ],
        "lifecycle_scope_empty_receipt_sha256": scope_receipt_digest,
        "staging_transaction_intent_sha256": staging_intent[
            "record_sha256"
        ],
        "staging_terminal_receipt_sha256": required_details[
            "terminal_receipt_sha256"
        ],
        "staging_tombstone_sha256": required_details[
            "tombstone_sha256"
        ],
        "staging_terminal_disposition": "absent",
        "final_parent_identity_sha256": adoption_details[
            "final_parent_identity_sha256"
        ],
        "final_parent_filesystem_device": adoption_details[
            "final_parent_filesystem_device"
        ],
        "final_name": adoption_details["final_name"],
        "expected_object_identity_sha256": adoption_details[
            "capture_object_identity_sha256"
        ],
        "expected_verifier_gid": adoption_details["verifier_gid"],
        "adoption_limits": limits,
        "result": RECOVERED_ADOPTION_STATUS,
        "final_observation": "exact_present",
        "staging_observation": "absent",
        "final_object_identity_sha256": adoption_details[
            "capture_object_identity_sha256"
        ],
        "final_object_owner_uid": 0,
        "final_object_group_gid": adoption_details["verifier_gid"],
        "final_object_mode": ADOPTED_DIRECTORY_MODE,
        "final_parent_fsynced": True,
        "staging_parents_fsynced": True,
        "observations_rechecked_under_lock": True,
    }
    for field, expected in expected_receipt_fields.items():
        _assert_equal(
            receipt[field],
            expected,
            field=f"reconciliation_{field}",
        )

    _assert_equal(
        staging_details["required_device"],
        adoption_details["final_parent_filesystem_device"],
        field="staging_final_filesystem_device",
    )
    _assert_equal(
        capture_details["provisional_name"],
        adoption_details["provisional_name"],
        field="provisional_name",
    )
    _assert_equal(
        capture_details["capture_object_identity_sha256"],
        adoption_details["capture_object_identity_sha256"],
        field="capture_object_identity_sha256",
    )

    evidence = {
        "schema_version": RECOVERED_ADOPTION_EVIDENCE_SCHEMA,
        "status": RECOVERED_ADOPTION_STATUS,
        "transaction_journal_schema": TRANSACTION_JOURNAL_SCHEMA,
        "adoption_reconciliation_receipt_schema": (
            ADOPTION_RECONCILIATION_RECEIPT_SCHEMA
        ),
        "instance_slug": records[0]["instance_slug"],
        "capture_session_id": records[0]["session_id"],
        "staging_transaction_intent_record_sha256": staging_intent[
            "record_sha256"
        ],
        "capture_ready_record_sha256": capture_ready["record_sha256"],
        "lifecycle_scope_empty_record_sha256": scope_empty[
            "record_sha256"
        ],
        "lifecycle_scope_empty_receipt_sha256": scope_receipt_digest,
        "adoption_intent_record_sha256": adoption_intent[
            "record_sha256"
        ],
        "adoption_reconciliation_required_record_sha256": (
            reconciliation_required["record_sha256"]
        ),
        "adoption_reconciliation_record_sha256": reconciled[
            "record_sha256"
        ],
        "adoption_reconciliation_receipt_sha256": receipt_digest,
        "capture_uid": staging_details["capture_uid"],
        "capture_export_gid": staging_details["export_gid"],
        "final_object_owner_uid": receipt["final_object_owner_uid"],
        "verifier_gid": adoption_details["verifier_gid"],
        "final_object_group_gid": receipt["final_object_group_gid"],
        "capture_adoption_policy_sha256": adoption_details[
            "adoption_policy_sha256"
        ],
        "capture_selection_sha256": capture_details[
            "capture_selection_sha256"
        ],
        "capture_plan_sha256": capture_details["capture_plan_sha256"],
        "capture_manifest_sha256": capture_details[
            "capture_manifest_sha256"
        ],
        "capture_request_sha256": capture_details["request_sha256"],
        "capture_boundary_policy_sha256": capture_details[
            "capture_boundary_policy_sha256"
        ],
        "helper_activation_policy_sha256": capture_details[
            "helper_activation_policy_sha256"
        ],
        "final_name": adoption_details["final_name"],
        "final_parent_identity_sha256": adoption_details[
            "final_parent_identity_sha256"
        ],
        "final_parent_filesystem_device": adoption_details[
            "final_parent_filesystem_device"
        ],
        "capture_object_identity_sha256": adoption_details[
            "capture_object_identity_sha256"
        ],
        "adoption_limits": limits,
        "reconciliation_result": RECOVERED_ADOPTION_STATUS,
        "final_observation": "exact_present",
        "staging_observation": "absent",
        "staging_terminal_disposition": "absent",
        "reconciled_final_object_stat_sha256": receipt[
            "final_object_stat_sha256"
        ],
        "reconciled_content_inventory_sha256": receipt[
            "final_content_inventory_sha256"
        ],
        "reconciled_file_count": receipt["final_file_count"],
        "reconciled_directory_count": receipt[
            "final_directory_count"
        ],
        "reconciled_total_bytes": receipt["final_total_bytes"],
        "reconciled_largest_file_bytes": receipt[
            "final_largest_file_bytes"
        ],
        "reconciled_maximum_depth": receipt["final_maximum_depth"],
        "final_object_mode": receipt["final_object_mode"],
        "final_object_nlink": receipt["final_object_nlink"],
        "staging_terminal_receipt_sha256": required_details[
            "terminal_receipt_sha256"
        ],
        "staging_tombstone_sha256": required_details[
            "tombstone_sha256"
        ],
        "dual_parent_lock_epoch_sha256": receipt[
            "dual_parent_lock_epoch_sha256"
        ],
        "final_parent_fsynced": True,
        "staging_parents_fsynced": True,
        "observations_rechecked_under_lock": True,
    }
    return normalize_recovered_adoption_evidence(evidence)


__all__ = [
    "ADOPTED_DIRECTORY_MODE",
    "ADOPTION_LIMIT_FIELDS",
    "ADOPTION_RECONCILIATION_RECEIPT_SCHEMA",
    "LIFECYCLE_OPERATION_BINDING_SCHEMA",
    "PRODUCTION_ACTIVATION",
    "RECOVERED_ADOPTION_EVIDENCE_FIELDS",
    "RECOVERED_ADOPTION_EVIDENCE_SCHEMA",
    "RECOVERED_ADOPTION_STATUS",
    "TRANSACTION_JOURNAL_SCHEMA",
    "ZERO_SHA256",
    "RecoveredAdoptionEvidenceError",
    "ValidatedRecoveredAdoptionHistoryV5",
    "bind_recovered_adoption_evidence",
    "normalize_recovered_adoption_evidence",
    "recovered_adoption_evidence_sha256",
]
