"""Pure canonical receipts for the protected capture-staging boundary.

The module deliberately owns no filesystem descriptor, process, signalling,
signing, verifier, publication, clock, or path authority.  It only validates
path-free receipt values and computes their canonical SHA-256 digests.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping
from typing import Any


STAGING_EXPOSURE_RECEIPT_SCHEMA = (
    "john-lomein.persona-qualification-staging-exposure-receipt.v1"
)
STAGING_ABSENCE_RECEIPT_SCHEMA = (
    "john-lomein.persona-qualification-staging-absence-receipt.v1"
)
STAGING_QUARANTINE_RECEIPT_SCHEMA = (
    "john-lomein.persona-qualification-staging-quarantine-receipt.v1"
)
STAGING_TOMBSTONE_ACK_RECEIPT_SCHEMA = (
    "john-lomein.persona-qualification-staging-tombstone-ack-receipt.v1"
)
CAPTURE_STAGING_JOURNAL_SCHEMA = (
    "john-lomein.persona-qualification-capture-staging-journal.v3"
)

STAGING_EXPOSURE_STATUS = "staging_exposed"
STAGING_ABSENCE_STATUS = "staging_absent"
STAGING_QUARANTINE_STATUS = "staging_quarantined"
STAGING_TOMBSTONE_ACK_STATUS = "tombstone_acknowledged"
STAGING_TOMBSTONE_ACK_EVENT = "outer_tombstone_acknowledged"
STAGING_EXPOSED_LEAF_MODE = 0o700
STAGING_EXPOSURE_JOURNAL_SEQUENCE = 3
STAGING_QUARANTINE_NAMESPACE = "staging"

STAGING_EXPOSURE_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "capture_session_id",
        "staging_leaf_name",
        "staging_transaction_intent_sha256",
        "staging_leaf_identity_sha256",
        "capture_uid",
        "export_gid",
        "staging_leaf_mode",
        "filesystem_device",
        "shared_root_identity_sha256",
        "recovery_namespace_identity_sha256",
        "quarantine_namespace_identity_sha256",
        "transactions_namespace_identity_sha256",
        "staging_journal_schema",
        "staging_journal_sequence",
        "staging_journal_head_sha256",
    }
)

STAGING_ABSENCE_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "capture_session_id",
        "staging_leaf_name",
        "staging_transaction_intent_sha256",
        "staging_leaf_identity_sha256",
        "filesystem_device",
        "shared_root_identity_sha256",
        "recovery_namespace_identity_sha256",
        "quarantine_namespace_identity_sha256",
        "transactions_namespace_identity_sha256",
        "staging_journal_schema",
        "terminal_event",
        "terminal_sequence",
        "terminal_record_sha256",
        "tombstone_sha256",
        "quarantine_reason_code",
        "inspection_lock_epoch_sha256",
        "lifecycle_status",
        "lifecycle_scope_empty_receipt_sha256",
    }
)

STAGING_QUARANTINE_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "capture_session_id",
        "staging_leaf_name",
        "staging_transaction_intent_sha256",
        "staging_leaf_identity_sha256",
        "filesystem_device",
        "shared_root_identity_sha256",
        "recovery_namespace_identity_sha256",
        "quarantine_namespace_identity_sha256",
        "transactions_namespace_identity_sha256",
        "staging_journal_schema",
        "inspection_lock_epoch_sha256",
        "quarantine_namespace",
        "quarantine_name",
        "quarantined_stat_sha256",
        "reason_code",
        "lifecycle_status",
        "lifecycle_scope_empty_receipt_sha256",
        "rename_primitive",
        "rename_noreplace",
        "parents_fsynced",
        "terminal_event",
        "terminal_sequence",
        "terminal_record_sha256",
        "tombstone_sha256",
    }
)

STAGING_TOMBSTONE_ACK_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "capture_session_id",
        "staging_transaction_intent_sha256",
        "terminal_receipt_sha256",
        "tombstone_sha256",
        "outer_ack_pending_record_sha256",
        "outer_quarantine_intent_record_sha256",
        "outer_lifecycle_clearance_record_sha256",
        "terminal_disposition",
        "staging_journal_schema",
        "ack_event",
        "ack_sequence",
        "ack_previous_record_sha256",
        "ack_record_sha256",
        "inspection_lock_epoch_sha256",
        "journal_storage_disposition",
        "ack_journal_identity_sha256",
        "ack_journal_readback_sha256",
        "transactions_parent_fsynced",
        "completed_parent_fsynced",
    }
)

LIFECYCLE_STATUSES = frozenset(
    {"not_applicable", "scope_empty", "scope_not_proven"}
)
RENAME_PRIMITIVES = frozenset(
    {"renameat2_noreplace", "renameatx_np_excl"}
)
TERMINAL_DISPOSITIONS = frozenset({"absent", "quarantined"})
JOURNAL_STORAGE_DISPOSITIONS = frozenset(
    {
        "completed_absence_journal",
        "retained_quarantine_journal",
    }
)
ABSENCE_TERMINAL_EVENTS = frozenset(
    {
        "removed",
        "quarantine_removed",
        "startup_absent",
    }
)
QUARANTINE_TERMINAL_EVENTS = frozenset(
    {"quarantined", "startup_quarantined"}
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SESSION_ID_RE = SHA256_RE
SESSION_NAME_RE = re.compile(r"^session-([0-9a-f]{64})$")
TOKEN_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_IDENTITY = (1 << 31) - 1
MAX_DEVICE = (1 << 63) - 1


class CaptureStagingReceiptError(ValueError):
    """Stable public-safe rejection from the pure receipt boundary."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _error(code: str) -> CaptureStagingReceiptError:
    return CaptureStagingReceiptError(code)


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise _error("capture_staging_receipt_json_invalid") from exc


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _strict_mapping(
    value: Any,
    fields: frozenset[str],
    *,
    code: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise _error(code)
    return {field: value[field] for field in fields}


def _nfc_ascii_token(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or unicodedata.normalize("NFC", value) != value
        or TOKEN_RE.fullmatch(value) is None
    ):
        raise _error(f"{field}_invalid")
    return value


def _session_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or unicodedata.normalize("NFC", value) != value
        or SESSION_ID_RE.fullmatch(value) is None
    ):
        raise _error("capture_staging_receipt_session_id_invalid")
    return value


def _staging_leaf_name(value: Any, *, session_id: str) -> str:
    if (
        not isinstance(value, str)
        or unicodedata.normalize("NFC", value) != value
        or SESSION_NAME_RE.fullmatch(value) is None
        or value != f"session-{session_id}"
    ):
        raise _error("capture_staging_receipt_leaf_name_invalid")
    return value


def _digest(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise _error(f"{field}_invalid")
    return value


def _nullable_digest(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    return _digest(value, field=field)


def _integer(
    value: Any,
    *,
    field: str,
    minimum: int = 0,
    maximum: int = MAX_SAFE_INTEGER,
) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise _error(f"{field}_invalid")
    return value


def _schema(value: Any, expected: str, *, field: str) -> str:
    if value != expected:
        raise _error(f"{field}_invalid")
    return expected


def _status(value: Any, expected: str, *, field: str) -> str:
    if value != expected:
        raise _error(f"{field}_invalid")
    return expected


def _journal_schema(value: Any) -> str:
    return _schema(
        value,
        CAPTURE_STAGING_JOURNAL_SCHEMA,
        field="capture_staging_receipt_journal_schema",
    )


def _common_session(
    selected: Mapping[str, Any],
) -> tuple[str, str]:
    session_id = _session_id(selected["capture_session_id"])
    leaf_name = _staging_leaf_name(
        selected["staging_leaf_name"],
        session_id=session_id,
    )
    return session_id, leaf_name


def normalize_staging_exposure_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize one durable, path-free staging-exposure receipt."""

    selected = _strict_mapping(
        value,
        STAGING_EXPOSURE_RECEIPT_FIELDS,
        code="capture_staging_exposure_receipt_fields_invalid",
    )
    session_id, leaf_name = _common_session(selected)
    leaf_mode = _integer(
        selected["staging_leaf_mode"],
        field="capture_staging_exposure_receipt_staging_leaf_mode",
        maximum=0o7777,
    )
    if leaf_mode != STAGING_EXPOSED_LEAF_MODE:
        raise _error(
            "capture_staging_exposure_receipt_staging_leaf_mode_invalid"
        )
    journal_sequence = _integer(
        selected["staging_journal_sequence"],
        field="capture_staging_exposure_receipt_journal_sequence",
        minimum=3,
    )
    if journal_sequence != STAGING_EXPOSURE_JOURNAL_SEQUENCE:
        raise _error(
            "capture_staging_exposure_receipt_journal_sequence_invalid"
        )
    return {
        "schema_version": _schema(
            selected["schema_version"],
            STAGING_EXPOSURE_RECEIPT_SCHEMA,
            field="capture_staging_exposure_receipt_schema",
        ),
        "status": _status(
            selected["status"],
            STAGING_EXPOSURE_STATUS,
            field="capture_staging_exposure_receipt_status",
        ),
        "capture_session_id": session_id,
        "staging_leaf_name": leaf_name,
        "staging_transaction_intent_sha256": _digest(
            selected["staging_transaction_intent_sha256"],
            field=(
                "capture_staging_exposure_receipt_"
                "transaction_intent_sha256"
            ),
        ),
        "staging_leaf_identity_sha256": _digest(
            selected["staging_leaf_identity_sha256"],
            field=(
                "capture_staging_exposure_receipt_"
                "leaf_identity_sha256"
            ),
        ),
        "capture_uid": _integer(
            selected["capture_uid"],
            field="capture_staging_exposure_receipt_capture_uid",
            minimum=1,
            maximum=MAX_IDENTITY,
        ),
        "export_gid": _integer(
            selected["export_gid"],
            field="capture_staging_exposure_receipt_export_gid",
            minimum=1,
            maximum=MAX_IDENTITY,
        ),
        "staging_leaf_mode": leaf_mode,
        "filesystem_device": _integer(
            selected["filesystem_device"],
            field="capture_staging_exposure_receipt_filesystem_device",
            maximum=MAX_DEVICE,
        ),
        "shared_root_identity_sha256": _digest(
            selected["shared_root_identity_sha256"],
            field=(
                "capture_staging_exposure_receipt_"
                "shared_root_identity_sha256"
            ),
        ),
        "recovery_namespace_identity_sha256": _digest(
            selected["recovery_namespace_identity_sha256"],
            field=(
                "capture_staging_exposure_receipt_"
                "recovery_namespace_identity_sha256"
            ),
        ),
        "quarantine_namespace_identity_sha256": _digest(
            selected["quarantine_namespace_identity_sha256"],
            field=(
                "capture_staging_exposure_receipt_"
                "quarantine_namespace_identity_sha256"
            ),
        ),
        "transactions_namespace_identity_sha256": _digest(
            selected["transactions_namespace_identity_sha256"],
            field=(
                "capture_staging_exposure_receipt_"
                "transactions_namespace_identity_sha256"
            ),
        ),
        "staging_journal_schema": _journal_schema(
            selected["staging_journal_schema"]
        ),
        "staging_journal_sequence": journal_sequence,
        "staging_journal_head_sha256": _digest(
            selected["staging_journal_head_sha256"],
            field=(
                "capture_staging_exposure_receipt_"
                "journal_head_sha256"
            ),
        ),
    }


def staging_exposure_receipt_sha256(
    value: Mapping[str, Any],
) -> str:
    """Return the canonical digest of one exposure receipt."""

    return _sha256(
        _canonical_json(normalize_staging_exposure_receipt(value))
    )


def normalize_staging_absence_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize one locked inspection proving the exact leaf is absent."""

    selected = _strict_mapping(
        value,
        STAGING_ABSENCE_RECEIPT_FIELDS,
        code="capture_staging_absence_receipt_fields_invalid",
    )
    session_id, leaf_name = _common_session(selected)
    leaf_identity = _nullable_digest(
        selected["staging_leaf_identity_sha256"],
        field=(
            "capture_staging_absence_receipt_"
            "leaf_identity_sha256"
        ),
    )
    terminal_event = _nfc_ascii_token(
        selected["terminal_event"],
        field="capture_staging_absence_receipt_terminal_event",
    )
    if terminal_event not in ABSENCE_TERMINAL_EVENTS:
        raise _error(
            "capture_staging_absence_receipt_terminal_event_invalid"
        )
    if terminal_event != "startup_absent" and leaf_identity is None:
        raise _error(
            "capture_staging_absence_receipt_leaf_identity_required"
        )
    selected_reason = selected["quarantine_reason_code"]
    quarantine_reason = (
        None
        if selected_reason is None
        else _nfc_ascii_token(
            selected_reason,
            field=(
                "capture_staging_absence_receipt_"
                "quarantine_reason_code"
            ),
        )
    )
    if (
        terminal_event == "quarantine_removed"
        and quarantine_reason is None
    ):
        raise _error(
            "capture_staging_absence_receipt_"
            "quarantine_reason_required"
        )
    if terminal_event == "removed" and quarantine_reason is not None:
        raise _error(
            "capture_staging_absence_receipt_"
            "quarantine_reason_unexpected"
        )
    lifecycle_status = selected["lifecycle_status"]
    if lifecycle_status not in LIFECYCLE_STATUSES:
        raise _error(
            "capture_staging_absence_receipt_lifecycle_status_invalid"
        )
    scope_receipt = _nullable_digest(
        selected["lifecycle_scope_empty_receipt_sha256"],
        field=(
            "capture_staging_absence_receipt_"
            "lifecycle_scope_empty_receipt_sha256"
        ),
    )
    if (lifecycle_status == "scope_empty") != (
        scope_receipt is not None
    ):
        raise _error(
            "capture_staging_absence_receipt_"
            "lifecycle_scope_receipt_invalid"
        )
    return {
        "schema_version": _schema(
            selected["schema_version"],
            STAGING_ABSENCE_RECEIPT_SCHEMA,
            field="capture_staging_absence_receipt_schema",
        ),
        "status": _status(
            selected["status"],
            STAGING_ABSENCE_STATUS,
            field="capture_staging_absence_receipt_status",
        ),
        "capture_session_id": session_id,
        "staging_leaf_name": leaf_name,
        "staging_transaction_intent_sha256": _digest(
            selected["staging_transaction_intent_sha256"],
            field=(
                "capture_staging_absence_receipt_"
                "transaction_intent_sha256"
            ),
        ),
        "staging_leaf_identity_sha256": leaf_identity,
        "filesystem_device": _integer(
            selected["filesystem_device"],
            field="capture_staging_absence_receipt_filesystem_device",
            maximum=MAX_DEVICE,
        ),
        "shared_root_identity_sha256": _digest(
            selected["shared_root_identity_sha256"],
            field=(
                "capture_staging_absence_receipt_"
                "shared_root_identity_sha256"
            ),
        ),
        "recovery_namespace_identity_sha256": _digest(
            selected["recovery_namespace_identity_sha256"],
            field=(
                "capture_staging_absence_receipt_"
                "recovery_namespace_identity_sha256"
            ),
        ),
        "quarantine_namespace_identity_sha256": _digest(
            selected["quarantine_namespace_identity_sha256"],
            field=(
                "capture_staging_absence_receipt_"
                "quarantine_namespace_identity_sha256"
            ),
        ),
        "transactions_namespace_identity_sha256": _digest(
            selected["transactions_namespace_identity_sha256"],
            field=(
                "capture_staging_absence_receipt_"
                "transactions_namespace_identity_sha256"
            ),
        ),
        "staging_journal_schema": _journal_schema(
            selected["staging_journal_schema"]
        ),
        "terminal_event": terminal_event,
        "terminal_sequence": _integer(
            selected["terminal_sequence"],
            field="capture_staging_absence_receipt_terminal_sequence",
        ),
        "terminal_record_sha256": _digest(
            selected["terminal_record_sha256"],
            field=(
                "capture_staging_absence_receipt_"
                "terminal_record_sha256"
            ),
        ),
        "tombstone_sha256": _digest(
            selected["tombstone_sha256"],
            field=(
                "capture_staging_absence_receipt_tombstone_sha256"
            ),
        ),
        "quarantine_reason_code": quarantine_reason,
        "inspection_lock_epoch_sha256": _digest(
            selected["inspection_lock_epoch_sha256"],
            field=(
                "capture_staging_absence_receipt_"
                "inspection_lock_epoch_sha256"
            ),
        ),
        "lifecycle_status": lifecycle_status,
        "lifecycle_scope_empty_receipt_sha256": scope_receipt,
    }


def staging_absence_receipt_sha256(
    value: Mapping[str, Any],
) -> str:
    """Return the canonical digest of one absence receipt."""

    return _sha256(
        _canonical_json(normalize_staging_absence_receipt(value))
    )


def normalize_staging_quarantine_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize one exact, no-replace staging-quarantine receipt."""

    selected = _strict_mapping(
        value,
        STAGING_QUARANTINE_RECEIPT_FIELDS,
        code="capture_staging_quarantine_receipt_fields_invalid",
    )
    session_id, leaf_name = _common_session(selected)
    quarantine_namespace = selected["quarantine_namespace"]
    if quarantine_namespace != STAGING_QUARANTINE_NAMESPACE:
        raise _error(
            "capture_staging_quarantine_receipt_namespace_invalid"
        )
    quarantine_name = _staging_leaf_name(
        selected["quarantine_name"],
        session_id=session_id,
    )
    if quarantine_name != leaf_name:
        raise _error(
            "capture_staging_quarantine_receipt_name_mismatch"
        )
    lifecycle_status = selected["lifecycle_status"]
    if lifecycle_status not in LIFECYCLE_STATUSES:
        raise _error(
            "capture_staging_quarantine_receipt_lifecycle_status_invalid"
        )
    scope_receipt = _nullable_digest(
        selected["lifecycle_scope_empty_receipt_sha256"],
        field=(
            "capture_staging_quarantine_receipt_"
            "lifecycle_scope_empty_receipt_sha256"
        ),
    )
    if (lifecycle_status == "scope_empty") != (
        scope_receipt is not None
    ):
        raise _error(
            "capture_staging_quarantine_receipt_"
            "lifecycle_scope_receipt_invalid"
        )
    rename_primitive = selected["rename_primitive"]
    if rename_primitive not in RENAME_PRIMITIVES:
        raise _error(
            "capture_staging_quarantine_receipt_rename_primitive_invalid"
        )
    if selected["rename_noreplace"] is not True:
        raise _error(
            "capture_staging_quarantine_receipt_rename_noreplace_invalid"
        )
    if selected["parents_fsynced"] is not True:
        raise _error(
            "capture_staging_quarantine_receipt_parents_fsynced_invalid"
        )
    terminal_event = _nfc_ascii_token(
        selected["terminal_event"],
        field="capture_staging_quarantine_receipt_terminal_event",
    )
    if terminal_event not in QUARANTINE_TERMINAL_EVENTS:
        raise _error(
            "capture_staging_quarantine_receipt_terminal_event_invalid"
        )
    return {
        "schema_version": _schema(
            selected["schema_version"],
            STAGING_QUARANTINE_RECEIPT_SCHEMA,
            field="capture_staging_quarantine_receipt_schema",
        ),
        "status": _status(
            selected["status"],
            STAGING_QUARANTINE_STATUS,
            field="capture_staging_quarantine_receipt_status",
        ),
        "capture_session_id": session_id,
        "staging_leaf_name": leaf_name,
        "staging_transaction_intent_sha256": _digest(
            selected["staging_transaction_intent_sha256"],
            field=(
                "capture_staging_quarantine_receipt_"
                "transaction_intent_sha256"
            ),
        ),
        "staging_leaf_identity_sha256": _digest(
            selected["staging_leaf_identity_sha256"],
            field=(
                "capture_staging_quarantine_receipt_"
                "leaf_identity_sha256"
            ),
        ),
        "filesystem_device": _integer(
            selected["filesystem_device"],
            field=(
                "capture_staging_quarantine_receipt_filesystem_device"
            ),
            maximum=MAX_DEVICE,
        ),
        "shared_root_identity_sha256": _digest(
            selected["shared_root_identity_sha256"],
            field=(
                "capture_staging_quarantine_receipt_"
                "shared_root_identity_sha256"
            ),
        ),
        "recovery_namespace_identity_sha256": _digest(
            selected["recovery_namespace_identity_sha256"],
            field=(
                "capture_staging_quarantine_receipt_"
                "recovery_namespace_identity_sha256"
            ),
        ),
        "quarantine_namespace_identity_sha256": _digest(
            selected["quarantine_namespace_identity_sha256"],
            field=(
                "capture_staging_quarantine_receipt_"
                "quarantine_namespace_identity_sha256"
            ),
        ),
        "transactions_namespace_identity_sha256": _digest(
            selected["transactions_namespace_identity_sha256"],
            field=(
                "capture_staging_quarantine_receipt_"
                "transactions_namespace_identity_sha256"
            ),
        ),
        "staging_journal_schema": _journal_schema(
            selected["staging_journal_schema"]
        ),
        "inspection_lock_epoch_sha256": _digest(
            selected["inspection_lock_epoch_sha256"],
            field=(
                "capture_staging_quarantine_receipt_"
                "inspection_lock_epoch_sha256"
            ),
        ),
        "quarantine_namespace": quarantine_namespace,
        "quarantine_name": quarantine_name,
        "quarantined_stat_sha256": _digest(
            selected["quarantined_stat_sha256"],
            field=(
                "capture_staging_quarantine_receipt_"
                "quarantined_stat_sha256"
            ),
        ),
        "reason_code": _nfc_ascii_token(
            selected["reason_code"],
            field="capture_staging_quarantine_receipt_reason_code",
        ),
        "lifecycle_status": lifecycle_status,
        "lifecycle_scope_empty_receipt_sha256": scope_receipt,
        "rename_primitive": rename_primitive,
        "rename_noreplace": True,
        "parents_fsynced": True,
        "terminal_event": terminal_event,
        "terminal_sequence": _integer(
            selected["terminal_sequence"],
            field=(
                "capture_staging_quarantine_receipt_terminal_sequence"
            ),
        ),
        "terminal_record_sha256": _digest(
            selected["terminal_record_sha256"],
            field=(
                "capture_staging_quarantine_receipt_"
                "terminal_record_sha256"
            ),
        ),
        "tombstone_sha256": _digest(
            selected["tombstone_sha256"],
            field=(
                "capture_staging_quarantine_receipt_tombstone_sha256"
            ),
        ),
    }


def staging_quarantine_receipt_sha256(
    value: Mapping[str, Any],
) -> str:
    """Return the canonical digest of one quarantine receipt."""

    return _sha256(
        _canonical_json(normalize_staging_quarantine_receipt(value))
    )


def normalize_staging_tombstone_ack_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize one deterministic outer-journal tombstone acknowledgement."""

    selected = _strict_mapping(
        value,
        STAGING_TOMBSTONE_ACK_RECEIPT_FIELDS,
        code="capture_staging_tombstone_ack_receipt_fields_invalid",
    )
    disposition = selected["terminal_disposition"]
    if disposition not in TERMINAL_DISPOSITIONS:
        raise _error(
            "capture_staging_tombstone_ack_receipt_disposition_invalid"
        )
    storage_disposition = selected["journal_storage_disposition"]
    if storage_disposition not in JOURNAL_STORAGE_DISPOSITIONS:
        raise _error(
            "capture_staging_tombstone_ack_receipt_"
            "storage_disposition_invalid"
        )
    expected_storage = (
        "completed_absence_journal"
        if disposition == "absent"
        else "retained_quarantine_journal"
    )
    if storage_disposition != expected_storage:
        raise _error(
            "capture_staging_tombstone_ack_receipt_"
            "storage_disposition_mismatch"
        )
    outer_quarantine_intent = _nullable_digest(
        selected["outer_quarantine_intent_record_sha256"],
        field=(
            "capture_staging_tombstone_ack_receipt_"
            "outer_quarantine_intent_record_sha256"
        ),
    )
    if (
        disposition == "quarantined"
        and outer_quarantine_intent is None
    ):
        raise _error(
            "capture_staging_tombstone_ack_receipt_"
            "outer_quarantine_intent_missing"
        )
    if selected["transactions_parent_fsynced"] is not True:
        raise _error(
            "capture_staging_tombstone_ack_receipt_"
            "transactions_parent_fsync_invalid"
        )
    expected_completed_fsync = disposition == "absent"
    if (
        selected["completed_parent_fsynced"]
        is not expected_completed_fsync
    ):
        raise _error(
            "capture_staging_tombstone_ack_receipt_"
            "completed_parent_fsync_invalid"
        )
    return {
        "schema_version": _schema(
            selected["schema_version"],
            STAGING_TOMBSTONE_ACK_RECEIPT_SCHEMA,
            field="capture_staging_tombstone_ack_receipt_schema",
        ),
        "status": _status(
            selected["status"],
            STAGING_TOMBSTONE_ACK_STATUS,
            field="capture_staging_tombstone_ack_receipt_status",
        ),
        "capture_session_id": _session_id(
            selected["capture_session_id"]
        ),
        "staging_transaction_intent_sha256": _digest(
            selected["staging_transaction_intent_sha256"],
            field=(
                "capture_staging_tombstone_ack_receipt_"
                "transaction_intent_sha256"
            ),
        ),
        "terminal_receipt_sha256": _digest(
            selected["terminal_receipt_sha256"],
            field=(
                "capture_staging_tombstone_ack_receipt_"
                "terminal_receipt_sha256"
            ),
        ),
        "tombstone_sha256": _digest(
            selected["tombstone_sha256"],
            field=(
                "capture_staging_tombstone_ack_receipt_"
                "tombstone_sha256"
            ),
        ),
        "outer_ack_pending_record_sha256": _digest(
            selected["outer_ack_pending_record_sha256"],
            field=(
                "capture_staging_tombstone_ack_receipt_"
                "outer_ack_pending_record_sha256"
            ),
        ),
        "outer_quarantine_intent_record_sha256": (
            outer_quarantine_intent
        ),
        "outer_lifecycle_clearance_record_sha256": _nullable_digest(
            selected["outer_lifecycle_clearance_record_sha256"],
            field=(
                "capture_staging_tombstone_ack_receipt_"
                "outer_lifecycle_clearance_record_sha256"
            ),
        ),
        "terminal_disposition": disposition,
        "staging_journal_schema": _journal_schema(
            selected["staging_journal_schema"]
        ),
        "ack_event": _status(
            selected["ack_event"],
            STAGING_TOMBSTONE_ACK_EVENT,
            field=(
                "capture_staging_tombstone_ack_receipt_ack_event"
            ),
        ),
        "ack_sequence": _integer(
            selected["ack_sequence"],
            field=(
                "capture_staging_tombstone_ack_receipt_ack_sequence"
            ),
            minimum=1,
        ),
        "ack_previous_record_sha256": _digest(
            selected["ack_previous_record_sha256"],
            field=(
                "capture_staging_tombstone_ack_receipt_"
                "ack_previous_record_sha256"
            ),
        ),
        "ack_record_sha256": _digest(
            selected["ack_record_sha256"],
            field=(
                "capture_staging_tombstone_ack_receipt_"
                "ack_record_sha256"
            ),
        ),
        "inspection_lock_epoch_sha256": _digest(
            selected["inspection_lock_epoch_sha256"],
            field=(
                "capture_staging_tombstone_ack_receipt_"
                "inspection_lock_epoch_sha256"
            ),
        ),
        "journal_storage_disposition": storage_disposition,
        "ack_journal_identity_sha256": _digest(
            selected["ack_journal_identity_sha256"],
            field=(
                "capture_staging_tombstone_ack_receipt_"
                "ack_journal_identity_sha256"
            ),
        ),
        "ack_journal_readback_sha256": _digest(
            selected["ack_journal_readback_sha256"],
            field=(
                "capture_staging_tombstone_ack_receipt_"
                "ack_journal_readback_sha256"
            ),
        ),
        "transactions_parent_fsynced": True,
        "completed_parent_fsynced": expected_completed_fsync,
    }


def staging_tombstone_ack_receipt_sha256(
    value: Mapping[str, Any],
) -> str:
    """Return the canonical digest of one tombstone acknowledgement."""

    return _sha256(
        _canonical_json(normalize_staging_tombstone_ack_receipt(value))
    )


__all__ = [
    "ABSENCE_TERMINAL_EVENTS",
    "CAPTURE_STAGING_JOURNAL_SCHEMA",
    "CaptureStagingReceiptError",
    "LIFECYCLE_STATUSES",
    "JOURNAL_STORAGE_DISPOSITIONS",
    "RENAME_PRIMITIVES",
    "QUARANTINE_TERMINAL_EVENTS",
    "STAGING_ABSENCE_RECEIPT_FIELDS",
    "STAGING_ABSENCE_RECEIPT_SCHEMA",
    "STAGING_ABSENCE_STATUS",
    "STAGING_EXPOSED_LEAF_MODE",
    "STAGING_EXPOSURE_JOURNAL_SEQUENCE",
    "STAGING_EXPOSURE_RECEIPT_FIELDS",
    "STAGING_EXPOSURE_RECEIPT_SCHEMA",
    "STAGING_EXPOSURE_STATUS",
    "STAGING_QUARANTINE_NAMESPACE",
    "STAGING_QUARANTINE_RECEIPT_FIELDS",
    "STAGING_QUARANTINE_RECEIPT_SCHEMA",
    "STAGING_QUARANTINE_STATUS",
    "STAGING_TOMBSTONE_ACK_RECEIPT_FIELDS",
    "STAGING_TOMBSTONE_ACK_RECEIPT_SCHEMA",
    "STAGING_TOMBSTONE_ACK_EVENT",
    "STAGING_TOMBSTONE_ACK_STATUS",
    "TERMINAL_DISPOSITIONS",
    "normalize_staging_absence_receipt",
    "normalize_staging_exposure_receipt",
    "normalize_staging_quarantine_receipt",
    "normalize_staging_tombstone_ack_receipt",
    "staging_absence_receipt_sha256",
    "staging_exposure_receipt_sha256",
    "staging_quarantine_receipt_sha256",
    "staging_tombstone_ack_receipt_sha256",
]
