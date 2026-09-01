"""Crash-durable transaction journal for protected qualification sessions.

This module is deliberately narrower than the qualification orchestrator.  It
does not import or accept a verifier, signer, private-key loader, publisher,
capture helper, PID, or process-group authority.  Its only authority is an
exclusive lock over a root-owned append-only filesystem journal.

Production activation remains disabled.  The implementation exists so the
durability and tamper boundary can be exercised before it is connected to the
capture and publication state machines.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import stat
import sys
import threading
import time
import unicodedata
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from qualification_attestor import (
    john_lomein_persona_qualification_capture_staging_receipts
    as staging_receipts,
)
from qualification_attestor import (
    john_lomein_persona_qualification_adoption_reconciliation
    as adoption_reconciliation,
)
from qualification_attestor import (
    john_lomein_persona_qualification_adoption_result
    as adoption_result,
)
from qualification_attestor import (
    john_lomein_persona_qualification_lifecycle_receipts
    as lifecycle_receipts,
)
from qualification_attestor import (
    john_lomein_persona_qualification_recovered_adoption_evidence
    as recovered_adoption_evidence,
)
from qualification_attestor import (
    john_lomein_persona_qualification_capture_selection
    as capture_selection,
)
from qualification_attestor import (
    john_lomein_persona_qualification_source_revalidation_binding
    as source_revalidation_binding,
)


PRODUCTION_ACTIVATION = False

JOURNAL_RECORD_SCHEMA = (
    "john-lomein.persona-qualification-transaction-journal.v5"
)
LIFECYCLE_OPERATION_BINDING_SCHEMA = (
    "john-lomein.persona-qualification-lifecycle-operation-binding.v1"
)
LIFECYCLE_CAPTURE_EVENT_EVIDENCE_SCHEMA = (
    "john-lomein.persona-qualification-lifecycle-"
    "capture-event-evidence.v1"
)
RECOVERED_ADOPTION_LEASE_BINDING_V2_SCHEMA = (
    "john-lomein.persona-qualification-recovered-adoption-"
    "lease-binding.v2"
)
RECOVERED_ADOPTION_JOURNAL_BINDING_SCHEMA = (
    RECOVERED_ADOPTION_LEASE_BINDING_V2_SCHEMA
)
RECOVERED_ADOPTION_CONTINUATION_SCHEMA = (
    "john-lomein.persona-qualification-recovered-adoption-"
    "continuation.v1"
)
RECOVERED_VERIFIER_SOURCE_EVIDENCE_SCHEMA = (
    "john-lomein.persona-qualification-recovered-verifier-"
    "source-evidence.v1"
)
VERIFIER_REQUEST_V5_SCHEMA = (
    "john-lomein.persona.operator-verifier-request.v5"
)
VERIFIER_OUTPUT_V4_SCHEMA = (
    "john-lomein.persona.operator-verification.v4"
)
VERIFIER_V5_VERSION = "john-lomein.persona.operator-verifier.v5"
VERIFIER_CLAIM_STRENGTH = "operator_verified_local_conformance"
RECOVERED_REVALIDATION_STATE_SEMANTICS = (
    "post_effect_durability_projection"
)
SOURCE_REVALIDATION_RECEIPT_V2_SCHEMA = (
    source_revalidation_binding.SOURCE_REVALIDATION_RECEIPT_V2_SCHEMA
)
STAGING_ABSENCE_RECEIPT_SCHEMA = (
    staging_receipts.STAGING_ABSENCE_RECEIPT_SCHEMA
)
STAGING_ABSENCE_STATUS = staging_receipts.STAGING_ABSENCE_STATUS
STAGING_EXPOSURE_RECEIPT_SCHEMA = (
    staging_receipts.STAGING_EXPOSURE_RECEIPT_SCHEMA
)
STAGING_QUARANTINE_RECEIPT_SCHEMA = (
    staging_receipts.STAGING_QUARANTINE_RECEIPT_SCHEMA
)
STAGING_QUARANTINE_STATUS = (
    staging_receipts.STAGING_QUARANTINE_STATUS
)
STAGING_TOMBSTONE_ACK_RECEIPT_SCHEMA = (
    staging_receipts.STAGING_TOMBSTONE_ACK_RECEIPT_SCHEMA
)
STAGING_TOMBSTONE_ACK_STATUS = (
    staging_receipts.STAGING_TOMBSTONE_ACK_STATUS
)
CAPTURE_STAGING_JOURNAL_SCHEMA = (
    staging_receipts.CAPTURE_STAGING_JOURNAL_SCHEMA
)
STAGING_EXPOSURE_STATUS = staging_receipts.STAGING_EXPOSURE_STATUS
STAGING_EXPOSED_LEAF_MODE = (
    staging_receipts.STAGING_EXPOSED_LEAF_MODE
)
STAGING_EXPOSURE_JOURNAL_SEQUENCE = (
    staging_receipts.STAGING_EXPOSURE_JOURNAL_SEQUENCE
)
STAGING_EXPOSURE_RECEIPT_FIELDS = (
    staging_receipts.STAGING_EXPOSURE_RECEIPT_FIELDS
)
STORE_MODE = 0o700
LOCK_FILE_MODE = 0o600
COMPLETED_DIRECTORY_MODE = 0o700
SESSION_DIRECTORY_MODE = 0o700
RECORD_FILE_MODE = 0o400
TEMP_FILE_MODE = 0o600

MAX_RECORD_BYTES = 64 * 1024
MAX_RECOVERED_VERIFIER_OUTPUT_BYTES = 48 * 1024
MAX_EVENTS_PER_SESSION = 32
MAX_SESSION_DIRECTORIES = 4_096
MAX_COMPLETED_SESSION_DIRECTORIES = 4_096
MAX_COMPLETED_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_SESSION_ARCHIVE_BYTES = (
    MAX_EVENTS_PER_SESSION * MAX_RECORD_BYTES
)
MAX_STALE_TEMP_FILES = 8
ZERO_SHA256 = "0" * 64

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SESSION_ID_RE = SHA256_RE
SLUG_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$"
)
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
REASON_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
CAPTURE_NAME_RE = re.compile(r"^opaque-capture-[0-9a-f]{32}$")
SESSION_DIRECTORY_RE = re.compile(r"^session-([0-9a-f]{64})$")
TEMP_FILE_RE = re.compile(r"^\.tmp-([0-9a-f]{32})$")
EVENT_FILE_RE = re.compile(
    r"^([0-9]{6})-([a-z][a-z0-9_]*)-([0-9a-f]{64})\.json$"
)
MAX_CAPTURE_FILES = 4_096
MAX_CAPTURE_DIRECTORIES = 4_096
MAX_CAPTURE_BYTES = 128 * 1024 * 1024
MAX_CAPTURE_FILE_BYTES = 16 * 1024 * 1024
MAX_CAPTURE_DEPTH = 64

RECORD_FIELDS = frozenset(
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

RECOVERED_ADOPTION_JOURNAL_BINDING_FIELDS = frozenset(
    {
        "schema_version",
        "transaction_journal_schema",
        "transaction_journal_head_state",
        "transaction_journal_head_revision",
        "transaction_journal_head_record_sha256",
        "staging_tombstone_acked_record_sha256",
        "capture_session_id",
        "final_parent_identity_sha256",
        "capture_object_identity_sha256",
        "reconciled_final_object_stat_sha256",
        "reconciled_content_inventory_sha256",
        "recovered_adoption_evidence_sha256",
        "capture_adoption_result_sha256",
        "capture_adoption_provenance_sha256",
    }
)
RECOVERED_ADOPTION_LEASE_BINDING_V2_FIELDS = (
    RECOVERED_ADOPTION_JOURNAL_BINDING_FIELDS
)
RECOVERED_ADOPTION_CONTINUATION_FIELDS = frozenset(
    {
        "schema_version",
        "recovered_adoption_evidence_sha256",
        "capture_adoption_result_sha256",
        "capture_adoption_provenance",
        "capture_adoption_provenance_sha256",
        "pre_ack_recovered_adoption_lease_binding",
        "pre_ack_recovered_adoption_lease_binding_sha256",
    }
)
VERIFIER_OUTPUT_V4_FIELDS = frozenset(
    {"schema_version", "status", "evidence"}
)
VERIFIER_EVIDENCE_V4_FIELDS = frozenset(
    {
        "run_id",
        "summary_sha256",
        "binding_sha256",
        "status",
        "qualified_at_unix",
        "expires_at_unix",
        "verifier_version",
        "verifier_uid",
        "verifier_bundle_sha256",
        "verification_policy_sha256",
        "capture_manifest_sha256",
        "capture_plan_sha256",
        "operator_policy_sha256",
        "claim_strength",
        "public_reputation_eligible",
        "verified_at_unix",
        "observed_evidence_uid",
        "capture_creator_uid",
        "capture_export_gid",
        "capture_adopted_uid",
        "capture_adoption_policy_sha256",
        "capture_object_identity_sha256",
        "capture_content_inventory_sha256",
        "capture_request_sha256",
        "capture_boundary_policy_sha256",
        "capture_helper_activation_policy_sha256",
        "capture_adoption_provenance",
        "capture_adoption_provenance_sha256",
    }
)
VERIFIED_EVIDENCE_V6_FIELDS = frozenset(
    VERIFIER_EVIDENCE_V4_FIELDS
    | source_revalidation_binding.SOURCE_REVALIDATION_EVIDENCE_FIELDS
)
VERIFIER_REQUEST_V5_FIELDS = frozenset(
    {
        "schema_version",
        "snapshot_root",
        "capture_manifest_sha256",
        "capture_plan_sha256",
        "capture_selection",
        "capture_selection_sha256",
        "capture_adoption_result",
        "capture_adoption_result_sha256",
        "capture_adoption_policy_sha256",
        "adoption_verifier_limits",
        "capture_session_id",
        "capture_request_sha256",
        "capture_boundary_policy_sha256",
        "capture_helper_activation_policy_sha256",
        "expected_run_id",
        "capture_uid",
        "capture_export_gid",
        "adopted_uid",
        "instance_manifest_path",
        "instance_manifest_sha256",
        "qualification_private_root",
        "qualification_public_root",
        "evidence_home_path",
        "checkout_identity_path",
        "runtime_identity_path",
        "instance_slug",
        "evidence_uid",
        "verifier_uid",
        "verifier_gid",
        "verifier_bundle_sha256",
        "verification_policy_sha256",
        "operator_policy_sha256",
        "verified_at_unix",
    }
)
RECOVERED_VERIFIER_SOURCE_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "verifier_request_schema",
        "verifier_request_v5_sha256",
        "expected_run_id",
        "verifier_output_schema",
        "verifier_output_v4",
        "verifier_output_v4_sha256",
        "source_revalidation_receipt_schema",
        "source_revalidation_receipt_v2",
        "source_revalidation_receipt_v2_sha256",
        "source_revalidation_effect_completed_under_acked_head",
        "staging_tombstone_acked_record_sha256",
        "recovered_adoption_continuation_sha256",
        "capture_adoption_provenance",
        "capture_adoption_provenance_sha256",
        "pre_verifier_recovered_adoption_lease_binding",
        "pre_verifier_recovered_adoption_lease_binding_sha256",
        "post_verifier_recovered_adoption_lease_binding",
        "post_verifier_recovered_adoption_lease_binding_sha256",
        "recovered_adoption_lease_bindings_equal",
        "verified_evidence_v6_sha256",
    }
)
RECOVERED_VERIFIER_OUTPUT_BOUND_DETAIL_FIELDS = frozenset(
    {
        "verifier_output_sha256",
        "recovered_verifier_source_evidence",
        "recovered_verifier_source_evidence_sha256",
    }
)
RECOVERED_LIVE_REVALIDATION_STARTED_DETAIL_FIELDS = frozenset(
    {
        "verifier_output_sha256",
        "recovered_verifier_source_evidence_sha256",
        "staging_tombstone_acked_record_sha256",
        "state_semantics",
    }
)
RECOVERED_LIVE_REVALIDATION_COMPLETE_DETAIL_FIELDS = frozenset(
    {
        "verifier_output_sha256",
        "source_revalidation_receipt_sha256",
        "recovered_verifier_source_evidence_sha256",
        "staging_tombstone_acked_record_sha256",
        "verified_evidence_v6_sha256",
        "state_semantics",
    }
)

STATES = (
    "reserved",
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
    "committed_cleanup_pending",
    "cleanup_complete",
    "staging_tombstone_ack_pending",
    "staging_tombstone_acked",
    "adoption_reconciliation_required",
    "adoption_reconciled",
    "staging_absent_cleanup_complete",
    "staging_quarantined_cleanup_complete",
    "quarantine_pending",
    "quarantined",
    "operator_attention",
    "operator_resolved",
)
STATE_SET = frozenset(STATES)

LIFECYCLE_EFFECT_ORIGIN_STATES = frozenset(
    {"child_launch_intent", "child_running", "capture_ready"}
)
LIFECYCLE_OPERATION_BINDING_FIELDS = frozenset(
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
LIFECYCLE_OPERATIONS = frozenset(
    {
        "start_scope",
        "await_capture_event",
        "request_clearance",
        "recover_scope",
        "prepare_clearance",
    }
)
LIFECYCLE_OPERATION_OUTCOMES = frozenset(
    {
        "success",
        "no_effect",
        "recovery",
        "attention",
        "local_intent",
    }
)
LIFECYCLE_SUPERVISOR_EVENTS = frozenset(
    {
        "capture_ready",
        "child_exited",
        "capture_deadline_exceeded",
    }
)
_REMOTE_LIFECYCLE_OPERATIONS = LIFECYCLE_OPERATIONS - {
    "prepare_clearance"
}
_LIFECYCLE_OPERATION_BASE_STATES = {
    "start_scope": frozenset({"child_launch_intent"}),
    "await_capture_event": frozenset(
        {"child_running", "capture_ready"}
    ),
    "request_clearance": frozenset(
        {"lifecycle_clearance_intent"}
    ),
    "recover_scope": frozenset(
        {
            "child_launch_intent",
            "child_running",
            "capture_ready",
            "lifecycle_clearance_intent",
            "operator_attention",
            "lifecycle_scope_empty",
        }
    ),
    "prepare_clearance": frozenset(
        {
            "child_launch_intent",
            "child_running",
            "capture_ready",
            "operator_attention",
        }
    ),
}
_LIFECYCLE_OPERATION_SUCCESSORS = {
    "start_scope": frozenset({"child_running", "operator_attention"}),
    "await_capture_event": frozenset(
        {
            "capture_ready",
            "lifecycle_clearance_intent",
            "operator_attention",
        }
    ),
    "request_clearance": frozenset(
        {"lifecycle_scope_empty", "operator_attention"}
    ),
    "recover_scope": frozenset(
        {
            "child_running",
            "capture_ready",
            "lifecycle_clearance_intent",
            "lifecycle_scope_empty",
            "operator_attention",
        }
    ),
    "prepare_clearance": frozenset(
        {"lifecycle_clearance_intent"}
    ),
}
_LIFECYCLE_OPERATION_SUCCESSORS_BY_BASE = {
    ("start_scope", "child_launch_intent"): frozenset(
        {"child_running", "operator_attention"}
    ),
    ("await_capture_event", "child_running"): frozenset(
        {
            "capture_ready",
            "lifecycle_clearance_intent",
            "operator_attention",
        }
    ),
    ("await_capture_event", "capture_ready"): frozenset(
        {"lifecycle_clearance_intent", "operator_attention"}
    ),
    ("request_clearance", "lifecycle_clearance_intent"): (
        frozenset({"lifecycle_scope_empty", "operator_attention"})
    ),
    ("recover_scope", "child_launch_intent"): frozenset(
        {
            "child_running",
            "lifecycle_clearance_intent",
            "operator_attention",
        }
    ),
    ("recover_scope", "child_running"): frozenset(
        {
            "capture_ready",
            "lifecycle_clearance_intent",
            "operator_attention",
        }
    ),
    ("recover_scope", "capture_ready"): frozenset(
        {"lifecycle_clearance_intent", "operator_attention"}
    ),
    ("recover_scope", "lifecycle_clearance_intent"): frozenset(
        {"lifecycle_scope_empty", "operator_attention"}
    ),
    ("recover_scope", "operator_attention"): frozenset(
        {"lifecycle_clearance_intent", "lifecycle_scope_empty"}
    ),
    ("recover_scope", "lifecycle_scope_empty"): frozenset(),
    ("prepare_clearance", "child_launch_intent"): frozenset(
        {"lifecycle_clearance_intent"}
    ),
    ("prepare_clearance", "child_running"): frozenset(
        {"lifecycle_clearance_intent"}
    ),
    ("prepare_clearance", "capture_ready"): frozenset(
        {"lifecycle_clearance_intent"}
    ),
    ("prepare_clearance", "operator_attention"): frozenset(
        {"lifecycle_clearance_intent"}
    ),
}
_SUPERVISOR_DERIVED_SUCCESSOR_STATES = frozenset(
    {
        "child_running",
        "capture_ready",
        "lifecycle_scope_empty",
    }
)
CLEANUP_PHASES = frozenset({"name_bound", "parent_fsync_only"})
CLEANUP_RESULTS = frozenset(
    {
        "removed_and_fsynced",
        "parent_fsynced",
        "already_absent_parent_fsynced",
    }
)
QUARANTINE_NAMESPACES = frozenset({"staging", "adopted"})
LIFECYCLE_STATUSES = frozenset(
    {"scope_empty", "scope_not_proven", "not_applicable"}
)
TERMINAL_STATES = frozenset(
    {
        "cleanup_complete",
        "staging_absent_cleanup_complete",
        "staging_quarantined_cleanup_complete",
        "quarantined",
        "operator_resolved",
    }
)

_LINEAR_SUCCESSORS = {
    "reserved": "staging_create_intent",
    "staging_create_intent": "staging_exposed",
    "staging_exposed": "child_launch_intent",
    "child_launch_intent": "child_running",
    "child_running": "capture_ready",
    "capture_ready": "lifecycle_clearance_intent",
    "lifecycle_clearance_intent": "lifecycle_scope_empty",
    "lifecycle_scope_empty": "adoption_intent",
    "adoption_intent": "adopted",
    "verifier_output_bound": "live_revalidation_started",
    "live_revalidation_started": (
        "live_revalidation_receipt_complete"
    ),
    "live_revalidation_receipt_complete": "signing_intent",
    "signing_intent": "attestation_archive_durable_head_pending",
    "attestation_archive_durable_head_pending": (
        "attestation_head_committed_trust_projection_pending"
    ),
    "attestation_head_committed_trust_projection_pending": (
        "full_publication_committed_cleanup_required"
    ),
}

_RENAME_NOREPLACE = 1
_DARWIN_RENAME_EXCL = 0x00000004


class TransactionJournalError(ValueError):
    """Stable public-safe rejection from the journal boundary."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _error(code: str) -> TransactionJournalError:
    return TransactionJournalError(code)


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
        raise _error("transaction_journal_json_invalid") from exc


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _strict_mapping(
    value: Any,
    fields: frozenset[str] | set[str],
    *,
    code: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise _error(code)
    return value


def _digest(value: Any, *, field: str, allow_zero: bool = False) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise _error(f"{field}_invalid")
    if not allow_zero and value == ZERO_SHA256:
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
    minimum: int,
    maximum: int = (1 << 53) - 1,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _error(f"{field}_invalid")
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
        raise _error(f"{field}_invalid")
    return value


def _component(value: Any, *, field: str) -> str:
    text = _text(value, field=field, expression=COMPONENT_RE)
    if text in {".", ".."} or "/" in text or "\x00" in text:
        raise _error(f"{field}_invalid")
    return text


def _capture_name(value: Any, *, field: str) -> str:
    return _text(value, field=field, expression=CAPTURE_NAME_RE)


def _session_id(value: Any) -> str:
    return _text(
        value,
        field="transaction_journal_session_id",
        expression=SESSION_ID_RE,
    )


def _instance_slug(value: Any) -> str:
    return _text(
        value,
        field="transaction_journal_instance_slug",
        expression=SLUG_RE,
    )


def _reason(value: Any, *, field: str) -> str:
    return _text(value, field=field, expression=REASON_RE)


def _run_id(value: Any) -> str:
    return _text(
        value,
        field="transaction_journal_run_id",
        expression=RUN_ID_RE,
    )


def _token(value: Any, *, field: str) -> str:
    return _text(value, field=field, expression=TOKEN_RE)


def _absolute_path(value: Path | str, *, field: str) -> Path:
    text = str(value)
    path = Path(text)
    if (
        not text
        or len(text) > 4_096
        or "\x00" in text
        or any(ord(character) < 32 for character in text)
        or unicodedata.normalize("NFC", text) != text
        or not path.is_absolute()
        or "." in path.parts
        or ".." in path.parts
        or text != str(path)
    ):
        raise _error(f"{field}_invalid")
    return path


def _stable_object_tuple(info: os.stat_result) -> tuple[int, int, int]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(stat.S_IFMT(info.st_mode)),
    )


def _full_stat_tuple(info: os.stat_result) -> tuple[int, ...]:
    return (
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
    )


def _directory_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("transaction_journal_nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _read_file_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("transaction_journal_nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _write_file_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("transaction_journal_nofollow_unsupported")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _lock_file_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("transaction_journal_nofollow_unsupported")
    flags = os.O_RDWR | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _reject_fd_metadata(descriptor: int, *, field: str) -> None:
    """Reject discretionary ACLs and non-platform-managed xattrs."""

    libc = ctypes.CDLL(None, use_errno=True)
    if not hasattr(libc, "flistxattr"):
        raise _error(f"{field}_fd_metadata_unsupported")
    libc.flistxattr.restype = ctypes.c_ssize_t
    if sys.platform == "darwin":
        libc.flistxattr.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_int,
        ]
        size = libc.flistxattr(descriptor, None, 0, 0)
        permitted = {
            b"com.apple.provenance",
            b"com.apple.rootless",
        }
    elif sys.platform.startswith("linux"):
        libc.flistxattr.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        size = libc.flistxattr(descriptor, None, 0)
        permitted = {b"security.selinux"}
    else:
        raise _error(f"{field}_fd_metadata_unsupported")
    if size < 0:
        raise _error(f"{field}_metadata_unreadable")
    attributes: set[bytes] = set()
    if size:
        buffer = ctypes.create_string_buffer(size)
        observed = (
            libc.flistxattr(descriptor, buffer, size, 0)
            if sys.platform == "darwin"
            else libc.flistxattr(descriptor, buffer, size)
        )
        if observed != size:
            raise _error(f"{field}_metadata_changed")
        attributes = {
            value
            for value in bytes(buffer.raw[:observed]).split(b"\x00")
            if value
        }
    if not attributes.issubset(permitted):
        raise _error(f"{field}_extended_metadata_unsupported")
    if sys.platform != "darwin":
        return
    if not hasattr(libc, "acl_get_fd_np"):
        raise _error(f"{field}_fd_acl_unsupported")
    libc.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    libc.acl_get_fd_np.restype = ctypes.c_void_p
    libc.acl_to_text.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ssize_t),
    ]
    libc.acl_to_text.restype = ctypes.c_void_p
    libc.acl_free.argtypes = [ctypes.c_void_p]
    acl = libc.acl_get_fd_np(descriptor, 0x100)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return
        raise _error(f"{field}_acl_unreadable")
    text_pointer = None
    try:
        length = ctypes.c_ssize_t()
        text_pointer = libc.acl_to_text(acl, ctypes.byref(length))
        if not text_pointer:
            raise _error(f"{field}_acl_unreadable")
        if b":allow:" in ctypes.string_at(text_pointer, length.value):
            raise _error(f"{field}_acl_grants_unsupported")
    finally:
        if text_pointer:
            libc.acl_free(text_pointer)
        libc.acl_free(acl)


def _path_parent_chain(path: Path) -> list[Path]:
    values: list[Path] = []
    current = path
    while current != current.parent:
        values.append(current)
        current = current.parent
    values.append(current)
    return list(reversed(values))


def _validate_trusted_parent_chain(path: Path, *, owner_uid: int) -> None:
    for parent in _path_parent_chain(path):
        try:
            info = parent.lstat()
        except OSError as exc:
            raise _error(
                "transaction_journal_parent_unreadable"
            ) from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != owner_uid
            or info.st_mode & 0o022
        ):
            raise _error("transaction_journal_parent_unsafe")


def _validate_directory(
    descriptor: int,
    *,
    owner_uid: int,
    owner_gid: int,
    mode: int | None,
    field: str,
) -> os.stat_result:
    try:
        info = os.fstat(descriptor)
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != owner_uid
        or info.st_gid != owner_gid
        or (mode is not None and stat.S_IMODE(info.st_mode) != mode)
        or (mode is None and info.st_mode & 0o022)
    ):
        raise _error(f"{field}_unsafe")
    _reject_fd_metadata(descriptor, field=field)
    return info


def _validate_regular_file(
    descriptor: int,
    *,
    owner_uid: int,
    owner_gid: int,
    modes: frozenset[int],
    maximum_bytes: int,
    field: str,
) -> os.stat_result:
    try:
        info = os.fstat(descriptor)
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != owner_uid
        or info.st_gid != owner_gid
        or stat.S_IMODE(info.st_mode) not in modes
        or info.st_nlink != 1
        or info.st_size < 0
        or info.st_size > maximum_bytes
    ):
        raise _error(f"{field}_unsafe")
    _reject_fd_metadata(descriptor, field=field)
    return info


def _validate_path_fd_binding(
    path: Path,
    descriptor: int,
    *,
    field: str,
) -> None:
    try:
        named = path.lstat()
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    if (
        not stat.S_ISDIR(named.st_mode)
        or _stable_object_tuple(named) != _stable_object_tuple(opened)
    ):
        raise _error(f"{field}_inode_mismatch")


def _validate_named_fd_binding(
    parent_fd: int,
    name: str,
    descriptor: int,
    *,
    directory: bool,
    field: str,
) -> None:
    try:
        named = os.stat(
            name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_type(named.st_mode)
        or _stable_object_tuple(named) != _stable_object_tuple(opened)
    ):
        raise _error(f"{field}_inode_mismatch")


def _bounded_entries(
    descriptor: int,
    *,
    maximum: int,
    field: str,
) -> list[str]:
    try:
        values = os.listdir(descriptor)
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    if len(values) > maximum:
        raise _error(f"{field}_too_many")
    identities: set[str] = set()
    result: list[str] = []
    for value in values:
        if (
            not isinstance(value, str)
            or not value
            or value in {".", ".."}
            or "/" in value
            or "\x00" in value
            or unicodedata.normalize("NFC", value) != value
        ):
            raise _error(f"{field}_entry_invalid")
        identity = value.casefold()
        if identity in identities:
            raise _error(f"{field}_entry_alias")
        identities.add(identity)
        result.append(value)
    return sorted(result)


def _write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        try:
            written = os.write(descriptor, raw[offset:])
        except OSError as exc:
            raise _error("transaction_journal_record_write_failed") from exc
        if written <= 0:
            raise _error("transaction_journal_record_write_failed")
        offset += written


def _read_bounded(
    descriptor: int,
    *,
    expected_size: int,
    maximum: int,
) -> bytes:
    if expected_size < 1 or expected_size > maximum:
        raise _error("transaction_journal_record_size_invalid")
    chunks: list[bytes] = []
    remaining = expected_size
    while remaining:
        try:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
        except OSError as exc:
            raise _error("transaction_journal_record_read_failed") from exc
        if not chunk:
            raise _error("transaction_journal_record_truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    try:
        extra = os.read(descriptor, 1)
    except OSError as exc:
        raise _error("transaction_journal_record_read_failed") from exc
    if extra:
        raise _error("transaction_journal_record_changed")
    return b"".join(chunks)


def _exclusive_rename(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
    *,
    destination_exists_code: str,
) -> str:
    source = source_name.encode("ascii")
    destination = destination_name.encode("ascii")
    libc = ctypes.CDLL(None, use_errno=True)
    system = platform.system()
    if system == "Linux" and hasattr(libc, "renameat2"):
        libc.renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        libc.renameat2.restype = ctypes.c_int
        result = libc.renameat2(
            source_parent_fd,
            source,
            destination_parent_fd,
            destination,
            _RENAME_NOREPLACE,
        )
        primitive = "renameat2_noreplace"
    elif system == "Darwin" and hasattr(libc, "renameatx_np"):
        libc.renameatx_np.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        libc.renameatx_np.restype = ctypes.c_int
        result = libc.renameatx_np(
            source_parent_fd,
            source,
            destination_parent_fd,
            destination,
            _DARWIN_RENAME_EXCL,
        )
        primitive = "renameatx_np_excl"
    else:
        raise _error(
            "transaction_journal_exclusive_rename_unsupported"
        )
    if result != 0:
        observed = ctypes.get_errno()
        if observed in {errno.EEXIST, errno.ENOTEMPTY}:
            raise _error(destination_exists_code)
        raise _error("transaction_journal_record_commit_failed")
    return primitive


def _limits(value: Any) -> dict[str, int]:
    selected = _strict_mapping(
        value,
        {
            "max_files",
            "max_directories",
            "max_bytes",
            "max_file_bytes",
            "max_depth",
        },
        code="transaction_journal_adoption_limits_fields_invalid",
    )
    normalized = {
        "max_files": _integer(
            selected["max_files"],
            field="transaction_journal_max_files",
            minimum=1,
            maximum=MAX_CAPTURE_FILES,
        ),
        "max_directories": _integer(
            selected["max_directories"],
            field="transaction_journal_max_directories",
            minimum=1,
            maximum=MAX_CAPTURE_DIRECTORIES,
        ),
        "max_bytes": _integer(
            selected["max_bytes"],
            field="transaction_journal_max_bytes",
            minimum=1,
            maximum=MAX_CAPTURE_BYTES,
        ),
        "max_file_bytes": _integer(
            selected["max_file_bytes"],
            field="transaction_journal_max_file_bytes",
            minimum=1,
            maximum=MAX_CAPTURE_FILE_BYTES,
        ),
        "max_depth": _integer(
            selected["max_depth"],
            field="transaction_journal_max_depth",
            minimum=1,
            maximum=MAX_CAPTURE_DEPTH,
        ),
    }
    if normalized["max_file_bytes"] > normalized["max_bytes"]:
        raise _error("transaction_journal_adoption_limits_invalid")
    return normalized


_ATTESTATION_BINDING_FIELDS = frozenset(
    {
        "transaction_binding_sha256",
        "fresh_evidence_sha256",
        "requested_attestation_evidence_sha256",
        "authoritative_attestation_evidence_sha256",
        "requested_run_id",
        "requested_chain_sequence",
        "requested_attestation_sha256",
        "authoritative_run_id",
        "authoritative_chain_sequence",
        "authoritative_attestation_sha256",
        "attestor_config_sha256",
        "public_key_sha256",
        "operator_policy_sha256",
        "projection_policy_sha256",
    }
)


def _normalize_attestation_binding(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    normalized = {
        "requested_run_id": _run_id(value["requested_run_id"]),
        "requested_chain_sequence": _integer(
            value["requested_chain_sequence"],
            field="transaction_journal_requested_chain_sequence",
            minimum=1,
        ),
        "authoritative_run_id": _run_id(
            value["authoritative_run_id"]
        ),
        "authoritative_chain_sequence": _integer(
            value["authoritative_chain_sequence"],
            field=(
                "transaction_journal_authoritative_chain_sequence"
            ),
            minimum=1,
        ),
    }
    for field in _ATTESTATION_BINDING_FIELDS - {
        "requested_run_id",
        "requested_chain_sequence",
        "authoritative_run_id",
        "authoritative_chain_sequence",
    }:
        normalized[field] = _digest(
            value[field],
            field=f"transaction_journal_{field}",
        )
    return normalized


def normalize_staging_exposure_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the receipt minted after staging exposure is durable."""

    try:
        return staging_receipts.normalize_staging_exposure_receipt(
            value
        )
    except staging_receipts.CaptureStagingReceiptError as exc:
        raise _error(exc.code) from exc


def staging_exposure_receipt_sha256(
    value: Mapping[str, Any],
) -> str:
    """Digest one normalized staging exposure receipt."""

    try:
        return staging_receipts.staging_exposure_receipt_sha256(
            value
        )
    except staging_receipts.CaptureStagingReceiptError as exc:
        raise _error(exc.code) from exc


def normalize_staging_absence_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a staging absence receipt minted under the staging lock."""

    try:
        return staging_receipts.normalize_staging_absence_receipt(
            value
        )
    except staging_receipts.CaptureStagingReceiptError as exc:
        raise _error(exc.code) from exc


def staging_absence_receipt_sha256(
    value: Mapping[str, Any],
) -> str:
    """Digest one normalized staging absence receipt."""

    try:
        return staging_receipts.staging_absence_receipt_sha256(
            value
        )
    except staging_receipts.CaptureStagingReceiptError as exc:
        raise _error(exc.code) from exc


def normalize_staging_quarantine_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a staging quarantine receipt minted under the staging lock."""

    try:
        return staging_receipts.normalize_staging_quarantine_receipt(
            value
        )
    except staging_receipts.CaptureStagingReceiptError as exc:
        raise _error(exc.code) from exc


def staging_quarantine_receipt_sha256(
    value: Mapping[str, Any],
) -> str:
    """Digest one normalized staging quarantine receipt."""

    try:
        return staging_receipts.staging_quarantine_receipt_sha256(
            value
        )
    except staging_receipts.CaptureStagingReceiptError as exc:
        raise _error(exc.code) from exc


def normalize_staging_tombstone_ack_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a staging tombstone acknowledgement receipt."""

    try:
        return (
            staging_receipts.normalize_staging_tombstone_ack_receipt(
                value
            )
        )
    except staging_receipts.CaptureStagingReceiptError as exc:
        raise _error(exc.code) from exc


def staging_tombstone_ack_receipt_sha256(
    value: Mapping[str, Any],
) -> str:
    """Digest one normalized tombstone acknowledgement receipt."""

    try:
        return (
            staging_receipts.staging_tombstone_ack_receipt_sha256(
                value
            )
        )
    except staging_receipts.CaptureStagingReceiptError as exc:
        raise _error(exc.code) from exc


def normalize_recovered_adoption_lease_binding_v2(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize the v2 journal-head binding used across recovered ACK."""

    selected = _strict_mapping(
        value,
        RECOVERED_ADOPTION_LEASE_BINDING_V2_FIELDS,
        code=(
            "transaction_journal_"
            "recovered_adoption_journal_binding_fields_invalid"
        ),
    )
    if (
        selected["schema_version"]
        != RECOVERED_ADOPTION_LEASE_BINDING_V2_SCHEMA
        or selected["transaction_journal_schema"]
        != JOURNAL_RECORD_SCHEMA
    ):
        raise _error(
            "transaction_journal_"
            "recovered_adoption_journal_binding_schema_invalid"
        )
    state = selected["transaction_journal_head_state"]
    if state not in {
        "adoption_reconciled",
        "staging_tombstone_acked",
    }:
        raise _error(
            "transaction_journal_"
            "recovered_adoption_journal_binding_state_invalid"
        )
    head_digest = _digest(
        selected["transaction_journal_head_record_sha256"],
        field=(
            "transaction_journal_recovered_adoption_"
            "head_record_sha256"
        ),
    )
    ack_digest = _nullable_digest(
        selected["staging_tombstone_acked_record_sha256"],
        field=(
            "transaction_journal_recovered_adoption_"
            "tombstone_acked_record_sha256"
        ),
    )
    if (
        (state == "adoption_reconciled" and ack_digest is not None)
        or (
            state == "staging_tombstone_acked"
            and (
                ack_digest is None
                or not hmac.compare_digest(
                    ack_digest, head_digest
                )
            )
        )
    ):
        raise _error(
            "transaction_journal_"
            "recovered_adoption_journal_binding_ack_invalid"
        )
    return {
        "schema_version": (
            RECOVERED_ADOPTION_LEASE_BINDING_V2_SCHEMA
        ),
        "transaction_journal_schema": JOURNAL_RECORD_SCHEMA,
        "transaction_journal_head_state": state,
        "transaction_journal_head_revision": _integer(
            selected["transaction_journal_head_revision"],
            field=(
                "transaction_journal_recovered_adoption_"
                "head_revision"
            ),
            minimum=1,
            maximum=MAX_EVENTS_PER_SESSION,
        ),
        "transaction_journal_head_record_sha256": head_digest,
        "staging_tombstone_acked_record_sha256": ack_digest,
        "capture_session_id": _session_id(
            selected["capture_session_id"]
        ),
        "final_parent_identity_sha256": _digest(
            selected["final_parent_identity_sha256"],
            field=(
                "transaction_journal_recovered_adoption_"
                "final_parent_identity_sha256"
            ),
        ),
        "capture_object_identity_sha256": _digest(
            selected["capture_object_identity_sha256"],
            field=(
                "transaction_journal_recovered_adoption_"
                "capture_object_identity_sha256"
            ),
        ),
        "reconciled_final_object_stat_sha256": _digest(
            selected["reconciled_final_object_stat_sha256"],
            field=(
                "transaction_journal_recovered_adoption_"
                "final_object_stat_sha256"
            ),
        ),
        "reconciled_content_inventory_sha256": _digest(
            selected["reconciled_content_inventory_sha256"],
            field=(
                "transaction_journal_recovered_adoption_"
                "content_inventory_sha256"
            ),
        ),
        "recovered_adoption_evidence_sha256": _digest(
            selected["recovered_adoption_evidence_sha256"],
            field=(
                "transaction_journal_recovered_adoption_"
                "evidence_sha256"
            ),
        ),
        "capture_adoption_result_sha256": _digest(
            selected["capture_adoption_result_sha256"],
            field=(
                "transaction_journal_recovered_adoption_"
                "result_sha256"
            ),
        ),
        "capture_adoption_provenance_sha256": _digest(
            selected["capture_adoption_provenance_sha256"],
            field=(
                "transaction_journal_recovered_adoption_"
                "provenance_sha256"
            ),
        ),
    }


def recovered_adoption_lease_binding_v2_sha256(
    value: Mapping[str, Any],
) -> str:
    """Digest one canonical recovered-adoption journal-head binding."""

    return _sha256(
        _canonical_json(
            normalize_recovered_adoption_lease_binding_v2(value)
        )
    )


def normalize_recovered_adoption_journal_binding(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Compatibility alias for the canonical shared lease-binding v2."""

    return normalize_recovered_adoption_lease_binding_v2(value)


def recovered_adoption_journal_binding_sha256(
    value: Mapping[str, Any],
) -> str:
    """Compatibility alias for the canonical shared lease-binding digest."""

    return recovered_adoption_lease_binding_v2_sha256(value)


def normalize_recovered_adoption_continuation(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize the recovered-only continuation nested in the outer ACK."""

    selected = _strict_mapping(
        value,
        RECOVERED_ADOPTION_CONTINUATION_FIELDS,
        code=(
            "transaction_journal_"
            "recovered_adoption_continuation_fields_invalid"
        ),
    )
    if (
        selected["schema_version"]
        != RECOVERED_ADOPTION_CONTINUATION_SCHEMA
    ):
        raise _error(
            "transaction_journal_"
            "recovered_adoption_continuation_schema_invalid"
        )
    try:
        provenance = (
            adoption_result.normalize_capture_adoption_provenance(
                selected["capture_adoption_provenance"]
            )
        )
        provenance_digest = (
            adoption_result.capture_adoption_provenance_sha256(
                provenance
            )
        )
    except adoption_result.CaptureAdoptionResultError as exc:
        raise _error(exc.code) from exc
    if provenance["kind"] != adoption_result.RECOVERED_ADOPTION_KIND:
        raise _error(
            "transaction_journal_"
            "recovered_adoption_continuation_kind_invalid"
        )
    observed_provenance_digest = _digest(
        selected["capture_adoption_provenance_sha256"],
        field=(
            "transaction_journal_recovered_adoption_"
            "continuation_provenance_sha256"
        ),
    )
    if not hmac.compare_digest(
        observed_provenance_digest, provenance_digest
    ):
        raise _error(
            "transaction_journal_"
            "recovered_adoption_continuation_provenance_digest_mismatch"
        )
    evidence_digest = _digest(
        selected["recovered_adoption_evidence_sha256"],
        field=(
            "transaction_journal_recovered_adoption_"
            "continuation_evidence_sha256"
        ),
    )
    result_digest = _digest(
        selected["capture_adoption_result_sha256"],
        field=(
            "transaction_journal_recovered_adoption_"
            "continuation_result_sha256"
        ),
    )
    if not hmac.compare_digest(
        evidence_digest, provenance["evidence_sha256"]
    ):
        raise _error(
            "transaction_journal_"
            "recovered_adoption_continuation_evidence_digest_mismatch"
        )
    binding = normalize_recovered_adoption_lease_binding_v2(
        selected["pre_ack_recovered_adoption_lease_binding"]
    )
    binding_digest = recovered_adoption_lease_binding_v2_sha256(
        binding
    )
    observed_binding_digest = _digest(
        selected[
            "pre_ack_recovered_adoption_lease_binding_sha256"
        ],
        field=(
            "transaction_journal_recovered_adoption_"
            "pre_ack_lease_binding_sha256"
        ),
    )
    if not hmac.compare_digest(
        observed_binding_digest, binding_digest
    ):
        raise _error(
            "transaction_journal_"
            "recovered_adoption_continuation_binding_digest_mismatch"
        )
    provenance_details = provenance["details"]
    if (
        binding["transaction_journal_head_state"]
        != "adoption_reconciled"
        or binding["staging_tombstone_acked_record_sha256"]
        is not None
        or not hmac.compare_digest(
            binding["transaction_journal_head_record_sha256"],
            provenance_details[
                "adoption_reconciliation_record_sha256"
            ],
        )
        or not hmac.compare_digest(
            binding["recovered_adoption_evidence_sha256"],
            evidence_digest,
        )
        or not hmac.compare_digest(
            binding["capture_adoption_result_sha256"],
            result_digest,
        )
        or not hmac.compare_digest(
            binding["capture_adoption_provenance_sha256"],
            observed_provenance_digest,
        )
    ):
        raise _error(
            "transaction_journal_"
            "recovered_adoption_continuation_binding_mismatch"
        )
    return {
        "schema_version": RECOVERED_ADOPTION_CONTINUATION_SCHEMA,
        "recovered_adoption_evidence_sha256": evidence_digest,
        "capture_adoption_result_sha256": result_digest,
        "capture_adoption_provenance": provenance,
        "capture_adoption_provenance_sha256": (
            observed_provenance_digest
        ),
        "pre_ack_recovered_adoption_lease_binding": binding,
        "pre_ack_recovered_adoption_lease_binding_sha256": (
            observed_binding_digest
        ),
    }


def recovered_adoption_continuation_sha256(
    value: Mapping[str, Any],
) -> str:
    """Digest one canonical recovered-adoption continuation."""

    return _sha256(
        _canonical_json(
            normalize_recovered_adoption_continuation(value)
        )
    )


def _normalize_verifier_request_v5_for_recovered_evidence(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one full request without retaining any of its paths.

    This is an audit-and-binding contract only.  It neither opens a request
    path nor turns one into authority owned by the journal.
    """

    selected = _strict_mapping(
        value,
        VERIFIER_REQUEST_V5_FIELDS,
        code=(
            "transaction_journal_recovered_verifier_"
            "request_v5_fields_invalid"
        ),
    )
    if selected["schema_version"] != VERIFIER_REQUEST_V5_SCHEMA:
        raise _error(
            "transaction_journal_recovered_verifier_"
            "request_v5_schema_invalid"
        )
    try:
        normalized_selection = (
            capture_selection.normalize_capture_selection(
                selected["capture_selection"]
            )
        )
        selection_sha256 = (
            capture_selection.capture_selection_sha256(
                normalized_selection
            )
        )
        result = adoption_result.normalize_capture_adoption_result(
            selected["capture_adoption_result"]
        )
        result_sha256 = (
            adoption_result.capture_adoption_result_sha256(result)
        )
    except (
        capture_selection.CaptureSelectionError,
        adoption_result.CaptureAdoptionResultError,
    ) as exc:
        raise _error(exc.code) from exc
    claimed_selection_sha256 = _digest(
        selected["capture_selection_sha256"],
        field=(
            "transaction_journal_recovered_verifier_"
            "capture_selection_sha256"
        ),
    )
    claimed_result_sha256 = _digest(
        selected["capture_adoption_result_sha256"],
        field=(
            "transaction_journal_recovered_verifier_"
            "capture_adoption_result_sha256"
        ),
    )
    if not hmac.compare_digest(
        claimed_selection_sha256, selection_sha256
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "capture_selection_digest_mismatch"
        )
    if not hmac.compare_digest(
        claimed_result_sha256, result_sha256
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "capture_adoption_result_digest_mismatch"
        )
    if result["kind"] != adoption_result.RECOVERED_ADOPTION_KIND:
        raise _error(
            "transaction_journal_recovered_verifier_"
            "capture_adoption_result_kind_invalid"
        )
    result_evidence = result["evidence"]
    raw_limits = _strict_mapping(
        selected["adoption_verifier_limits"],
        {
            "max_files",
            "max_directories",
            "max_bytes",
            "max_file_bytes",
            "max_depth",
        },
        code=(
            "transaction_journal_recovered_verifier_"
            "adoption_limits_invalid"
        ),
    )
    limits = {
        field: _integer(
            raw_limits[field],
            field=(
                "transaction_journal_recovered_verifier_"
                f"adoption_{field}"
            ),
            minimum=1,
        )
        for field in (
            "max_files",
            "max_directories",
            "max_bytes",
            "max_file_bytes",
            "max_depth",
        )
    }
    if (
        limits["max_file_bytes"] > limits["max_bytes"]
        or limits != result_evidence["adoption_limits"]
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "adoption_limits_mismatch"
        )
    normalized = {
        "schema_version": VERIFIER_REQUEST_V5_SCHEMA,
        "snapshot_root": str(
            _absolute_path(
                selected["snapshot_root"],
                field=(
                    "transaction_journal_recovered_verifier_"
                    "snapshot_root"
                ),
            )
        ),
        "capture_manifest_sha256": _digest(
            selected["capture_manifest_sha256"],
            field=(
                "transaction_journal_recovered_verifier_"
                "capture_manifest_sha256"
            ),
        ),
        "capture_plan_sha256": _digest(
            selected["capture_plan_sha256"],
            field=(
                "transaction_journal_recovered_verifier_"
                "capture_plan_sha256"
            ),
        ),
        "capture_selection": normalized_selection,
        "capture_selection_sha256": claimed_selection_sha256,
        "capture_adoption_result": result,
        "capture_adoption_result_sha256": claimed_result_sha256,
        "capture_adoption_policy_sha256": _digest(
            selected["capture_adoption_policy_sha256"],
            field=(
                "transaction_journal_recovered_verifier_"
                "capture_adoption_policy_sha256"
            ),
        ),
        "adoption_verifier_limits": limits,
        "capture_session_id": _session_id(
            selected["capture_session_id"]
        ),
        "capture_request_sha256": _digest(
            selected["capture_request_sha256"],
            field=(
                "transaction_journal_recovered_verifier_"
                "capture_request_sha256"
            ),
        ),
        "capture_boundary_policy_sha256": _digest(
            selected["capture_boundary_policy_sha256"],
            field=(
                "transaction_journal_recovered_verifier_"
                "capture_boundary_policy_sha256"
            ),
        ),
        "capture_helper_activation_policy_sha256": _digest(
            selected["capture_helper_activation_policy_sha256"],
            field=(
                "transaction_journal_recovered_verifier_"
                "capture_helper_activation_policy_sha256"
            ),
        ),
        "expected_run_id": _run_id(selected["expected_run_id"]),
        "capture_uid": _integer(
            selected["capture_uid"],
            field=(
                "transaction_journal_recovered_verifier_capture_uid"
            ),
            minimum=1,
        ),
        "capture_export_gid": _integer(
            selected["capture_export_gid"],
            field=(
                "transaction_journal_recovered_verifier_"
                "capture_export_gid"
            ),
            minimum=1,
        ),
        "adopted_uid": _integer(
            selected["adopted_uid"],
            field=(
                "transaction_journal_recovered_verifier_adopted_uid"
            ),
            minimum=0,
        ),
        "instance_manifest_path": str(
            _absolute_path(
                selected["instance_manifest_path"],
                field=(
                    "transaction_journal_recovered_verifier_"
                    "instance_manifest_path"
                ),
            )
        ),
        "instance_manifest_sha256": _digest(
            selected["instance_manifest_sha256"],
            field=(
                "transaction_journal_recovered_verifier_"
                "instance_manifest_sha256"
            ),
        ),
        "qualification_private_root": str(
            _absolute_path(
                selected["qualification_private_root"],
                field=(
                    "transaction_journal_recovered_verifier_"
                    "qualification_private_root"
                ),
            )
        ),
        "qualification_public_root": str(
            _absolute_path(
                selected["qualification_public_root"],
                field=(
                    "transaction_journal_recovered_verifier_"
                    "qualification_public_root"
                ),
            )
        ),
        "evidence_home_path": str(
            _absolute_path(
                selected["evidence_home_path"],
                field=(
                    "transaction_journal_recovered_verifier_"
                    "evidence_home_path"
                ),
            )
        ),
        "checkout_identity_path": str(
            _absolute_path(
                selected["checkout_identity_path"],
                field=(
                    "transaction_journal_recovered_verifier_"
                    "checkout_identity_path"
                ),
            )
        ),
        "runtime_identity_path": str(
            _absolute_path(
                selected["runtime_identity_path"],
                field=(
                    "transaction_journal_recovered_verifier_"
                    "runtime_identity_path"
                ),
            )
        ),
        "instance_slug": _instance_slug(selected["instance_slug"]),
        "evidence_uid": _integer(
            selected["evidence_uid"],
            field=(
                "transaction_journal_recovered_verifier_evidence_uid"
            ),
            minimum=1,
        ),
        "verifier_uid": _integer(
            selected["verifier_uid"],
            field=(
                "transaction_journal_recovered_verifier_verifier_uid"
            ),
            minimum=1,
        ),
        "verifier_gid": _integer(
            selected["verifier_gid"],
            field=(
                "transaction_journal_recovered_verifier_verifier_gid"
            ),
            minimum=1,
        ),
        "verifier_bundle_sha256": _digest(
            selected["verifier_bundle_sha256"],
            field=(
                "transaction_journal_recovered_verifier_"
                "verifier_bundle_sha256"
            ),
        ),
        "verification_policy_sha256": _digest(
            selected["verification_policy_sha256"],
            field=(
                "transaction_journal_recovered_verifier_"
                "verification_policy_sha256"
            ),
        ),
        "operator_policy_sha256": _digest(
            selected["operator_policy_sha256"],
            field=(
                "transaction_journal_recovered_verifier_"
                "operator_policy_sha256"
            ),
        ),
        "verified_at_unix": _integer(
            selected["verified_at_unix"],
            field=(
                "transaction_journal_recovered_verifier_"
                "verified_at_unix"
            ),
            minimum=1,
        ),
    }
    if (
        normalized["adopted_uid"] != 0
        or normalized["capture_uid"]
        in {
            normalized["evidence_uid"],
            normalized["verifier_uid"],
        }
        or normalized["capture_export_gid"]
        == normalized["verifier_gid"]
        or normalized["evidence_uid"] == normalized["verifier_uid"]
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "request_identity_invalid"
        )
    if (
        Path(normalized["snapshot_root"]).name
        != result_evidence["final_name"]
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "snapshot_result_name_mismatch"
        )
    request_result_bindings = {
        "capture_manifest_sha256": "capture_manifest_sha256",
        "capture_plan_sha256": "capture_plan_sha256",
        "capture_selection_sha256": "capture_selection_sha256",
        "capture_adoption_policy_sha256": (
            "capture_adoption_policy_sha256"
        ),
        "capture_session_id": "capture_session_id",
        "capture_request_sha256": "capture_request_sha256",
        "capture_boundary_policy_sha256": (
            "capture_boundary_policy_sha256"
        ),
        "capture_helper_activation_policy_sha256": (
            "helper_activation_policy_sha256"
        ),
        "capture_uid": "capture_uid",
        "capture_export_gid": "capture_export_gid",
        "adopted_uid": "final_object_owner_uid",
        "verifier_gid": "verifier_gid",
        "instance_slug": "instance_slug",
    }
    if (
        result_evidence["final_object_group_gid"]
        != normalized["verifier_gid"]
        or any(
            normalized[request_field]
            != result_evidence[evidence_field]
            for request_field, evidence_field
            in request_result_bindings.items()
        )
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "request_result_binding_mismatch"
        )
    if (
        normalized_selection["instance_slug"]
        != normalized["instance_slug"]
        or normalized_selection["evidence_uid"]
        != normalized["evidence_uid"]
        or normalized_selection["verifier_gid"]
        != normalized["verifier_gid"]
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "selection_identity_mismatch"
        )
    public_root = Path(normalized["qualification_public_root"])
    runtime_root = public_root.parent.parent
    expected_source_roots = {
        "instance_manifest": normalized["instance_manifest_path"],
        "qualification_private": (
            normalized["qualification_private_root"]
        ),
        "qualification_public": (
            normalized["qualification_public_root"]
        ),
        "runtime": str(runtime_root),
    }
    expected_identity_paths = {
        "evidence_home": normalized["evidence_home_path"],
        "checkout": normalized["checkout_identity_path"],
        "runtime": normalized["runtime_identity_path"],
    }
    if (
        public_root
        != runtime_root / "state" / "persona-qualification"
        or normalized_selection["source_roots"]
        != expected_source_roots
        or any(
            normalized_selection["path_identities"][field]
            != path
            for field, path in expected_identity_paths.items()
        )
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "selection_path_binding_mismatch"
        )
    return normalized


def normalize_verifier_evidence_v4(
    value: Mapping[str, Any],
    *,
    expected_evidence_uid: int,
) -> dict[str, Any]:
    """Normalize the path-free result-aware verifier evidence contract."""

    selected = _strict_mapping(
        value,
        VERIFIER_EVIDENCE_V4_FIELDS,
        code=(
            "transaction_journal_recovered_verifier_"
            "evidence_v4_fields_invalid"
        ),
    )
    run_id = _run_id(selected["run_id"])
    if (
        selected["status"] != "qualified"
        or selected["claim_strength"] != VERIFIER_CLAIM_STRENGTH
        or selected["public_reputation_eligible"] is not False
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "evidence_v4_claim_invalid"
        )
    qualified = _integer(
        selected["qualified_at_unix"],
        field=(
            "transaction_journal_recovered_verifier_"
            "qualified_at_unix"
        ),
        minimum=0,
    )
    expires = _integer(
        selected["expires_at_unix"],
        field=(
            "transaction_journal_recovered_verifier_expires_at_unix"
        ),
        minimum=0,
    )
    verified = _integer(
        selected["verified_at_unix"],
        field=(
            "transaction_journal_recovered_verifier_verified_at_unix"
        ),
        minimum=0,
    )
    observed_uid = _integer(
        selected["observed_evidence_uid"],
        field=(
            "transaction_journal_recovered_verifier_"
            "observed_evidence_uid"
        ),
        minimum=1,
    )
    expected_uid = _integer(
        expected_evidence_uid,
        field=(
            "transaction_journal_recovered_verifier_"
            "expected_evidence_uid"
        ),
        minimum=1,
    )
    verifier_uid = _integer(
        selected["verifier_uid"],
        field=(
            "transaction_journal_recovered_verifier_output_verifier_uid"
        ),
        minimum=1,
    )
    creator_uid = _integer(
        selected["capture_creator_uid"],
        field=(
            "transaction_journal_recovered_verifier_"
            "capture_creator_uid"
        ),
        minimum=1,
    )
    export_gid = _integer(
        selected["capture_export_gid"],
        field=(
            "transaction_journal_recovered_verifier_"
            "output_capture_export_gid"
        ),
        minimum=1,
    )
    adopted_uid = _integer(
        selected["capture_adopted_uid"],
        field=(
            "transaction_journal_recovered_verifier_"
            "capture_adopted_uid"
        ),
        minimum=0,
    )
    if (
        observed_uid != expected_uid
        or verifier_uid == expected_uid
        or creator_uid in {expected_uid, verifier_uid}
        or adopted_uid != 0
        or not qualified <= verified < expires
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "evidence_v4_identity_or_time_invalid"
        )
    try:
        provenance = (
            adoption_result.normalize_capture_adoption_provenance(
                selected["capture_adoption_provenance"]
            )
        )
        provenance_sha256 = (
            adoption_result.capture_adoption_provenance_sha256(
                provenance
            )
        )
    except adoption_result.CaptureAdoptionResultError as exc:
        raise _error(exc.code) from exc
    claimed_provenance_sha256 = _digest(
        selected["capture_adoption_provenance_sha256"],
        field=(
            "transaction_journal_recovered_verifier_"
            "output_provenance_sha256"
        ),
    )
    if not hmac.compare_digest(
        provenance_sha256, claimed_provenance_sha256
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "output_provenance_digest_mismatch"
        )
    normalized = {
        "run_id": run_id,
        "status": "qualified",
        "qualified_at_unix": qualified,
        "expires_at_unix": expires,
        "verifier_version": _token(
            selected["verifier_version"],
            field=(
                "transaction_journal_recovered_verifier_version"
            ),
        ),
        "verifier_uid": verifier_uid,
        "claim_strength": VERIFIER_CLAIM_STRENGTH,
        "public_reputation_eligible": False,
        "verified_at_unix": verified,
        "observed_evidence_uid": observed_uid,
        "capture_creator_uid": creator_uid,
        "capture_export_gid": export_gid,
        "capture_adopted_uid": 0,
        "capture_adoption_provenance": provenance,
        "capture_adoption_provenance_sha256": provenance_sha256,
    }
    for field in (
        "summary_sha256",
        "binding_sha256",
        "verifier_bundle_sha256",
        "verification_policy_sha256",
        "capture_manifest_sha256",
        "capture_plan_sha256",
        "operator_policy_sha256",
        "capture_adoption_policy_sha256",
        "capture_object_identity_sha256",
        "capture_content_inventory_sha256",
        "capture_request_sha256",
        "capture_boundary_policy_sha256",
        "capture_helper_activation_policy_sha256",
    ):
        normalized[field] = _digest(
            selected[field],
            field=(
                "transaction_journal_recovered_verifier_"
                f"output_{field}"
            ),
        )
    return {
        field: normalized[field]
        for field in (
            "run_id",
            "summary_sha256",
            "binding_sha256",
            "status",
            "qualified_at_unix",
            "expires_at_unix",
            "verifier_version",
            "verifier_uid",
            "verifier_bundle_sha256",
            "verification_policy_sha256",
            "capture_manifest_sha256",
            "capture_plan_sha256",
            "operator_policy_sha256",
            "claim_strength",
            "public_reputation_eligible",
            "verified_at_unix",
            "observed_evidence_uid",
            "capture_creator_uid",
            "capture_export_gid",
            "capture_adopted_uid",
            "capture_adoption_policy_sha256",
            "capture_object_identity_sha256",
            "capture_content_inventory_sha256",
            "capture_request_sha256",
            "capture_boundary_policy_sha256",
            "capture_helper_activation_policy_sha256",
            "capture_adoption_provenance",
            "capture_adoption_provenance_sha256",
        )
    }


def normalize_verifier_output_v4(
    value: Mapping[str, Any],
    *,
    expected_evidence_uid: int,
) -> dict[str, Any]:
    """Normalize one complete successful verifier-v5/output-v4 object."""

    selected = _strict_mapping(
        value,
        VERIFIER_OUTPUT_V4_FIELDS,
        code=(
            "transaction_journal_recovered_verifier_"
            "output_v4_fields_invalid"
        ),
    )
    if (
        selected["schema_version"] != VERIFIER_OUTPUT_V4_SCHEMA
        or selected["status"] != "verified"
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "output_v4_schema_or_status_invalid"
        )
    evidence = normalize_verifier_evidence_v4(
        selected["evidence"],
        expected_evidence_uid=expected_evidence_uid,
    )
    if evidence["verifier_version"] != VERIFIER_V5_VERSION:
        raise _error(
            "transaction_journal_recovered_verifier_version_invalid"
        )
    normalized = {
        "schema_version": VERIFIER_OUTPUT_V4_SCHEMA,
        "status": "verified",
        "evidence": evidence,
    }
    if (
        len(_canonical_json(normalized))
        > MAX_RECOVERED_VERIFIER_OUTPUT_BYTES
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "output_v4_too_large"
        )
    return normalized


def verifier_output_v4_sha256(
    value: Mapping[str, Any],
    *,
    expected_evidence_uid: int,
) -> str:
    """Digest a complete canonical verifier-v5/output-v4 object."""

    return _sha256(
        _canonical_json(
            normalize_verifier_output_v4(
                value,
                expected_evidence_uid=expected_evidence_uid,
            )
        )
    )


def normalize_recovered_verified_evidence_v6(
    value: Mapping[str, Any],
    *,
    expected_evidence_uid: int,
    expected_verifier_output_sha256: str,
) -> dict[str, Any]:
    """Normalize signable v6 evidence without importing signing authority."""

    selected = _strict_mapping(
        value,
        VERIFIED_EVIDENCE_V6_FIELDS,
        code=(
            "transaction_journal_recovered_verifier_"
            "verified_evidence_v6_fields_invalid"
        ),
    )
    evidence = normalize_verifier_evidence_v4(
        {
            field: selected[field]
            for field in VERIFIER_EVIDENCE_V4_FIELDS
        },
        expected_evidence_uid=expected_evidence_uid,
    )
    output_sha256 = _digest(
        expected_verifier_output_sha256,
        field=(
            "transaction_journal_recovered_verifier_"
            "expected_output_sha256"
        ),
    )
    try:
        receipt = (
            source_revalidation_binding
            .normalize_source_revalidation_receipt_v2(
                selected[
                    "post_verifier_live_source_"
                    "revalidation_receipt"
                ]
            )
        )
        bound = (
            source_revalidation_binding
            .bind_source_revalidation_receipt_v2(
                receipt,
                expected_receipt_sha256=selected[
                    "post_verifier_live_source_"
                    "revalidation_receipt_sha256"
                ],
                expected_capture_adoption_provenance=(
                    evidence["capture_adoption_provenance"]
                ),
                expected_capture_adoption_provenance_sha256=(
                    evidence[
                        "capture_adoption_provenance_sha256"
                    ]
                ),
                expected_capture_object_identity_sha256=(
                    evidence["capture_object_identity_sha256"]
                ),
                expected_capture_plan_sha256=(
                    evidence["capture_plan_sha256"]
                ),
                expected_capture_manifest_sha256=(
                    evidence["capture_manifest_sha256"]
                ),
                expected_verifier_output_sha256=output_sha256,
                verified_at_unix=evidence["verified_at_unix"],
                expires_at_unix=evidence["expires_at_unix"],
            )
        )
    except (
        source_revalidation_binding.SourceRevalidationBindingError
    ) as exc:
        raise _error(exc.code) from exc
    return {**evidence, **bound}


def recovered_verified_evidence_v6_sha256(
    value: Mapping[str, Any],
    *,
    expected_evidence_uid: int,
    expected_verifier_output_sha256: str,
) -> str:
    """Digest one reconstructed canonical signable v6 evidence value."""

    return _sha256(
        _canonical_json(
            normalize_recovered_verified_evidence_v6(
                value,
                expected_evidence_uid=expected_evidence_uid,
                expected_verifier_output_sha256=(
                    expected_verifier_output_sha256
                ),
            )
        )
    )


def normalize_recovered_verifier_source_evidence(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize the path-free durable recovered-verification envelope."""

    selected = _strict_mapping(
        value,
        RECOVERED_VERIFIER_SOURCE_EVIDENCE_FIELDS,
        code=(
            "transaction_journal_recovered_verifier_"
            "source_evidence_fields_invalid"
        ),
    )
    if (
        selected["schema_version"]
        != RECOVERED_VERIFIER_SOURCE_EVIDENCE_SCHEMA
        or selected["verifier_request_schema"]
        != VERIFIER_REQUEST_V5_SCHEMA
        or selected["verifier_output_schema"]
        != VERIFIER_OUTPUT_V4_SCHEMA
        or selected["source_revalidation_receipt_schema"]
        != SOURCE_REVALIDATION_RECEIPT_V2_SCHEMA
        or selected[
            "source_revalidation_effect_completed_under_acked_head"
        ]
        is not True
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "source_evidence_schema_invalid"
        )
    raw_output = selected["verifier_output_v4"]
    if (
        not isinstance(raw_output, Mapping)
        or not isinstance(raw_output.get("evidence"), Mapping)
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "output_v4_invalid"
        )
    expected_uid = _integer(
        raw_output["evidence"].get("observed_evidence_uid"),
        field=(
            "transaction_journal_recovered_verifier_"
            "envelope_evidence_uid"
        ),
        minimum=1,
    )
    output = normalize_verifier_output_v4(
        raw_output,
        expected_evidence_uid=expected_uid,
    )
    expected_run_id = _run_id(selected["expected_run_id"])
    if output["evidence"]["run_id"] != expected_run_id:
        raise _error(
            "transaction_journal_recovered_verifier_"
            "envelope_expected_run_id_mismatch"
        )
    output_sha256 = verifier_output_v4_sha256(
        output,
        expected_evidence_uid=expected_uid,
    )
    claimed_output_sha256 = _digest(
        selected["verifier_output_v4_sha256"],
        field=(
            "transaction_journal_recovered_verifier_"
            "envelope_output_sha256"
        ),
    )
    if not hmac.compare_digest(
        output_sha256, claimed_output_sha256
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "output_v4_digest_mismatch"
        )
    try:
        receipt = (
            source_revalidation_binding
            .normalize_source_revalidation_receipt_v2(
                selected["source_revalidation_receipt_v2"]
            )
        )
        receipt_sha256 = (
            source_revalidation_binding
            .source_revalidation_receipt_v2_sha256(receipt)
        )
    except (
        source_revalidation_binding.SourceRevalidationBindingError
    ) as exc:
        raise _error(exc.code) from exc
    claimed_receipt_sha256 = _digest(
        selected["source_revalidation_receipt_v2_sha256"],
        field=(
            "transaction_journal_recovered_verifier_"
            "envelope_receipt_sha256"
        ),
    )
    if not hmac.compare_digest(
        receipt_sha256, claimed_receipt_sha256
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "receipt_v2_digest_mismatch"
        )
    try:
        provenance = (
            adoption_result.normalize_capture_adoption_provenance(
                selected["capture_adoption_provenance"]
            )
        )
        provenance_sha256 = (
            adoption_result.capture_adoption_provenance_sha256(
                provenance
            )
        )
    except adoption_result.CaptureAdoptionResultError as exc:
        raise _error(exc.code) from exc
    claimed_provenance_sha256 = _digest(
        selected["capture_adoption_provenance_sha256"],
        field=(
            "transaction_journal_recovered_verifier_"
            "envelope_provenance_sha256"
        ),
    )
    evidence = output["evidence"]
    if (
        provenance["kind"]
        != adoption_result.RECOVERED_ADOPTION_KIND
        or provenance != evidence["capture_adoption_provenance"]
        or not hmac.compare_digest(
            provenance_sha256, claimed_provenance_sha256
        )
        or not hmac.compare_digest(
            claimed_provenance_sha256,
            evidence["capture_adoption_provenance_sha256"],
        )
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "envelope_provenance_mismatch"
        )
    pre_binding = normalize_recovered_adoption_lease_binding_v2(
        selected[
            "pre_verifier_recovered_adoption_lease_binding"
        ]
    )
    post_binding = normalize_recovered_adoption_lease_binding_v2(
        selected[
            "post_verifier_recovered_adoption_lease_binding"
        ]
    )
    pre_sha256 = recovered_adoption_lease_binding_v2_sha256(
        pre_binding
    )
    post_sha256 = recovered_adoption_lease_binding_v2_sha256(
        post_binding
    )
    claimed_pre_sha256 = _digest(
        selected[
            "pre_verifier_recovered_adoption_lease_binding_sha256"
        ],
        field=(
            "transaction_journal_recovered_verifier_"
            "pre_lease_binding_sha256"
        ),
    )
    claimed_post_sha256 = _digest(
        selected[
            "post_verifier_recovered_adoption_lease_binding_sha256"
        ],
        field=(
            "transaction_journal_recovered_verifier_"
            "post_lease_binding_sha256"
        ),
    )
    ack_sha256 = _digest(
        selected["staging_tombstone_acked_record_sha256"],
        field=(
            "transaction_journal_recovered_verifier_ack_record_sha256"
        ),
    )
    if (
        selected["recovered_adoption_lease_bindings_equal"] is not True
        or pre_binding != post_binding
        or pre_binding["transaction_journal_head_state"]
        != "staging_tombstone_acked"
        or not hmac.compare_digest(
            pre_binding["transaction_journal_head_record_sha256"],
            ack_sha256,
        )
        or not hmac.compare_digest(
            pre_binding["staging_tombstone_acked_record_sha256"],
            ack_sha256,
        )
        or not hmac.compare_digest(pre_sha256, claimed_pre_sha256)
        or not hmac.compare_digest(post_sha256, claimed_post_sha256)
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "lease_binding_mismatch"
        )
    verified_v6 = normalize_recovered_verified_evidence_v6(
        {
            **evidence,
            "post_verifier_live_source_revalidation_receipt": (
                receipt
            ),
            (
                "post_verifier_live_source_"
                "revalidation_receipt_sha256"
            ): claimed_receipt_sha256,
        },
        expected_evidence_uid=expected_uid,
        expected_verifier_output_sha256=claimed_output_sha256,
    )
    v6_sha256 = recovered_verified_evidence_v6_sha256(
        verified_v6,
        expected_evidence_uid=expected_uid,
        expected_verifier_output_sha256=claimed_output_sha256,
    )
    claimed_v6_sha256 = _digest(
        selected["verified_evidence_v6_sha256"],
        field=(
            "transaction_journal_recovered_verifier_"
            "verified_evidence_v6_sha256"
        ),
    )
    if not hmac.compare_digest(v6_sha256, claimed_v6_sha256):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "verified_evidence_v6_digest_mismatch"
        )
    return {
        "schema_version": (
            RECOVERED_VERIFIER_SOURCE_EVIDENCE_SCHEMA
        ),
        "verifier_request_schema": VERIFIER_REQUEST_V5_SCHEMA,
        "verifier_request_v5_sha256": _digest(
            selected["verifier_request_v5_sha256"],
            field=(
                "transaction_journal_recovered_verifier_"
                "request_v5_sha256"
            ),
        ),
        "expected_run_id": expected_run_id,
        "verifier_output_schema": VERIFIER_OUTPUT_V4_SCHEMA,
        "verifier_output_v4": output,
        "verifier_output_v4_sha256": claimed_output_sha256,
        "source_revalidation_receipt_schema": (
            SOURCE_REVALIDATION_RECEIPT_V2_SCHEMA
        ),
        "source_revalidation_receipt_v2": receipt,
        "source_revalidation_receipt_v2_sha256": (
            claimed_receipt_sha256
        ),
        "source_revalidation_effect_completed_under_acked_head": (
            True
        ),
        "staging_tombstone_acked_record_sha256": ack_sha256,
        "recovered_adoption_continuation_sha256": _digest(
            selected["recovered_adoption_continuation_sha256"],
            field=(
                "transaction_journal_recovered_verifier_"
                "continuation_sha256"
            ),
        ),
        "capture_adoption_provenance": provenance,
        "capture_adoption_provenance_sha256": (
            claimed_provenance_sha256
        ),
        "pre_verifier_recovered_adoption_lease_binding": (
            pre_binding
        ),
        "pre_verifier_recovered_adoption_lease_binding_sha256": (
            claimed_pre_sha256
        ),
        "post_verifier_recovered_adoption_lease_binding": (
            post_binding
        ),
        "post_verifier_recovered_adoption_lease_binding_sha256": (
            claimed_post_sha256
        ),
        "recovered_adoption_lease_bindings_equal": True,
        "verified_evidence_v6_sha256": claimed_v6_sha256,
    }


def recovered_verifier_source_evidence_sha256(
    value: Mapping[str, Any],
) -> str:
    """Digest one canonical durable recovered-verification envelope."""

    return _sha256(
        _canonical_json(
            normalize_recovered_verifier_source_evidence(value)
        )
    )


def _normalize_lifecycle_activation_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        return lifecycle_receipts.normalize_activation_receipt(value)
    except lifecycle_receipts.LifecycleReceiptError as exc:
        raise _error(exc.code) from exc


def _lifecycle_activation_receipt_sha256(
    value: Mapping[str, Any],
) -> str:
    try:
        return lifecycle_receipts.activation_receipt_sha256(value)
    except lifecycle_receipts.LifecycleReceiptError as exc:
        raise _error(exc.code) from exc


def _normalize_lifecycle_scope_started_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        return lifecycle_receipts.normalize_scope_started_receipt(
            value
        )
    except lifecycle_receipts.LifecycleReceiptError as exc:
        raise _error(exc.code) from exc


def _lifecycle_scope_started_receipt_sha256(
    value: Mapping[str, Any],
) -> str:
    try:
        return lifecycle_receipts.scope_started_receipt_sha256(value)
    except lifecycle_receipts.LifecycleReceiptError as exc:
        raise _error(exc.code) from exc


def _normalize_lifecycle_clearance_bundle(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        return lifecycle_receipts.normalize_clearance_bundle(value)
    except lifecycle_receipts.LifecycleReceiptError as exc:
        raise _error(exc.code) from exc


def _lifecycle_clearance_bundle_sha256(
    value: Mapping[str, Any],
) -> str:
    try:
        return lifecycle_receipts.clearance_bundle_sha256(value)
    except lifecycle_receipts.LifecycleReceiptError as exc:
        raise _error(exc.code) from exc


def normalize_adoption_reconciliation_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one pure dual-parent reconciliation receipt."""

    try:
        return (
            adoption_reconciliation
            .normalize_adoption_reconciliation_receipt(value)
        )
    except (
        adoption_reconciliation.AdoptionReconciliationError
    ) as exc:
        raise _error(exc.code) from exc


def adoption_reconciliation_receipt_sha256(
    value: Mapping[str, Any],
) -> str:
    """Digest one canonical dual-parent reconciliation receipt."""

    try:
        return (
            adoption_reconciliation
            .adoption_reconciliation_receipt_sha256(value)
        )
    except (
        adoption_reconciliation.AdoptionReconciliationError
    ) as exc:
        raise _error(exc.code) from exc


def normalize_lifecycle_operation_binding(
    value: Any,
) -> dict[str, Any]:
    """Normalize the exact outer-head-to-supervisor-effect binding."""

    selected = _strict_mapping(
        value,
        LIFECYCLE_OPERATION_BINDING_FIELDS,
        code=(
            "transaction_journal_"
            "lifecycle_operation_binding_fields_invalid"
        ),
    )
    if (
        selected["schema_version"]
        != LIFECYCLE_OPERATION_BINDING_SCHEMA
    ):
        raise _error(
            "transaction_journal_"
            "lifecycle_operation_binding_schema_unsupported"
        )
    operation = selected["operation"]
    if operation not in LIFECYCLE_OPERATIONS:
        raise _error(
            "transaction_journal_lifecycle_operation_invalid"
        )
    outcome = selected["outcome"]
    if outcome not in LIFECYCLE_OPERATION_OUTCOMES:
        raise _error(
            "transaction_journal_lifecycle_operation_outcome_invalid"
        )
    normalized: dict[str, Any] = {
        "schema_version": LIFECYCLE_OPERATION_BINDING_SCHEMA,
        "operation": operation,
        "base_record_revision": _integer(
            selected["base_record_revision"],
            field=(
                "transaction_journal_"
                "lifecycle_operation_base_record_revision"
            ),
            minimum=1,
            maximum=MAX_EVENTS_PER_SESSION,
        ),
        "base_record_sha256": _digest(
            selected["base_record_sha256"],
            field=(
                "transaction_journal_"
                "lifecycle_operation_base_record_sha256"
            ),
        ),
        "request_sha256": _nullable_digest(
            selected["request_sha256"],
            field=(
                "transaction_journal_"
                "lifecycle_operation_request_sha256"
            ),
        ),
        "response_sha256": _nullable_digest(
            selected["response_sha256"],
            field=(
                "transaction_journal_"
                "lifecycle_operation_response_sha256"
            ),
        ),
        "outcome": outcome,
        "error_code": (
            None
            if selected["error_code"] is None
            else _reason(
                selected["error_code"],
                field=(
                    "transaction_journal_"
                    "lifecycle_operation_error_code"
                ),
            )
        ),
        "result_sha256": _nullable_digest(
            selected["result_sha256"],
            field=(
                "transaction_journal_"
                "lifecycle_operation_result_sha256"
            ),
        ),
        "supervisor_ledger_head_sha256": _nullable_digest(
            selected["supervisor_ledger_head_sha256"],
            field=(
                "transaction_journal_"
                "lifecycle_operation_supervisor_ledger_head_sha256"
            ),
        ),
        "supervisor_event_sequence": (
            None
            if selected["supervisor_event_sequence"] is None
            else _integer(
                selected["supervisor_event_sequence"],
                field=(
                    "transaction_journal_"
                    "lifecycle_operation_supervisor_event_sequence"
                ),
                minimum=1,
            )
        ),
        "supervisor_event": (
            None
            if selected["supervisor_event"] is None
            else selected["supervisor_event"]
        ),
        "supervisor_event_record_sha256": _nullable_digest(
            selected["supervisor_event_record_sha256"],
            field=(
                "transaction_journal_"
                "lifecycle_operation_supervisor_event_record_sha256"
            ),
        ),
        "supervisor_event_evidence_sha256": _nullable_digest(
            selected["supervisor_event_evidence_sha256"],
            field=(
                "transaction_journal_"
                "lifecycle_operation_supervisor_event_evidence_sha256"
            ),
        ),
    }
    event_sequence = normalized["supervisor_event_sequence"]
    event = normalized["supervisor_event"]
    event_record = normalized["supervisor_event_record_sha256"]
    if event is not None and event not in LIFECYCLE_SUPERVISOR_EVENTS:
        raise _error(
            "transaction_journal_lifecycle_operation_event_invalid"
        )
    if (
        (event_sequence is None) != (event_record is None)
        or (event_sequence is None) != (event is None)
    ):
        raise _error(
            "transaction_journal_lifecycle_operation_event_incomplete"
        )
    if operation == "prepare_clearance":
        if (
            outcome != "local_intent"
            or any(
                normalized[field] is not None
                for field in (
                    "request_sha256",
                    "response_sha256",
                    "error_code",
                    "result_sha256",
                    "supervisor_event_sequence",
                    "supervisor_event",
                    "supervisor_event_record_sha256",
                    "supervisor_event_evidence_sha256",
                )
            )
        ):
            raise _error(
                "transaction_journal_"
                "lifecycle_operation_local_intent_invalid"
            )
    else:
        if normalized["request_sha256"] is None:
            raise _error(
                "transaction_journal_"
                "lifecycle_operation_request_missing"
            )
        if outcome == "local_intent":
            raise _error(
                "transaction_journal_"
                "lifecycle_operation_remote_outcome_invalid"
            )
        if outcome == "success":
            if (
                normalized["response_sha256"] is None
                or normalized["result_sha256"] is None
                or normalized["error_code"] is not None
                or normalized[
                    "supervisor_ledger_head_sha256"
                ]
                is None
            ):
                raise _error(
                    "transaction_journal_"
                    "lifecycle_operation_success_binding_invalid"
                )
        elif outcome == "no_effect":
            if (
                normalized["result_sha256"] is not None
                or normalized["error_code"] is None
                or normalized["response_sha256"] is None
                or normalized["supervisor_event_sequence"]
                is not None
                or normalized["supervisor_event"] is not None
                or normalized[
                    "supervisor_event_record_sha256"
                ]
                is not None
                or normalized[
                    "supervisor_event_evidence_sha256"
                ]
                is not None
            ):
                raise _error(
                    "transaction_journal_"
                    "lifecycle_operation_no_effect_binding_invalid"
                )
        elif outcome in {"recovery", "attention"}:
            if (
                normalized["result_sha256"] is not None
                or normalized["error_code"] is None
                or normalized[
                    "supervisor_event_evidence_sha256"
                ]
                is not None
            ):
                raise _error(
                    "transaction_journal_"
                    "lifecycle_operation_failure_binding_invalid"
                )
    return normalized


def lifecycle_operation_binding_sha256(value: Any) -> str:
    """Digest one normalized lifecycle operation binding."""

    return _sha256(
        _canonical_json(normalize_lifecycle_operation_binding(value))
    )


def _capture_event_evidence_sha256(
    details: Mapping[str, Any],
) -> str:
    capture_ready = {
        field: details[field]
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
    return _sha256(
        _canonical_json(
            {
                "schema_version": (
                    LIFECYCLE_CAPTURE_EVENT_EVIDENCE_SCHEMA
                ),
                "capture_ready": capture_ready,
            }
        )
    )


def _normalize_details(
    state: str,
    value: Any,
    *,
    session_id: str,
) -> dict[str, Any]:
    if state not in STATE_SET:
        raise _error("transaction_journal_state_invalid")
    if state == "reserved":
        _strict_mapping(
            value,
            set(),
            code="transaction_journal_reserved_details_invalid",
        )
        return {}
    if state == "staging_create_intent":
        selected = _strict_mapping(
            value,
            {
                "staging_leaf_name",
                "capture_uid",
                "export_gid",
                "required_device",
            },
            code="transaction_journal_staging_create_details_invalid",
        )
        staging_leaf_name = _component(
            selected["staging_leaf_name"],
            field="transaction_journal_staging_leaf_name",
        )
        if staging_leaf_name != f"session-{session_id}":
            raise _error(
                "transaction_journal_staging_leaf_name_mismatch"
            )
        return {
            "staging_leaf_name": staging_leaf_name,
            "capture_uid": _integer(
                selected["capture_uid"],
                field="transaction_journal_capture_uid",
                minimum=1,
                maximum=(1 << 31) - 1,
            ),
            "export_gid": _integer(
                selected["export_gid"],
                field="transaction_journal_export_gid",
                minimum=1,
                maximum=(1 << 31) - 1,
            ),
            "required_device": _integer(
                selected["required_device"],
                field="transaction_journal_required_device",
                minimum=0,
                maximum=(1 << 63) - 1,
            ),
        }
    if state == "staging_exposed":
        selected = _strict_mapping(
            value,
            {
                "staging_exposure_receipt",
                "staging_exposure_receipt_sha256",
            },
            code=(
                "transaction_journal_"
                "staging_exposure_details_invalid"
            ),
        )
        receipt = normalize_staging_exposure_receipt(
            selected["staging_exposure_receipt"]
        )
        observed = _digest(
            selected["staging_exposure_receipt_sha256"],
            field=(
                "transaction_journal_"
                "staging_exposure_receipt_sha256"
            ),
        )
        expected = staging_exposure_receipt_sha256(receipt)
        if not hmac.compare_digest(observed, expected):
            raise _error(
                "transaction_journal_staging_exposure_receipt_digest_mismatch"
            )
        return {
            "staging_exposure_receipt": receipt,
            "staging_exposure_receipt_sha256": observed,
        }
    if state == "child_launch_intent":
        selected = _strict_mapping(
            value,
            {
                "lifecycle_activation_receipt",
                "lifecycle_activation_receipt_sha256",
            },
            code=(
                "transaction_journal_"
                "child_launch_intent_details_invalid"
            ),
        )
        receipt = _normalize_lifecycle_activation_receipt(
            selected["lifecycle_activation_receipt"]
        )
        observed = _digest(
            selected["lifecycle_activation_receipt_sha256"],
            field=(
                "transaction_journal_"
                "lifecycle_activation_receipt_sha256"
            ),
        )
        expected = _lifecycle_activation_receipt_sha256(receipt)
        if not hmac.compare_digest(observed, expected):
            raise _error(
                "transaction_journal_"
                "lifecycle_activation_receipt_digest_mismatch"
            )
        return {
            "lifecycle_activation_receipt": receipt,
            "lifecycle_activation_receipt_sha256": observed,
        }
    if state == "child_running":
        selected = _strict_mapping(
            value,
            {
                "lifecycle_scope_started_receipt",
                "lifecycle_scope_started_receipt_sha256",
                "lifecycle_operation_binding",
            },
            code="transaction_journal_child_running_details_invalid",
        )
        receipt = _normalize_lifecycle_scope_started_receipt(
            selected["lifecycle_scope_started_receipt"]
        )
        observed = _digest(
            selected["lifecycle_scope_started_receipt_sha256"],
            field=(
                "transaction_journal_"
                "lifecycle_scope_started_receipt_sha256"
            ),
        )
        expected = _lifecycle_scope_started_receipt_sha256(receipt)
        if not hmac.compare_digest(observed, expected):
            raise _error(
                "transaction_journal_"
                "lifecycle_scope_started_receipt_digest_mismatch"
            )
        return {
            "lifecycle_scope_started_receipt": receipt,
            "lifecycle_scope_started_receipt_sha256": observed,
            "lifecycle_operation_binding": (
                normalize_lifecycle_operation_binding(
                    selected["lifecycle_operation_binding"]
                )
            ),
        }
    if state == "lifecycle_clearance_intent":
        selected = _strict_mapping(
            value,
            {
                "effect_origin_state",
                "effect_origin_record_revision",
                "effect_origin_record_sha256",
                "scope_started_receipt_sha256",
                "clearance_mode",
                "lifecycle_operation_binding",
            },
            code=(
                "transaction_journal_"
                "lifecycle_clearance_intent_details_invalid"
            ),
        )
        origin = selected["effect_origin_state"]
        if origin not in LIFECYCLE_EFFECT_ORIGIN_STATES:
            raise _error(
                "transaction_journal_"
                "lifecycle_clearance_effect_origin_invalid"
            )
        mode = selected["clearance_mode"]
        if mode not in lifecycle_receipts.CLEARANCE_MODES:
            raise _error(
                "transaction_journal_lifecycle_clearance_mode_invalid"
            )
        if (
            origin in {"child_launch_intent", "child_running"}
            and mode != "terminate_and_clear"
        ):
            raise _error(
                "transaction_journal_"
                "lifecycle_clearance_mode_origin_mismatch"
            )
        started_digest = _nullable_digest(
            selected["scope_started_receipt_sha256"],
            field=(
                "transaction_journal_"
                "lifecycle_scope_started_receipt_sha256"
            ),
        )
        if origin == "child_launch_intent" and started_digest is not None:
            raise _error(
                "transaction_journal_"
                "lifecycle_clearance_recovered_start_must_be_deferred"
            )
        if origin != "child_launch_intent" and started_digest is None:
            raise _error(
                "transaction_journal_"
                "lifecycle_clearance_start_receipt_missing"
            )
        return {
            "effect_origin_state": origin,
            "effect_origin_record_revision": _integer(
                selected["effect_origin_record_revision"],
                field=(
                    "transaction_journal_"
                    "lifecycle_effect_origin_record_revision"
                ),
                minimum=1,
                maximum=MAX_EVENTS_PER_SESSION,
            ),
            "effect_origin_record_sha256": _digest(
                selected["effect_origin_record_sha256"],
                field=(
                    "transaction_journal_"
                    "lifecycle_effect_origin_record_sha256"
                ),
            ),
            "scope_started_receipt_sha256": started_digest,
            "clearance_mode": mode,
            "lifecycle_operation_binding": (
                normalize_lifecycle_operation_binding(
                    selected["lifecycle_operation_binding"]
                )
            ),
        }
    if state == "lifecycle_scope_empty":
        selected = _strict_mapping(
            value,
            {
                "lifecycle_clearance_bundle",
                "lifecycle_clearance_bundle_sha256",
                "lifecycle_operation_binding",
            },
            code=(
                "transaction_journal_"
                "lifecycle_scope_empty_details_invalid"
            ),
        )
        bundle = _normalize_lifecycle_clearance_bundle(
            selected["lifecycle_clearance_bundle"]
        )
        observed = _digest(
            selected["lifecycle_clearance_bundle_sha256"],
            field=(
                "transaction_journal_"
                "lifecycle_clearance_bundle_sha256"
            ),
        )
        expected = _lifecycle_clearance_bundle_sha256(bundle)
        if not hmac.compare_digest(observed, expected):
            raise _error(
                "transaction_journal_"
                "lifecycle_clearance_bundle_digest_mismatch"
            )
        return {
            "lifecycle_clearance_bundle": bundle,
            "lifecycle_clearance_bundle_sha256": observed,
            "lifecycle_operation_binding": (
                normalize_lifecycle_operation_binding(
                    selected["lifecycle_operation_binding"]
                )
            ),
        }
    if state == "capture_ready":
        selected = _strict_mapping(
            value,
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
            },
            code="transaction_journal_capture_ready_details_invalid",
        )
        normalized = {
            "provisional_name": _component(
                selected["provisional_name"],
                field="transaction_journal_provisional_name",
            )
        }
        for field in (
            "capture_object_identity_sha256",
            "capture_selection_sha256",
            "capture_plan_sha256",
            "capture_manifest_sha256",
            "capture_boundary_policy_sha256",
            "helper_activation_policy_sha256",
            "request_sha256",
        ):
            normalized[field] = _digest(
                selected[field],
                field=f"transaction_journal_{field}",
            )
        normalized["lifecycle_operation_binding"] = (
            normalize_lifecycle_operation_binding(
                selected["lifecycle_operation_binding"]
            )
        )
        return normalized
    if state == "adoption_intent":
        selected = _strict_mapping(
            value,
            {
                "adoption_policy_sha256",
                "provisional_name",
                "final_name",
                "final_parent_identity_sha256",
                "final_parent_filesystem_device",
                "capture_object_identity_sha256",
                "verifier_gid",
                "limits",
            },
            code="transaction_journal_adoption_intent_details_invalid",
        )
        return {
            "adoption_policy_sha256": _digest(
                selected["adoption_policy_sha256"],
                field="transaction_journal_adoption_policy_sha256",
            ),
            "provisional_name": _component(
                selected["provisional_name"],
                field="transaction_journal_provisional_name",
            ),
            "final_name": _capture_name(
                selected["final_name"],
                field="transaction_journal_final_name",
            ),
            "final_parent_identity_sha256": _digest(
                selected["final_parent_identity_sha256"],
                field=(
                    "transaction_journal_"
                    "final_parent_identity_sha256"
                ),
            ),
            "final_parent_filesystem_device": _integer(
                selected["final_parent_filesystem_device"],
                field=(
                    "transaction_journal_"
                    "final_parent_filesystem_device"
                ),
                minimum=0,
                maximum=(1 << 63) - 1,
            ),
            "capture_object_identity_sha256": _digest(
                selected["capture_object_identity_sha256"],
                field=(
                    "transaction_journal_"
                    "capture_object_identity_sha256"
                ),
            ),
            "verifier_gid": _integer(
                selected["verifier_gid"],
                field="transaction_journal_verifier_gid",
                minimum=1,
                maximum=(1 << 31) - 1,
            ),
            "limits": _limits(selected["limits"]),
        }
    if state == "adopted":
        selected = _strict_mapping(
            value,
            {
                "adoption_policy_sha256",
                "adoption_receipt_sha256",
                "final_name",
                "final_parent_identity_sha256",
                "final_parent_filesystem_device",
                "capture_object_identity_sha256",
                "adopted_stat_sha256",
                "content_inventory_sha256",
            },
            code="transaction_journal_adopted_details_invalid",
        )
        normalized = {
            "final_name": _component(
                selected["final_name"],
                field="transaction_journal_final_name",
            ),
            "final_parent_filesystem_device": _integer(
                selected["final_parent_filesystem_device"],
                field=(
                    "transaction_journal_"
                    "final_parent_filesystem_device"
                ),
                minimum=0,
                maximum=(1 << 63) - 1,
            ),
        }
        for field in (
            "adoption_policy_sha256",
            "adoption_receipt_sha256",
            "final_parent_identity_sha256",
            "capture_object_identity_sha256",
            "adopted_stat_sha256",
            "content_inventory_sha256",
        ):
            normalized[field] = _digest(
                selected[field],
                field=f"transaction_journal_{field}",
            )
        return normalized
    if state == "verifier_output_bound":
        if (
            isinstance(value, Mapping)
            and "recovered_verifier_source_evidence" in value
        ):
            selected = _strict_mapping(
                value,
                RECOVERED_VERIFIER_OUTPUT_BOUND_DETAIL_FIELDS,
                code=(
                    "transaction_journal_recovered_verifier_"
                    "output_bound_details_invalid"
                ),
            )
            envelope = (
                normalize_recovered_verifier_source_evidence(
                    selected["recovered_verifier_source_evidence"]
                )
            )
            envelope_sha256 = (
                recovered_verifier_source_evidence_sha256(envelope)
            )
            claimed_envelope_sha256 = _digest(
                selected[
                    "recovered_verifier_source_evidence_sha256"
                ],
                field=(
                    "transaction_journal_recovered_verifier_"
                    "source_evidence_sha256"
                ),
            )
            verifier_sha256 = _digest(
                selected["verifier_output_sha256"],
                field=(
                    "transaction_journal_verifier_output_sha256"
                ),
            )
            if (
                not hmac.compare_digest(
                    envelope_sha256, claimed_envelope_sha256
                )
                or not hmac.compare_digest(
                    verifier_sha256,
                    envelope["verifier_output_v4_sha256"],
                )
            ):
                raise _error(
                    "transaction_journal_recovered_verifier_"
                    "output_bound_digest_mismatch"
                )
            return {
                "verifier_output_sha256": verifier_sha256,
                "recovered_verifier_source_evidence": envelope,
                "recovered_verifier_source_evidence_sha256": (
                    claimed_envelope_sha256
                ),
            }
        selected = _strict_mapping(
            value,
            {"verifier_output_sha256"},
            code="transaction_journal_verifier_binding_details_invalid",
        )
        return {
            "verifier_output_sha256": _digest(
                selected["verifier_output_sha256"],
                field="transaction_journal_verifier_output_sha256",
            )
        }
    if state == "live_revalidation_started":
        if (
            isinstance(value, Mapping)
            and "recovered_verifier_source_evidence_sha256" in value
        ):
            selected = _strict_mapping(
                value,
                RECOVERED_LIVE_REVALIDATION_STARTED_DETAIL_FIELDS,
                code=(
                    "transaction_journal_recovered_verifier_"
                    "revalidation_started_details_invalid"
                ),
            )
            if (
                selected["state_semantics"]
                != RECOVERED_REVALIDATION_STATE_SEMANTICS
            ):
                raise _error(
                    "transaction_journal_recovered_verifier_"
                    "revalidation_state_semantics_invalid"
                )
            normalized_started = {
                field: _digest(
                    selected[field],
                    field=(
                        "transaction_journal_recovered_verifier_"
                        f"started_{field}"
                    ),
                )
                for field in (
                    "verifier_output_sha256",
                    "recovered_verifier_source_evidence_sha256",
                    "staging_tombstone_acked_record_sha256",
                )
            }
            normalized_started["state_semantics"] = (
                RECOVERED_REVALIDATION_STATE_SEMANTICS
            )
            return normalized_started
        selected = _strict_mapping(
            value,
            {"verifier_output_sha256"},
            code="transaction_journal_verifier_binding_details_invalid",
        )
        return {
            "verifier_output_sha256": _digest(
                selected["verifier_output_sha256"],
                field="transaction_journal_verifier_output_sha256",
            )
        }
    if state == "live_revalidation_receipt_complete":
        if (
            isinstance(value, Mapping)
            and "recovered_verifier_source_evidence_sha256" in value
        ):
            selected = _strict_mapping(
                value,
                RECOVERED_LIVE_REVALIDATION_COMPLETE_DETAIL_FIELDS,
                code=(
                    "transaction_journal_recovered_verifier_"
                    "revalidation_complete_details_invalid"
                ),
            )
            if (
                selected["state_semantics"]
                != RECOVERED_REVALIDATION_STATE_SEMANTICS
            ):
                raise _error(
                    "transaction_journal_recovered_verifier_"
                    "revalidation_state_semantics_invalid"
                )
            normalized_complete = {
                field: _digest(
                    selected[field],
                    field=(
                        "transaction_journal_recovered_verifier_"
                        f"complete_{field}"
                    ),
                )
                for field in (
                    "verifier_output_sha256",
                    "source_revalidation_receipt_sha256",
                    "recovered_verifier_source_evidence_sha256",
                    "staging_tombstone_acked_record_sha256",
                    "verified_evidence_v6_sha256",
                )
            }
            normalized_complete["state_semantics"] = (
                RECOVERED_REVALIDATION_STATE_SEMANTICS
            )
            return normalized_complete
        selected = _strict_mapping(
            value,
            {
                "verifier_output_sha256",
                "source_revalidation_receipt_sha256",
            },
            code=(
                "transaction_journal_"
                "live_revalidation_receipt_details_invalid"
            ),
        )
        return {
            "verifier_output_sha256": _digest(
                selected["verifier_output_sha256"],
                field="transaction_journal_verifier_output_sha256",
            ),
            "source_revalidation_receipt_sha256": _digest(
                selected["source_revalidation_receipt_sha256"],
                field=(
                    "transaction_journal_"
                    "source_revalidation_receipt_sha256"
                ),
            ),
        }
    if state == "signing_intent":
        selected = _strict_mapping(
            value,
            {
                "transaction_binding_sha256",
                "fresh_evidence_sha256",
                "requested_run_id",
                "expected_next_chain_sequence",
                "predecessor_head_sha256",
                "predecessor_attestation_sha256",
                "updated_at_unix",
                "attestor_config_sha256",
                "attestor_key_id",
                "public_key_sha256",
                "operator_policy_sha256",
                "projection_policy_sha256",
            },
            code="transaction_journal_signing_intent_details_invalid",
        )
        normalized = {
            "transaction_binding_sha256": _digest(
                selected["transaction_binding_sha256"],
                field="transaction_journal_transaction_binding_sha256",
            ),
            "fresh_evidence_sha256": _digest(
                selected["fresh_evidence_sha256"],
                field="transaction_journal_fresh_evidence_sha256",
            ),
            "requested_run_id": _run_id(
                selected["requested_run_id"]
            ),
            "expected_next_chain_sequence": _integer(
                selected["expected_next_chain_sequence"],
                field=(
                    "transaction_journal_"
                    "expected_next_chain_sequence"
                ),
                minimum=1,
            ),
            "predecessor_head_sha256": _digest(
                selected["predecessor_head_sha256"],
                field="transaction_journal_predecessor_head_sha256",
                allow_zero=True,
            ),
            "predecessor_attestation_sha256": _digest(
                selected["predecessor_attestation_sha256"],
                field=(
                    "transaction_journal_"
                    "predecessor_attestation_sha256"
                ),
                allow_zero=True,
            ),
            "updated_at_unix": _integer(
                selected["updated_at_unix"],
                field="transaction_journal_updated_at_unix",
                minimum=1,
            ),
            "attestor_key_id": _token(
                selected["attestor_key_id"],
                field="transaction_journal_attestor_key_id",
            ),
        }
        if (
            normalized["expected_next_chain_sequence"] == 1
            and normalized["predecessor_attestation_sha256"]
            != ZERO_SHA256
        ) or (
            normalized["expected_next_chain_sequence"] > 1
            and normalized["predecessor_attestation_sha256"]
            == ZERO_SHA256
        ):
            raise _error(
                "transaction_journal_predecessor_binding_invalid"
            )
        for field in (
            "attestor_config_sha256",
            "public_key_sha256",
            "operator_policy_sha256",
            "projection_policy_sha256",
        ):
            normalized[field] = _digest(
                selected[field],
                field=f"transaction_journal_{field}",
            )
        return normalized
    if state == "attestation_archive_durable_head_pending":
        fields = set(_ATTESTATION_BINDING_FIELDS)
        fields.add("attestation_archive_receipt_sha256")
        selected = _strict_mapping(
            value,
            fields,
            code=(
                "transaction_journal_"
                "attestation_archive_details_invalid"
            ),
        )
        return {
            **_normalize_attestation_binding(selected),
            "attestation_archive_receipt_sha256": _digest(
                selected["attestation_archive_receipt_sha256"],
                field=(
                    "transaction_journal_"
                    "attestation_archive_receipt_sha256"
                ),
            ),
        }
    if state == (
        "attestation_head_committed_trust_projection_pending"
    ):
        fields = set(_ATTESTATION_BINDING_FIELDS)
        fields.update(
            {
                "attestation_archive_receipt_sha256",
                "authoritative_head_sha256",
                "head_commit_receipt_sha256",
                "trust_projection_sha256",
                "projection_generated_at_unix",
            }
        )
        selected = _strict_mapping(
            value,
            fields,
            code=(
                "transaction_journal_"
                "attestation_head_commit_details_invalid"
            ),
        )
        normalized = {
            **_normalize_attestation_binding(selected),
            "projection_generated_at_unix": _integer(
                selected["projection_generated_at_unix"],
                field=(
                    "transaction_journal_projection_generated_at_unix"
                ),
                minimum=1,
            ),
        }
        for field in (
            "attestation_archive_receipt_sha256",
            "authoritative_head_sha256",
            "head_commit_receipt_sha256",
            "trust_projection_sha256",
        ):
            normalized[field] = _digest(
                selected[field],
                field=f"transaction_journal_{field}",
            )
        return normalized
    if state == "full_publication_committed_cleanup_required":
        fields = set(_ATTESTATION_BINDING_FIELDS)
        fields.update(
            {
                "attestation_archive_receipt_sha256",
                "authoritative_head_sha256",
                "head_commit_receipt_sha256",
                "trust_projection_sha256",
                "trust_projection_receipt_sha256",
                "projection_generated_at_unix",
                "adoption_receipt_sha256",
                "final_name",
                "capture_object_identity_sha256",
                "cleanup_phase",
            }
        )
        selected = _strict_mapping(
            value,
            fields,
            code=(
                "transaction_journal_"
                "full_publication_commit_details_invalid"
            ),
        )
        if selected["cleanup_phase"] != "name_bound":
            raise _error(
                "transaction_journal_cleanup_phase_invalid"
            )
        normalized = {
            **_normalize_attestation_binding(selected),
            "projection_generated_at_unix": _integer(
                selected["projection_generated_at_unix"],
                field=(
                    "transaction_journal_projection_generated_at_unix"
                ),
                minimum=1,
            ),
            "final_name": _component(
                selected["final_name"],
                field="transaction_journal_final_name",
            ),
            "cleanup_phase": "name_bound",
        }
        for field in (
            "attestation_archive_receipt_sha256",
            "authoritative_head_sha256",
            "head_commit_receipt_sha256",
            "trust_projection_sha256",
            "trust_projection_receipt_sha256",
            "adoption_receipt_sha256",
            "capture_object_identity_sha256",
        ):
            normalized[field] = _digest(
                selected[field],
                field=f"transaction_journal_{field}",
            )
        return normalized
    if state == "committed_cleanup_pending":
        selected = _strict_mapping(
            value,
            {
                "commit_record_sha256",
                "cleanup_phase",
                "cleanup_error_code",
            },
            code="transaction_journal_committed_cleanup_details_invalid",
        )
        cleanup_phase = selected["cleanup_phase"]
        if cleanup_phase not in CLEANUP_PHASES:
            raise _error(
                "transaction_journal_cleanup_phase_invalid"
            )
        return {
            "commit_record_sha256": _digest(
                selected["commit_record_sha256"],
                field="transaction_journal_commit_record_sha256",
            ),
            "cleanup_phase": cleanup_phase,
            "cleanup_error_code": _reason(
                selected["cleanup_error_code"],
                field="transaction_journal_cleanup_error_code",
            ),
        }
    if state == "cleanup_complete":
        selected = _strict_mapping(
            value,
            {
                "commit_record_sha256",
                "trust_projection_sha256",
                "cleanup_result",
            },
            code="transaction_journal_cleanup_complete_details_invalid",
        )
        cleanup_result = selected["cleanup_result"]
        if cleanup_result not in CLEANUP_RESULTS:
            raise _error(
                "transaction_journal_cleanup_result_invalid"
            )
        return {
            "commit_record_sha256": _digest(
                selected["commit_record_sha256"],
                field="transaction_journal_commit_record_sha256",
            ),
            "trust_projection_sha256": _digest(
                selected["trust_projection_sha256"],
                field="transaction_journal_trust_projection_sha256",
            ),
            "cleanup_result": cleanup_result,
        }
    if state == "staging_tombstone_ack_pending":
        selected = _strict_mapping(
            value,
            {
                "from_state",
                "effect_origin_state",
                "terminal_disposition",
                "terminal_receipt",
                "terminal_receipt_sha256",
                "tombstone_sha256",
                "staging_quarantine_intent_record_sha256",
            },
            code=(
                "transaction_journal_"
                "staging_tombstone_pending_details_invalid"
            ),
        )
        from_state = selected["from_state"]
        effect_origin = selected["effect_origin_state"]
        if (
            from_state not in STATE_SET
            or from_state in TERMINAL_STATES
            or effect_origin not in STATE_SET
            or effect_origin in TERMINAL_STATES
        ):
            raise _error(
                "transaction_journal_staging_tombstone_origin_invalid"
            )
        disposition = selected["terminal_disposition"]
        if disposition == "absent":
            receipt = normalize_staging_absence_receipt(
                selected["terminal_receipt"]
            )
            expected_digest = staging_absence_receipt_sha256(receipt)
        elif disposition == "quarantined":
            receipt = normalize_staging_quarantine_receipt(
                selected["terminal_receipt"]
            )
            expected_digest = staging_quarantine_receipt_sha256(
                receipt
            )
        else:
            raise _error(
                "transaction_journal_staging_terminal_disposition_invalid"
            )
        observed_digest = _digest(
            selected["terminal_receipt_sha256"],
            field=(
                "transaction_journal_staging_terminal_receipt_sha256"
            ),
        )
        if not hmac.compare_digest(
            observed_digest, expected_digest
        ):
            raise _error(
                "transaction_journal_"
                "staging_terminal_receipt_digest_mismatch"
            )
        tombstone_digest = _digest(
            selected["tombstone_sha256"],
            field="transaction_journal_staging_tombstone_sha256",
        )
        if not hmac.compare_digest(
            tombstone_digest, receipt["tombstone_sha256"]
        ):
            raise _error(
                "transaction_journal_staging_tombstone_digest_mismatch"
            )
        return {
            "from_state": from_state,
            "effect_origin_state": effect_origin,
            "terminal_disposition": disposition,
            "terminal_receipt": receipt,
            "terminal_receipt_sha256": observed_digest,
            "tombstone_sha256": tombstone_digest,
            "staging_quarantine_intent_record_sha256": (
                _nullable_digest(
                    selected[
                        "staging_quarantine_intent_record_sha256"
                    ],
                    field=(
                        "transaction_journal_"
                        "staging_quarantine_intent_record_sha256"
                    ),
                )
            ),
        }
    if state == "staging_tombstone_acked":
        acked_fields = {
            "from_state",
            "terminal_disposition",
            "terminal_receipt_sha256",
            "tombstone_sha256",
            "outer_ack_pending_record_sha256",
            "adoption_reconciliation_record_sha256",
            "adoption_reconciliation_receipt_sha256",
            "tombstone_ack_receipt",
            "tombstone_ack_receipt_sha256",
        }
        if (
            isinstance(value, Mapping)
            and "recovered_adoption_continuation" in value
        ):
            acked_fields.add("recovered_adoption_continuation")
        selected = _strict_mapping(
            value,
            acked_fields,
            code=(
                "transaction_journal_"
                "staging_tombstone_acked_details_invalid"
            ),
        )
        from_state = selected["from_state"]
        if from_state not in {
            "staging_tombstone_ack_pending",
            "operator_attention",
            "adoption_reconciled",
        }:
            raise _error(
                "transaction_journal_staging_tombstone_ack_from_invalid"
            )
        receipt = normalize_staging_tombstone_ack_receipt(
            selected["tombstone_ack_receipt"]
        )
        observed_digest = _digest(
            selected["tombstone_ack_receipt_sha256"],
            field=(
                "transaction_journal_"
                "staging_tombstone_ack_receipt_sha256"
            ),
        )
        expected_digest = staging_tombstone_ack_receipt_sha256(
            receipt
        )
        if not hmac.compare_digest(
            observed_digest, expected_digest
        ):
            raise _error(
                "transaction_journal_"
                "staging_tombstone_ack_receipt_digest_mismatch"
            )
        disposition = selected["terminal_disposition"]
        if disposition not in {"absent", "quarantined"}:
            raise _error(
                "transaction_journal_staging_terminal_disposition_invalid"
            )
        normalized_acked = {
            "from_state": from_state,
            "terminal_disposition": disposition,
            "terminal_receipt_sha256": _digest(
                selected["terminal_receipt_sha256"],
                field=(
                    "transaction_journal_"
                    "staging_terminal_receipt_sha256"
                ),
            ),
            "tombstone_sha256": _digest(
                selected["tombstone_sha256"],
                field="transaction_journal_staging_tombstone_sha256",
            ),
            "outer_ack_pending_record_sha256": _digest(
                selected["outer_ack_pending_record_sha256"],
                field=(
                    "transaction_journal_"
                    "outer_ack_pending_record_sha256"
                ),
            ),
            "adoption_reconciliation_record_sha256": (
                _nullable_digest(
                    selected[
                        "adoption_reconciliation_record_sha256"
                    ],
                    field=(
                        "transaction_journal_"
                        "adoption_reconciliation_record_sha256"
                    ),
                )
            ),
            "adoption_reconciliation_receipt_sha256": (
                _nullable_digest(
                    selected[
                        "adoption_reconciliation_receipt_sha256"
                    ],
                    field=(
                        "transaction_journal_"
                        "adoption_reconciliation_receipt_sha256"
                    ),
                )
            ),
            "tombstone_ack_receipt": receipt,
            "tombstone_ack_receipt_sha256": observed_digest,
        }
        if "recovered_adoption_continuation" in selected:
            if (
                from_state != "adoption_reconciled"
                or disposition != "absent"
            ):
                raise _error(
                    "transaction_journal_"
                    "recovered_adoption_continuation_disposition_invalid"
                )
            normalized_acked["recovered_adoption_continuation"] = (
                normalize_recovered_adoption_continuation(
                    selected["recovered_adoption_continuation"]
                )
            )
        return normalized_acked
    if state == "adoption_reconciliation_required":
        selected = _strict_mapping(
            value,
            {
                "from_state",
                "adoption_intent_record_sha256",
                "terminal_receipt_sha256",
                "tombstone_sha256",
            },
            code=(
                "transaction_journal_"
                "adoption_reconciliation_details_invalid"
            ),
        )
        from_state = selected["from_state"]
        if from_state not in {
            "staging_tombstone_ack_pending",
            "operator_attention",
        }:
            raise _error(
                "transaction_journal_"
                "adoption_reconciliation_from_state_invalid"
            )
        return {
            "from_state": from_state,
            "adoption_intent_record_sha256": _digest(
                selected["adoption_intent_record_sha256"],
                field=(
                    "transaction_journal_"
                    "adoption_intent_record_sha256"
                ),
            ),
            "terminal_receipt_sha256": _digest(
                selected["terminal_receipt_sha256"],
                field=(
                    "transaction_journal_"
                    "staging_terminal_receipt_sha256"
                ),
            ),
            "tombstone_sha256": _digest(
                selected["tombstone_sha256"],
                field="transaction_journal_staging_tombstone_sha256",
            ),
        }
    if state == "adoption_reconciled":
        selected = _strict_mapping(
            value,
            {
                "adoption_reconciliation_required_record_sha256",
                "adoption_reconciliation_receipt",
                "adoption_reconciliation_receipt_sha256",
            },
            code=(
                "transaction_journal_"
                "adoption_reconciled_details_invalid"
            ),
        )
        receipt = normalize_adoption_reconciliation_receipt(
            selected["adoption_reconciliation_receipt"]
        )
        observed = _digest(
            selected["adoption_reconciliation_receipt_sha256"],
            field=(
                "transaction_journal_"
                "adoption_reconciliation_receipt_sha256"
            ),
        )
        expected = adoption_reconciliation_receipt_sha256(receipt)
        if not hmac.compare_digest(observed, expected):
            raise _error(
                "transaction_journal_"
                "adoption_reconciliation_receipt_digest_mismatch"
            )
        return {
            "adoption_reconciliation_required_record_sha256": (
                _digest(
                    selected[
                        "adoption_reconciliation_required_record_sha256"
                    ],
                    field=(
                        "transaction_journal_"
                        "adoption_reconciliation_required_record_sha256"
                    ),
                )
            ),
            "adoption_reconciliation_receipt": receipt,
            "adoption_reconciliation_receipt_sha256": observed,
        }
    if state in {
        "staging_absent_cleanup_complete",
        "staging_quarantined_cleanup_complete",
    }:
        selected = _strict_mapping(
            value,
            {
                "from_state",
                "terminal_disposition",
                "terminal_receipt_sha256",
                "tombstone_ack_receipt_sha256",
            },
            code=(
                "transaction_journal_"
                "staging_terminal_complete_details_invalid"
            ),
        )
        expected_disposition = (
            "absent"
            if state == "staging_absent_cleanup_complete"
            else "quarantined"
        )
        if (
            selected["from_state"] != "staging_tombstone_acked"
            or selected["terminal_disposition"]
            != expected_disposition
        ):
            raise _error(
                "transaction_journal_"
                "staging_terminal_complete_disposition_invalid"
            )
        return {
            "from_state": "staging_tombstone_acked",
            "terminal_disposition": expected_disposition,
            "terminal_receipt_sha256": _digest(
                selected["terminal_receipt_sha256"],
                field=(
                    "transaction_journal_"
                    "staging_terminal_receipt_sha256"
                ),
            ),
            "tombstone_ack_receipt_sha256": _digest(
                selected["tombstone_ack_receipt_sha256"],
                field=(
                    "transaction_journal_"
                    "staging_tombstone_ack_receipt_sha256"
                ),
            ),
        }
    if state in {"quarantine_pending", "quarantined"}:
        if not isinstance(value, Mapping):
            raise _error(
                "transaction_journal_quarantine_details_invalid"
            )
        raw_lifecycle_status = value.get("lifecycle_status")
        quarantine_fields = {
            "from_state",
            "namespace",
            "quarantine_name",
            "object_identity_sha256",
            "reason_code",
            "lifecycle_status",
        }
        if state == "quarantine_pending":
            quarantine_fields.add("empty_leaf_policy")
        if raw_lifecycle_status == "scope_empty":
            quarantine_fields.add(
                "lifecycle_scope_empty_receipt_sha256"
            )
        selected = _strict_mapping(
            value,
            quarantine_fields,
            code="transaction_journal_quarantine_details_invalid",
        )
        from_state = selected["from_state"]
        if from_state not in STATE_SET or (
            from_state in TERMINAL_STATES
            and from_state != "quarantined"
        ):
            raise _error(
                "transaction_journal_quarantine_from_state_invalid"
            )
        namespace = selected["namespace"]
        if namespace not in QUARANTINE_NAMESPACES:
            raise _error(
                "transaction_journal_quarantine_namespace_invalid"
            )
        lifecycle_status = selected["lifecycle_status"]
        expected_statuses = {"scope_empty", "not_applicable"}
        if lifecycle_status not in expected_statuses:
            raise _error(
                "transaction_journal_lifecycle_status_invalid"
            )
        normalized_quarantine = {
            "from_state": from_state,
            "namespace": namespace,
            "quarantine_name": _component(
                selected["quarantine_name"],
                field="transaction_journal_quarantine_name",
            ),
            "object_identity_sha256": _digest(
                selected["object_identity_sha256"],
                field="transaction_journal_object_identity_sha256",
            ),
            "reason_code": _reason(
                selected["reason_code"],
                field="transaction_journal_quarantine_reason_code",
            ),
            "lifecycle_status": lifecycle_status,
        }
        if state == "quarantine_pending":
            if selected["empty_leaf_policy"] != "remove_and_fsync":
                raise _error(
                    "transaction_journal_"
                    "quarantine_empty_leaf_policy_invalid"
                )
            normalized_quarantine["empty_leaf_policy"] = (
                "remove_and_fsync"
            )
        if lifecycle_status == "scope_empty":
            normalized_quarantine[
                "lifecycle_scope_empty_receipt_sha256"
            ] = _digest(
                selected["lifecycle_scope_empty_receipt_sha256"],
                field=(
                    "transaction_journal_"
                    "lifecycle_scope_empty_receipt_sha256"
                ),
            )
        return normalized_quarantine
    if state == "operator_attention":
        if not isinstance(value, Mapping):
            raise _error(
                "transaction_journal_operator_attention_details_invalid"
            )
        from_state = value.get("from_state")
        lifecycle_specific = from_state in (
            LIFECYCLE_EFFECT_ORIGIN_STATES
            | {"lifecycle_clearance_intent"}
        )
        selected = _strict_mapping(
            value,
            (
                {
                    "from_state",
                    "reason_code",
                    "incident_sha256",
                    "lifecycle_operation_binding",
                }
                if lifecycle_specific
                else {"from_state", "reason_code", "incident_sha256"}
            ),
            code="transaction_journal_operator_attention_details_invalid",
        )
        from_state = selected["from_state"]
        if from_state not in STATE_SET or from_state in TERMINAL_STATES:
            raise _error(
                "transaction_journal_attention_from_state_invalid"
            )
        normalized_attention = {
            "from_state": from_state,
            "reason_code": _reason(
                selected["reason_code"],
                field="transaction_journal_attention_reason_code",
            ),
            "incident_sha256": _digest(
                selected["incident_sha256"],
                field="transaction_journal_incident_sha256",
            ),
        }
        if lifecycle_specific:
            normalized_attention["lifecycle_operation_binding"] = (
                normalize_lifecycle_operation_binding(
                    selected["lifecycle_operation_binding"]
                )
            )
        return normalized_attention
    selected = _strict_mapping(
        value,
        {
            "operator_attention_record_sha256",
            "resolution_code",
            "resolution_receipt_sha256",
        },
        code="transaction_journal_operator_resolution_details_invalid",
    )
    return {
        "operator_attention_record_sha256": _digest(
            selected["operator_attention_record_sha256"],
            field=(
                "transaction_journal_"
                "operator_attention_record_sha256"
            ),
        ),
        "resolution_code": _reason(
            selected["resolution_code"],
            field="transaction_journal_resolution_code",
        ),
        "resolution_receipt_sha256": _digest(
            selected["resolution_receipt_sha256"],
            field="transaction_journal_resolution_receipt_sha256",
        ),
    }


def _allowed_transition(previous: str | None, next_state: str) -> bool:
    if previous is None:
        return next_state == "reserved"
    if previous in TERMINAL_STATES:
        return False
    if previous == "staging_tombstone_ack_pending":
        return next_state in {
            "staging_tombstone_acked",
            "adoption_reconciliation_required",
            "operator_attention",
        }
    if previous == "adoption_reconciliation_required":
        return next_state in {
            "adoption_reconciled",
            "operator_attention",
        }
    if previous == "adoption_reconciled":
        return next_state in {
            "staging_tombstone_acked",
            "operator_attention",
        }
    if previous == "staging_tombstone_acked":
        return next_state in {
            "staging_absent_cleanup_complete",
            "staging_quarantined_cleanup_complete",
            "verifier_output_bound",
            "operator_attention",
        }
    if previous == "adopted":
        return next_state in {
            "staging_tombstone_ack_pending",
            "quarantine_pending",
            "operator_attention",
        }
    if previous == "quarantine_pending":
        return next_state in {
            "staging_tombstone_ack_pending",
            "quarantined",
            "operator_attention",
        }
    if previous == "staging_create_intent":
        return next_state in {
            "staging_exposed",
            "staging_tombstone_ack_pending",
            "operator_attention",
        }
    if previous == "operator_attention":
        return next_state in {
            "operator_resolved",
            "lifecycle_clearance_intent",
            "lifecycle_scope_empty",
            "staging_tombstone_ack_pending",
            "staging_tombstone_acked",
            "adoption_reconciliation_required",
            "adoption_reconciled",
            "quarantined",
            "attestation_head_committed_trust_projection_pending",
            "full_publication_committed_cleanup_required",
            "cleanup_complete",
        }
    if next_state == "staging_tombstone_ack_pending":
        return previous in {
            "staging_exposed",
            "lifecycle_scope_empty",
            "adoption_intent",
            "adopted",
        }
    if next_state == "lifecycle_clearance_intent":
        return previous in LIFECYCLE_EFFECT_ORIGIN_STATES
    if next_state == "lifecycle_scope_empty":
        return previous == "lifecycle_clearance_intent"
    if next_state == "quarantine_pending":
        return previous in {
            "staging_exposed",
            "lifecycle_scope_empty",
            "adoption_intent",
            "adopted",
        }
    if next_state == "quarantined":
        return previous == "quarantine_pending"
    if next_state == "operator_attention":
        return True
    if previous in _LINEAR_SUCCESSORS:
        return _LINEAR_SUCCESSORS[previous] == next_state
    if previous == "full_publication_committed_cleanup_required":
        return next_state in {
            "committed_cleanup_pending",
            "cleanup_complete",
        }
    if previous == "committed_cleanup_pending":
        return next_state in {
            "committed_cleanup_pending",
            "cleanup_complete",
        }
    return False


def _record_without_digest(
    *,
    instance_slug: str,
    session_id: str,
    revision: int,
    previous_record_sha256: str,
    state: str,
    recorded_at_unix: int,
    control_sha256: str,
    handoff_policy_sha256: str,
    details: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": JOURNAL_RECORD_SCHEMA,
        "instance_slug": instance_slug,
        "session_id": session_id,
        "revision": revision,
        "previous_record_sha256": previous_record_sha256,
        "state": state,
        "recorded_at_unix": recorded_at_unix,
        "control_sha256": control_sha256,
        "handoff_policy_sha256": handoff_policy_sha256,
        "details": dict(details),
    }


def _build_record(
    *,
    instance_slug: str,
    session_id: str,
    revision: int,
    previous_record_sha256: str,
    state: str,
    recorded_at_unix: int,
    control_sha256: str,
    handoff_policy_sha256: str,
    details: Mapping[str, Any],
) -> dict[str, Any]:
    payload = _record_without_digest(
        instance_slug=instance_slug,
        session_id=session_id,
        revision=revision,
        previous_record_sha256=previous_record_sha256,
        state=state,
        recorded_at_unix=recorded_at_unix,
        control_sha256=control_sha256,
        handoff_policy_sha256=handoff_policy_sha256,
        details=details,
    )
    return {
        **payload,
        "record_sha256": _sha256(_canonical_json(payload)),
    }


class _DuplicateKeyError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, selected in pairs:
        if key in value:
            raise _DuplicateKeyError(key)
        value[key] = selected
    return value


def _decode_record(raw: bytes) -> dict[str, Any]:
    if (
        not raw
        or len(raw) > MAX_RECORD_BYTES
        or not raw.endswith(b"\n")
        or raw.endswith(b"\n\n")
    ):
        raise _error("transaction_journal_record_encoding_invalid")
    try:
        text = raw[:-1].decode("ascii")
        value = json.loads(text, object_pairs_hook=_unique_object)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateKeyError,
    ) as exc:
        raise _error("transaction_journal_record_encoding_invalid") from exc
    if not isinstance(value, dict):
        raise _error("transaction_journal_record_fields_invalid")
    if _canonical_json(value) + b"\n" != raw:
        raise _error("transaction_journal_record_not_canonical")
    return value


def _normalize_record(value: Any) -> dict[str, Any]:
    selected = _strict_mapping(
        value,
        RECORD_FIELDS,
        code="transaction_journal_record_fields_invalid",
    )
    if selected["schema_version"] != JOURNAL_RECORD_SCHEMA:
        raise _error("transaction_journal_record_schema_unsupported")
    session_id = _session_id(selected["session_id"])
    state = selected["state"]
    if state not in STATE_SET:
        raise _error("transaction_journal_state_invalid")
    normalized = _record_without_digest(
        instance_slug=_instance_slug(selected["instance_slug"]),
        session_id=session_id,
        revision=_integer(
            selected["revision"],
            field="transaction_journal_revision",
            minimum=1,
            maximum=MAX_EVENTS_PER_SESSION,
        ),
        previous_record_sha256=_digest(
            selected["previous_record_sha256"],
            field="transaction_journal_previous_record_sha256",
            allow_zero=True,
        ),
        state=state,
        recorded_at_unix=_integer(
            selected["recorded_at_unix"],
            field="transaction_journal_recorded_at_unix",
            minimum=1,
        ),
        control_sha256=_digest(
            selected["control_sha256"],
            field="transaction_journal_control_sha256",
        ),
        handoff_policy_sha256=_digest(
            selected["handoff_policy_sha256"],
            field="transaction_journal_handoff_policy_sha256",
        ),
        details=_normalize_details(
            state,
            selected["details"],
            session_id=session_id,
        ),
    )
    observed_digest = _digest(
        selected["record_sha256"],
        field="transaction_journal_record_sha256",
    )
    expected_digest = _sha256(_canonical_json(normalized))
    if not hmac.compare_digest(observed_digest, expected_digest):
        raise _error("transaction_journal_record_digest_mismatch")
    return {**normalized, "record_sha256": observed_digest}


class TransactionJournalRecord:
    """Immutable canonical journal record value."""

    __slots__ = ("_canonical",)

    def __init__(self, value: Mapping[str, Any]) -> None:
        normalized = _normalize_record(value)
        self._canonical = _canonical_json(normalized)

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self._canonical.decode("ascii"))
        if not isinstance(value, dict):
            raise AssertionError("canonical journal record is not an object")
        return value

    @property
    def state(self) -> str:
        return self.to_dict()["state"]

    @property
    def revision(self) -> int:
        return self.to_dict()["revision"]

    @property
    def record_sha256(self) -> str:
        return self.to_dict()["record_sha256"]

    @property
    def recorded_at_unix(self) -> int:
        return self.to_dict()["recorded_at_unix"]

    @property
    def details(self) -> dict[str, Any]:
        return self.to_dict()["details"]


def _record_for_state(
    records: tuple[TransactionJournalRecord, ...],
    state: str,
) -> TransactionJournalRecord:
    for record in records:
        if record.state == state:
            return record
    raise _error("transaction_journal_history_binding_missing")


def _immediate_predecessor(
    records: tuple[TransactionJournalRecord, ...],
    record: TransactionJournalRecord,
    *,
    expected_state: str | None = None,
) -> TransactionJournalRecord:
    """Return the exact record immediately preceding ``record``.

    Recovery states such as ``operator_attention`` and
    ``quarantine_pending`` may legitimately occur more than once.  Looking
    them up by state alone can therefore bind a later effect to an unrelated
    earlier attempt.  All repeatable recovery transitions must walk the
    record chain by position instead.
    """

    try:
        index = records.index(record)
    except ValueError as exc:
        raise _error(
            "transaction_journal_history_binding_missing"
        ) from exc
    if index == 0:
        raise _error("transaction_journal_history_binding_missing")
    predecessor = records[index - 1]
    if (
        expected_state is not None
        and predecessor.state != expected_state
    ):
        raise _error(
            "transaction_journal_history_predecessor_mismatch"
        )
    return predecessor


def _effect_record_for_clearance_intent(
    records: tuple[TransactionJournalRecord, ...],
    clearance_intent: TransactionJournalRecord,
) -> TransactionJournalRecord:
    predecessor = _immediate_predecessor(records, clearance_intent)
    if predecessor.state == "operator_attention":
        if predecessor.details["from_state"] not in (
            LIFECYCLE_EFFECT_ORIGIN_STATES
        ):
            raise _error(
                "transaction_journal_"
                "lifecycle_clearance_attention_origin_invalid"
            )
        predecessor = _immediate_predecessor(
            records,
            predecessor,
            expected_state=predecessor.details["from_state"],
        )
    if predecessor.state not in LIFECYCLE_EFFECT_ORIGIN_STATES:
        raise _error(
            "transaction_journal_"
            "lifecycle_clearance_effect_origin_invalid"
        )
    return predecessor


def _clearance_intent_for_scope_empty(
    records: tuple[TransactionJournalRecord, ...],
    scope_empty: TransactionJournalRecord,
) -> TransactionJournalRecord:
    predecessor = _immediate_predecessor(records, scope_empty)
    if predecessor.state == "operator_attention":
        if predecessor.details["from_state"] != (
            "lifecycle_clearance_intent"
        ):
            raise _error(
                "transaction_journal_"
                "lifecycle_scope_empty_attention_origin_invalid"
            )
        predecessor = _immediate_predecessor(
            records,
            predecessor,
            expected_state="lifecycle_clearance_intent",
        )
    if predecessor.state != "lifecycle_clearance_intent":
        raise _error(
            "transaction_journal_lifecycle_clearance_intent_missing"
        )
    return predecessor


def _validate_scope_started_binding(
    receipt: Mapping[str, Any],
    *,
    receipt_sha256: str,
    records: tuple[TransactionJournalRecord, ...],
    expected_session_id: str,
    handoff_policy_sha256: str,
    activation_receipt: Mapping[str, Any],
    activation_receipt_sha256: str,
) -> None:
    staging_create = _record_for_state(
        records, "staging_create_intent"
    )
    staging_exposed = _record_for_state(records, "staging_exposed")
    launch_intent = _record_for_state(
        records, "child_launch_intent"
    )
    expected = {
        "capture_session_id": expected_session_id,
        "lifecycle_backend": lifecycle_receipts.LIFECYCLE_BACKEND,
        "lifecycle_provider": activation_receipt[
            "lifecycle_provider"
        ],
        "lifecycle_scope_id": (
            f"jlq-{lifecycle_receipts.LIFECYCLE_BACKEND}-"
            f"{expected_session_id}"
        ),
        "staging_transaction_intent_sha256": (
            staging_create.record_sha256
        ),
        "staging_exposure_receipt_sha256": staging_exposed.details[
            "staging_exposure_receipt_sha256"
        ],
        "child_launch_intent_record_sha256": (
            launch_intent.record_sha256
        ),
        "handoff_policy_sha256": handoff_policy_sha256,
        "helper_activation_policy_sha256": activation_receipt[
            "helper_activation_policy_sha256"
        ],
        "capture_uid": staging_create.details["capture_uid"],
        "export_gid": staging_create.details["export_gid"],
        "lifecycle_activation_receipt_sha256": (
            activation_receipt_sha256
        ),
        "host_boot_id_sha256": activation_receipt[
            "host_boot_id_sha256"
        ],
    }
    if any(receipt[field] != value for field, value in expected.items()):
        raise _error(
            "transaction_journal_lifecycle_scope_started_binding_changed"
        )
    if not hmac.compare_digest(
        receipt_sha256,
        _lifecycle_scope_started_receipt_sha256(receipt),
    ):
        raise _error(
            "transaction_journal_"
            "lifecycle_scope_started_receipt_digest_mismatch"
        )


def _validate_lifecycle_operation_successor_binding(
    previous: TransactionJournalRecord,
    record: TransactionJournalRecord,
) -> None:
    details = record.details
    if "lifecycle_operation_binding" not in details:
        raise _error(
            "transaction_journal_lifecycle_operation_binding_missing"
        )
    binding = details["lifecycle_operation_binding"]
    if (
        binding["base_record_revision"] != previous.revision
        or binding["base_record_sha256"] != previous.record_sha256
    ):
        raise _error(
            "transaction_journal_lifecycle_operation_base_changed"
        )
    operation = binding["operation"]
    if previous.state not in _LIFECYCLE_OPERATION_BASE_STATES[
        operation
    ]:
        raise _error(
            "transaction_journal_lifecycle_operation_base_state_invalid"
        )
    if record.state not in (
        _LIFECYCLE_OPERATION_SUCCESSORS_BY_BASE[
            (operation, previous.state)
        ]
    ):
        raise _error(
            "transaction_journal_lifecycle_operation_successor_invalid"
        )
    if record.state == "operator_attention":
        if binding["outcome"] not in {"attention", "recovery"}:
            raise _error(
                "transaction_journal_"
                "lifecycle_operation_attention_outcome_invalid"
            )
        if details["incident_sha256"] != (
            lifecycle_operation_binding_sha256(binding)
        ):
            raise _error(
                "transaction_journal_"
                "lifecycle_operation_attention_incident_changed"
            )
        return
    expected_outcome = (
        "local_intent"
        if operation == "prepare_clearance"
        else "success"
    )
    if binding["outcome"] != expected_outcome:
        raise _error(
            "transaction_journal_lifecycle_operation_outcome_mismatch"
        )
    evidence = binding["supervisor_event_evidence_sha256"]
    if (record.state == "capture_ready") != (evidence is not None):
        raise _error(
            "transaction_journal_"
            "lifecycle_operation_event_evidence_mismatch"
        )
    if record.state == "capture_ready" and evidence != (
        _capture_event_evidence_sha256(details)
    ):
        raise _error(
            "transaction_journal_"
            "lifecycle_operation_event_evidence_changed"
        )
    event_present = (
        binding["supervisor_event_sequence"] is not None
    )
    event_required = record.state == "capture_ready" or (
        operation == "await_capture_event"
        and binding["outcome"] == "success"
    )
    if event_present != event_required:
        raise _error(
            "transaction_journal_lifecycle_operation_event_mismatch"
        )
    if record.state == "capture_ready" and (
        binding["supervisor_event"] != "capture_ready"
    ):
        raise _error(
            "transaction_journal_lifecycle_operation_event_mismatch"
        )
    if (
        operation == "await_capture_event"
        and record.state == "lifecycle_clearance_intent"
        and binding["supervisor_event"] not in {
            "child_exited",
            "capture_deadline_exceeded",
        }
    ):
        raise _error(
            "transaction_journal_lifecycle_operation_event_mismatch"
        )
    if operation == "prepare_clearance":
        inherited_head = None
        if "lifecycle_operation_binding" in previous.details:
            inherited_head = previous.details[
                "lifecycle_operation_binding"
            ]["supervisor_ledger_head_sha256"]
        if (
            binding["supervisor_ledger_head_sha256"]
            != inherited_head
        ):
            raise _error(
                "transaction_journal_"
                "lifecycle_operation_ledger_head_changed"
            )


def _validate_lifecycle_history(
    records: tuple[TransactionJournalRecord, ...],
    *,
    expected_session_id: str,
    handoff_policy_sha256: str,
) -> None:
    states = {record.state for record in records}
    lifecycle_states = {
        "child_launch_intent",
        "child_running",
        "capture_ready",
        "lifecycle_clearance_intent",
        "lifecycle_scope_empty",
        "adoption_intent",
    }
    if not (states & lifecycle_states):
        return
    if "child_launch_intent" not in states:
        raise _error(
            "transaction_journal_lifecycle_launch_intent_missing"
        )
    launch_record = _record_for_state(
        records, "child_launch_intent"
    )
    activation = launch_record.details[
        "lifecycle_activation_receipt"
    ]
    activation_digest = launch_record.details[
        "lifecycle_activation_receipt_sha256"
    ]

    for index, record in enumerate(records):
        if record.state in {
            "child_running",
            "capture_ready",
            "lifecycle_clearance_intent",
            "lifecycle_scope_empty",
        } or (
            record.state == "operator_attention"
            and "lifecycle_operation_binding" in record.details
        ):
            if index == 0:
                raise _error(
                    "transaction_journal_"
                    "lifecycle_operation_base_missing"
                )
            _validate_lifecycle_operation_successor_binding(
                records[index - 1],
                record,
            )

    started: Mapping[str, Any] | None = None
    started_digest: str | None = None
    if "child_running" in states:
        running = _record_for_state(records, "child_running").details
        started = running["lifecycle_scope_started_receipt"]
        started_digest = running[
            "lifecycle_scope_started_receipt_sha256"
        ]
        _validate_scope_started_binding(
            started,
            receipt_sha256=started_digest,
            records=records,
            expected_session_id=expected_session_id,
            handoff_policy_sha256=handoff_policy_sha256,
            activation_receipt=activation,
            activation_receipt_sha256=activation_digest,
        )

    if "capture_ready" in states:
        if started is None:
            raise _error(
                "transaction_journal_lifecycle_start_receipt_missing"
            )
        ready = _record_for_state(records, "capture_ready").details
        if ready["helper_activation_policy_sha256"] != activation[
            "helper_activation_policy_sha256"
        ]:
            raise _error(
                "transaction_journal_"
                "lifecycle_helper_activation_policy_changed"
            )

    if "lifecycle_clearance_intent" not in states:
        return
    clearance_record = _record_for_state(
        records, "lifecycle_clearance_intent"
    )
    clearance = clearance_record.details
    effect_record = _effect_record_for_clearance_intent(
        records, clearance_record
    )
    if (
        clearance["effect_origin_state"] != effect_record.state
        or clearance["effect_origin_record_revision"]
        != effect_record.revision
        or clearance["effect_origin_record_sha256"]
        != effect_record.record_sha256
    ):
        raise _error(
            "transaction_journal_"
            "lifecycle_clearance_effect_origin_changed"
        )
    if effect_record.state == "child_launch_intent":
        expected_started_digest = None
    else:
        if started_digest is None:
            raise _error(
                "transaction_journal_lifecycle_start_receipt_missing"
            )
        expected_started_digest = started_digest
    if clearance["scope_started_receipt_sha256"] != (
        expected_started_digest
    ):
        raise _error(
            "transaction_journal_"
            "lifecycle_clearance_start_binding_changed"
        )

    if "lifecycle_scope_empty" not in states:
        return
    scope_empty_record = _record_for_state(
        records, "lifecycle_scope_empty"
    )
    bound_clearance_record = _clearance_intent_for_scope_empty(
        records, scope_empty_record
    )
    if bound_clearance_record.record_sha256 != (
        clearance_record.record_sha256
    ):
        raise _error(
            "transaction_journal_lifecycle_clearance_intent_changed"
        )
    bundle = scope_empty_record.details[
        "lifecycle_clearance_bundle"
    ]
    if (
        bundle["activation_receipt"] != activation
        or bundle["activation_receipt_sha256"] != activation_digest
    ):
        raise _error(
            "transaction_journal_lifecycle_activation_binding_changed"
        )
    intent_receipt = bundle["clearance_intent_receipt"]
    expected_scope_id = (
        f"jlq-{lifecycle_receipts.LIFECYCLE_BACKEND}-"
        f"{expected_session_id}"
    )
    if (
        intent_receipt["capture_session_id"] != expected_session_id
        or intent_receipt["lifecycle_scope_id"]
        != expected_scope_id
    ):
        raise _error(
            "transaction_journal_lifecycle_scope_binding_changed"
        )
    if (
        intent_receipt["effect_origin_state"]
        != clearance["effect_origin_state"]
        or intent_receipt["effect_origin_record_sha256"]
        != clearance["effect_origin_record_sha256"]
        or intent_receipt["scope_started_receipt_sha256"]
        != clearance["scope_started_receipt_sha256"]
        or intent_receipt["clearance_mode"]
        != clearance["clearance_mode"]
        or intent_receipt["outer_clearance_intent_record_sha256"]
        != clearance_record.record_sha256
    ):
        raise _error(
            "transaction_journal_lifecycle_clearance_binding_changed"
        )
    bundled_started = bundle["scope_started_receipt"]
    bundled_started_digest = bundle["scope_started_receipt_sha256"]
    if started is not None:
        if (
            bundled_started != started
            or bundled_started_digest != started_digest
        ):
            raise _error(
                "transaction_journal_"
                "lifecycle_scope_started_binding_changed"
            )
    elif bundled_started is not None:
        if effect_record.state != "child_launch_intent":
            raise _error(
                "transaction_journal_"
                "lifecycle_recovered_start_origin_invalid"
            )
        _validate_scope_started_binding(
            bundled_started,
            receipt_sha256=bundled_started_digest,
            records=records,
            expected_session_id=expected_session_id,
            handoff_policy_sha256=handoff_policy_sha256,
            activation_receipt=activation,
            activation_receipt_sha256=activation_digest,
        )

    if "adoption_intent" in states:
        empty = bundle["scope_empty_receipt"]
        if (
            empty["effect_origin_state"] != "capture_ready"
            or empty["completion_disposition"] != "clean_exit"
            or empty["stderr_bytes"] != 0
            or empty["stderr_sha256"]
            != lifecycle_receipts.EMPTY_SHA256
            or empty["clearance_mode"]
            != "wait_clean_then_terminate_on_deadline"
            or empty["adoption_eligible"] is not True
        ):
            raise _error(
                "transaction_journal_lifecycle_adoption_forbidden"
            )


_STAGING_TOMBSTONE_EFFECT_ORIGINS = frozenset(
    {
        "staging_create_intent",
        "staging_exposed",
        "child_launch_intent",
        "child_running",
        "capture_ready",
        "lifecycle_scope_empty",
        "adoption_intent",
        "adopted",
    }
)


def _staging_tombstone_effect_origin(
    records: tuple[TransactionJournalRecord, ...],
    pending: TransactionJournalRecord,
) -> str:
    index = records.index(pending)
    if index == 0:
        raise _error(
            "transaction_journal_staging_tombstone_origin_missing"
        )
    previous = records[index - 1]
    origin = previous.state
    if origin == "quarantine_pending":
        origin = previous.details["from_state"]
    elif origin == "operator_attention":
        origin = previous.details["from_state"]
        if origin == "quarantine_pending":
            prior_pending = _immediate_predecessor(
                records,
                previous,
                expected_state="quarantine_pending",
            )
            origin = prior_pending.details["from_state"]
    if origin == "lifecycle_scope_empty":
        scope_empty = _record_for_state(
            records, "lifecycle_scope_empty"
        ).details["lifecycle_clearance_bundle"][
            "scope_empty_receipt"
        ]
        origin = scope_empty["effect_origin_state"]
    if origin not in _STAGING_TOMBSTONE_EFFECT_ORIGINS:
        raise _error(
            "transaction_journal_staging_tombstone_origin_invalid"
        )
    return origin


def _validate_adoption_reconciled_binding(
    records: tuple[TransactionJournalRecord, ...],
    *,
    expected_session_id: str,
    pending_record: TransactionJournalRecord,
    required_record: TransactionJournalRecord,
    reconciled_record: TransactionJournalRecord,
) -> str:
    predecessor = _immediate_predecessor(
        records, reconciled_record
    )
    if predecessor.state == "operator_attention":
        if predecessor.details["from_state"] != (
            "adoption_reconciliation_required"
        ):
            raise _error(
                "transaction_journal_"
                "adoption_reconciliation_predecessor_invalid"
            )
        predecessor = _immediate_predecessor(
            records,
            predecessor,
            expected_state="adoption_reconciliation_required",
        )
    if predecessor.record_sha256 != required_record.record_sha256:
        raise _error(
            "transaction_journal_"
            "adoption_reconciliation_predecessor_invalid"
        )

    reconciled = reconciled_record.details
    if (
        reconciled[
            "adoption_reconciliation_required_record_sha256"
        ]
        != required_record.record_sha256
    ):
        raise _error(
            "transaction_journal_"
            "adoption_reconciliation_required_record_changed"
        )
    receipt = reconciled["adoption_reconciliation_receipt"]
    pending = pending_record.details
    terminal = pending["terminal_receipt"]
    adoption_intent_record = _record_for_state(
        records, "adoption_intent"
    )
    adoption_intent = adoption_intent_record.details
    staging_create = _record_for_state(
        records, "staging_create_intent"
    )
    scope_empty = _record_for_state(
        records, "lifecycle_scope_empty"
    ).details["lifecycle_clearance_bundle"]

    namespace_fields = (
        "shared_root_identity_sha256",
        "recovery_namespace_identity_sha256",
        "quarantine_namespace_identity_sha256",
        "transactions_namespace_identity_sha256",
    )
    expected = {
        "capture_session_id": expected_session_id,
        "adoption_intent_record_sha256": (
            adoption_intent_record.record_sha256
        ),
        "adoption_policy_sha256": adoption_intent[
            "adoption_policy_sha256"
        ],
        "lifecycle_scope_empty_receipt_sha256": scope_empty[
            "scope_empty_receipt_sha256"
        ],
        "staging_transaction_intent_sha256": (
            staging_create.record_sha256
        ),
        "staging_terminal_receipt_sha256": pending[
            "terminal_receipt_sha256"
        ],
        "staging_tombstone_sha256": pending["tombstone_sha256"],
        "staging_terminal_disposition": pending[
            "terminal_disposition"
        ],
        "staging_leaf_identity_sha256": terminal[
            "staging_leaf_identity_sha256"
        ],
        "staging_inspection_lock_epoch_sha256": terminal[
            "inspection_lock_epoch_sha256"
        ],
        "final_parent_identity_sha256": adoption_intent[
            "final_parent_identity_sha256"
        ],
        "final_parent_filesystem_device": adoption_intent[
            "final_parent_filesystem_device"
        ],
        "final_name": adoption_intent["final_name"],
        "expected_object_identity_sha256": adoption_intent[
            "capture_object_identity_sha256"
        ],
        "expected_verifier_gid": adoption_intent["verifier_gid"],
        "adoption_limits": adoption_intent["limits"],
    }
    expected.update(
        {field: terminal[field] for field in namespace_fields}
    )
    if pending["terminal_disposition"] == "quarantined":
        expected.update(
            {
                "staging_terminal_quarantine_name": terminal[
                    "quarantine_name"
                ],
                "staging_terminal_quarantine_reason_code": terminal[
                    "reason_code"
                ],
                "staging_terminal_quarantined_stat_sha256": (
                    terminal["quarantined_stat_sha256"]
                ),
            }
        )
    else:
        expected.update(
            {
                "staging_terminal_quarantine_name": None,
                "staging_terminal_quarantine_reason_code": None,
                "staging_terminal_quarantined_stat_sha256": None,
            }
        )
    if any(
        receipt[field] != expected_value
        for field, expected_value in expected.items()
    ):
        raise _error(
            "transaction_journal_"
            "adoption_reconciliation_receipt_binding_changed"
        )
    return receipt["result"]


def _derive_recovered_adoption_artifacts(
    records: tuple[TransactionJournalRecord, ...],
) -> dict[str, Any]:
    """Derive every recovered result claim from an exact reconciled prefix."""

    if not records or records[-1].state != "adoption_reconciled":
        raise _error(
            "transaction_journal_"
            "recovered_adoption_context_prefix_invalid"
        )
    reconciled = records[-1]
    embedded_receipt = reconciled.details[
        "adoption_reconciliation_receipt"
    ]
    receipt = normalize_adoption_reconciliation_receipt(
        embedded_receipt
    )
    if (
        receipt != embedded_receipt
        or receipt["result"] != "recovered_adoption"
    ):
        raise _error(
            "transaction_journal_"
            "recovered_adoption_context_result_invalid"
        )
    try:
        validated_history = (
            recovered_adoption_evidence
            ._mint_validated_recovered_adoption_history_v5(
                tuple(record.to_dict() for record in records)
            )
        )
        evidence = (
            recovered_adoption_evidence
            .bind_recovered_adoption_evidence(
                validated_history=validated_history,
                adoption_reconciliation_receipt=receipt,
            )
        )
        evidence_digest = (
            recovered_adoption_evidence
            .recovered_adoption_evidence_sha256(evidence)
        )
        result = adoption_result.build_capture_adoption_result(
            adoption_result.RECOVERED_ADOPTION_KIND,
            evidence,
        )
        result_digest = (
            adoption_result.capture_adoption_result_sha256(result)
        )
        provenance = (
            adoption_result.project_capture_adoption_provenance(
                result
            )
        )
        provenance_digest = (
            adoption_result.capture_adoption_provenance_sha256(
                provenance
            )
        )
    except (
        recovered_adoption_evidence.RecoveredAdoptionEvidenceError,
        adoption_result.CaptureAdoptionResultError,
    ) as exc:
        raise _error(exc.code) from exc
    binding = normalize_recovered_adoption_lease_binding_v2(
        {
            "schema_version": (
                RECOVERED_ADOPTION_LEASE_BINDING_V2_SCHEMA
            ),
            "transaction_journal_schema": JOURNAL_RECORD_SCHEMA,
            "transaction_journal_head_state": (
                "adoption_reconciled"
            ),
            "transaction_journal_head_revision": (
                reconciled.revision
            ),
            "transaction_journal_head_record_sha256": (
                reconciled.record_sha256
            ),
            "staging_tombstone_acked_record_sha256": None,
            "capture_session_id": evidence["capture_session_id"],
            "final_parent_identity_sha256": evidence[
                "final_parent_identity_sha256"
            ],
            "capture_object_identity_sha256": evidence[
                "capture_object_identity_sha256"
            ],
            "reconciled_final_object_stat_sha256": evidence[
                "reconciled_final_object_stat_sha256"
            ],
            "reconciled_content_inventory_sha256": evidence[
                "reconciled_content_inventory_sha256"
            ],
            "recovered_adoption_evidence_sha256": (
                evidence_digest
            ),
            "capture_adoption_result_sha256": result_digest,
            "capture_adoption_provenance_sha256": (
                provenance_digest
            ),
        }
    )
    continuation = normalize_recovered_adoption_continuation(
        {
            "schema_version": (
                RECOVERED_ADOPTION_CONTINUATION_SCHEMA
            ),
            "recovered_adoption_evidence_sha256": (
                evidence_digest
            ),
            "capture_adoption_result_sha256": result_digest,
            "capture_adoption_provenance": provenance,
            "capture_adoption_provenance_sha256": (
                provenance_digest
            ),
            "pre_ack_recovered_adoption_lease_binding": binding,
            "pre_ack_recovered_adoption_lease_binding_sha256": (
                recovered_adoption_lease_binding_v2_sha256(binding)
            ),
        }
    )
    return {
        "evidence": evidence,
        "evidence_sha256": evidence_digest,
        "result": result,
        "result_sha256": result_digest,
        "provenance": provenance,
        "provenance_sha256": provenance_digest,
        "pre_ack_recovered_adoption_lease_binding": binding,
        "continuation": continuation,
        "continuation_sha256": (
            recovered_adoption_continuation_sha256(continuation)
        ),
    }


def _post_ack_recovered_adoption_journal_binding(
    artifacts: Mapping[str, Any],
    acked_record: TransactionJournalRecord,
) -> dict[str, Any]:
    if acked_record.state != "staging_tombstone_acked":
        raise _error(
            "transaction_journal_"
            "recovered_adoption_context_ack_record_invalid"
        )
    pre_ack = artifacts[
        "pre_ack_recovered_adoption_lease_binding"
    ]
    return normalize_recovered_adoption_lease_binding_v2(
        {
            **pre_ack,
            "transaction_journal_head_state": (
                "staging_tombstone_acked"
            ),
            "transaction_journal_head_revision": (
                acked_record.revision
            ),
            "transaction_journal_head_record_sha256": (
                acked_record.record_sha256
            ),
            "staging_tombstone_acked_record_sha256": (
                acked_record.record_sha256
            ),
        }
    )


def _validate_staging_tombstone_handshake(
    records: tuple[TransactionJournalRecord, ...],
    *,
    expected_session_id: str,
) -> None:
    pending_records = tuple(
        record
        for record in records
        if record.state == "staging_tombstone_ack_pending"
    )
    acked_records = tuple(
        record
        for record in records
        if record.state == "staging_tombstone_acked"
    )
    reconciliation_records = tuple(
        record
        for record in records
        if record.state == "adoption_reconciliation_required"
    )
    reconciled_records = tuple(
        record
        for record in records
        if record.state == "adoption_reconciled"
    )
    completion_records = tuple(
        record
        for record in records
        if record.state
        in {
            "staging_absent_cleanup_complete",
            "staging_quarantined_cleanup_complete",
        }
    )
    if not pending_records:
        if (
            acked_records
            or reconciliation_records
            or reconciled_records
            or completion_records
        ):
            raise _error(
                "transaction_journal_"
                "staging_tombstone_pending_missing"
            )
        return
    if (
        len(pending_records) != 1
        or len(acked_records) > 1
        or len(reconciliation_records) > 1
        or len(reconciled_records) > 1
        or len(completion_records) > 1
    ):
        raise _error(
            "transaction_journal_staging_tombstone_handshake_ambiguous"
        )

    pending_record = pending_records[0]
    pending = pending_record.details
    origin = _staging_tombstone_effect_origin(
        records, pending_record
    )
    if pending["effect_origin_state"] != origin:
        raise _error(
            "transaction_journal_staging_tombstone_origin_changed"
        )

    staging_create = _record_for_state(
        records, "staging_create_intent"
    )
    intent = staging_create.details
    receipt = pending["terminal_receipt"]
    if (
        receipt["capture_session_id"] != expected_session_id
        or receipt["staging_leaf_name"]
        != intent["staging_leaf_name"]
        or receipt["staging_transaction_intent_sha256"]
        != staging_create.record_sha256
        or receipt["filesystem_device"] != intent["required_device"]
        or receipt["tombstone_sha256"]
        != pending["tombstone_sha256"]
    ):
        raise _error(
            "transaction_journal_"
            "staging_terminal_receipt_binding_changed"
        )

    pending_predecessor = _immediate_predecessor(
        records, pending_record
    )
    quarantine_intent: TransactionJournalRecord | None = None
    if pending_predecessor.state == "quarantine_pending":
        quarantine_intent = pending_predecessor
    elif (
        pending_predecessor.state == "operator_attention"
        and pending_predecessor.details["from_state"]
        == "quarantine_pending"
    ):
        quarantine_intent = _immediate_predecessor(
            records,
            pending_predecessor,
            expected_state="quarantine_pending",
        )
    quarantine_effect_claimed = (
        pending["terminal_disposition"] == "quarantined"
        or receipt["terminal_event"] == "quarantine_removed"
    )
    if quarantine_effect_claimed and quarantine_intent is None:
        raise _error(
            "transaction_journal_"
            "staging_quarantine_intent_missing"
        )
    if quarantine_intent is not None:
        quarantine_details = quarantine_intent.details
        if (
            pending["staging_quarantine_intent_record_sha256"]
            != quarantine_intent.record_sha256
            or quarantine_details["namespace"] != "staging"
            or quarantine_details["empty_leaf_policy"]
            != "remove_and_fsync"
        ):
            raise _error(
                "transaction_journal_"
                "staging_quarantine_effect_binding_changed"
            )
        if pending["terminal_disposition"] == "quarantined":
            quarantine_binding_changed = (
                receipt["quarantine_namespace"] != "staging"
                or receipt["quarantine_name"]
                != quarantine_details["quarantine_name"]
                or receipt["staging_leaf_identity_sha256"]
                != quarantine_details["object_identity_sha256"]
                or receipt["reason_code"]
                != quarantine_details["reason_code"]
            )
        elif pending["terminal_disposition"] == "absent":
            quarantine_binding_changed = (
                receipt["terminal_event"] != "quarantine_removed"
                or receipt["staging_leaf_name"]
                != quarantine_details["quarantine_name"]
                or receipt["staging_leaf_identity_sha256"]
                != quarantine_details["object_identity_sha256"]
                or receipt["quarantine_reason_code"]
                != quarantine_details["reason_code"]
            )
        else:
            quarantine_binding_changed = True
        if quarantine_binding_changed:
            raise _error(
                "transaction_journal_"
                "staging_quarantine_effect_binding_changed"
            )
    elif (
        pending["staging_quarantine_intent_record_sha256"]
        is not None
        or (
            pending["terminal_disposition"] == "absent"
            and receipt["quarantine_reason_code"] is not None
        )
    ):
        raise _error(
            "transaction_journal_"
            "staging_quarantine_effect_binding_changed"
        )

    exposure_records = tuple(
        record
        for record in records[: records.index(pending_record)]
        if record.state == "staging_exposed"
    )
    if exposure_records:
        if len(exposure_records) != 1:
            raise _error(
                "transaction_journal_staging_exposure_ambiguous"
            )
        exposed = exposure_records[0].details[
            "staging_exposure_receipt"
        ]
        namespace_identity_fields = (
            "shared_root_identity_sha256",
            "recovery_namespace_identity_sha256",
            "quarantine_namespace_identity_sha256",
            "transactions_namespace_identity_sha256",
        )
        if (
            receipt["staging_leaf_identity_sha256"]
            != exposed["staging_leaf_identity_sha256"]
            or receipt["terminal_sequence"]
            <= exposed["staging_journal_sequence"]
            or receipt["staging_journal_schema"]
            != exposed["staging_journal_schema"]
            or any(
                receipt[field] != exposed[field]
                for field in namespace_identity_fields
            )
        ):
            raise _error(
                "transaction_journal_"
                "staging_terminal_receipt_identity_changed"
            )
    lifecycle_status = receipt["lifecycle_status"]
    scope_receipt = receipt[
        "lifecycle_scope_empty_receipt_sha256"
    ]
    if origin in {"staging_create_intent", "staging_exposed"}:
        if (
            lifecycle_status != "not_applicable"
            or scope_receipt is not None
        ):
            raise _error(
                "transaction_journal_"
                "staging_terminal_lifecycle_mismatch"
            )
    else:
        scope_empty = _record_for_state(
            records, "lifecycle_scope_empty"
        ).details["lifecycle_clearance_bundle"]
        if (
            lifecycle_status != "scope_empty"
            or scope_receipt
            != scope_empty["scope_empty_receipt_sha256"]
        ):
            raise _error(
                "transaction_journal_"
                "staging_terminal_lifecycle_mismatch"
            )

    adoption_cleanup_result: str | None = None
    expected_reconciliation_record_sha256: str | None = None
    expected_reconciliation_receipt_sha256: str | None = None
    if origin == "adoption_intent":
        if not reconciliation_records:
            if reconciled_records:
                raise _error(
                    "transaction_journal_"
                    "adoption_reconciliation_required_missing"
                )
            if acked_records or completion_records:
                raise _error(
                    "transaction_journal_"
                    "adoption_reconciliation_required"
                )
            return
        reconciliation_record = reconciliation_records[0]
        reconciliation = reconciliation_record.details
        adoption_intent = _record_for_state(
            records, "adoption_intent"
        )
        if (
            reconciliation["adoption_intent_record_sha256"]
            != adoption_intent.record_sha256
            or reconciliation["terminal_receipt_sha256"]
            != pending["terminal_receipt_sha256"]
            or reconciliation["tombstone_sha256"]
            != pending["tombstone_sha256"]
        ):
            raise _error(
                "transaction_journal_"
                "adoption_reconciliation_binding_changed"
            )
        if not reconciled_records:
            if acked_records or completion_records:
                raise _error(
                    "transaction_journal_"
                    "adoption_reconciliation_receipt_required"
                )
            return
        reconciled_record = reconciled_records[0]
        adoption_cleanup_result = (
            _validate_adoption_reconciled_binding(
                records,
                expected_session_id=expected_session_id,
                pending_record=pending_record,
                required_record=reconciliation_record,
                reconciled_record=reconciled_record,
            )
        )
        if adoption_cleanup_result not in {
            "staging_absent",
            "staging_quarantined",
            "recovered_adoption",
        }:
            if acked_records or completion_records:
                raise _error(
                    "transaction_journal_"
                    "adoption_reconciliation_cleanup_unsafe"
                )
            return
        expected_disposition = (
            "absent"
            if adoption_cleanup_result
            in {"staging_absent", "recovered_adoption"}
            else "quarantined"
        )
        if pending["terminal_disposition"] != expected_disposition:
            raise _error(
                "transaction_journal_"
                "adoption_reconciliation_disposition_changed"
            )
        expected_reconciliation_record_sha256 = (
            reconciled_record.record_sha256
        )
        expected_reconciliation_receipt_sha256 = (
            reconciled_record.details[
                "adoption_reconciliation_receipt_sha256"
            ]
        )
    elif reconciliation_records or reconciled_records:
        raise _error(
            "transaction_journal_adoption_reconciliation_origin_invalid"
        )

    if not acked_records:
        if completion_records:
            raise _error(
                "transaction_journal_staging_tombstone_ack_missing"
            )
        return

    acked_record = acked_records[0]
    if records.index(acked_record) <= records.index(pending_record):
        raise _error(
            "transaction_journal_staging_tombstone_ack_order_invalid"
        )
    acked = acked_record.details
    acknowledgement = acked["tombstone_ack_receipt"]
    recovered_continuation = acked.get(
        "recovered_adoption_continuation"
    )
    if adoption_cleanup_result == "recovered_adoption":
        if recovered_continuation is None:
            raise _error(
                "transaction_journal_"
                "adoption_reconciliation_cleanup_unsafe"
            )
        if pending["terminal_disposition"] != "absent":
            raise _error(
                "transaction_journal_"
                "recovered_adoption_continuation_disposition_invalid"
            )
        reconciled_record = reconciled_records[0]
        if (
            acked_record.revision != reconciled_record.revision + 1
            or records.index(acked_record)
            != records.index(reconciled_record) + 1
        ):
            raise _error(
                "transaction_journal_"
                "recovered_adoption_ack_successor_invalid"
            )
        artifacts = _derive_recovered_adoption_artifacts(
            records[: records.index(reconciled_record) + 1]
        )
        if recovered_continuation != artifacts["continuation"]:
            raise _error(
                "transaction_journal_"
                "recovered_adoption_continuation_binding_changed"
            )
    elif recovered_continuation is not None:
        raise _error(
            "transaction_journal_"
            "recovered_adoption_continuation_forbidden"
        )
    expected_lifecycle_clearance_record_sha256 = None
    if receipt["lifecycle_status"] == "scope_empty":
        expected_lifecycle_clearance_record_sha256 = (
            _record_for_state(
                records, "lifecycle_scope_empty"
            ).record_sha256
        )
    stable = {
        "terminal_disposition": pending["terminal_disposition"],
        "terminal_receipt_sha256": pending[
            "terminal_receipt_sha256"
        ],
        "tombstone_sha256": pending["tombstone_sha256"],
        "adoption_reconciliation_record_sha256": (
            expected_reconciliation_record_sha256
        ),
        "adoption_reconciliation_receipt_sha256": (
            expected_reconciliation_receipt_sha256
        ),
    }
    if any(acked[field] != value for field, value in stable.items()):
        raise _error(
            "transaction_journal_staging_tombstone_ack_binding_changed"
        )
    if (
        acked["outer_ack_pending_record_sha256"]
        != pending_record.record_sha256
        or acknowledgement["capture_session_id"]
        != expected_session_id
        or acknowledgement["staging_transaction_intent_sha256"]
        != staging_create.record_sha256
        or acknowledgement["terminal_receipt_sha256"]
        != pending["terminal_receipt_sha256"]
        or acknowledgement["tombstone_sha256"]
        != pending["tombstone_sha256"]
        or acknowledgement["outer_ack_pending_record_sha256"]
        != pending_record.record_sha256
        or acknowledgement[
            "outer_quarantine_intent_record_sha256"
        ]
        != pending["staging_quarantine_intent_record_sha256"]
        or acknowledgement["terminal_disposition"]
        != pending["terminal_disposition"]
        or acknowledgement["staging_journal_schema"]
        != receipt["staging_journal_schema"]
        or acknowledgement["ack_sequence"]
        != receipt["terminal_sequence"] + 1
        or acknowledgement["ack_previous_record_sha256"]
        != receipt["terminal_record_sha256"]
        or acknowledgement["inspection_lock_epoch_sha256"]
        != receipt["inspection_lock_epoch_sha256"]
        or acknowledgement[
            "outer_lifecycle_clearance_record_sha256"
        ]
        != expected_lifecycle_clearance_record_sha256
    ):
        raise _error(
            "transaction_journal_"
            "staging_tombstone_ack_receipt_binding_changed"
        )

    verifier_records = tuple(
        record
        for record in records
        if record.state == "verifier_output_bound"
    )
    if verifier_records:
        recovered_verifier = (
            "recovered_verifier_source_evidence"
            in verifier_records[0].details
        )
        if (
            len(verifier_records) != 1
            or pending["terminal_disposition"] != "absent"
            or (
                origin == "adopted"
                and recovered_verifier
            )
            or (
                adoption_cleanup_result == "recovered_adoption"
                and not recovered_verifier
            )
            or (
                origin != "adopted"
                and adoption_cleanup_result
                != "recovered_adoption"
            )
        ):
            raise _error(
                "transaction_journal_"
                "staging_cleanup_continuation_unsafe"
            )
        if completion_records:
            raise _error(
                "transaction_journal_"
                "staging_cleanup_continuation_ambiguous"
            )
        return

    if not completion_records:
        return
    completion = completion_records[0]
    if (
        origin == "adoption_intent"
        and adoption_cleanup_result
        not in {"staging_absent", "staging_quarantined"}
    ):
        raise _error(
            "transaction_journal_adoption_reconciliation_required"
        )
    if origin not in {
        "staging_create_intent",
        "staging_exposed",
        "child_launch_intent",
        "child_running",
        "capture_ready",
        "adoption_intent",
    }:
        raise _error(
            "transaction_journal_staging_terminal_origin_unresolved"
        )
    expected_completion = (
        "staging_absent_cleanup_complete"
        if pending["terminal_disposition"] == "absent"
        else "staging_quarantined_cleanup_complete"
    )
    if completion.state != expected_completion:
        raise _error(
            "transaction_journal_"
            "staging_terminal_completion_disposition_changed"
        )
    completed = completion.details
    if (
        completed["terminal_receipt_sha256"]
        != pending["terminal_receipt_sha256"]
        or completed["tombstone_ack_receipt_sha256"]
        != acked["tombstone_ack_receipt_sha256"]
    ):
        raise _error(
            "transaction_journal_"
            "staging_terminal_completion_binding_changed"
        )


def _validate_recovered_verifier_source_evidence_history(
    records: tuple[TransactionJournalRecord, ...],
) -> None:
    """Bind every recovered-only verifier record to its exact ACK prefix."""

    verifier_records = tuple(
        record
        for record in records
        if record.state == "verifier_output_bound"
    )
    started_records = tuple(
        record
        for record in records
        if record.state == "live_revalidation_started"
    )
    complete_records = tuple(
        record
        for record in records
        if record.state == "live_revalidation_receipt_complete"
    )
    enriched_verifier_records = tuple(
        record
        for record in verifier_records
        if "recovered_verifier_source_evidence" in record.details
    )
    enriched_started_records = tuple(
        record
        for record in started_records
        if "recovered_verifier_source_evidence_sha256"
        in record.details
    )
    enriched_complete_records = tuple(
        record
        for record in complete_records
        if "recovered_verifier_source_evidence_sha256"
        in record.details
    )
    enriched_present = bool(
        enriched_verifier_records
        or enriched_started_records
        or enriched_complete_records
    )
    if not enriched_present:
        return
    if (
        len(enriched_verifier_records) != 1
        or len(enriched_started_records)
        != len(started_records)
        or len(enriched_complete_records)
        != len(complete_records)
        or len(verifier_records) != 1
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "history_variant_ambiguous"
        )
    verifier_record = enriched_verifier_records[0]
    verifier_index = records.index(verifier_record)
    if verifier_index < 2:
        raise _error(
            "transaction_journal_recovered_verifier_"
            "ack_prefix_missing"
        )
    ack_record = records[verifier_index - 1]
    reconciled_record = records[verifier_index - 2]
    continuation = ack_record.details.get(
        "recovered_adoption_continuation"
    )
    if (
        ack_record.state != "staging_tombstone_acked"
        or reconciled_record.state != "adoption_reconciled"
        or continuation is None
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "ack_prefix_invalid"
        )
    envelope = verifier_record.details[
        "recovered_verifier_source_evidence"
    ]
    envelope_sha256 = verifier_record.details[
        "recovered_verifier_source_evidence_sha256"
    ]
    if (
        not hmac.compare_digest(
            envelope[
                "staging_tombstone_acked_record_sha256"
            ],
            ack_record.record_sha256,
        )
        or not hmac.compare_digest(
            envelope["recovered_adoption_continuation_sha256"],
            recovered_adoption_continuation_sha256(continuation),
        )
        or envelope["capture_adoption_provenance"]
        != continuation["capture_adoption_provenance"]
        or not hmac.compare_digest(
            envelope["capture_adoption_provenance_sha256"],
            continuation["capture_adoption_provenance_sha256"],
        )
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "continuation_binding_changed"
        )
    artifacts = _derive_recovered_adoption_artifacts(
        records[:verifier_index - 1]
    )
    expected_binding = (
        _post_ack_recovered_adoption_journal_binding(
            artifacts, ack_record
        )
    )
    if (
        envelope[
            "pre_verifier_recovered_adoption_lease_binding"
        ]
        != expected_binding
        or envelope[
            "post_verifier_recovered_adoption_lease_binding"
        ]
        != expected_binding
        or envelope["capture_adoption_provenance"]
        != artifacts["provenance"]
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "lease_or_provenance_binding_changed"
        )
    output_evidence = envelope["verifier_output_v4"]["evidence"]
    recovered_evidence = artifacts["evidence"]
    receipt = envelope["source_revalidation_receipt_v2"]
    if (
        output_evidence["verified_at_unix"]
        < ack_record.recorded_at_unix
        or receipt["revalidated_at_unix"]
        < output_evidence["verified_at_unix"]
        or verifier_record.recorded_at_unix
        != receipt["revalidated_at_unix"]
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "effect_chronology_invalid"
        )
    expected_output_bindings = {
        "capture_manifest_sha256": "capture_manifest_sha256",
        "capture_plan_sha256": "capture_plan_sha256",
        "capture_creator_uid": "capture_uid",
        "capture_export_gid": "capture_export_gid",
        "capture_adopted_uid": "final_object_owner_uid",
        "capture_adoption_policy_sha256": (
            "capture_adoption_policy_sha256"
        ),
        "capture_object_identity_sha256": (
            "capture_object_identity_sha256"
        ),
        "capture_content_inventory_sha256": (
            "reconciled_content_inventory_sha256"
        ),
        "capture_request_sha256": "capture_request_sha256",
        "capture_boundary_policy_sha256": (
            "capture_boundary_policy_sha256"
        ),
        "capture_helper_activation_policy_sha256": (
            "helper_activation_policy_sha256"
        ),
    }
    if (
        any(
            output_evidence[output_field]
            != recovered_evidence[evidence_field]
            for output_field, evidence_field
            in expected_output_bindings.items()
        )
        or output_evidence["capture_adoption_provenance"]
        != artifacts["provenance"]
        or output_evidence["capture_adoption_provenance_sha256"]
        != artifacts["provenance_sha256"]
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "output_adoption_binding_changed"
        )
    expected_started = {
        "verifier_output_sha256": (
            envelope["verifier_output_v4_sha256"]
        ),
        "recovered_verifier_source_evidence_sha256": (
            envelope_sha256
        ),
        "staging_tombstone_acked_record_sha256": (
            ack_record.record_sha256
        ),
        "state_semantics": (
            RECOVERED_REVALIDATION_STATE_SEMANTICS
        ),
    }
    if started_records:
        started = started_records[0]
        if (
            records.index(started) != verifier_index + 1
            or started.details != expected_started
            or started.recorded_at_unix
            != verifier_record.recorded_at_unix
        ):
            raise _error(
                "transaction_journal_recovered_verifier_"
                "revalidation_started_binding_changed"
            )
    if complete_records:
        if not started_records:
            raise _error(
                "transaction_journal_recovered_verifier_"
                "revalidation_started_missing"
            )
        complete = complete_records[0]
        expected_complete = {
            "verifier_output_sha256": (
                envelope["verifier_output_v4_sha256"]
            ),
            "source_revalidation_receipt_sha256": (
                envelope["source_revalidation_receipt_v2_sha256"]
            ),
            "recovered_verifier_source_evidence_sha256": (
                envelope_sha256
            ),
            "staging_tombstone_acked_record_sha256": (
                ack_record.record_sha256
            ),
            "verified_evidence_v6_sha256": (
                envelope["verified_evidence_v6_sha256"]
            ),
            "state_semantics": (
                RECOVERED_REVALIDATION_STATE_SEMANTICS
            ),
        }
        if (
            records.index(complete)
            != records.index(started_records[0]) + 1
            or complete.details != expected_complete
            or complete.recorded_at_unix
            != started_records[0].recorded_at_unix
        ):
            raise _error(
                "transaction_journal_recovered_verifier_"
                "revalidation_complete_binding_changed"
            )


def _validate_history(
    records: tuple[TransactionJournalRecord, ...],
    *,
    expected_session_id: str,
) -> None:
    if not records:
        raise _error("transaction_journal_session_empty")
    if len(records) > MAX_EVENTS_PER_SESSION:
        raise _error("transaction_journal_event_limit_exceeded")
    first = records[0].to_dict()
    constants = {
        "instance_slug": first["instance_slug"],
        "session_id": first["session_id"],
        "control_sha256": first["control_sha256"],
        "handoff_policy_sha256": first["handoff_policy_sha256"],
    }
    if constants["session_id"] != expected_session_id:
        raise _error("transaction_journal_session_binding_mismatch")
    previous: TransactionJournalRecord | None = None
    for index, record in enumerate(records, start=1):
        value = record.to_dict()
        if value["revision"] != index:
            raise _error("transaction_journal_revision_gap")
        if any(
            value[field] != selected
            for field, selected in constants.items()
        ):
            raise _error("transaction_journal_record_binding_changed")
        if previous is None:
            if value["previous_record_sha256"] != ZERO_SHA256:
                raise _error(
                    "transaction_journal_previous_digest_mismatch"
                )
            previous_state = None
        else:
            if value["previous_record_sha256"] != previous.record_sha256:
                raise _error(
                    "transaction_journal_previous_digest_mismatch"
                )
            if value["recorded_at_unix"] < previous.recorded_at_unix:
                raise _error("transaction_journal_clock_rollback")
            previous_state = previous.state
        if not _allowed_transition(previous_state, value["state"]):
            raise _error("transaction_journal_transition_invalid")
        if value["state"] in {
            "staging_tombstone_ack_pending",
            "staging_tombstone_acked",
            "adoption_reconciliation_required",
            "staging_absent_cleanup_complete",
            "staging_quarantined_cleanup_complete",
            "quarantine_pending",
            "quarantined",
            "operator_attention",
        }:
            if value["details"]["from_state"] != previous_state:
                raise _error(
                    "transaction_journal_terminal_state_mismatch"
                )
        if (
            value["state"] == "quarantined"
            and previous is not None
            and previous.state == "quarantine_pending"
        ):
            for field in (
                "namespace",
                "quarantine_name",
                "object_identity_sha256",
                "reason_code",
            ):
                if (
                    value["details"][field]
                    != previous.details[field]
                ):
                    raise _error(
                        "transaction_journal_quarantine_binding_changed"
                    )
        if (
            value["state"] == "operator_attention"
            and previous is not None
            and previous.state == "adoption_reconciled"
        ):
            reconciliation_result = previous.details[
                "adoption_reconciliation_receipt"
            ]["result"]
            if reconciliation_result not in {
                "recovered_adoption",
                "operator_attention",
            }:
                raise _error(
                    "transaction_journal_"
                    "adoption_reconciliation_attention_unsafe"
                )
            if value["details"]["incident_sha256"] != (
                previous.details[
                    "adoption_reconciliation_receipt_sha256"
                ]
            ):
                raise _error(
                    "transaction_journal_"
                    "adoption_reconciliation_attention_binding_changed"
                )
        if previous is not None and previous.state == "operator_attention":
            attention_origin = previous.details["from_state"]
            if attention_origin == "reserved":
                expected_resolution = "operator_resolved"
            elif attention_origin == "staging_create_intent":
                expected_resolution = (
                    "staging_tombstone_ack_pending"
                )
            elif attention_origin == (
                "attestation_archive_durable_head_pending"
            ):
                expected_resolution = (
                    "attestation_head_committed_"
                    "trust_projection_pending"
                )
            elif attention_origin == (
                "attestation_head_committed_"
                "trust_projection_pending"
            ):
                expected_resolution = (
                    "full_publication_committed_cleanup_required"
                )
            elif attention_origin in {
                "full_publication_committed_cleanup_required",
                "committed_cleanup_pending",
            }:
                expected_resolution = "cleanup_complete"
            elif attention_origin in (
                LIFECYCLE_EFFECT_ORIGIN_STATES
            ):
                expected_resolution = "lifecycle_clearance_intent"
            elif attention_origin == "lifecycle_clearance_intent":
                expected_resolution = "lifecycle_scope_empty"
            elif attention_origin in {
                "staging_exposed",
                "lifecycle_scope_empty",
                "adoption_intent",
            }:
                expected_resolution = (
                    "staging_tombstone_ack_pending"
                )
            elif attention_origin == "staging_tombstone_ack_pending":
                pending_record = _immediate_predecessor(
                    records,
                    previous,
                    expected_state="staging_tombstone_ack_pending",
                )
                expected_resolution = (
                    "adoption_reconciliation_required"
                    if _staging_tombstone_effect_origin(
                        records, pending_record
                    )
                    == "adoption_intent"
                    else "staging_tombstone_acked"
                )
            elif attention_origin == (
                "adoption_reconciliation_required"
            ):
                expected_resolution = "adoption_reconciled"
            elif attention_origin in {
                "adopted",
                "verifier_output_bound",
                "live_revalidation_started",
                "live_revalidation_receipt_complete",
                "signing_intent",
            }:
                expected_resolution = "quarantined"
            elif attention_origin == "quarantine_pending":
                pending_record = _immediate_predecessor(
                    records,
                    previous,
                    expected_state="quarantine_pending",
                )
                expected_resolution = (
                    "staging_tombstone_ack_pending"
                    if pending_record.details["namespace"] == "staging"
                    else "quarantined"
                )
            else:
                raise _error(
                    "transaction_journal_operator_resolution_unsupported"
                )
            if value["state"] != expected_resolution:
                raise _error(
                    "transaction_journal_operator_resolution_unsafe"
                )
        if value["state"] == "operator_resolved":
            if (
                previous is None
                or value["details"][
                    "operator_attention_record_sha256"
                ]
                != previous.record_sha256
            ):
                raise _error(
                    "transaction_journal_operator_resolution_mismatch"
                )
        previous = record

    _validate_staging_tombstone_handshake(
        records,
        expected_session_id=expected_session_id,
    )
    _validate_recovered_verifier_source_evidence_history(records)

    states = {record.state for record in records}
    staging_create = (
        _record_for_state(records, "staging_create_intent")
        if "staging_create_intent" in states
        else None
    )
    capture_ready = (
        _record_for_state(records, "capture_ready").details
        if "capture_ready" in states
        else None
    )
    _validate_lifecycle_history(
        records,
        expected_session_id=expected_session_id,
        handoff_policy_sha256=constants["handoff_policy_sha256"],
    )
    for record in records[1:]:
        details = record.details
        if "staging_leaf_name" in details:
            if staging_create is None:
                raise _error(
                    "transaction_journal_staging_leaf_binding_missing"
                )
            if (
                details["staging_leaf_name"]
                != staging_create.details["staging_leaf_name"]
            ):
                raise _error(
                    "transaction_journal_staging_leaf_binding_changed"
                )
        if "final_name" in details:
            if capture_ready is None:
                raise _error(
                    "transaction_journal_final_name_binding_missing"
                )
            if (
                details["final_name"]
                != capture_ready["provisional_name"]
            ):
                raise _error(
                    "transaction_journal_final_name_binding_changed"
                )
    if "staging_exposed" in states:
        if staging_create is None:
            raise _error(
                "transaction_journal_staging_intent_missing"
            )
        receipt = _record_for_state(
            records, "staging_exposed"
        ).details["staging_exposure_receipt"]
        intent = staging_create.details
        if (
            receipt["capture_session_id"] != expected_session_id
            or receipt["staging_leaf_name"]
            != intent["staging_leaf_name"]
            or receipt["capture_uid"] != intent["capture_uid"]
            or receipt["export_gid"] != intent["export_gid"]
            or receipt["filesystem_device"]
            != intent["required_device"]
            or receipt["staging_transaction_intent_sha256"]
            != staging_create.record_sha256
        ):
            raise _error(
                "transaction_journal_staging_exposure_binding_changed"
            )
    staging_quarantine_states = {
        "staging_exposed",
        "lifecycle_scope_empty",
    }
    adopted_quarantine_states = {
        "adopted",
        "verifier_output_bound",
        "live_revalidation_started",
        "live_revalidation_receipt_complete",
        "signing_intent",
    }
    for record in records:
        if record.state not in {"quarantine_pending", "quarantined"}:
            continue
        details = record.details
        if details["from_state"] == "quarantine_pending":
            pending_record = _immediate_predecessor(
                records,
                record,
                expected_state="quarantine_pending",
            )
            origin = pending_record.details["from_state"]
        elif details["from_state"] == "operator_attention":
            attention_record = _immediate_predecessor(
                records,
                record,
                expected_state="operator_attention",
            )
            origin = attention_record.details["from_state"]
            if origin == "quarantine_pending":
                origin = _immediate_predecessor(
                    records,
                    attention_record,
                    expected_state="quarantine_pending",
                ).details["from_state"]
        else:
            origin = details["from_state"]
        namespace = details["namespace"]
        if origin == "adoption_intent":
            allowed_namespaces = {"staging", "adopted"}
        elif origin in staging_quarantine_states:
            allowed_namespaces = {"staging"}
        elif origin in adopted_quarantine_states:
            allowed_namespaces = {"staging", "adopted"}
        else:
            raise _error(
                "transaction_journal_quarantine_phase_invalid"
            )
        if namespace not in allowed_namespaces:
            raise _error(
                "transaction_journal_quarantine_namespace_mismatch"
            )
        if namespace == "staging":
            if "staging_exposed" not in states:
                raise _error(
                    "transaction_journal_quarantine_identity_missing"
                )
            exposure_receipt = _record_for_state(
                records, "staging_exposed"
            ).details["staging_exposure_receipt"]
            expected_name = exposure_receipt["staging_leaf_name"]
            expected_identity = exposure_receipt[
                "staging_leaf_identity_sha256"
            ]
        else:
            if "capture_ready" not in states:
                raise _error(
                    "transaction_journal_quarantine_identity_missing"
                )
            expected_name = _record_for_state(
                records, "capture_ready"
            ).details["provisional_name"]
            expected_identity = _record_for_state(
                records, "capture_ready"
            ).details["capture_object_identity_sha256"]
        if namespace == "staging" and record.state == "quarantined":
            raise _error(
                "transaction_journal_staging_quarantine_ack_required"
            )
        if (
            details["quarantine_name"] != expected_name
            or details["object_identity_sha256"]
            != expected_identity
        ):
            raise _error(
                "transaction_journal_quarantine_object_mismatch"
            )
        if origin == "staging_exposed":
            if details["lifecycle_status"] != "not_applicable":
                raise _error(
                    "transaction_journal_quarantine_lifecycle_mismatch"
                )
        else:
            if details["lifecycle_status"] != "scope_empty":
                raise _error(
                    "transaction_journal_quarantine_lifecycle_mismatch"
                )
            scope_receipt_sha256 = details[
                "lifecycle_scope_empty_receipt_sha256"
            ]
            expected_scope_receipt = _record_for_state(
                records, "lifecycle_scope_empty"
            ).details["lifecycle_clearance_bundle"][
                "scope_empty_receipt_sha256"
            ]
            if scope_receipt_sha256 != expected_scope_receipt:
                raise _error(
                    "transaction_journal_"
                    "quarantine_lifecycle_receipt_changed"
                )
    if "capture_ready" in states:
        ready = _record_for_state(records, "capture_ready").details
        for record in records:
            if "capture_object_identity_sha256" in record.details and (
                record.details["capture_object_identity_sha256"]
                != ready["capture_object_identity_sha256"]
            ):
                raise _error(
                    "transaction_journal_capture_identity_changed"
                )
            if "provisional_name" in record.details and (
                record.details["provisional_name"]
                != ready["provisional_name"]
            ):
                raise _error(
                    "transaction_journal_provisional_name_changed"
                )
    if "adoption_intent" in states:
        intent = _record_for_state(records, "adoption_intent").details
        if (
            staging_create is None
            or intent["final_parent_filesystem_device"]
            != staging_create.details["required_device"]
        ):
            raise _error(
                "transaction_journal_"
                "adoption_final_parent_device_mismatch"
            )
    if "adoption_intent" in states and "adopted" in states:
        intent = _record_for_state(records, "adoption_intent").details
        adopted = _record_for_state(records, "adopted").details
        for field, code in (
            (
                "adoption_policy_sha256",
                "transaction_journal_adoption_policy_changed",
            ),
            (
                "final_parent_identity_sha256",
                "transaction_journal_"
                "adoption_final_parent_identity_changed",
            ),
            (
                "final_parent_filesystem_device",
                "transaction_journal_"
                "adoption_final_parent_device_changed",
            ),
        ):
            if adopted[field] != intent[field]:
                raise _error(code)
    if "verifier_output_bound" in states:
        verifier_digest = _record_for_state(
            records, "verifier_output_bound"
        ).details["verifier_output_sha256"]
        for record in records:
            if "verifier_output_sha256" in record.details and (
                record.details["verifier_output_sha256"]
                != verifier_digest
            ):
                raise _error(
                    "transaction_journal_verifier_output_changed"
                )
    archive_state = "attestation_archive_durable_head_pending"
    head_state = (
        "attestation_head_committed_trust_projection_pending"
    )
    commit_state = "full_publication_committed_cleanup_required"
    if "signing_intent" in states and archive_state in states:
        signing = _record_for_state(records, "signing_intent").details
        archived = _record_for_state(records, archive_state).details
        signing_fields = {
            "transaction_binding_sha256",
            "fresh_evidence_sha256",
            "requested_run_id",
            "attestor_config_sha256",
            "public_key_sha256",
            "operator_policy_sha256",
            "projection_policy_sha256",
        }
        if any(
            archived[field] != signing[field]
            for field in signing_fields
        ):
            raise _error(
                "transaction_journal_archive_binding_changed"
            )
        expected_next = signing["expected_next_chain_sequence"]
        if (
            archived["requested_chain_sequence"]
            > archived["authoritative_chain_sequence"]
            or archived["requested_chain_sequence"] > expected_next
            or archived["authoritative_chain_sequence"]
            not in {expected_next, max(1, expected_next - 1)}
        ):
            raise _error(
                "transaction_journal_archive_sequence_invalid"
            )
    if archive_state in states and head_state in states:
        archived = _record_for_state(records, archive_state).details
        head_committed = _record_for_state(records, head_state).details
        stable_fields = set(_ATTESTATION_BINDING_FIELDS)
        stable_fields.add("attestation_archive_receipt_sha256")
        if any(
            head_committed[field] != archived[field]
            for field in stable_fields
        ):
            raise _error(
                "transaction_journal_head_binding_changed"
            )
    if head_state in states and commit_state in states:
        head_committed = _record_for_state(records, head_state).details
        committed = _record_for_state(records, commit_state).details
        stable_fields = set(_ATTESTATION_BINDING_FIELDS)
        stable_fields.update(
            {
                "attestation_archive_receipt_sha256",
                "authoritative_head_sha256",
                "head_commit_receipt_sha256",
                "trust_projection_sha256",
                "projection_generated_at_unix",
            }
        )
        if any(
            committed[field] != head_committed[field]
            for field in stable_fields
        ):
            raise _error(
                "transaction_journal_projection_binding_changed"
            )
    if commit_state in states:
        commit_record = _record_for_state(
            records,
            commit_state,
        )
        committed = commit_record.details
        if "adopted" in states:
            adopted = _record_for_state(records, "adopted").details
            if (
                committed["adoption_receipt_sha256"]
                != adopted["adoption_receipt_sha256"]
            ):
                raise _error(
                    "transaction_journal_commit_adoption_changed"
                )
        last_cleanup_phase = committed["cleanup_phase"]
        pending_seen = False
        for record in records:
            if record.state != "committed_cleanup_pending":
                continue
            pending = record.details
            if pending["commit_record_sha256"] != (
                commit_record.record_sha256
            ):
                raise _error(
                    "transaction_journal_cleanup_binding_changed"
                )
            if pending_seen and last_cleanup_phase == "parent_fsync_only":
                raise _error(
                    "transaction_journal_cleanup_pending_exhausted"
                )
            if (
                pending_seen
                and pending["cleanup_phase"] != "parent_fsync_only"
            ):
                raise _error(
                    "transaction_journal_cleanup_phase_not_advanced"
                )
            last_cleanup_phase = pending["cleanup_phase"]
            pending_seen = True
        if records[-1].state == "cleanup_complete":
            completed = records[-1].details
            if (
                completed["commit_record_sha256"]
                != commit_record.record_sha256
                or completed["trust_projection_sha256"]
                != committed["trust_projection_sha256"]
            ):
                raise _error(
                    "transaction_journal_cleanup_complete_binding_changed"
                )
            compatible_results = (
                {
                    "removed_and_fsynced",
                    "already_absent_parent_fsynced",
                }
                if last_cleanup_phase == "name_bound"
                else {
                    "parent_fsynced",
                    "already_absent_parent_fsynced",
                }
            )
            if completed["cleanup_result"] not in compatible_results:
                raise _error(
                    "transaction_journal_cleanup_result_phase_mismatch"
                )


def _event_filename(record: TransactionJournalRecord) -> str:
    return (
        f"{record.revision:06d}-{record.state}-"
        f"{record.record_sha256}.json"
    )


def _call_fault(
    fault_hook: Callable[[str], None] | None,
    phase: str,
) -> None:
    if fault_hook is not None:
        if not callable(fault_hook):
            raise _error("transaction_journal_fault_hook_invalid")
        fault_hook(phase)


_STORE_TOKEN = object()
_SESSION_TOKEN = object()
_CAPTURE_RECORDER_TOKEN = object()
_LIVE_SNAPSHOT_TOKEN = object()
_OPERATION_LEASE_TOKEN = object()
_OUTER_SUCCESSOR_PERMIT_TOKEN = object()
_PERMIT_SUCCESSOR_TOKEN = object()
_RECOVERED_ADOPTION_CONTEXT_TOKEN = object()
_RECOVERED_ADOPTION_ACK_OPERATION_TOKEN = object()
_RECOVERED_ADOPTION_CLEARANCE_TOKEN = object()
_RECOVERED_ADOPTION_ACK_SUCCESSOR_TOKEN = object()
_RECOVERED_VERIFIER_MATERIAL_TOKEN = object()
_RECOVERED_VERIFIER_OPERATION_TOKEN = object()
_RECOVERED_VERIFIED_EVIDENCE_CLEARANCE_TOKEN = object()
_RECOVERED_VERIFIER_SUCCESSOR_TOKEN = object()
_HISTORY_VALIDATION_TEST_TOKEN = object()

_LIVE_SNAPSHOT_FIELDS = frozenset(
    {
        "instance_slug",
        "session_id",
        "state",
        "revision",
        "head_record_sha256",
        "record_sha256s",
        "descriptor_device",
        "descriptor_inode",
    }
)


def _canonical_live_snapshot_records(
    records: Any,
) -> tuple[bytes, ...]:
    if type(records) is not tuple or not records:
        raise _error(
            "transaction_journal_live_snapshot_records_invalid"
        )
    canonical: list[bytes] = []
    for record in records:
        if type(record) is not TransactionJournalRecord:
            raise _error(
                "transaction_journal_live_snapshot_records_invalid"
            )
        try:
            value = record.to_dict()
            normalized = _normalize_record(value)
            raw = _canonical_json(normalized)
        except (
            AttributeError,
            TransactionJournalError,
            TypeError,
            UnicodeError,
            ValueError,
        ) as exc:
            raise _error(
                "transaction_journal_live_snapshot_records_invalid"
            ) from exc
        canonical.append(raw)
    return tuple(canonical)


class TransactionJournalLiveSnapshot:
    """Immutable, path-free observation of one live session descriptor.

    The snapshot is a read-only value, not an append capability.  It retains
    only a private identity token for the exact session that minted it; the
    session object and its descriptors are never retained or exposed.
    """

    __slots__ = (
        "__canonical",
        "__canonical_records",
        "__session_binding",
    )

    def __init__(
        self,
        *,
        _token: object,
        session_binding: object,
        records: tuple[TransactionJournalRecord, ...],
        descriptor_device: int,
        descriptor_inode: int,
    ) -> None:
        if _token is not _LIVE_SNAPSHOT_TOKEN:
            raise TypeError(
                "TransactionJournalLiveSnapshot cannot be "
                "constructed directly"
            )
        canonical_records = _canonical_live_snapshot_records(records)
        first = records[0].to_dict()
        latest = records[-1]
        if (
            type(session_binding) is not object
            or type(descriptor_device) is not int
            or descriptor_device < 0
            or type(descriptor_inode) is not int
            or descriptor_inode < 1
            or latest.revision != len(records)
        ):
            raise _error(
                "transaction_journal_live_snapshot_source_invalid"
            )
        metadata = {
            "instance_slug": first["instance_slug"],
            "session_id": first["session_id"],
            "state": latest.state,
            "revision": latest.revision,
            "head_record_sha256": latest.record_sha256,
            "record_sha256s": [
                record.record_sha256 for record in records
            ],
            "descriptor_device": descriptor_device,
            "descriptor_inode": descriptor_inode,
        }
        object.__setattr__(
            self,
            "_TransactionJournalLiveSnapshot__canonical",
            _canonical_json(metadata),
        )
        object.__setattr__(
            self,
            "_TransactionJournalLiveSnapshot__canonical_records",
            canonical_records,
        )
        object.__setattr__(
            self,
            "_TransactionJournalLiveSnapshot__session_binding",
            session_binding,
        )
        self._validated_contents()

    def _metadata(self) -> dict[str, Any]:
        try:
            raw = self.__canonical
            if type(raw) is not bytes:
                raise TypeError("snapshot canonical value is not bytes")
            decoded = json.loads(raw.decode("ascii"))
            selected = _strict_mapping(
                decoded,
                _LIVE_SNAPSHOT_FIELDS,
                code=(
                    "transaction_journal_live_snapshot_fields_invalid"
                ),
            )
            record_sha256s = selected["record_sha256s"]
            if (
                not isinstance(record_sha256s, list)
                or not record_sha256s
                or len(record_sha256s) > MAX_EVENTS_PER_SESSION
            ):
                raise _error(
                    "transaction_journal_live_snapshot_digests_invalid"
                )
            normalized = {
                "instance_slug": _instance_slug(
                    selected["instance_slug"]
                ),
                "session_id": _session_id(selected["session_id"]),
                "state": selected["state"],
                "revision": _integer(
                    selected["revision"],
                    field=(
                        "transaction_journal_live_snapshot_revision"
                    ),
                    minimum=1,
                    maximum=MAX_EVENTS_PER_SESSION,
                ),
                "head_record_sha256": _digest(
                    selected["head_record_sha256"],
                    field=(
                        "transaction_journal_live_snapshot_head_sha256"
                    ),
                ),
                "record_sha256s": [
                    _digest(
                        value,
                        field=(
                            "transaction_journal_live_snapshot_"
                            "record_sha256"
                        ),
                    )
                    for value in record_sha256s
                ],
                "descriptor_device": selected[
                    "descriptor_device"
                ],
                "descriptor_inode": selected["descriptor_inode"],
            }
            if (
                normalized["state"] not in STATE_SET
                or type(normalized["descriptor_device"]) is not int
                or normalized["descriptor_device"] < 0
                or type(normalized["descriptor_inode"]) is not int
                or normalized["descriptor_inode"] < 1
                or not hmac.compare_digest(
                    raw, _canonical_json(normalized)
                )
            ):
                raise _error(
                    "transaction_journal_live_snapshot_value_invalid"
                )
            return normalized
        except TransactionJournalError:
            raise
        except (AttributeError, TypeError, ValueError, UnicodeError) as exc:
            raise _error(
                "transaction_journal_live_snapshot_value_invalid"
            ) from exc

    def _validated_contents(
        self,
    ) -> tuple[
        dict[str, Any],
        tuple[TransactionJournalRecord, ...],
    ]:
        metadata = self._metadata()
        try:
            canonical_records = self.__canonical_records
            if (
                type(canonical_records) is not tuple
                or not canonical_records
                or any(
                    type(raw) is not bytes
                    for raw in canonical_records
                )
            ):
                raise TypeError("snapshot record tuple is invalid")
            records = tuple(
                TransactionJournalRecord(
                    json.loads(raw.decode("ascii"))
                )
                for raw in canonical_records
            )
            if (
                _canonical_live_snapshot_records(records)
                != canonical_records
            ):
                raise TypeError(
                    "snapshot records are not canonical"
                )
            _validate_history(
                records,
                expected_session_id=metadata["session_id"],
            )
            first = records[0].to_dict()
            digests = tuple(
                record.record_sha256 for record in records
            )
            if (
                len(records) != metadata["revision"]
                or len(digests)
                != len(metadata["record_sha256s"])
                or digests != tuple(metadata["record_sha256s"])
                or first["instance_slug"]
                != metadata["instance_slug"]
                or records[-1].state != metadata["state"]
                or records[-1].revision != metadata["revision"]
                or not hmac.compare_digest(
                    records[-1].record_sha256,
                    metadata["head_record_sha256"],
                )
            ):
                raise TypeError("snapshot record binding changed")
        except TransactionJournalError as exc:
            raise _error(
                "transaction_journal_live_snapshot_records_invalid"
            ) from exc
        except (AttributeError, TypeError, ValueError, UnicodeError) as exc:
            raise _error(
                "transaction_journal_live_snapshot_records_invalid"
            ) from exc
        return metadata, records

    def _is_bound_to(self, session_binding: object) -> bool:
        try:
            return self.__session_binding is session_binding
        except AttributeError:
            return False

    def _matches(
        self,
        other: TransactionJournalLiveSnapshot,
    ) -> bool:
        if type(other) is not TransactionJournalLiveSnapshot:
            return False
        try:
            self._validated_contents()
            other._validated_contents()
            return (
                hmac.compare_digest(
                    self.__canonical, other.__canonical
                )
                and self.__canonical_records
                == other.__canonical_records
            )
        except TransactionJournalError:
            return False

    @property
    def instance_slug(self) -> str:
        return self._metadata()["instance_slug"]

    @property
    def session_id(self) -> str:
        return self._metadata()["session_id"]

    @property
    def state(self) -> str:
        return self._metadata()["state"]

    @property
    def revision(self) -> int:
        return self._metadata()["revision"]

    @property
    def head_record_sha256(self) -> str:
        return self._metadata()["head_record_sha256"]

    @property
    def record_sha256s(self) -> tuple[str, ...]:
        return tuple(self._metadata()["record_sha256s"])

    @property
    def records(self) -> tuple[TransactionJournalRecord, ...]:
        return self._validated_contents()[1]

    @property
    def descriptor_device(self) -> int:
        return self._metadata()["descriptor_device"]

    @property
    def descriptor_inode(self) -> int:
        return self._metadata()["descriptor_inode"]

    def __setattr__(self, name: str, value: Any) -> None:
        del name, value
        raise TypeError("TransactionJournalLiveSnapshot is immutable")

    def __delattr__(self, name: str) -> None:
        del name
        raise TypeError("TransactionJournalLiveSnapshot is immutable")

    def __reduce__(self) -> Any:
        raise TypeError(
            "TransactionJournalLiveSnapshot is not serializable"
        )

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError(
            "TransactionJournalLiveSnapshot is not serializable"
        )


class TransactionJournalOperationLease:
    """One-shot reservation of an exact outer head for one lifecycle RPC."""

    __slots__ = (
        "__session",
        "__session_binding",
        "__operation",
        "__base_revision",
        "__base_record_sha256",
        "__request_sha256",
        "__state",
    )

    def __init__(
        self,
        *,
        _token: object,
        session: TransactionJournalSession,
        session_binding: object,
        operation: str,
        base_revision: int,
        base_record_sha256: str,
    ) -> None:
        if _token is not _OPERATION_LEASE_TOKEN:
            raise TypeError(
                "TransactionJournalOperationLease cannot be "
                "constructed directly"
            )
        self.__session = session
        self.__session_binding = session_binding
        self.__operation = operation
        self.__base_revision = base_revision
        self.__base_record_sha256 = base_record_sha256
        self.__request_sha256: str | None = None
        self.__state = "open"

    @property
    def operation(self) -> str:
        return self.__operation

    @property
    def base_record_revision(self) -> int:
        return self.__base_revision

    @property
    def base_record_sha256(self) -> str:
        return self.__base_record_sha256

    @property
    def state(self) -> str:
        return self.__state

    @property
    def request_sha256(self) -> str | None:
        return self.__request_sha256

    def _is_bound_to(
        self,
        session: TransactionJournalSession,
        session_binding: object,
    ) -> bool:
        return (
            self.__session is session
            and self.__session_binding is session_binding
        )

    def _set_state(self, expected: str, selected: str) -> None:
        if self.__state != expected:
            raise _error(
                "transaction_journal_lifecycle_operation_lease_spent"
            )
        self.__state = selected

    def _set_request_sha256(self, value: str) -> None:
        if self.__state != "open" or self.__request_sha256 is not None:
            raise _error(
                "transaction_journal_lifecycle_operation_lease_spent"
            )
        self.__request_sha256 = value

    def _request_matches(self, value: str | None) -> bool:
        return (
            self.__request_sha256 is not None
            and value is not None
            and hmac.compare_digest(self.__request_sha256, value)
        )

    def mark_dispatched(self, request_sha256: str) -> None:
        self.__session._mark_lifecycle_operation_dispatched(
            self, request_sha256
        )

    def cancel_before_dispatch(self) -> None:
        self.__session._cancel_lifecycle_operation_before_dispatch(
            self
        )

    def require_recovery(self) -> None:
        self.__session._require_lifecycle_operation_recovery(self)

    def complete_no_effect(
        self,
        lifecycle_operation_binding: Mapping[str, Any],
    ) -> None:
        self.__session._complete_lifecycle_operation_no_effect(
            self,
            lifecycle_operation_binding,
            expected_outcome="no_effect",
        )

    def complete_success_no_change(
        self,
        lifecycle_operation_binding: Mapping[str, Any],
    ) -> None:
        self.__session._complete_lifecycle_operation_no_effect(
            self,
            lifecycle_operation_binding,
            expected_outcome="success",
        )

    def mint_successor_permit(
        self,
        *,
        next_state: str,
        details: Mapping[str, Any],
        lifecycle_operation_binding: Mapping[str, Any],
        recorded_at_unix: int,
    ) -> TransactionJournalOuterSuccessorPermit:
        return self.__session._mint_outer_successor_permit(
            self,
            next_state=next_state,
            details=details,
            lifecycle_operation_binding=(
                lifecycle_operation_binding
            ),
            recorded_at_unix=recorded_at_unix,
        )

    def __copy__(self) -> Any:
        raise TypeError(
            "TransactionJournalOperationLease is not copyable"
        )

    def __deepcopy__(self, memo: Any) -> Any:
        del memo
        raise TypeError(
            "TransactionJournalOperationLease is not copyable"
        )

    def __reduce__(self) -> Any:
        raise TypeError(
            "TransactionJournalOperationLease is not serializable"
        )

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError(
            "TransactionJournalOperationLease is not serializable"
        )


class TransactionJournalOuterSuccessorPermit:
    """One-shot exact-head CAS permit carrying one frozen record candidate."""

    __slots__ = (
        "__session",
        "__session_binding",
        "__lease",
        "__candidate_canonical",
        "__spent",
    )

    def __init__(
        self,
        *,
        _token: object,
        session: TransactionJournalSession,
        session_binding: object,
        lease: TransactionJournalOperationLease,
        candidate: TransactionJournalRecord,
    ) -> None:
        if _token is not _OUTER_SUCCESSOR_PERMIT_TOKEN:
            raise TypeError(
                "TransactionJournalOuterSuccessorPermit cannot be "
                "constructed directly"
            )
        self.__session = session
        self.__session_binding = session_binding
        self.__lease = lease
        self.__candidate_canonical = _canonical_json(
            candidate.to_dict()
        )
        self.__spent = False

    @property
    def state(self) -> str:
        try:
            candidate = TransactionJournalRecord(
                json.loads(self.__candidate_canonical.decode("ascii"))
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise _error(
                "transaction_journal_outer_successor_permit_invalid"
            ) from exc
        return candidate.state

    @property
    def record_sha256(self) -> str:
        try:
            candidate = TransactionJournalRecord(
                json.loads(self.__candidate_canonical.decode("ascii"))
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise _error(
                "transaction_journal_outer_successor_permit_invalid"
            ) from exc
        return candidate.record_sha256

    def _contents(
        self,
    ) -> tuple[
        TransactionJournalSession,
        object,
        TransactionJournalOperationLease,
        TransactionJournalRecord,
    ]:
        if self.__spent:
            raise _error(
                "transaction_journal_outer_successor_permit_spent"
            )
        try:
            raw = self.__candidate_canonical
            if type(raw) is not bytes:
                raise TypeError("candidate is not canonical bytes")
            candidate = TransactionJournalRecord(
                json.loads(raw.decode("ascii"))
            )
            if _canonical_json(candidate.to_dict()) != raw:
                raise TypeError("candidate canonical value changed")
        except (
            AttributeError,
            TransactionJournalError,
            TypeError,
            UnicodeError,
            ValueError,
        ) as exc:
            raise _error(
                "transaction_journal_outer_successor_permit_invalid"
            ) from exc
        return (
            self.__session,
            self.__session_binding,
            self.__lease,
            candidate,
        )

    def commit(self) -> TransactionJournalRecord:
        return self.__session._commit_outer_successor_permit(self)

    def _spend(self) -> None:
        if self.__spent:
            raise _error(
                "transaction_journal_outer_successor_permit_spent"
            )
        self.__spent = True

    def __copy__(self) -> Any:
        raise TypeError(
            "TransactionJournalOuterSuccessorPermit is not copyable"
        )

    def __deepcopy__(self, memo: Any) -> Any:
        del memo
        raise TypeError(
            "TransactionJournalOuterSuccessorPermit is not copyable"
        )

    def __reduce__(self) -> Any:
        raise TypeError(
            "TransactionJournalOuterSuccessorPermit is not serializable"
        )

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError(
            "TransactionJournalOuterSuccessorPermit is not serializable"
        )


class RecoveredAdoptionJournalContext:
    """Creator- and session-bound claims from one exact recovered head."""

    __slots__ = (
        "__session",
        "__session_binding",
        "__owner_pid",
        "__evidence_canonical",
        "__result_canonical",
        "__provenance_canonical",
        "__journal_binding_canonical",
        "__continuation_canonical",
    )

    def __init__(
        self,
        *,
        _token: object,
        session: TransactionJournalSession,
        session_binding: object,
        evidence: Mapping[str, Any],
        result: Mapping[str, Any],
        provenance: Mapping[str, Any],
        journal_binding: Mapping[str, Any],
        continuation: Mapping[str, Any],
    ) -> None:
        if _token is not _RECOVERED_ADOPTION_CONTEXT_TOKEN:
            raise TypeError(
                "RecoveredAdoptionJournalContext cannot be "
                "constructed directly"
            )
        try:
            normalized_evidence = (
                recovered_adoption_evidence
                .normalize_recovered_adoption_evidence(evidence)
            )
            normalized_result = (
                adoption_result.normalize_capture_adoption_result(
                    result
                )
            )
            normalized_provenance = (
                adoption_result.normalize_capture_adoption_provenance(
                    provenance
                )
            )
            normalized_binding = (
                normalize_recovered_adoption_lease_binding_v2(
                    journal_binding
                )
            )
            normalized_continuation = (
                normalize_recovered_adoption_continuation(
                    continuation
                )
            )
        except (
            recovered_adoption_evidence
            .RecoveredAdoptionEvidenceError,
            adoption_result.CaptureAdoptionResultError,
        ) as exc:
            raise _error(exc.code) from exc
        if (
            type(session) is not TransactionJournalSession
            or normalized_result["kind"]
            != adoption_result.RECOVERED_ADOPTION_KIND
            or normalized_result["evidence"] != normalized_evidence
            or normalized_provenance
            != adoption_result.project_capture_adoption_provenance(
                normalized_result
            )
            or normalized_continuation[
                "pre_ack_recovered_adoption_lease_binding"
            ]["capture_session_id"]
            != normalized_binding["capture_session_id"]
        ):
            raise _error(
                "transaction_journal_"
                "recovered_adoption_context_invalid"
            )
        self.__session = session
        self.__session_binding = session_binding
        self.__owner_pid = os.getpid()
        self.__evidence_canonical = _canonical_json(
            normalized_evidence
        )
        self.__result_canonical = _canonical_json(normalized_result)
        self.__provenance_canonical = _canonical_json(
            normalized_provenance
        )
        self.__journal_binding_canonical = _canonical_json(
            normalized_binding
        )
        self.__continuation_canonical = _canonical_json(
            normalized_continuation
        )

    def _decoded(self) -> tuple[
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
    ]:
        if os.getpid() != self.__owner_pid:
            raise _error(
                "transaction_journal_"
                "recovered_adoption_context_creator_process_mismatch"
            )
        try:
            evidence = (
                recovered_adoption_evidence
                .normalize_recovered_adoption_evidence(
                    json.loads(
                        self.__evidence_canonical.decode("ascii")
                    )
                )
            )
            result = adoption_result.normalize_capture_adoption_result(
                json.loads(self.__result_canonical.decode("ascii"))
            )
            provenance = (
                adoption_result.normalize_capture_adoption_provenance(
                    json.loads(
                        self.__provenance_canonical.decode("ascii")
                    )
                )
            )
            binding = normalize_recovered_adoption_lease_binding_v2(
                json.loads(
                    self.__journal_binding_canonical.decode("ascii")
                )
            )
            continuation = normalize_recovered_adoption_continuation(
                json.loads(
                    self.__continuation_canonical.decode("ascii")
                )
            )
        except (
            AttributeError,
            TypeError,
            UnicodeError,
            ValueError,
            recovered_adoption_evidence
            .RecoveredAdoptionEvidenceError,
            adoption_result.CaptureAdoptionResultError,
        ) as exc:
            raise _error(
                "transaction_journal_"
                "recovered_adoption_context_invalid"
            ) from exc
        if (
            result["evidence"] != evidence
            or provenance
            != adoption_result.project_capture_adoption_provenance(
                result
            )
            or not hmac.compare_digest(
                recovered_adoption_evidence
                .recovered_adoption_evidence_sha256(evidence),
                binding["recovered_adoption_evidence_sha256"],
            )
            or not hmac.compare_digest(
                adoption_result.capture_adoption_result_sha256(
                    result
                ),
                binding["capture_adoption_result_sha256"],
            )
            or not hmac.compare_digest(
                adoption_result.capture_adoption_provenance_sha256(
                    provenance
                ),
                binding["capture_adoption_provenance_sha256"],
            )
        ):
            raise _error(
                "transaction_journal_"
                "recovered_adoption_context_binding_changed"
            )
        return evidence, result, provenance, binding, continuation

    def _contents_for_session(
        self,
        session: TransactionJournalSession,
        session_binding: object,
    ) -> tuple[
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
    ]:
        if (
            self.__session is not session
            or self.__session_binding is not session_binding
        ):
            raise _error(
                "transaction_journal_"
                "recovered_adoption_context_session_mismatch"
            )
        contents = self._decoded()
        binding = contents[3]
        records, _descriptor_info = session._scan_live_snapshot()
        head = records[-1]
        if (
            head.state
            != binding["transaction_journal_head_state"]
            or head.revision
            != binding["transaction_journal_head_revision"]
            or not hmac.compare_digest(
                head.record_sha256,
                binding[
                    "transaction_journal_head_record_sha256"
                ],
            )
        ):
            raise _error(
                "transaction_journal_"
                "recovered_adoption_context_head_changed"
            )
        return contents

    def _public_contents(self) -> tuple[
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
    ]:
        with self.__session._operation_lock:
            return self._contents_for_session(
                self.__session, self.__session_binding
            )

    @property
    def recovered_adoption_evidence(self) -> dict[str, Any]:
        return self._public_contents()[0]

    @property
    def capture_adoption_result(self) -> dict[str, Any]:
        return self._public_contents()[1]

    @property
    def capture_adoption_provenance(self) -> dict[str, Any]:
        return self._public_contents()[2]

    @property
    def journal_binding(self) -> dict[str, Any]:
        return self._public_contents()[3]

    @property
    def recovered_adoption_continuation(self) -> dict[str, Any]:
        return self._public_contents()[4]

    def __copy__(self) -> Any:
        raise TypeError(
            "RecoveredAdoptionJournalContext is not copyable"
        )

    def __deepcopy__(self, memo: Any) -> Any:
        del memo
        raise TypeError(
            "RecoveredAdoptionJournalContext is not copyable"
        )

    def __reduce__(self) -> Any:
        raise TypeError(
            "RecoveredAdoptionJournalContext is not serializable"
        )

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError(
            "RecoveredAdoptionJournalContext is not serializable"
        )


class RecoveredAdoptionTombstoneAckOperation:
    """One-shot reservation of an exact reconciled head for staging ACK."""

    __slots__ = (
        "__session",
        "__session_binding",
        "__context",
        "__owner_pid",
        "__state",
    )

    def __init__(
        self,
        *,
        _token: object,
        session: TransactionJournalSession,
        session_binding: object,
        context: RecoveredAdoptionJournalContext,
    ) -> None:
        if _token is not _RECOVERED_ADOPTION_ACK_OPERATION_TOKEN:
            raise TypeError(
                "RecoveredAdoptionTombstoneAckOperation cannot be "
                "constructed directly"
            )
        self.__session = session
        self.__session_binding = session_binding
        self.__context = context
        self.__owner_pid = os.getpid()
        self.__state = "open"

    @property
    def state(self) -> str:
        return self.__state

    @property
    def journal_context(self) -> RecoveredAdoptionJournalContext:
        if os.getpid() != self.__owner_pid:
            raise _error(
                "transaction_journal_"
                "recovered_adoption_ack_creator_process_mismatch"
            )
        return self.__context

    def _contents(
        self,
    ) -> tuple[
        TransactionJournalSession,
        object,
        RecoveredAdoptionJournalContext,
    ]:
        if os.getpid() != self.__owner_pid:
            raise _error(
                "transaction_journal_"
                "recovered_adoption_ack_creator_process_mismatch"
            )
        if self.__state != "open":
            raise _error(
                "transaction_journal_"
                "recovered_adoption_ack_operation_spent"
            )
        return (
            self.__session,
            self.__session_binding,
            self.__context,
        )

    def _set_state(self, expected: str, selected: str) -> None:
        if self.__state != expected:
            raise _error(
                "transaction_journal_"
                "recovered_adoption_ack_operation_spent"
            )
        self.__state = selected

    def commit(
        self,
        control: Any,
    ) -> RecoveredAdoptionContinuationClearance:
        return self.__session._commit_recovered_adoption_tombstone_ack(
            self, control
        )

    def cancel(self) -> None:
        self.__session._cancel_recovered_adoption_tombstone_ack(
            self
        )

    def __copy__(self) -> Any:
        raise TypeError(
            "RecoveredAdoptionTombstoneAckOperation is not copyable"
        )

    def __deepcopy__(self, memo: Any) -> Any:
        del memo
        raise TypeError(
            "RecoveredAdoptionTombstoneAckOperation is not copyable"
        )

    def __reduce__(self) -> Any:
        raise TypeError(
            "RecoveredAdoptionTombstoneAckOperation is not serializable"
        )

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError(
            "RecoveredAdoptionTombstoneAckOperation is not serializable"
        )


class RecoveredAdoptionContinuationClearance:
    """Proof that the exact recovered ACK record is durably committed."""

    __slots__ = (
        "__session",
        "__session_binding",
        "__owner_pid",
        "__record_canonical",
        "__context",
    )

    def __init__(
        self,
        *,
        _token: object,
        session: TransactionJournalSession,
        session_binding: object,
        record: TransactionJournalRecord,
        context: RecoveredAdoptionJournalContext,
    ) -> None:
        if _token is not _RECOVERED_ADOPTION_CLEARANCE_TOKEN:
            raise TypeError(
                "RecoveredAdoptionContinuationClearance cannot be "
                "constructed directly"
            )
        if (
            type(record) is not TransactionJournalRecord
            or record.state != "staging_tombstone_acked"
            or "recovered_adoption_continuation"
            not in record.details
        ):
            raise _error(
                "transaction_journal_"
                "recovered_adoption_clearance_record_invalid"
            )
        self.__session = session
        self.__session_binding = session_binding
        self.__owner_pid = os.getpid()
        self.__record_canonical = _canonical_json(
            record.to_dict()
        )
        self.__context = context

    def _record(self) -> TransactionJournalRecord:
        if os.getpid() != self.__owner_pid:
            raise _error(
                "transaction_journal_"
                "recovered_adoption_clearance_creator_process_mismatch"
            )
        try:
            record = TransactionJournalRecord(
                json.loads(
                    self.__record_canonical.decode("ascii")
                )
            )
        except (
            AttributeError,
            TransactionJournalError,
            TypeError,
            UnicodeError,
            ValueError,
        ) as exc:
            raise _error(
                "transaction_journal_"
                "recovered_adoption_clearance_invalid"
            ) from exc
        with self.__session._operation_lock:
            if (
                type(self.__session) is not TransactionJournalSession
                or self.__session._live_snapshot_binding
                is not self.__session_binding
            ):
                raise _error(
                    "transaction_journal_"
                    "recovered_adoption_clearance_session_mismatch"
                )
            records, _descriptor_info = (
                self.__session._scan_live_snapshot()
            )
            matches = tuple(
                candidate
                for candidate in records
                if candidate.record_sha256 == record.record_sha256
            )
            if len(matches) != 1 or (
                matches[0].to_dict() != record.to_dict()
            ):
                raise _error(
                    "transaction_journal_"
                    "recovered_adoption_clearance_record_changed"
                )
        return record

    @property
    def committed_record(self) -> TransactionJournalRecord:
        return self._record()

    @property
    def committed_record_sha256(self) -> str:
        return self._record().record_sha256

    @property
    def recovered_adoption_continuation(self) -> dict[str, Any]:
        return self._record().details[
            "recovered_adoption_continuation"
        ]

    @property
    def journal_context(self) -> RecoveredAdoptionJournalContext:
        self._record()
        return self.__context

    def __copy__(self) -> Any:
        raise TypeError(
            "RecoveredAdoptionContinuationClearance is not copyable"
        )

    def __deepcopy__(self, memo: Any) -> Any:
        del memo
        raise TypeError(
            "RecoveredAdoptionContinuationClearance is not copyable"
        )

    def __reduce__(self) -> Any:
        raise TypeError(
            "RecoveredAdoptionContinuationClearance is not serializable"
        )

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError(
            "RecoveredAdoptionContinuationClearance is not serializable"
        )


def _build_recovered_verifier_source_evidence_envelope(
    *,
    verifier_request_v5: Mapping[str, Any],
    verifier_output_v4: Mapping[str, Any],
    source_revalidation_receipt_v2: Mapping[str, Any],
    pre_verifier_recovered_adoption_lease_binding: Mapping[str, Any],
    post_verifier_recovered_adoption_lease_binding: Mapping[str, Any],
    expected_capture_adoption_result: Mapping[str, Any],
    expected_capture_adoption_provenance: Mapping[str, Any],
    expected_post_ack_binding: Mapping[str, Any],
    recovered_adoption_continuation: Mapping[str, Any],
    staging_tombstone_acked_record_sha256: str,
    staging_tombstone_acked_recorded_at_unix: int,
) -> dict[str, Any]:
    """Bind completed verifier and live-source evidence under one ACK head."""

    request = _normalize_verifier_request_v5_for_recovered_evidence(
        verifier_request_v5
    )
    expected_result = (
        adoption_result.normalize_capture_adoption_result(
            expected_capture_adoption_result
        )
    )
    expected_provenance = (
        adoption_result.normalize_capture_adoption_provenance(
            expected_capture_adoption_provenance
        )
    )
    continuation = normalize_recovered_adoption_continuation(
        recovered_adoption_continuation
    )
    ack_sha256 = _digest(
        staging_tombstone_acked_record_sha256,
        field=(
            "transaction_journal_recovered_verifier_"
            "material_ack_record_sha256"
        ),
    )
    ack_recorded_at = _integer(
        staging_tombstone_acked_recorded_at_unix,
        field=(
            "transaction_journal_recovered_verifier_"
            "material_ack_recorded_at_unix"
        ),
        minimum=1,
    )
    expected_binding = normalize_recovered_adoption_lease_binding_v2(
        expected_post_ack_binding
    )
    pre_binding = normalize_recovered_adoption_lease_binding_v2(
        pre_verifier_recovered_adoption_lease_binding
    )
    post_binding = normalize_recovered_adoption_lease_binding_v2(
        post_verifier_recovered_adoption_lease_binding
    )
    if (
        request["capture_adoption_result"] != expected_result
        or request["capture_adoption_result_sha256"]
        != continuation["capture_adoption_result_sha256"]
        or expected_provenance
        != continuation["capture_adoption_provenance"]
        or request["capture_session_id"]
        != expected_binding["capture_session_id"]
        or pre_binding != expected_binding
        or post_binding != expected_binding
        or expected_binding["transaction_journal_head_state"]
        != "staging_tombstone_acked"
        or expected_binding[
            "transaction_journal_head_record_sha256"
        ]
        != ack_sha256
        or expected_binding[
            "staging_tombstone_acked_record_sha256"
        ]
        != ack_sha256
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "material_ack_or_result_binding_mismatch"
        )
    if request["verified_at_unix"] < ack_recorded_at:
        raise _error(
            "transaction_journal_recovered_verifier_"
            "material_effect_precedes_ack"
        )
    output = normalize_verifier_output_v4(
        verifier_output_v4,
        expected_evidence_uid=request["evidence_uid"],
    )
    evidence = output["evidence"]
    request_output_bindings = {
        "expected_run_id": "run_id",
        "verifier_uid": "verifier_uid",
        "verifier_bundle_sha256": "verifier_bundle_sha256",
        "verification_policy_sha256": (
            "verification_policy_sha256"
        ),
        "capture_manifest_sha256": "capture_manifest_sha256",
        "capture_plan_sha256": "capture_plan_sha256",
        "operator_policy_sha256": "operator_policy_sha256",
        "verified_at_unix": "verified_at_unix",
        "evidence_uid": "observed_evidence_uid",
        "capture_uid": "capture_creator_uid",
        "capture_export_gid": "capture_export_gid",
        "adopted_uid": "capture_adopted_uid",
        "capture_adoption_policy_sha256": (
            "capture_adoption_policy_sha256"
        ),
        "capture_request_sha256": "capture_request_sha256",
        "capture_boundary_policy_sha256": (
            "capture_boundary_policy_sha256"
        ),
        "capture_helper_activation_policy_sha256": (
            "capture_helper_activation_policy_sha256"
        ),
    }
    result_evidence = expected_result["evidence"]
    if (
        any(
            request[request_field] != evidence[output_field]
            for request_field, output_field
            in request_output_bindings.items()
        )
        or evidence["capture_object_identity_sha256"]
        != result_evidence["capture_object_identity_sha256"]
        or evidence["capture_content_inventory_sha256"]
        != result_evidence[
            "reconciled_content_inventory_sha256"
        ]
        or evidence["capture_adoption_provenance"]
        != expected_provenance
        or evidence["capture_adoption_provenance_sha256"]
        != adoption_result.capture_adoption_provenance_sha256(
            expected_provenance
        )
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "material_request_output_binding_mismatch"
        )
    output_sha256 = verifier_output_v4_sha256(
        output,
        expected_evidence_uid=request["evidence_uid"],
    )
    try:
        receipt = (
            source_revalidation_binding
            .normalize_source_revalidation_receipt_v2(
                source_revalidation_receipt_v2
            )
        )
        receipt_sha256 = (
            source_revalidation_binding
            .source_revalidation_receipt_v2_sha256(receipt)
        )
    except (
        source_revalidation_binding.SourceRevalidationBindingError
    ) as exc:
        raise _error(exc.code) from exc
    verified_v6 = normalize_recovered_verified_evidence_v6(
        {
            **evidence,
            "post_verifier_live_source_revalidation_receipt": (
                receipt
            ),
            (
                "post_verifier_live_source_"
                "revalidation_receipt_sha256"
            ): receipt_sha256,
        },
        expected_evidence_uid=request["evidence_uid"],
        expected_verifier_output_sha256=output_sha256,
    )
    verified_v6_sha256 = recovered_verified_evidence_v6_sha256(
        verified_v6,
        expected_evidence_uid=request["evidence_uid"],
        expected_verifier_output_sha256=output_sha256,
    )
    request_sha256 = _sha256(_canonical_json(request))
    pre_binding_sha256 = (
        recovered_adoption_lease_binding_v2_sha256(pre_binding)
    )
    post_binding_sha256 = (
        recovered_adoption_lease_binding_v2_sha256(post_binding)
    )
    return normalize_recovered_verifier_source_evidence(
        {
            "schema_version": (
                RECOVERED_VERIFIER_SOURCE_EVIDENCE_SCHEMA
            ),
            "verifier_request_schema": VERIFIER_REQUEST_V5_SCHEMA,
            "verifier_request_v5_sha256": request_sha256,
            "expected_run_id": request["expected_run_id"],
            "verifier_output_schema": VERIFIER_OUTPUT_V4_SCHEMA,
            "verifier_output_v4": output,
            "verifier_output_v4_sha256": output_sha256,
            "source_revalidation_receipt_schema": (
                SOURCE_REVALIDATION_RECEIPT_V2_SCHEMA
            ),
            "source_revalidation_receipt_v2": receipt,
            "source_revalidation_receipt_v2_sha256": (
                receipt_sha256
            ),
            (
                "source_revalidation_effect_"
                "completed_under_acked_head"
            ): True,
            "staging_tombstone_acked_record_sha256": (
                ack_sha256
            ),
            "recovered_adoption_continuation_sha256": (
                recovered_adoption_continuation_sha256(
                    continuation
                )
            ),
            "capture_adoption_provenance": expected_provenance,
            "capture_adoption_provenance_sha256": (
                adoption_result.capture_adoption_provenance_sha256(
                    expected_provenance
                )
            ),
            "pre_verifier_recovered_adoption_lease_binding": (
                pre_binding
            ),
            (
                "pre_verifier_recovered_adoption_"
                "lease_binding_sha256"
            ): pre_binding_sha256,
            "post_verifier_recovered_adoption_lease_binding": (
                post_binding
            ),
            (
                "post_verifier_recovered_adoption_"
                "lease_binding_sha256"
            ): post_binding_sha256,
            "recovered_adoption_lease_bindings_equal": True,
            "verified_evidence_v6_sha256": (
                verified_v6_sha256
            ),
        }
    )


def _reconstruct_recovered_verified_evidence_v6(
    records: tuple[TransactionJournalRecord, ...],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Reconstruct and re-digest v6 from one exact recovered projection head."""

    if (
        not records
        or records[-1].state
        not in {
            "verifier_output_bound",
            "live_revalidation_started",
            "live_revalidation_receipt_complete",
        }
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "evidence_head_state_invalid"
        )
    _validate_recovered_verifier_source_evidence_history(records)
    matches = tuple(
        record
        for record in records
        if record.state == "verifier_output_bound"
        and "recovered_verifier_source_evidence"
        in record.details
    )
    if len(matches) != 1:
        raise _error(
            "transaction_journal_recovered_verifier_"
            "evidence_record_missing"
        )
    verifier_record = matches[0]
    envelope = normalize_recovered_verifier_source_evidence(
        verifier_record.details[
            "recovered_verifier_source_evidence"
        ]
    )
    envelope_sha256 = (
        recovered_verifier_source_evidence_sha256(envelope)
    )
    if not hmac.compare_digest(
        envelope_sha256,
        verifier_record.details[
            "recovered_verifier_source_evidence_sha256"
        ],
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "evidence_envelope_digest_mismatch"
        )
    evidence_v4 = envelope["verifier_output_v4"]["evidence"]
    expected_uid = evidence_v4["observed_evidence_uid"]
    verified_v6 = normalize_recovered_verified_evidence_v6(
        {
            **evidence_v4,
            "post_verifier_live_source_revalidation_receipt": (
                envelope["source_revalidation_receipt_v2"]
            ),
            (
                "post_verifier_live_source_"
                "revalidation_receipt_sha256"
            ): envelope["source_revalidation_receipt_v2_sha256"],
        },
        expected_evidence_uid=expected_uid,
        expected_verifier_output_sha256=(
            envelope["verifier_output_v4_sha256"]
        ),
    )
    verified_v6_sha256 = recovered_verified_evidence_v6_sha256(
        verified_v6,
        expected_evidence_uid=expected_uid,
        expected_verifier_output_sha256=(
            envelope["verifier_output_v4_sha256"]
        ),
    )
    if not hmac.compare_digest(
        verified_v6_sha256,
        envelope["verified_evidence_v6_sha256"],
    ):
        raise _error(
            "transaction_journal_recovered_verifier_"
            "evidence_reconstruction_digest_mismatch"
        )
    return envelope, verified_v6


class RecoveredVerifierSourceEvidenceMaterial:
    """Nonconstructible material already completed under one ACK head."""

    __slots__ = (
        "__session",
        "__session_binding",
        "__operation",
        "__owner_pid",
        "__head_record_sha256",
        "__envelope_canonical",
    )

    def __init__(
        self,
        *,
        _token: object,
        session: TransactionJournalSession,
        session_binding: object,
        operation: RecoveredVerifierSourceEvidenceOperation,
        head_record_sha256: str,
        envelope: Mapping[str, Any],
    ) -> None:
        if _token is not _RECOVERED_VERIFIER_MATERIAL_TOKEN:
            raise TypeError(
                "RecoveredVerifierSourceEvidenceMaterial cannot be "
                "constructed directly"
            )
        self.__session = session
        self.__session_binding = session_binding
        self.__operation = operation
        self.__owner_pid = os.getpid()
        self.__head_record_sha256 = _digest(
            head_record_sha256,
            field=(
                "transaction_journal_recovered_verifier_"
                "material_head_record_sha256"
            ),
        )
        self.__envelope_canonical = _canonical_json(
            normalize_recovered_verifier_source_evidence(envelope)
        )

    def _contents_for_operation(
        self,
        session: TransactionJournalSession,
        session_binding: object,
        operation: RecoveredVerifierSourceEvidenceOperation,
        head_record_sha256: str,
    ) -> dict[str, Any]:
        if os.getpid() != self.__owner_pid:
            raise _error(
                "transaction_journal_recovered_verifier_"
                "material_creator_process_mismatch"
            )
        if (
            self.__session is not session
            or self.__session_binding is not session_binding
            or self.__operation is not operation
            or not hmac.compare_digest(
                self.__head_record_sha256,
                head_record_sha256,
            )
        ):
            raise _error(
                "transaction_journal_recovered_verifier_"
                "material_operation_mismatch"
            )
        try:
            return normalize_recovered_verifier_source_evidence(
                json.loads(
                    self.__envelope_canonical.decode("ascii")
                )
            )
        except (
            AttributeError,
            TransactionJournalError,
            TypeError,
            UnicodeError,
            ValueError,
        ) as exc:
            raise _error(
                "transaction_journal_recovered_verifier_"
                "material_invalid"
            ) from exc

    @property
    def recovered_verifier_source_evidence(
        self,
    ) -> dict[str, Any]:
        if os.getpid() != self.__owner_pid:
            raise _error(
                "transaction_journal_recovered_verifier_"
                "material_creator_process_mismatch"
            )
        return normalize_recovered_verifier_source_evidence(
            json.loads(self.__envelope_canonical.decode("ascii"))
        )

    def __copy__(self) -> Any:
        raise TypeError(
            "RecoveredVerifierSourceEvidenceMaterial is not copyable"
        )

    def __deepcopy__(self, memo: Any) -> Any:
        del memo
        raise TypeError(
            "RecoveredVerifierSourceEvidenceMaterial is not copyable"
        )

    def __reduce__(self) -> Any:
        raise TypeError(
            "RecoveredVerifierSourceEvidenceMaterial is not serializable"
        )

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError(
            "RecoveredVerifierSourceEvidenceMaterial is not serializable"
        )


class RecoveredVerifierSourceEvidenceOperation:
    """One-shot exact-ACK reservation for already-completed evidence."""

    __slots__ = (
        "__session",
        "__session_binding",
        "__owner_pid",
        "__head_revision",
        "__head_record_sha256",
        "__phase",
    )

    def __init__(
        self,
        *,
        _token: object,
        session: TransactionJournalSession,
        session_binding: object,
        head_revision: int,
        head_record_sha256: str,
    ) -> None:
        if _token is not _RECOVERED_VERIFIER_OPERATION_TOKEN:
            raise TypeError(
                "RecoveredVerifierSourceEvidenceOperation cannot be "
                "constructed directly"
            )
        self.__session = session
        self.__session_binding = session_binding
        self.__owner_pid = os.getpid()
        self.__head_revision = head_revision
        self.__head_record_sha256 = head_record_sha256
        self.__phase: tuple[str, str | None] = ("open", None)

    @property
    def state(self) -> str:
        return self.__phase[0]

    def _contents(
        self,
    ) -> tuple[
        TransactionJournalSession,
        object,
        int,
        str,
    ]:
        if os.getpid() != self.__owner_pid:
            raise _error(
                "transaction_journal_recovered_verifier_"
                "operation_creator_process_mismatch"
            )
        if self.__phase != ("open", None):
            raise _error(
                "transaction_journal_recovered_verifier_"
                "operation_spent"
            )
        return (
            self.__session,
            self.__session_binding,
            self.__head_revision,
            self.__head_record_sha256,
        )

    def _contents_for_finalization(
        self,
    ) -> tuple[
        TransactionJournalSession,
        object,
        int,
        str,
        str,
        str,
    ]:
        if os.getpid() != self.__owner_pid:
            raise _error(
                "transaction_journal_recovered_verifier_"
                "operation_creator_process_mismatch"
            )
        state, expected_successor_record_sha256 = self.__phase
        if state not in {
            "committing",
            "committed",
            "interrupted_reconciled",
        }:
            raise _error(
                "transaction_journal_recovered_verifier_"
                "operation_not_finalizing"
            )
        return (
            self.__session,
            self.__session_binding,
            self.__head_revision,
            self.__head_record_sha256,
            _digest(
                expected_successor_record_sha256,
                field=(
                    "transaction_journal_recovered_verifier_"
                    "operation_expected_successor_record_sha256"
                ),
            ),
            state,
        )

    def _contents_for_cancellation(
        self,
    ) -> tuple[
        TransactionJournalSession,
        object,
        str,
    ]:
        if os.getpid() != self.__owner_pid:
            raise _error(
                "transaction_journal_recovered_verifier_"
                "operation_creator_process_mismatch"
            )
        if self.__phase not in {
            ("open", None),
            ("cancelled", None),
        }:
            raise _error(
                "transaction_journal_recovered_verifier_"
                "operation_spent"
            )
        return (
            self.__session,
            self.__session_binding,
            self.__phase[0],
        )

    def _begin_finalization(
        self,
        expected_successor_record_sha256: str,
    ) -> None:
        if self.__phase != ("open", None):
            raise _error(
                "transaction_journal_recovered_verifier_"
                "operation_spent"
            )
        successor_sha256 = _digest(
            expected_successor_record_sha256,
            field=(
                "transaction_journal_recovered_verifier_"
                "operation_expected_successor_record_sha256"
            ),
        )
        self.__phase = ("committing", successor_sha256)

    def _set_state(self, expected: str, selected: str) -> None:
        state, successor_sha256 = self.__phase
        if state != expected:
            raise _error(
                "transaction_journal_recovered_verifier_"
                "operation_spent"
            )
        self.__phase = (selected, successor_sha256)

    def mint_material(
        self,
        *,
        verifier_request_v5: Mapping[str, Any],
        verifier_output_v4: Mapping[str, Any],
        source_revalidation_receipt_v2: Mapping[str, Any],
        pre_verifier_recovered_adoption_lease_binding: (
            Mapping[str, Any]
        ),
        post_verifier_recovered_adoption_lease_binding: (
            Mapping[str, Any]
        ),
    ) -> RecoveredVerifierSourceEvidenceMaterial:
        """Validate complete effect evidence; retain no caller path."""

        return self.__session._mint_recovered_verifier_material(
            self,
            verifier_request_v5=verifier_request_v5,
            verifier_output_v4=verifier_output_v4,
            source_revalidation_receipt_v2=(
                source_revalidation_receipt_v2
            ),
            pre_verifier_recovered_adoption_lease_binding=(
                pre_verifier_recovered_adoption_lease_binding
            ),
            post_verifier_recovered_adoption_lease_binding=(
                post_verifier_recovered_adoption_lease_binding
            ),
        )

    def commit(
        self,
        material: RecoveredVerifierSourceEvidenceMaterial,
    ) -> RecoveredVerifiedEvidenceV6Clearance:
        return self.__session._commit_recovered_verifier_material(
            self, material
        )

    def cancel(self) -> None:
        self.__session._cancel_recovered_verifier_operation(self)

    def __copy__(self) -> Any:
        raise TypeError(
            "RecoveredVerifierSourceEvidenceOperation is not copyable"
        )

    def __deepcopy__(self, memo: Any) -> Any:
        del memo
        raise TypeError(
            "RecoveredVerifierSourceEvidenceOperation is not copyable"
        )

    def __reduce__(self) -> Any:
        raise TypeError(
            "RecoveredVerifierSourceEvidenceOperation is not serializable"
        )

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError(
            "RecoveredVerifierSourceEvidenceOperation is not serializable"
        )


class RecoveredVerifiedEvidenceV6Clearance:
    """Exact-head, restart-safe access to reconstructed signable v6."""

    __slots__ = (
        "__session",
        "__session_binding",
        "__owner_pid",
        "__head_record_canonical",
        "__verified_evidence_v6_sha256",
    )

    def __init__(
        self,
        *,
        _token: object,
        session: TransactionJournalSession,
        session_binding: object,
        head_record: TransactionJournalRecord,
        verified_evidence_v6_sha256: str,
    ) -> None:
        if _token is not _RECOVERED_VERIFIED_EVIDENCE_CLEARANCE_TOKEN:
            raise TypeError(
                "RecoveredVerifiedEvidenceV6Clearance cannot be "
                "constructed directly"
            )
        self.__session = session
        self.__session_binding = session_binding
        self.__owner_pid = os.getpid()
        self.__head_record_canonical = _canonical_json(
            head_record.to_dict()
        )
        self.__verified_evidence_v6_sha256 = _digest(
            verified_evidence_v6_sha256,
            field=(
                "transaction_journal_recovered_verifier_"
                "clearance_v6_sha256"
            ),
        )

    def _contents(
        self,
    ) -> tuple[
        TransactionJournalRecord,
        dict[str, Any],
        dict[str, Any],
    ]:
        if os.getpid() != self.__owner_pid:
            raise _error(
                "transaction_journal_recovered_verifier_"
                "clearance_creator_process_mismatch"
            )
        try:
            expected_head = TransactionJournalRecord(
                json.loads(
                    self.__head_record_canonical.decode("ascii")
                )
            )
        except (
            AttributeError,
            TransactionJournalError,
            TypeError,
            UnicodeError,
            ValueError,
        ) as exc:
            raise _error(
                "transaction_journal_recovered_verifier_"
                "clearance_invalid"
            ) from exc
        with self.__session._operation_lock:
            if (
                type(self.__session) is not TransactionJournalSession
                or self.__session._live_snapshot_binding
                is not self.__session_binding
            ):
                raise _error(
                    "transaction_journal_recovered_verifier_"
                    "clearance_session_mismatch"
                )
            records, _descriptor_info = (
                self.__session._scan_live_snapshot()
            )
            head = records[-1]
            if head.to_dict() != expected_head.to_dict():
                raise _error(
                    "transaction_journal_recovered_verifier_"
                    "clearance_head_changed"
                )
            envelope, evidence = (
                _reconstruct_recovered_verified_evidence_v6(
                    records
                )
            )
            observed_sha256 = recovered_verified_evidence_v6_sha256(
                evidence,
                expected_evidence_uid=(
                    evidence["observed_evidence_uid"]
                ),
                expected_verifier_output_sha256=(
                    envelope["verifier_output_v4_sha256"]
                ),
            )
            if not hmac.compare_digest(
                observed_sha256,
                self.__verified_evidence_v6_sha256,
            ):
                raise _error(
                    "transaction_journal_recovered_verifier_"
                    "clearance_v6_digest_changed"
                )
        return head, envelope, evidence

    @property
    def head_state(self) -> str:
        return self._contents()[0].state

    @property
    def head_record_sha256(self) -> str:
        return self._contents()[0].record_sha256

    @property
    def recovered_verifier_source_evidence(
        self,
    ) -> dict[str, Any]:
        return self._contents()[1]

    @property
    def verified_evidence_v6(self) -> dict[str, Any]:
        return self._contents()[2]

    @property
    def verified_evidence_v6_sha256(self) -> str:
        self._contents()
        return self.__verified_evidence_v6_sha256

    def __copy__(self) -> Any:
        raise TypeError(
            "RecoveredVerifiedEvidenceV6Clearance is not copyable"
        )

    def __deepcopy__(self, memo: Any) -> Any:
        del memo
        raise TypeError(
            "RecoveredVerifiedEvidenceV6Clearance is not copyable"
        )

    def __reduce__(self) -> Any:
        raise TypeError(
            "RecoveredVerifiedEvidenceV6Clearance is not serializable"
        )

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError(
            "RecoveredVerifiedEvidenceV6Clearance is not serializable"
        )


def _history_requires_lifecycle_recovery(
    records: tuple[TransactionJournalRecord, ...],
) -> bool:
    if not records:
        return False
    latest = records[-1]
    if latest.state in {
        "child_launch_intent",
        "child_running",
        "capture_ready",
        "lifecycle_clearance_intent",
    }:
        return True
    return (
        latest.state == "operator_attention"
        and latest.details["from_state"]
        in (
            LIFECYCLE_EFFECT_ORIGIN_STATES
            | {"lifecycle_clearance_intent"}
        )
    )


class TransactionJournalSession:
    """Append capability for one descriptor-bound journal session."""

    __slots__ = (
        "_store",
        "_directory_fd",
        "_directory_name",
        "_records",
        "_instance_slug",
        "_session_id",
        "_control_sha256",
        "_handoff_policy_sha256",
        "_live_snapshot_binding",
        "_operation_lock",
        "_owner_pid",
        "_active_operation_lease",
        "_active_recovered_adoption_ack_operation",
        "_active_recovered_verifier_operation",
        "_recovery_required",
    )

    def __init__(
        self,
        *,
        _token: object,
        store: TransactionJournalStore,
        directory_fd: int,
        directory_name: str,
        records: tuple[TransactionJournalRecord, ...],
        instance_slug: str,
        session_id: str,
        control_sha256: str,
        handoff_policy_sha256: str,
        recovery_required: bool = False,
    ) -> None:
        if _token is not _SESSION_TOKEN:
            raise TypeError(
                "TransactionJournalSession cannot be constructed directly"
            )
        os.set_inheritable(directory_fd, False)
        self._store = store
        self._directory_fd = directory_fd
        self._directory_name = directory_name
        self._records = records
        self._instance_slug = instance_slug
        self._session_id = session_id
        self._control_sha256 = control_sha256
        self._handoff_policy_sha256 = handoff_policy_sha256
        self._live_snapshot_binding = object()
        self._operation_lock = threading.RLock()
        self._owner_pid = os.getpid()
        self._active_operation_lease: (
            TransactionJournalOperationLease | None
        ) = None
        self._active_recovered_adoption_ack_operation: (
            RecoveredAdoptionTombstoneAckOperation | None
        ) = None
        self._active_recovered_verifier_operation: (
            RecoveredVerifierSourceEvidenceOperation | None
        ) = None
        self._recovery_required = bool(recovery_required)

    @property
    def active(self) -> bool:
        return (
            os.getpid() == self._owner_pid
            and self._directory_fd >= 0
            and self._store.active
        )

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def records(self) -> tuple[TransactionJournalRecord, ...]:
        with self._operation_lock:
            self._require_active()
            return self._records

    @property
    def latest_record(self) -> TransactionJournalRecord:
        with self._operation_lock:
            self._require_active()
            if not self._records:
                raise _error("transaction_journal_session_empty")
            return self._records[-1]

    @property
    def state(self) -> str:
        return self.latest_record.state

    @property
    def recovery_required(self) -> bool:
        with self._operation_lock:
            self._require_active()
            return self._recovery_required

    def _require_active(self) -> int:
        if os.getpid() != self._owner_pid:
            raise _error(
                "transaction_journal_session_creator_process_mismatch"
            )
        if not self.active:
            raise _error("transaction_journal_session_closed")
        return self._directory_fd

    def _scan_live_snapshot(
        self,
    ) -> tuple[
        tuple[TransactionJournalRecord, ...],
        os.stat_result,
    ]:
        if type(self) is not TransactionJournalSession:
            raise _error(
                "transaction_journal_live_snapshot_session_required"
            )
        descriptor = self._require_active()
        if (
            type(self._store) is not TransactionJournalStore
            or not any(
                candidate is self
                for candidate in self._store._sessions
            )
            or self._directory_name
            != f"session-{self._session_id}"
        ):
            raise _error(
                "transaction_journal_live_snapshot_session_invalid"
            )
        store_descriptor = self._store._require_active()
        try:
            inheritable = os.get_inheritable(descriptor)
        except OSError as exc:
            raise _error(
                "transaction_journal_live_snapshot_descriptor_unreadable"
            ) from exc
        before = _validate_directory(
            descriptor,
            owner_uid=self._store._owner_uid,
            owner_gid=self._store._owner_gid,
            mode=SESSION_DIRECTORY_MODE,
            field=(
                "transaction_journal_live_snapshot_directory"
            ),
        )
        if inheritable:
            raise _error(
                "transaction_journal_live_snapshot_descriptor_unsafe"
            )
        _validate_named_fd_binding(
            store_descriptor,
            self._directory_name,
            descriptor,
            directory=True,
            field=(
                "transaction_journal_live_snapshot_directory"
            ),
        )
        on_disk = self._store._scan_session(
            self._directory_name,
            descriptor,
            clean_stale_temps=False,
        )
        after = _validate_directory(
            descriptor,
            owner_uid=self._store._owner_uid,
            owner_gid=self._store._owner_gid,
            mode=SESSION_DIRECTORY_MODE,
            field=(
                "transaction_journal_live_snapshot_directory"
            ),
        )
        _validate_named_fd_binding(
            store_descriptor,
            self._directory_name,
            descriptor,
            directory=True,
            field=(
                "transaction_journal_live_snapshot_directory"
            ),
        )
        if _full_stat_tuple(before) != _full_stat_tuple(after):
            raise _error(
                "transaction_journal_live_snapshot_directory_changed"
            )
        try:
            disk_canonical = _canonical_live_snapshot_records(
                on_disk
            )
            memory_canonical = _canonical_live_snapshot_records(
                self._records
            )
        except TransactionJournalError as exc:
            raise _error(
                "transaction_journal_live_snapshot_session_changed"
            ) from exc
        if disk_canonical != memory_canonical:
            raise _error(
                "transaction_journal_live_snapshot_session_changed"
            )
        first = on_disk[0].to_dict()
        if (
            first["instance_slug"] != self._instance_slug
            or first["session_id"] != self._session_id
            or first["control_sha256"] != self._control_sha256
            or first["handoff_policy_sha256"]
            != self._handoff_policy_sha256
            or on_disk[-1].revision != len(on_disk)
        ):
            raise _error(
                "transaction_journal_live_snapshot_session_changed"
            )
        return on_disk, after

    def live_snapshot(self) -> TransactionJournalLiveSnapshot:
        """Return an exact, path-free observation of the live disk head."""

        if type(self) is not TransactionJournalSession:
            raise _error(
                "transaction_journal_live_snapshot_session_required"
            )
        with self._operation_lock:
            records, descriptor_info = self._scan_live_snapshot()
            return TransactionJournalLiveSnapshot(
                _token=_LIVE_SNAPSHOT_TOKEN,
                session_binding=self._live_snapshot_binding,
                records=records,
                descriptor_device=int(descriptor_info.st_dev),
                descriptor_inode=int(descriptor_info.st_ino),
            )

    def assert_live_snapshot_current(
        self,
        snapshot: Any,
    ) -> None:
        """Fail unless ``snapshot`` still names this exact live disk head."""

        if type(self) is not TransactionJournalSession:
            raise _error(
                "transaction_journal_live_snapshot_session_required"
            )
        with self._operation_lock:
            if type(snapshot) is not TransactionJournalLiveSnapshot:
                raise _error(
                    "transaction_journal_live_snapshot_required"
                )
            if not snapshot._is_bound_to(
                self._live_snapshot_binding
            ):
                raise _error(
                    "transaction_journal_live_snapshot_session_mismatch"
                )
            records, descriptor_info = self._scan_live_snapshot()
            current = TransactionJournalLiveSnapshot(
                _token=_LIVE_SNAPSHOT_TOKEN,
                session_binding=self._live_snapshot_binding,
                records=records,
                descriptor_device=int(descriptor_info.st_dev),
                descriptor_inode=int(descriptor_info.st_ino),
            )
            if not snapshot._matches(current):
                raise _error(
                    "transaction_journal_live_snapshot_stale"
                )

    def mint_recovered_adoption_evidence(self) -> dict[str, Any]:
        """Derive recovered-adoption evidence from the exact live disk head.

        This zero-input operation accepts no caller-authored journal records
        or reconciliation sidecar.  Its authority comes only from this
        session's live descriptor, the store's exclusive lock, and the full
        journal-v5 transition grammar.  Production activation remains
        disabled; downstream verification and publication do not consume
        this evidence yet.
        """

        if type(self) is not TransactionJournalSession:
            raise _error(
                "transaction_journal_"
                "recovered_adoption_evidence_session_required"
            )
        with self._operation_lock:
            self._require_active()
            if (
                self._active_operation_lease is not None
                or self._active_recovered_adoption_ack_operation
                is not None
                or self._active_recovered_verifier_operation
                is not None
            ):
                raise _error(
                    "transaction_journal_"
                    "recovered_adoption_evidence_operation_reserved"
                )
            if self._recovery_required:
                raise _error(
                    "transaction_journal_lifecycle_recovery_required"
                )

            records, _descriptor_info = self._scan_live_snapshot()
            _validate_history(
                records,
                expected_session_id=self._session_id,
            )
            head = records[-1]
            if head.state != "adoption_reconciled":
                raise _error(
                    "transaction_journal_"
                    "recovered_adoption_evidence_head_state_invalid"
                )

            embedded_receipt = head.details[
                "adoption_reconciliation_receipt"
            ]
            receipt = normalize_adoption_reconciliation_receipt(
                embedded_receipt
            )
            if receipt != embedded_receipt:
                raise _error(
                    "transaction_journal_"
                    "recovered_adoption_evidence_receipt_not_normalized"
                )
            if receipt["result"] != "recovered_adoption":
                raise _error(
                    "transaction_journal_"
                    "recovered_adoption_evidence_result_invalid"
                )

            canonical_records = tuple(
                record.to_dict() for record in records
            )
            try:
                validated_history = (
                    recovered_adoption_evidence
                    ._mint_validated_recovered_adoption_history_v5(
                        canonical_records
                    )
                )
                evidence = (
                    recovered_adoption_evidence
                    .bind_recovered_adoption_evidence(
                        validated_history=validated_history,
                        adoption_reconciliation_receipt=receipt,
                    )
                )
                (
                    recovered_adoption_evidence
                    .recovered_adoption_evidence_sha256(evidence)
                )
            except (
                recovered_adoption_evidence
                .RecoveredAdoptionEvidenceError
            ) as exc:
                raise _error(exc.code) from exc
            return evidence

    def _mint_recovered_adoption_context_from_records(
        self,
        records: tuple[TransactionJournalRecord, ...],
    ) -> RecoveredAdoptionJournalContext:
        if not records:
            raise _error(
                "transaction_journal_"
                "recovered_adoption_context_head_state_invalid"
            )
        head = records[-1]
        if head.state == "adoption_reconciled":
            reconciled_prefix = records
            artifacts = _derive_recovered_adoption_artifacts(
                reconciled_prefix
            )
            journal_binding = artifacts[
                "pre_ack_recovered_adoption_lease_binding"
            ]
        elif head.state == "staging_tombstone_acked":
            if len(records) < 2:
                raise _error(
                    "transaction_journal_"
                    "recovered_adoption_context_ack_successor_invalid"
                )
            predecessor = records[-2]
            continuation = head.details.get(
                "recovered_adoption_continuation"
            )
            if (
                predecessor.state != "adoption_reconciled"
                or head.revision != predecessor.revision + 1
                or continuation is None
            ):
                raise _error(
                    "transaction_journal_"
                    "recovered_adoption_context_ack_successor_invalid"
                )
            reconciled_prefix = records[:-1]
            artifacts = _derive_recovered_adoption_artifacts(
                reconciled_prefix
            )
            if continuation != artifacts["continuation"]:
                raise _error(
                    "transaction_journal_"
                    "recovered_adoption_context_continuation_changed"
                )
            journal_binding = (
                _post_ack_recovered_adoption_journal_binding(
                    artifacts, head
                )
            )
        else:
            raise _error(
                "transaction_journal_"
                "recovered_adoption_context_head_state_invalid"
            )
        return RecoveredAdoptionJournalContext(
            _token=_RECOVERED_ADOPTION_CONTEXT_TOKEN,
            session=self,
            session_binding=self._live_snapshot_binding,
            evidence=artifacts["evidence"],
            result=artifacts["result"],
            provenance=artifacts["provenance"],
            journal_binding=journal_binding,
            continuation=artifacts["continuation"],
        )

    def mint_recovered_adoption_journal_context(
        self,
    ) -> RecoveredAdoptionJournalContext:
        """Mint claims only from an exact reconciled or enriched-ACK head."""

        if type(self) is not TransactionJournalSession:
            raise _error(
                "transaction_journal_"
                "recovered_adoption_context_session_required"
            )
        with self._operation_lock:
            self._require_active()
            if (
                self._active_operation_lease is not None
                or self._active_recovered_adoption_ack_operation
                is not None
                or self._active_recovered_verifier_operation
                is not None
            ):
                raise _error(
                    "transaction_journal_"
                    "recovered_adoption_context_operation_reserved"
                )
            if self._recovery_required:
                raise _error(
                    "transaction_journal_lifecycle_recovery_required"
                )
            records, _descriptor_info = self._scan_live_snapshot()
            _validate_history(
                records,
                expected_session_id=self._session_id,
            )
            return self._mint_recovered_adoption_context_from_records(
                records
            )

    def begin_recovered_adoption_tombstone_ack(
        self,
    ) -> RecoveredAdoptionTombstoneAckOperation:
        """Reserve the exact recovered head for one descriptor-bound ACK."""

        if type(self) is not TransactionJournalSession:
            raise _error(
                "transaction_journal_"
                "recovered_adoption_ack_session_required"
            )
        with self._operation_lock:
            self._require_active()
            if (
                self._active_operation_lease is not None
                or self._active_recovered_adoption_ack_operation
                is not None
                or self._active_recovered_verifier_operation
                is not None
            ):
                raise _error(
                    "transaction_journal_"
                    "recovered_adoption_ack_already_reserved"
                )
            if self._recovery_required:
                raise _error(
                    "transaction_journal_lifecycle_recovery_required"
                )
            records, _descriptor_info = self._scan_live_snapshot()
            _validate_history(
                records,
                expected_session_id=self._session_id,
            )
            if records[-1].state != "adoption_reconciled":
                raise _error(
                    "transaction_journal_"
                    "recovered_adoption_ack_head_state_invalid"
                )
            context = (
                self._mint_recovered_adoption_context_from_records(
                    records
                )
            )
            operation = RecoveredAdoptionTombstoneAckOperation(
                _token=_RECOVERED_ADOPTION_ACK_OPERATION_TOKEN,
                session=self,
                session_binding=self._live_snapshot_binding,
                context=context,
            )
            self._active_recovered_adoption_ack_operation = (
                operation
            )
            return operation

    def _require_current_recovered_adoption_ack_operation(
        self,
        operation: Any,
    ) -> RecoveredAdoptionTombstoneAckOperation:
        if (
            type(operation)
            is not RecoveredAdoptionTombstoneAckOperation
            or self._active_recovered_adoption_ack_operation
            is not operation
        ):
            raise _error(
                "transaction_journal_"
                "recovered_adoption_ack_operation_invalid"
            )
        bound_session, session_binding, _context = (
            operation._contents()
        )
        if (
            bound_session is not self
            or session_binding is not self._live_snapshot_binding
        ):
            raise _error(
                "transaction_journal_"
                "recovered_adoption_ack_operation_session_mismatch"
            )
        return operation

    def _cancel_recovered_adoption_tombstone_ack(
        self,
        operation: Any,
    ) -> None:
        with self._operation_lock:
            selected = (
                self._require_current_recovered_adoption_ack_operation(
                    operation
                )
            )
            selected._set_state("open", "cancelled")
            self._active_recovered_adoption_ack_operation = None

    def _commit_recovered_adoption_tombstone_ack(
        self,
        operation: Any,
        control: Any,
    ) -> RecoveredAdoptionContinuationClearance:
        # Keep this import local: staging owns the installed root descriptor
        # and deliberately has no dependency on the outer journal.
        from qualification_attestor import (
            john_lomein_persona_qualification_capture_staging
            as capture_staging,
        )

        with self._operation_lock:
            selected = (
                self._require_current_recovered_adoption_ack_operation(
                    operation
                )
            )
            if (
                type(control)
                is not capture_staging.InstalledCaptureStagingControl
            ):
                raise _error(
                    "transaction_journal_"
                    "installed_capture_staging_control_required"
                )
            (
                _bound_session,
                _session_binding,
                context,
            ) = selected._contents()
            (
                _evidence,
                _result,
                _provenance,
                pre_ack_binding,
                continuation,
            ) = context._contents_for_session(
                self, self._live_snapshot_binding
            )
            records = self._records
            reconciled = records[-1]
            if (
                reconciled.state != "adoption_reconciled"
                or reconciled.record_sha256
                != pre_ack_binding[
                    "transaction_journal_head_record_sha256"
                ]
                or reconciled.revision
                != pre_ack_binding[
                    "transaction_journal_head_revision"
                ]
            ):
                raise _error(
                    "transaction_journal_"
                    "recovered_adoption_ack_head_changed"
                )
            pending_records = tuple(
                record
                for record in records
                if record.state
                == "staging_tombstone_ack_pending"
            )
            staging_intents = tuple(
                record
                for record in records
                if record.state == "staging_create_intent"
            )
            scope_empty_records = tuple(
                record
                for record in records
                if record.state == "lifecycle_scope_empty"
            )
            if (
                len(pending_records) != 1
                or len(staging_intents) != 1
                or len(scope_empty_records) != 1
            ):
                raise _error(
                    "transaction_journal_"
                    "recovered_adoption_ack_history_invalid"
                )
            pending_record = pending_records[0]
            pending = pending_record.details
            if (
                pending["terminal_disposition"] != "absent"
                or pending[
                    "staging_quarantine_intent_record_sha256"
                ]
                is not None
            ):
                raise _error(
                    "transaction_journal_"
                    "recovered_adoption_ack_disposition_invalid"
                )
            selected._set_state("open", "committing")
            try:
                acknowledgement = (
                    control._acknowledge_recovered_adoption_tombstone(
                        _token=(
                            capture_staging
                            ._RECOVERED_ADOPTION_ACK_CALL_TOKEN
                        ),
                        session_id=self._session_id,
                        staging_transaction_intent_sha256=(
                            staging_intents[0].record_sha256
                        ),
                        terminal_receipt=pending[
                            "terminal_receipt"
                        ],
                        outer_ack_pending_record_sha256=(
                            pending_record.record_sha256
                        ),
                        outer_quarantine_intent_record_sha256=None,
                        outer_lifecycle_clearance_record_sha256=(
                            scope_empty_records[0].record_sha256
                        ),
                    )
                )
            except capture_staging.CaptureStagingError as exc:
                selected._set_state("committing", "failed")
                self._active_recovered_adoption_ack_operation = None
                raise _error(exc.code) from exc
            except BaseException:
                # The staging control is one-shot and closes its retained
                # descriptor on every escape.  Its ACK is idempotent, while
                # no outer candidate exists yet, so release this reservation
                # and preserve the original BaseException identity.
                selected._set_state("committing", "failed")
                self._active_recovered_adoption_ack_operation = None
                raise
            old_digests = tuple(
                record.record_sha256 for record in self._records
            )
            candidate: TransactionJournalRecord | None = None
            try:
                normalized_ack = (
                    normalize_staging_tombstone_ack_receipt(
                        acknowledgement
                    )
                )
                ack_digest = (
                    staging_tombstone_ack_receipt_sha256(
                        normalized_ack
                    )
                )
                candidate = self._prepare_candidate(
                    next_state="staging_tombstone_acked",
                    details={
                        "from_state": "adoption_reconciled",
                        "terminal_disposition": "absent",
                        "terminal_receipt_sha256": pending[
                            "terminal_receipt_sha256"
                        ],
                        "tombstone_sha256": pending[
                            "tombstone_sha256"
                        ],
                        "outer_ack_pending_record_sha256": (
                            pending_record.record_sha256
                        ),
                        (
                            "adoption_reconciliation_"
                            "record_sha256"
                        ): reconciled.record_sha256,
                        (
                            "adoption_reconciliation_"
                            "receipt_sha256"
                        ): reconciled.details[
                            (
                                "adoption_reconciliation_"
                                "receipt_sha256"
                            )
                        ],
                        "tombstone_ack_receipt": normalized_ack,
                        "tombstone_ack_receipt_sha256": ack_digest,
                        "recovered_adoption_continuation": (
                            continuation
                        ),
                    },
                    recorded_at_unix=max(
                        reconciled.recorded_at_unix,
                        int(time.time()),
                    ),
                    _lifecycle_authorization=(
                        _RECOVERED_ADOPTION_ACK_SUCCESSOR_TOKEN
                    ),
                )
                committed = self._commit_candidate(
                    candidate,
                    fault_hook=None,
                    _lifecycle_authorization=(
                        _RECOVERED_ADOPTION_ACK_SUCCESSOR_TOKEN
                    ),
                )
                readback = self._store._scan_session(
                    self._directory_name,
                    self._require_active(),
                    clean_stale_temps=False,
                )
                if (
                    tuple(
                        record.record_sha256
                        for record in readback
                    )
                    != tuple(
                        record.record_sha256
                        for record in self._records
                    )
                    or readback[-1].to_dict()
                    != committed.to_dict()
                ):
                    raise _error(
                        "transaction_journal_"
                        "recovered_adoption_ack_readback_changed"
                    )
            except BaseException as commit_error:
                try:
                    observed = self._store._scan_session(
                        self._directory_name,
                        self._require_active(),
                        clean_stale_temps=False,
                    )
                    observed_digests = tuple(
                        record.record_sha256
                        for record in observed
                    )
                except BaseException:
                    observed = ()
                    observed_digests = ()
                candidate_digests = (
                    None
                    if candidate is None
                    else (*old_digests, candidate.record_sha256)
                )
                if (
                    candidate_digests is not None
                    and observed_digests == candidate_digests
                ):
                    try:
                        os.fsync(self._require_active())
                    except OSError:
                        selected._set_state(
                            "committing", "recovery_required"
                        )
                        self._recovery_required = True
                        self._active_recovered_adoption_ack_operation = (
                            None
                        )
                        raise commit_error
                    self._records = observed
                    committed = observed[-1]
                elif observed_digests == old_digests:
                    # The staging ACK may already be durable, but its
                    # descriptor-bound operation is idempotent.  No outer
                    # successor exists, so a fresh reserved operation and a
                    # fresh installed control can safely reconstruct it.
                    selected._set_state("committing", "failed")
                    self._active_recovered_adoption_ack_operation = (
                        None
                    )
                    raise commit_error
                else:
                    selected._set_state(
                        "committing", "recovery_required"
                    )
                    self._recovery_required = True
                    self._active_recovered_adoption_ack_operation = (
                        None
                    )
                    raise _error(
                        "transaction_journal_"
                        "recovered_adoption_ack_commit_ambiguous"
                    ) from commit_error
            selected._set_state("committing", "committed")
            self._active_recovered_adoption_ack_operation = None
            post_context = (
                self._mint_recovered_adoption_context_from_records(
                    self._records
                )
            )
            return RecoveredAdoptionContinuationClearance(
                _token=_RECOVERED_ADOPTION_CLEARANCE_TOKEN,
                session=self,
                session_binding=self._live_snapshot_binding,
                record=committed,
                context=post_context,
            )

    def begin_recovered_verifier_source_evidence(
        self,
    ) -> RecoveredVerifierSourceEvidenceOperation:
        """Reserve the exact enriched ACK head for completed evidence."""

        if type(self) is not TransactionJournalSession:
            raise _error(
                "transaction_journal_recovered_verifier_"
                "session_required"
            )
        with self._operation_lock:
            self._require_active()
            if (
                self._active_operation_lease is not None
                or self._active_recovered_adoption_ack_operation
                is not None
                or self._active_recovered_verifier_operation
                is not None
            ):
                raise _error(
                    "transaction_journal_recovered_verifier_"
                    "operation_already_reserved"
                )
            if self._recovery_required:
                raise _error(
                    "transaction_journal_lifecycle_recovery_required"
                )
            records, _descriptor_info = self._scan_live_snapshot()
            _validate_history(
                records,
                expected_session_id=self._session_id,
            )
            head = records[-1]
            if (
                head.state != "staging_tombstone_acked"
                or "recovered_adoption_continuation"
                not in head.details
            ):
                raise _error(
                    "transaction_journal_recovered_verifier_"
                    "ack_head_state_invalid"
                )
            # This also proves the ACK is the immediate enriched successor
            # of one exact recovered reconciliation record.
            self._mint_recovered_adoption_context_from_records(
                records
            )
            operation = RecoveredVerifierSourceEvidenceOperation(
                _token=_RECOVERED_VERIFIER_OPERATION_TOKEN,
                session=self,
                session_binding=self._live_snapshot_binding,
                head_revision=head.revision,
                head_record_sha256=head.record_sha256,
            )
            self._active_recovered_verifier_operation = operation
            return operation

    def _require_current_recovered_verifier_operation(
        self,
        operation: Any,
    ) -> tuple[
        RecoveredVerifierSourceEvidenceOperation,
        int,
        str,
    ]:
        if (
            type(operation)
            is not RecoveredVerifierSourceEvidenceOperation
            or self._active_recovered_verifier_operation
            is not operation
        ):
            raise _error(
                "transaction_journal_recovered_verifier_"
                "operation_invalid"
            )
        (
            bound_session,
            session_binding,
            head_revision,
            head_record_sha256,
        ) = operation._contents()
        if (
            bound_session is not self
            or session_binding is not self._live_snapshot_binding
        ):
            raise _error(
                "transaction_journal_recovered_verifier_"
                "operation_session_mismatch"
            )
        return operation, head_revision, head_record_sha256

    def _mint_recovered_verifier_material(
        self,
        operation: Any,
        *,
        verifier_request_v5: Mapping[str, Any],
        verifier_output_v4: Mapping[str, Any],
        source_revalidation_receipt_v2: Mapping[str, Any],
        pre_verifier_recovered_adoption_lease_binding: (
            Mapping[str, Any]
        ),
        post_verifier_recovered_adoption_lease_binding: (
            Mapping[str, Any]
        ),
    ) -> RecoveredVerifierSourceEvidenceMaterial:
        with self._operation_lock:
            (
                selected,
                head_revision,
                head_record_sha256,
            ) = self._require_current_recovered_verifier_operation(
                operation
            )
            records, _descriptor_info = self._scan_live_snapshot()
            _validate_history(
                records,
                expected_session_id=self._session_id,
            )
            head = records[-1]
            if (
                head.state != "staging_tombstone_acked"
                or head.revision != head_revision
                or not hmac.compare_digest(
                    head.record_sha256, head_record_sha256
                )
            ):
                raise _error(
                    "transaction_journal_recovered_verifier_"
                    "operation_head_changed"
                )
            context = (
                self._mint_recovered_adoption_context_from_records(
                    records
                )
            )
            (
                _recovered_evidence,
                result,
                provenance,
                post_ack_binding,
                continuation,
            ) = context._contents_for_session(
                self, self._live_snapshot_binding
            )
            envelope = (
                _build_recovered_verifier_source_evidence_envelope(
                    verifier_request_v5=verifier_request_v5,
                    verifier_output_v4=verifier_output_v4,
                    source_revalidation_receipt_v2=(
                        source_revalidation_receipt_v2
                    ),
                    pre_verifier_recovered_adoption_lease_binding=(
                        pre_verifier_recovered_adoption_lease_binding
                    ),
                    post_verifier_recovered_adoption_lease_binding=(
                        post_verifier_recovered_adoption_lease_binding
                    ),
                    expected_capture_adoption_result=result,
                    expected_capture_adoption_provenance=provenance,
                    expected_post_ack_binding=post_ack_binding,
                    recovered_adoption_continuation=continuation,
                    staging_tombstone_acked_record_sha256=(
                        head.record_sha256
                    ),
                    staging_tombstone_acked_recorded_at_unix=(
                        head.recorded_at_unix
                    ),
                )
            )
            return RecoveredVerifierSourceEvidenceMaterial(
                _token=_RECOVERED_VERIFIER_MATERIAL_TOKEN,
                session=self,
                session_binding=self._live_snapshot_binding,
                operation=selected,
                head_record_sha256=head.record_sha256,
                envelope=envelope,
            )

    def _cancel_recovered_verifier_operation(
        self,
        operation: Any,
    ) -> None:
        with self._operation_lock:
            if type(operation) is not (
                RecoveredVerifierSourceEvidenceOperation
            ):
                raise _error(
                    "transaction_journal_recovered_verifier_"
                    "operation_invalid"
                )
            selected = operation
            (
                bound_session,
                session_binding,
                state,
            ) = selected._contents_for_cancellation()
            if (
                bound_session is not self
                or session_binding is not self._live_snapshot_binding
            ):
                raise _error(
                    "transaction_journal_recovered_verifier_"
                    "operation_session_mismatch"
                )
            active = self._active_recovered_verifier_operation
            if active is None:
                if state == "open":
                    selected._set_state("open", "cancelled")
                return
            if active is not selected:
                raise _error(
                    "transaction_journal_recovered_verifier_"
                    "operation_invalid"
                )
            try:
                if state == "open":
                    selected._set_state("open", "cancelled")
                self._release_cancelled_recovered_verifier_operation(
                    selected
                )
            except BaseException:
                if (
                    self._active_recovered_verifier_operation
                    is selected
                ):
                    self._active_recovered_verifier_operation = None
                raise

    def _release_cancelled_recovered_verifier_operation(
        self,
        operation: RecoveredVerifierSourceEvidenceOperation,
    ) -> None:
        """Release only the exact reservation selected for cancellation."""

        if self._active_recovered_verifier_operation is not operation:
            raise _error(
                "transaction_journal_recovered_verifier_"
                "cancel_release_operation_changed"
            )
        self._active_recovered_verifier_operation = None

    def _release_committed_recovered_verifier_operation(
        self,
        operation: RecoveredVerifierSourceEvidenceOperation,
    ) -> None:
        """Release the in-memory reservation after a proven durable append."""

        if self._active_recovered_verifier_operation is not operation:
            raise _error(
                "transaction_journal_recovered_verifier_"
                "commit_release_operation_changed"
            )
        self._active_recovered_verifier_operation = None

    def _reconcile_recovered_verifier_commit_finalization(
        self,
        *,
        operation: RecoveredVerifierSourceEvidenceOperation,
        expected_digests: tuple[str, ...],
    ) -> None:
        """Make a durable commit resumable after async finalization failure."""

        try:
            observed = self._store._scan_session(
                self._directory_name,
                self._require_active(),
                clean_stale_temps=False,
            )
            _validate_history(
                observed,
                expected_session_id=self._session_id,
            )
            observed_digests = tuple(
                record.record_sha256 for record in observed
            )
        except BaseException:
            self._recovery_required = True
            self._active_recovered_verifier_operation = None
            return
        if observed_digests != expected_digests:
            self._recovery_required = True
            self._active_recovered_verifier_operation = None
            return
        self._records = observed
        if self._active_recovered_verifier_operation is operation:
            self._active_recovered_verifier_operation = None

    def _reconcile_stale_recovered_verifier_reservation(
        self,
    ) -> None:
        """Clear only a finalizing operation with its exact durable successor."""

        operation = self._active_recovered_verifier_operation
        if operation is None:
            return
        try:
            (
                bound_session,
                session_binding,
                head_revision,
                head_record_sha256,
                expected_successor_record_sha256,
                _operation_state,
            ) = operation._contents_for_finalization()
        except TransactionJournalError:
            return
        if (
            bound_session is not self
            or session_binding is not self._live_snapshot_binding
        ):
            return
        records, _descriptor_info = self._scan_live_snapshot()
        _validate_history(
            records,
            expected_session_id=self._session_id,
        )
        head = records[-1]
        if (
            head.state != "verifier_output_bound"
            or head.revision != head_revision + 1
            or not hmac.compare_digest(
                head.record_sha256,
                expected_successor_record_sha256,
            )
        ):
            return
        envelope = normalize_recovered_verifier_source_evidence(
            head.details["recovered_verifier_source_evidence"]
        )
        if not hmac.compare_digest(
            envelope["staging_tombstone_acked_record_sha256"],
            head_record_sha256,
        ):
            return
        self._records = records
        self._active_recovered_verifier_operation = None

    def _recovered_verified_evidence_clearance(
        self,
        records: tuple[TransactionJournalRecord, ...],
    ) -> RecoveredVerifiedEvidenceV6Clearance:
        envelope, evidence = (
            _reconstruct_recovered_verified_evidence_v6(records)
        )
        evidence_sha256 = recovered_verified_evidence_v6_sha256(
            evidence,
            expected_evidence_uid=(
                evidence["observed_evidence_uid"]
            ),
            expected_verifier_output_sha256=(
                envelope["verifier_output_v4_sha256"]
            ),
        )
        return RecoveredVerifiedEvidenceV6Clearance(
            _token=_RECOVERED_VERIFIED_EVIDENCE_CLEARANCE_TOKEN,
            session=self,
            session_binding=self._live_snapshot_binding,
            head_record=records[-1],
            verified_evidence_v6_sha256=evidence_sha256,
        )

    def _commit_recovered_verifier_material(
        self,
        operation: Any,
        material: Any,
    ) -> RecoveredVerifiedEvidenceV6Clearance:
        with self._operation_lock:
            (
                selected,
                head_revision,
                head_record_sha256,
            ) = self._require_current_recovered_verifier_operation(
                operation
            )
            if type(material) is not (
                RecoveredVerifierSourceEvidenceMaterial
            ):
                raise _error(
                    "transaction_journal_recovered_verifier_"
                    "material_required"
                )
            envelope = material._contents_for_operation(
                self,
                self._live_snapshot_binding,
                selected,
                head_record_sha256,
            )
            records, _descriptor_info = self._scan_live_snapshot()
            _validate_history(
                records,
                expected_session_id=self._session_id,
            )
            head = records[-1]
            if (
                head.state != "staging_tombstone_acked"
                or head.revision != head_revision
                or not hmac.compare_digest(
                    head.record_sha256, head_record_sha256
                )
                or not hmac.compare_digest(
                    envelope[
                        "staging_tombstone_acked_record_sha256"
                    ],
                    head.record_sha256,
                )
            ):
                raise _error(
                    "transaction_journal_recovered_verifier_"
                    "operation_head_changed"
                )
            candidate = self._prepare_candidate(
                next_state="verifier_output_bound",
                details={
                    "verifier_output_sha256": (
                        envelope["verifier_output_v4_sha256"]
                    ),
                    "recovered_verifier_source_evidence": (
                        envelope
                    ),
                    (
                        "recovered_verifier_source_"
                        "evidence_sha256"
                    ): (
                        recovered_verifier_source_evidence_sha256(
                            envelope
                        )
                    ),
                },
                recorded_at_unix=envelope[
                    "source_revalidation_receipt_v2"
                ]["revalidated_at_unix"],
                _lifecycle_authorization=(
                    _RECOVERED_VERIFIER_SUCCESSOR_TOKEN
                ),
            )
            old_digests = tuple(
                record.record_sha256 for record in records
            )
            try:
                selected._begin_finalization(
                    candidate.record_sha256
                )
                self._commit_candidate(
                    candidate,
                    fault_hook=None,
                    _lifecycle_authorization=(
                        _RECOVERED_VERIFIER_SUCCESSOR_TOKEN
                    ),
                )
                observed = self._store._scan_session(
                    self._directory_name,
                    self._require_active(),
                    clean_stale_temps=False,
                )
                if tuple(
                    record.record_sha256 for record in observed
                ) != (*old_digests, candidate.record_sha256):
                    raise _error(
                        "transaction_journal_recovered_verifier_"
                        "commit_readback_changed"
                    )
                self._records = observed
            except BaseException as commit_error:
                try:
                    observed = self._store._scan_session(
                        self._directory_name,
                        self._require_active(),
                        clean_stale_temps=False,
                    )
                    observed_digests = tuple(
                        record.record_sha256
                        for record in observed
                    )
                except BaseException:
                    observed = ()
                    observed_digests = ()
                candidate_digests = (
                    *old_digests,
                    candidate.record_sha256,
                )
                if observed_digests == candidate_digests:
                    try:
                        os.fsync(self._require_active())
                    except OSError:
                        selected._set_state(
                            "committing", "recovery_required"
                        )
                        self._recovery_required = True
                        self._active_recovered_verifier_operation = (
                            None
                        )
                        raise commit_error
                    self._records = observed
                    if not isinstance(commit_error, Exception):
                        selected._set_state(
                            "committing", "interrupted_reconciled"
                        )
                        self._active_recovered_verifier_operation = (
                            None
                        )
                        raise commit_error
                elif observed_digests == old_digests:
                    selected._set_state(selected.state, "failed")
                    self._active_recovered_verifier_operation = None
                    raise commit_error
                else:
                    selected._set_state(
                        selected.state, "recovery_required"
                    )
                    self._recovery_required = True
                    self._active_recovered_verifier_operation = None
                    if not isinstance(commit_error, Exception):
                        raise commit_error
                    raise _error(
                        "transaction_journal_recovered_verifier_"
                        "commit_ambiguous"
                    ) from commit_error
            committed_digests = (
                *old_digests,
                candidate.record_sha256,
            )
            try:
                selected._set_state("committing", "committed")
                self._release_committed_recovered_verifier_operation(
                    selected
                )
            except BaseException:
                self._reconcile_recovered_verifier_commit_finalization(
                    operation=selected,
                    expected_digests=committed_digests,
                )
                raise
            return self._recovered_verified_evidence_clearance(
                self._records
            )

    def recover_recovered_verified_evidence_v6(
        self,
    ) -> RecoveredVerifiedEvidenceV6Clearance:
        """Reconstruct full v6 only from one exact durable projection head."""

        with self._operation_lock:
            self._require_active()
            self._reconcile_stale_recovered_verifier_reservation()
            if (
                self._active_operation_lease is not None
                or self._active_recovered_adoption_ack_operation
                is not None
                or self._active_recovered_verifier_operation
                is not None
            ):
                raise _error(
                    "transaction_journal_recovered_verifier_"
                    "operation_reserved"
                )
            if self._recovery_required:
                raise _error(
                    "transaction_journal_lifecycle_recovery_required"
                )
            records, _descriptor_info = self._scan_live_snapshot()
            _validate_history(
                records,
                expected_session_id=self._session_id,
            )
            self._records = records
            return self._recovered_verified_evidence_clearance(
                records
            )

    def advance_recovered_verifier_source_evidence(
        self,
    ) -> RecoveredVerifiedEvidenceV6Clearance:
        """Append one post-effect durability projection, or read complete.

        The full source-revalidation receipt was already validated under the
        ACK head and stored by ``verifier_output_bound``.  These legacy-named
        states do not bracket or perform that live effect.
        """

        with self._operation_lock:
            self._require_active()
            self._reconcile_stale_recovered_verifier_reservation()
            if (
                self._active_operation_lease is not None
                or self._active_recovered_adoption_ack_operation
                is not None
                or self._active_recovered_verifier_operation
                is not None
            ):
                raise _error(
                    "transaction_journal_recovered_verifier_"
                    "operation_reserved"
                )
            if self._recovery_required:
                raise _error(
                    "transaction_journal_lifecycle_recovery_required"
                )
            records, _descriptor_info = self._scan_live_snapshot()
            _validate_history(
                records,
                expected_session_id=self._session_id,
            )
            self._records = records
            head = records[-1]
            if head.state == "live_revalidation_receipt_complete":
                return self._recovered_verified_evidence_clearance(
                    records
                )
            envelope, _evidence = (
                _reconstruct_recovered_verified_evidence_v6(records)
            )
            envelope_sha256 = (
                recovered_verifier_source_evidence_sha256(envelope)
            )
            if head.state == "verifier_output_bound":
                next_state = "live_revalidation_started"
                details = {
                    "verifier_output_sha256": (
                        envelope["verifier_output_v4_sha256"]
                    ),
                    "recovered_verifier_source_evidence_sha256": (
                        envelope_sha256
                    ),
                    "staging_tombstone_acked_record_sha256": (
                        envelope[
                            "staging_tombstone_acked_record_sha256"
                        ]
                    ),
                    "state_semantics": (
                        RECOVERED_REVALIDATION_STATE_SEMANTICS
                    ),
                }
            elif head.state == "live_revalidation_started":
                next_state = "live_revalidation_receipt_complete"
                details = {
                    "verifier_output_sha256": (
                        envelope["verifier_output_v4_sha256"]
                    ),
                    "source_revalidation_receipt_sha256": (
                        envelope[
                            "source_revalidation_receipt_v2_sha256"
                        ]
                    ),
                    "recovered_verifier_source_evidence_sha256": (
                        envelope_sha256
                    ),
                    "staging_tombstone_acked_record_sha256": (
                        envelope[
                            "staging_tombstone_acked_record_sha256"
                        ]
                    ),
                    "verified_evidence_v6_sha256": (
                        envelope["verified_evidence_v6_sha256"]
                    ),
                    "state_semantics": (
                        RECOVERED_REVALIDATION_STATE_SEMANTICS
                    ),
                }
            else:
                raise _error(
                    "transaction_journal_recovered_verifier_"
                    "advance_head_state_invalid"
                )
            candidate = self._prepare_candidate(
                next_state=next_state,
                details=details,
                recorded_at_unix=head.recorded_at_unix,
                _lifecycle_authorization=(
                    _RECOVERED_VERIFIER_SUCCESSOR_TOKEN
                ),
            )
            old_digests = tuple(
                record.record_sha256 for record in records
            )
            try:
                self._commit_candidate(
                    candidate,
                    fault_hook=None,
                    _lifecycle_authorization=(
                        _RECOVERED_VERIFIER_SUCCESSOR_TOKEN
                    ),
                )
                observed = self._store._scan_session(
                    self._directory_name,
                    self._require_active(),
                    clean_stale_temps=False,
                )
                if tuple(
                    record.record_sha256 for record in observed
                ) != (*old_digests, candidate.record_sha256):
                    raise _error(
                        "transaction_journal_recovered_verifier_"
                        "advance_readback_changed"
                    )
                self._records = observed
            except BaseException as advance_error:
                try:
                    observed = self._store._scan_session(
                        self._directory_name,
                        self._require_active(),
                        clean_stale_temps=False,
                    )
                    observed_digests = tuple(
                        record.record_sha256
                        for record in observed
                    )
                except BaseException:
                    observed = ()
                    observed_digests = ()
                candidate_digests = (
                    *old_digests,
                    candidate.record_sha256,
                )
                if observed_digests == candidate_digests:
                    try:
                        os.fsync(self._require_active())
                    except OSError:
                        self._recovery_required = True
                        raise advance_error
                    self._records = observed
                    if not isinstance(advance_error, Exception):
                        raise advance_error
                elif observed_digests == old_digests:
                    raise advance_error
                else:
                    self._recovery_required = True
                    if not isinstance(advance_error, Exception):
                        raise advance_error
                    raise _error(
                        "transaction_journal_recovered_verifier_"
                        "advance_ambiguous"
                    ) from advance_error
            return self._recovered_verified_evidence_clearance(
                self._records
            )

    def _require_current_operation_lease(
        self,
        lease: Any,
    ) -> TransactionJournalOperationLease:
        if (
            type(lease) is not TransactionJournalOperationLease
            or not lease._is_bound_to(
                self, self._live_snapshot_binding
            )
            or self._active_operation_lease is not lease
        ):
            raise _error(
                "transaction_journal_lifecycle_operation_lease_invalid"
            )
        return lease

    def _begin_lifecycle_operation_for_client(
        self,
        *,
        operation: str,
        snapshot: TransactionJournalLiveSnapshot,
    ) -> TransactionJournalOperationLease:
        """Privately reserve an exact live head for the lifecycle client."""

        with self._operation_lock:
            self._require_active()
            if type(operation) is not str or (
                operation not in LIFECYCLE_OPERATIONS
            ):
                raise _error(
                    "transaction_journal_lifecycle_operation_invalid"
                )
            if operation == "prepare_clearance":
                raise _error(
                    "transaction_journal_"
                    "lifecycle_operation_client_operation_invalid"
                )
            if (
                self._active_operation_lease is not None
                or self._active_recovered_adoption_ack_operation
                is not None
                or self._active_recovered_verifier_operation
                is not None
            ):
                raise _error(
                    "transaction_journal_"
                    "lifecycle_operation_already_reserved"
                )
            if self._recovery_required and operation != "recover_scope":
                raise _error(
                    "transaction_journal_lifecycle_recovery_required"
                )
            self.assert_live_snapshot_current(snapshot)
            base = self._records[-1]
            if base.state not in _LIFECYCLE_OPERATION_BASE_STATES[
                operation
            ]:
                raise _error(
                    "transaction_journal_"
                    "lifecycle_operation_base_state_invalid"
                )
            lease = TransactionJournalOperationLease(
                _token=_OPERATION_LEASE_TOKEN,
                session=self,
                session_binding=self._live_snapshot_binding,
                operation=operation,
                base_revision=base.revision,
                base_record_sha256=base.record_sha256,
            )
            self._active_operation_lease = lease
            return lease

    def _begin_local_clearance_operation(
        self,
    ) -> TransactionJournalOperationLease:
        with self._operation_lock:
            self._require_active()
            if (
                self._active_operation_lease is not None
                or self._active_recovered_adoption_ack_operation
                is not None
                or self._active_recovered_verifier_operation
                is not None
            ):
                raise _error(
                    "transaction_journal_"
                    "lifecycle_operation_already_reserved"
                )
            if self._recovery_required:
                raise _error(
                    "transaction_journal_lifecycle_recovery_required"
                )
            base = self._records[-1]
            if base.state not in _LIFECYCLE_OPERATION_BASE_STATES[
                "prepare_clearance"
            ]:
                raise _error(
                    "transaction_journal_"
                    "lifecycle_operation_base_state_invalid"
                )
            lease = TransactionJournalOperationLease(
                _token=_OPERATION_LEASE_TOKEN,
                session=self,
                session_binding=self._live_snapshot_binding,
                operation="prepare_clearance",
                base_revision=base.revision,
                base_record_sha256=base.record_sha256,
            )
            self._active_operation_lease = lease
            return lease

    def _mark_lifecycle_operation_dispatched(
        self,
        lease: TransactionJournalOperationLease,
        request_sha256: str,
    ) -> None:
        with self._operation_lock:
            selected = self._require_current_operation_lease(lease)
            request_digest = _digest(
                request_sha256,
                field=(
                    "transaction_journal_"
                    "lifecycle_operation_request_sha256"
                ),
            )
            selected._set_request_sha256(request_digest)
            selected._set_state("open", "dispatched")

    def _cancel_lifecycle_operation_before_dispatch(
        self,
        lease: TransactionJournalOperationLease,
    ) -> None:
        with self._operation_lock:
            selected = self._require_current_operation_lease(lease)
            selected._set_state("open", "cancelled")
            self._active_operation_lease = None

    def _require_lifecycle_operation_recovery(
        self,
        lease: TransactionJournalOperationLease,
    ) -> None:
        with self._operation_lock:
            selected = self._require_current_operation_lease(lease)
            if selected.state not in {"open", "dispatched"}:
                raise _error(
                    "transaction_journal_lifecycle_operation_lease_spent"
                )
            selected._set_state(
                selected.state, "recovery_required"
            )
            self._recovery_required = True
            self._active_operation_lease = None

    def _validate_operation_binding_for_lease(
        self,
        lease: TransactionJournalOperationLease,
        value: Mapping[str, Any],
    ) -> dict[str, Any]:
        binding = normalize_lifecycle_operation_binding(value)
        if (
            binding["operation"] != lease.operation
            or binding["base_record_revision"]
            != lease.base_record_revision
            or binding["base_record_sha256"]
            != lease.base_record_sha256
        ):
            raise _error(
                "transaction_journal_"
                "lifecycle_operation_binding_lease_mismatch"
            )
        if lease.operation != "prepare_clearance" and (
            not lease._request_matches(binding["request_sha256"])
        ):
            raise _error(
                "transaction_journal_"
                "lifecycle_operation_request_digest_mismatch"
            )
        return binding

    def _complete_lifecycle_operation_no_effect(
        self,
        lease: TransactionJournalOperationLease,
        lifecycle_operation_binding: Mapping[str, Any],
        *,
        expected_outcome: str,
    ) -> None:
        with self._operation_lock:
            selected = self._require_current_operation_lease(lease)
            if selected.state != "dispatched":
                raise _error(
                    "transaction_journal_lifecycle_operation_lease_spent"
                )
            binding = self._validate_operation_binding_for_lease(
                selected, lifecycle_operation_binding
            )
            if binding["outcome"] != expected_outcome:
                raise _error(
                    "transaction_journal_"
                    "lifecycle_operation_no_effect_outcome_invalid"
                )
            if expected_outcome == "success" and (
                selected.operation != "recover_scope"
            ):
                raise _error(
                    "transaction_journal_"
                    "lifecycle_operation_no_effect_outcome_invalid"
                )
            selected._set_state("dispatched", "no_effect_complete")
            if selected.operation == "recover_scope":
                self._recovery_required = (
                    self._records[-1].state
                    == "operator_attention"
                )
            self._active_operation_lease = None

    def _mint_outer_successor_permit(
        self,
        lease: TransactionJournalOperationLease,
        *,
        next_state: str,
        details: Mapping[str, Any],
        lifecycle_operation_binding: Mapping[str, Any],
        recorded_at_unix: int,
    ) -> TransactionJournalOuterSuccessorPermit:
        with self._operation_lock:
            selected = self._require_current_operation_lease(lease)
            expected_lease_state = (
                "open"
                if selected.operation == "prepare_clearance"
                else "dispatched"
            )
            if selected.state != expected_lease_state:
                raise _error(
                    "transaction_journal_lifecycle_operation_lease_spent"
                )
            binding = self._validate_operation_binding_for_lease(
                selected, lifecycle_operation_binding
            )
            base_state = self._records[-1].state
            if next_state not in (
                _LIFECYCLE_OPERATION_SUCCESSORS_BY_BASE[
                    (selected.operation, base_state)
                ]
            ):
                raise _error(
                    "transaction_journal_"
                    "lifecycle_operation_successor_invalid"
                )
            selected_details = dict(details)
            selected_details["lifecycle_operation_binding"] = binding
            if next_state == "operator_attention":
                selected_details["from_state"] = self._records[-1].state
                selected_details["incident_sha256"] = (
                    lifecycle_operation_binding_sha256(binding)
                )
            candidate = self._prepare_candidate(
                next_state=next_state,
                details=selected_details,
                recorded_at_unix=recorded_at_unix,
                _lifecycle_authorization=_PERMIT_SUCCESSOR_TOKEN,
            )
            selected._set_state(
                expected_lease_state, "successor_permit_minted"
            )
            return TransactionJournalOuterSuccessorPermit(
                _token=_OUTER_SUCCESSOR_PERMIT_TOKEN,
                session=self,
                session_binding=self._live_snapshot_binding,
                lease=selected,
                candidate=candidate,
            )

    def _commit_outer_successor_permit(
        self,
        permit: Any,
    ) -> TransactionJournalRecord:
        with self._operation_lock:
            if type(permit) is not TransactionJournalOuterSuccessorPermit:
                raise _error(
                    "transaction_journal_outer_successor_permit_required"
                )
            (
                bound_session,
                session_binding,
                lease,
                candidate,
            ) = permit._contents()
            if (
                bound_session is not self
                or session_binding is not self._live_snapshot_binding
            ):
                raise _error(
                    "transaction_journal_"
                    "outer_successor_permit_session_mismatch"
                )
            selected = self._require_current_operation_lease(lease)
            if selected.state != "successor_permit_minted":
                raise _error(
                    "transaction_journal_outer_successor_permit_spent"
                )
            permit._spend()
            try:
                on_disk = self._store._scan_session(
                    self._directory_name,
                    self._require_active(),
                    clean_stale_temps=False,
                )
                if (
                    tuple(
                        record.record_sha256 for record in on_disk
                    )
                    != tuple(
                        record.record_sha256
                        for record in self._records
                    )
                    or not on_disk
                    or on_disk[-1].revision
                    != selected.base_record_revision
                    or on_disk[-1].record_sha256
                    != selected.base_record_sha256
                    or candidate.revision
                    != selected.base_record_revision + 1
                    or candidate.to_dict()["previous_record_sha256"]
                    != selected.base_record_sha256
                ):
                    raise _error(
                        "transaction_journal_"
                        "outer_successor_permit_stale_head"
                    )
                committed = self._commit_candidate(
                    candidate,
                    fault_hook=None,
                    _lifecycle_authorization=(
                        _PERMIT_SUCCESSOR_TOKEN
                    ),
                )
            except BaseException as commit_error:
                old_digests = tuple(
                    record.record_sha256 for record in self._records
                )
                candidate_digests = (
                    *old_digests,
                    candidate.record_sha256,
                )
                try:
                    observed = self._store._scan_session(
                        self._directory_name,
                        self._require_active(),
                        clean_stale_temps=False,
                    )
                    observed_digests = tuple(
                        record.record_sha256 for record in observed
                    )
                except BaseException:
                    observed = ()
                    observed_digests = ()
                if observed_digests == candidate_digests:
                    try:
                        os.fsync(self._require_active())
                    except OSError:
                        selected._set_state(
                            "successor_permit_minted",
                            "recovery_required",
                        )
                        self._recovery_required = True
                        self._active_operation_lease = None
                        raise commit_error
                    self._records = observed
                    selected._set_state(
                        "successor_permit_minted", "committed"
                    )
                    self._recovery_required = (
                        observed[-1].state == "operator_attention"
                    )
                    self._active_operation_lease = None
                    return observed[-1]
                selected._set_state(
                    "successor_permit_minted", "recovery_required"
                )
                self._recovery_required = True
                self._active_operation_lease = None
                if observed_digests != old_digests:
                    raise _error(
                        "transaction_journal_"
                        "outer_successor_commit_reconciliation_ambiguous"
                    ) from commit_error
                raise
            selected._set_state(
                "successor_permit_minted", "committed"
            )
            self._recovery_required = (
                committed.state == "operator_attention"
            )
            self._active_operation_lease = None
            return committed

    def append_event(
        self,
        *,
        expected_state: str,
        next_state: str,
        details: Mapping[str, Any],
        recorded_at_unix: int,
    ) -> TransactionJournalRecord:
        """Append exactly one validated state transition."""

        with self._operation_lock:
            return self._append_event(
                expected_state=expected_state,
                next_state=next_state,
                details=details,
                recorded_at_unix=recorded_at_unix,
                fault_hook=None,
                _lifecycle_authorization=None,
            )

    def begin_capture_recording(
        self,
        *,
        capture_uid: int,
        export_gid: int,
        retained_final_parent_fd: int,
        handoff_policy_sha256: str,
        recorded_at_unix: int,
    ) -> CaptureTransactionRecorder:
        """Durably authorize one exact staging create before any effect."""

        with self._operation_lock:
            if (
                type(retained_final_parent_fd) is not int
                or retained_final_parent_fd < 0
            ):
                raise _error(
                    "transaction_journal_final_parent_fd_invalid"
                )
            try:
                final_parent = os.fstat(retained_final_parent_fd)
                inheritable = os.get_inheritable(
                    retained_final_parent_fd
                )
            except OSError as exc:
                raise _error(
                    "transaction_journal_final_parent_fd_unreadable"
                ) from exc
            if (
                not stat.S_ISDIR(final_parent.st_mode)
                or inheritable
                or final_parent.st_dev < 0
            ):
                raise _error(
                    "transaction_journal_final_parent_fd_unsafe"
                )
            policy_digest = _digest(
                handoff_policy_sha256,
                field="transaction_journal_handoff_policy_sha256",
            )
            if not hmac.compare_digest(
                policy_digest, self._handoff_policy_sha256
            ):
                raise _error(
                    "transaction_journal_handoff_policy_mismatch"
                )
            session_id = self._session_id
            intent = self.append_event(
                expected_state="reserved",
                next_state="staging_create_intent",
                details={
                    "staging_leaf_name": f"session-{session_id}",
                    "capture_uid": capture_uid,
                    "export_gid": export_gid,
                    "required_device": int(final_parent.st_dev),
                },
                recorded_at_unix=recorded_at_unix,
            )
            return CaptureTransactionRecorder(
                _token=_CAPTURE_RECORDER_TOKEN,
                session=self,
                intent=intent,
            )

    def _append_event_for_test(
        self,
        *,
        expected_state: str,
        next_state: str,
        details: Mapping[str, Any],
        recorded_at_unix: int,
        fault_hook: Callable[[str], None],
    ) -> TransactionJournalRecord:
        if not callable(fault_hook):
            raise _error("transaction_journal_fault_hook_invalid")
        return self._append_event(
            expected_state=expected_state,
            next_state=next_state,
            details=details,
            recorded_at_unix=recorded_at_unix,
            fault_hook=fault_hook,
            _lifecycle_authorization=None,
        )

    def _append_event_for_history_validation_test(
        self,
        *,
        expected_state: str,
        next_state: str,
        details: Mapping[str, Any],
        recorded_at_unix: int,
        fault_hook: Callable[[str], None] | None = None,
    ) -> TransactionJournalRecord:
        """Private seam for constructing hostile/legacy disk histories."""

        with self._operation_lock:
            return self._append_event(
                expected_state=expected_state,
                next_state=next_state,
                details=details,
                recorded_at_unix=recorded_at_unix,
                fault_hook=fault_hook,
                _lifecycle_authorization=(
                    _HISTORY_VALIDATION_TEST_TOKEN
                ),
            )

    def _append_event(
        self,
        *,
        expected_state: str,
        next_state: str,
        details: Mapping[str, Any],
        recorded_at_unix: int,
        fault_hook: Callable[[str], None] | None,
        _lifecycle_authorization: object | None,
    ) -> TransactionJournalRecord:
        with self._operation_lock:
            descriptor = self._require_active()
            if (
                self._active_operation_lease is not None
                or self._active_recovered_adoption_ack_operation
                is not None
                or self._active_recovered_verifier_operation
                is not None
            ):
                raise _error(
                    "transaction_journal_"
                    "lifecycle_operation_already_reserved"
                )
            if (
                self._recovery_required
                and _lifecycle_authorization
                is not _HISTORY_VALIDATION_TEST_TOKEN
            ):
                raise _error(
                    "transaction_journal_lifecycle_recovery_required"
                )
            if expected_state not in STATE_SET:
                raise _error(
                    "transaction_journal_expected_state_invalid"
                )
            on_disk = self._store._scan_session(
                self._directory_name,
                descriptor,
                clean_stale_temps=False,
            )
            if tuple(
                record.record_sha256 for record in on_disk
            ) != tuple(
                record.record_sha256 for record in self._records
            ):
                raise _error("transaction_journal_session_changed")
            if not on_disk or on_disk[-1].state != expected_state:
                raise _error(
                    "transaction_journal_expected_state_mismatch"
                )
            return self._append(
                next_state=next_state,
                details=details,
                recorded_at_unix=recorded_at_unix,
                fault_hook=fault_hook,
                _lifecycle_authorization=(
                    _lifecycle_authorization
                ),
            )

    def _append(
        self,
        *,
        next_state: str,
        details: Mapping[str, Any],
        recorded_at_unix: int,
        fault_hook: Callable[[str], None] | None,
        _lifecycle_authorization: object | None = None,
    ) -> TransactionJournalRecord:
        with self._operation_lock:
            candidate = self._prepare_candidate(
                next_state=next_state,
                details=details,
                recorded_at_unix=recorded_at_unix,
                _lifecycle_authorization=(
                    _lifecycle_authorization
                ),
            )
            return self._commit_candidate(
                candidate,
                fault_hook=fault_hook,
                _lifecycle_authorization=(
                    _lifecycle_authorization
                ),
            )

    def _prepare_candidate(
        self,
        *,
        next_state: str,
        details: Mapping[str, Any],
        recorded_at_unix: int,
        _lifecycle_authorization: object | None = None,
    ) -> TransactionJournalRecord:
        self._require_active()
        if len(self._records) >= MAX_EVENTS_PER_SESSION:
            raise _error("transaction_journal_event_limit_exceeded")
        previous = self._records[-1] if self._records else None
        previous_state = None if previous is None else previous.state
        if not _allowed_transition(previous_state, next_state):
            raise _error("transaction_journal_transition_invalid")
        normalized_details = _normalize_details(
            next_state,
            details,
            session_id=self._session_id,
        )
        lifecycle_attention = (
            next_state == "operator_attention"
            and previous_state
            in (
                LIFECYCLE_EFFECT_ORIGIN_STATES
                | {"lifecycle_clearance_intent"}
            )
        )
        timestamp = _integer(
            recorded_at_unix,
            field="transaction_journal_recorded_at_unix",
            minimum=1,
        )
        if previous is not None and timestamp < previous.recorded_at_unix:
            raise _error("transaction_journal_clock_rollback")
        record_value = _build_record(
            instance_slug=self._instance_slug,
            session_id=self._session_id,
            revision=len(self._records) + 1,
            previous_record_sha256=(
                ZERO_SHA256
                if previous is None
                else previous.record_sha256
            ),
            state=next_state,
            recorded_at_unix=timestamp,
            control_sha256=self._control_sha256,
            handoff_policy_sha256=self._handoff_policy_sha256,
            details=normalized_details,
        )
        candidate = TransactionJournalRecord(record_value)
        proposed = (*self._records, candidate)
        _validate_history(
            proposed,
            expected_session_id=self._session_id,
        )
        lifecycle_authorized = (
            _lifecycle_authorization is _PERMIT_SUCCESSOR_TOKEN
            or _lifecycle_authorization
            is _HISTORY_VALIDATION_TEST_TOKEN
        )
        if not lifecycle_authorized and (
            next_state in _SUPERVISOR_DERIVED_SUCCESSOR_STATES
            or next_state == "lifecycle_clearance_intent"
            or lifecycle_attention
        ):
            raise _error(
                "transaction_journal_"
                "lifecycle_operation_permit_required"
            )
        recovered_ack_candidate = (
            next_state == "staging_tombstone_acked"
            and "recovered_adoption_continuation"
            in normalized_details
        )
        recovered_ack_authorized = (
            _lifecycle_authorization
            is _RECOVERED_ADOPTION_ACK_SUCCESSOR_TOKEN
            or _lifecycle_authorization
            is _HISTORY_VALIDATION_TEST_TOKEN
        )
        if recovered_ack_candidate and not recovered_ack_authorized:
            raise _error(
                "transaction_journal_"
                "recovered_adoption_ack_operation_required"
            )
        recovered_verifier_candidate = (
            (
                next_state == "verifier_output_bound"
                and "recovered_verifier_source_evidence"
                in normalized_details
            )
            or (
                next_state
                in {
                    "live_revalidation_started",
                    "live_revalidation_receipt_complete",
                }
                and "recovered_verifier_source_evidence_sha256"
                in normalized_details
            )
        )
        recovered_verifier_authorized = (
            _lifecycle_authorization
            is _RECOVERED_VERIFIER_SUCCESSOR_TOKEN
            or _lifecycle_authorization
            is _HISTORY_VALIDATION_TEST_TOKEN
        )
        if (
            recovered_verifier_candidate
            and not recovered_verifier_authorized
        ):
            raise _error(
                "transaction_journal_recovered_verifier_"
                "operation_required"
            )
        return candidate

    def _commit_candidate(
        self,
        candidate: TransactionJournalRecord,
        *,
        fault_hook: Callable[[str], None] | None,
        _lifecycle_authorization: object | None = None,
    ) -> TransactionJournalRecord:
        descriptor = self._require_active()
        if type(candidate) is not TransactionJournalRecord:
            raise _error(
                "transaction_journal_record_candidate_invalid"
            )
        candidate_details = candidate.details
        protected_candidate = (
            candidate.state in _SUPERVISOR_DERIVED_SUCCESSOR_STATES
            or candidate.state == "lifecycle_clearance_intent"
            or (
                candidate.state == "operator_attention"
                and "lifecycle_operation_binding"
                in candidate_details
            )
        )
        lifecycle_authorized = (
            _lifecycle_authorization is _PERMIT_SUCCESSOR_TOKEN
            or _lifecycle_authorization
            is _HISTORY_VALIDATION_TEST_TOKEN
        )
        if protected_candidate and not lifecycle_authorized:
            raise _error(
                "transaction_journal_"
                "lifecycle_operation_permit_required"
            )
        recovered_ack_candidate = (
            candidate.state == "staging_tombstone_acked"
            and "recovered_adoption_continuation"
            in candidate_details
        )
        recovered_ack_authorized = (
            _lifecycle_authorization
            is _RECOVERED_ADOPTION_ACK_SUCCESSOR_TOKEN
            or _lifecycle_authorization
            is _HISTORY_VALIDATION_TEST_TOKEN
        )
        if recovered_ack_candidate and not recovered_ack_authorized:
            raise _error(
                "transaction_journal_"
                "recovered_adoption_ack_operation_required"
            )
        recovered_verifier_candidate = (
            (
                candidate.state == "verifier_output_bound"
                and "recovered_verifier_source_evidence"
                in candidate_details
            )
            or (
                candidate.state
                in {
                    "live_revalidation_started",
                    "live_revalidation_receipt_complete",
                }
                and "recovered_verifier_source_evidence_sha256"
                in candidate_details
            )
        )
        recovered_verifier_authorized = (
            _lifecycle_authorization
            is _RECOVERED_VERIFIER_SUCCESSOR_TOKEN
            or _lifecycle_authorization
            is _HISTORY_VALIDATION_TEST_TOKEN
        )
        if (
            recovered_verifier_candidate
            and not recovered_verifier_authorized
        ):
            raise _error(
                "transaction_journal_recovered_verifier_"
                "operation_required"
            )
        if (
            candidate.revision != len(self._records) + 1
            or candidate.to_dict()["previous_record_sha256"]
            != (
                ZERO_SHA256
                if not self._records
                else self._records[-1].record_sha256
            )
        ):
            raise _error(
                "transaction_journal_record_candidate_stale"
            )
        proposed = (*self._records, candidate)
        _validate_history(
            proposed,
            expected_session_id=self._session_id,
        )
        raw = _canonical_json(candidate.to_dict()) + b"\n"
        if len(raw) > MAX_RECORD_BYTES:
            raise _error("transaction_journal_record_too_large")
        temp_name = f".tmp-{secrets.token_hex(16)}"
        temp_fd = -1
        try:
            try:
                temp_fd = os.open(
                    temp_name,
                    _write_file_flags(),
                    TEMP_FILE_MODE,
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise _error(
                    "transaction_journal_temp_create_failed"
                ) from exc
            os.set_inheritable(temp_fd, False)
            _call_fault(fault_hook, "after_temp_open")
            _write_all(temp_fd, raw)
            _call_fault(fault_hook, "after_temp_write")
            try:
                os.fsync(temp_fd)
            except OSError as exc:
                raise _error(
                    "transaction_journal_record_fsync_failed"
                ) from exc
            _call_fault(fault_hook, "after_temp_file_fsync")
            try:
                os.fchmod(temp_fd, RECORD_FILE_MODE)
            except OSError as exc:
                raise _error(
                    "transaction_journal_record_chmod_failed"
                ) from exc
            _call_fault(fault_hook, "after_temp_chmod")
            try:
                os.fsync(temp_fd)
            except OSError as exc:
                raise _error(
                    "transaction_journal_record_metadata_fsync_failed"
                ) from exc
            _call_fault(fault_hook, "after_temp_metadata_fsync")
            _validate_regular_file(
                temp_fd,
                owner_uid=self._store._owner_uid,
                owner_gid=self._store._owner_gid,
                modes=frozenset({RECORD_FILE_MODE}),
                maximum_bytes=MAX_RECORD_BYTES,
                field="transaction_journal_temp_record",
            )
            _validate_named_fd_binding(
                descriptor,
                temp_name,
                temp_fd,
                directory=False,
                field="transaction_journal_temp_record",
            )
            _exclusive_rename(
                descriptor,
                temp_name,
                descriptor,
                _event_filename(candidate),
                destination_exists_code=(
                    "transaction_journal_record_revision_exists"
                ),
            )
            _call_fault(fault_hook, "after_noreplace_commit")
            try:
                os.fsync(descriptor)
            except OSError as exc:
                raise _error(
                    "transaction_journal_directory_fsync_failed"
                ) from exc
            _call_fault(
                fault_hook,
                "after_session_directory_fsync",
            )
        finally:
            if temp_fd >= 0:
                os.close(temp_fd)
        self._records = proposed
        return candidate

    def close(self) -> None:
        with self._operation_lock:
            if self._directory_fd >= 0:
                try:
                    os.close(self._directory_fd)
                finally:
                    self._directory_fd = -1

    def __enter__(self) -> TransactionJournalSession:
        self._require_active()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        del exc_type, exc, traceback
        self.close()
        return False

    def __reduce__(self) -> Any:
        raise TypeError("TransactionJournalSession is not serializable")

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError("TransactionJournalSession is not serializable")


class CaptureTransactionRecorder:
    """Narrow non-serializable capability for capture-side transitions."""

    __slots__ = ("__session", "__intent")

    def __init__(
        self,
        *,
        _token: object,
        session: TransactionJournalSession,
        intent: TransactionJournalRecord,
    ) -> None:
        if _token is not _CAPTURE_RECORDER_TOKEN:
            raise TypeError(
                "CaptureTransactionRecorder cannot be constructed directly"
            )
        if (
            type(session) is not TransactionJournalSession
            or type(intent) is not TransactionJournalRecord
            or intent.state != "staging_create_intent"
            or intent.record_sha256
            not in {
                record.record_sha256 for record in session.records
            }
        ):
            raise _error("transaction_journal_capture_recorder_invalid")
        self.__session = session
        self.__intent = intent

    @property
    def capture_session_id(self) -> str:
        return self.__session.session_id

    @property
    def staging_leaf_name(self) -> str:
        return self.__intent.details["staging_leaf_name"]

    @property
    def staging_transaction_intent_sha256(self) -> str:
        return self.__intent.record_sha256

    @property
    def capture_uid(self) -> int:
        return self.__intent.details["capture_uid"]

    @property
    def export_gid(self) -> int:
        return self.__intent.details["export_gid"]

    @property
    def required_device(self) -> int:
        return self.__intent.details["required_device"]

    def __record(
        self,
        *,
        expected_state: str,
        next_state: str,
        details: Mapping[str, Any],
        recorded_at_unix: int,
    ) -> TransactionJournalRecord:
        return self.__session.append_event(
            expected_state=expected_state,
            next_state=next_state,
            details=details,
            recorded_at_unix=recorded_at_unix,
        )

    def record_staging_exposed(
        self,
        receipt: Mapping[str, Any],
        *,
        receipt_sha256: str,
        recorded_at_unix: int,
    ) -> TransactionJournalRecord:
        return self.__record(
            expected_state="staging_create_intent",
            next_state="staging_exposed",
            details={
                "staging_exposure_receipt": receipt,
                "staging_exposure_receipt_sha256": receipt_sha256,
            },
            recorded_at_unix=recorded_at_unix,
        )

    def record_child_launch_intent(
        self,
        activation_receipt: Mapping[str, Any],
        *,
        activation_receipt_sha256: str,
        recorded_at_unix: int,
    ) -> TransactionJournalRecord:
        return self.__record(
            expected_state="staging_exposed",
            next_state="child_launch_intent",
            details={
                "lifecycle_activation_receipt": activation_receipt,
                "lifecycle_activation_receipt_sha256": (
                    activation_receipt_sha256
                ),
            },
            recorded_at_unix=recorded_at_unix,
        )

    def record_child_running(
        self,
        scope_started_receipt: Mapping[str, Any],
        *,
        scope_started_receipt_sha256: str,
        recorded_at_unix: int,
    ) -> TransactionJournalRecord:
        del scope_started_receipt
        del scope_started_receipt_sha256
        del recorded_at_unix
        raise _error(
            "transaction_journal_lifecycle_operation_permit_required"
        )

    def record_capture_ready(
        self,
        details: Mapping[str, Any],
        *,
        recorded_at_unix: int,
    ) -> TransactionJournalRecord:
        del details, recorded_at_unix
        raise _error(
            "transaction_journal_lifecycle_operation_permit_required"
        )

    def record_lifecycle_clearance_intent(
        self,
        *,
        effect_origin_state: str,
        effect_origin_record_sha256: str,
        scope_started_receipt_sha256: str | None,
        clearance_mode: str,
        recorded_at_unix: int,
    ) -> TransactionJournalRecord:
        effect_record = next(
            (
                record
                for record in self.__session.records
                if record.record_sha256
                == effect_origin_record_sha256
            ),
            None,
        )
        if effect_record is None:
            raise _error(
                "transaction_journal_"
                "lifecycle_clearance_effect_origin_missing"
            )
        lease = self.__session._begin_local_clearance_operation()
        try:
            base = self.__session.latest_record
            inherited_head = None
            if "lifecycle_operation_binding" in base.details:
                inherited_head = base.details[
                    "lifecycle_operation_binding"
                ]["supervisor_ledger_head_sha256"]
            binding = {
                "schema_version": (
                    LIFECYCLE_OPERATION_BINDING_SCHEMA
                ),
                "operation": "prepare_clearance",
                "base_record_revision": base.revision,
                "base_record_sha256": base.record_sha256,
                "request_sha256": None,
                "response_sha256": None,
                "outcome": "local_intent",
                "error_code": None,
                "result_sha256": None,
                "supervisor_ledger_head_sha256": inherited_head,
                "supervisor_event_sequence": None,
                "supervisor_event": None,
                "supervisor_event_record_sha256": None,
                "supervisor_event_evidence_sha256": None,
            }
            permit = lease.mint_successor_permit(
                next_state="lifecycle_clearance_intent",
                details={
                    "effect_origin_state": effect_origin_state,
                    "effect_origin_record_revision": (
                        effect_record.revision
                    ),
                    "effect_origin_record_sha256": (
                        effect_origin_record_sha256
                    ),
                    "scope_started_receipt_sha256": (
                        scope_started_receipt_sha256
                    ),
                    "clearance_mode": clearance_mode,
                },
                lifecycle_operation_binding=binding,
                recorded_at_unix=recorded_at_unix,
            )
            return permit.commit()
        except BaseException:
            if lease.state == "open":
                lease.cancel_before_dispatch()
            raise

    def record_lifecycle_scope_empty(
        self,
        clearance_bundle: Mapping[str, Any],
        *,
        clearance_bundle_sha256: str,
        recorded_at_unix: int,
    ) -> TransactionJournalRecord:
        del clearance_bundle
        del clearance_bundle_sha256
        del recorded_at_unix
        raise _error(
            "transaction_journal_lifecycle_operation_permit_required"
        )

    def record_adoption_intent(
        self,
        details: Mapping[str, Any],
        *,
        recorded_at_unix: int,
    ) -> TransactionJournalRecord:
        return self.__record(
            expected_state="lifecycle_scope_empty",
            next_state="adoption_intent",
            details=details,
            recorded_at_unix=recorded_at_unix,
        )

    def record_adopted(
        self,
        details: Mapping[str, Any],
        *,
        recorded_at_unix: int,
    ) -> TransactionJournalRecord:
        return self.__record(
            expected_state="adoption_intent",
            next_state="adopted",
            details=details,
            recorded_at_unix=recorded_at_unix,
        )

    def __reduce__(self) -> Any:
        raise TypeError("CaptureTransactionRecorder is not serializable")

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError("CaptureTransactionRecorder is not serializable")


class TransactionJournalStore:
    """Exclusive root-owned transaction-journal store lease."""

    __slots__ = (
        "_store_path",
        "_store_fd",
        "_anchor_fd",
        "_completed_fd",
        "_lock_fd",
        "_owner_uid",
        "_owner_gid",
        "_sessions",
        "_operation_lock",
        "_owner_pid",
    )

    def __init__(
        self,
        *,
        _token: object,
        store_path: Path,
        store_fd: int,
        anchor_fd: int,
        completed_fd: int,
        lock_fd: int,
        owner_uid: int,
        owner_gid: int,
    ) -> None:
        if _token is not _STORE_TOKEN:
            raise TypeError(
                "TransactionJournalStore cannot be constructed directly"
            )
        for descriptor in (
            store_fd,
            anchor_fd,
            completed_fd,
            lock_fd,
        ):
            os.set_inheritable(descriptor, False)
        self._store_path = store_path
        self._store_fd = store_fd
        self._anchor_fd = anchor_fd
        self._completed_fd = completed_fd
        self._lock_fd = lock_fd
        self._owner_uid = owner_uid
        self._owner_gid = owner_gid
        self._sessions: list[TransactionJournalSession] = []
        self._operation_lock = threading.RLock()
        self._owner_pid = os.getpid()

    @property
    def active(self) -> bool:
        return (
            os.getpid() == self._owner_pid
            and self._store_fd >= 0
            and self._anchor_fd >= 0
            and self._completed_fd >= 0
            and self._lock_fd >= 0
        )

    @property
    def store_path(self) -> Path:
        self._require_active()
        return self._store_path

    def _require_active(self) -> int:
        if os.getpid() != self._owner_pid:
            raise _error(
                "transaction_journal_store_creator_process_mismatch"
            )
        if not self.active:
            raise _error("transaction_journal_store_closed")
        return self._store_fd

    def _open_session_directory(
        self,
        directory_name: str,
        *,
        parent_fd: int | None = None,
        field: str = "transaction_journal_session_directory",
    ) -> int:
        selected_parent_fd = (
            self._require_active()
            if parent_fd is None
            else parent_fd
        )
        try:
            descriptor = os.open(
                directory_name,
                _directory_flags(),
                dir_fd=selected_parent_fd,
            )
        except OSError as exc:
            raise _error(f"{field}_unreadable") from exc
        os.set_inheritable(descriptor, False)
        try:
            _validate_directory(
                descriptor,
                owner_uid=self._owner_uid,
                owner_gid=self._owner_gid,
                mode=SESSION_DIRECTORY_MODE,
                field=field,
            )
            _validate_named_fd_binding(
                selected_parent_fd,
                directory_name,
                descriptor,
                directory=True,
                field=field,
            )
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def _session_record_bytes(self, session_fd: int) -> int:
        entries = _bounded_entries(
            session_fd,
            maximum=MAX_EVENTS_PER_SESSION,
            field="transaction_journal_archive_session_inventory",
        )
        total = 0
        for name in entries:
            if EVENT_FILE_RE.fullmatch(name) is None:
                raise _error(
                    "transaction_journal_archive_session_entry_invalid"
                )
            try:
                info = os.stat(
                    name,
                    dir_fd=session_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise _error(
                    "transaction_journal_archive_session_unreadable"
                ) from exc
            total += info.st_size
            if total > MAX_COMPLETED_ARCHIVE_BYTES:
                raise _error(
                    "transaction_journal_completed_archive_too_large"
                )
        return total

    def _validate_completed_archive(self) -> tuple[int, int]:
        names = _bounded_entries(
            self._completed_fd,
            maximum=MAX_COMPLETED_SESSION_DIRECTORIES,
            field="transaction_journal_completed_archive_inventory",
        )
        total_bytes = 0
        for name in names:
            if SESSION_DIRECTORY_RE.fullmatch(name) is None:
                raise _error(
                    "transaction_journal_completed_archive_entry_invalid"
                )
            descriptor = self._open_session_directory(
                name,
                parent_fd=self._completed_fd,
                field=(
                    "transaction_journal_"
                    "completed_archive_session"
                ),
            )
            try:
                records = self._scan_session(
                    name,
                    descriptor,
                    clean_stale_temps=False,
                )
                if (
                    not records
                    or records[-1].state not in TERMINAL_STATES
                ):
                    raise _error(
                        "transaction_journal_"
                        "completed_archive_state_invalid"
                    )
                total_bytes += self._session_record_bytes(descriptor)
                if total_bytes > MAX_COMPLETED_ARCHIVE_BYTES:
                    raise _error(
                        "transaction_journal_"
                        "completed_archive_too_large"
                    )
            finally:
                os.close(descriptor)
        return len(names), total_bytes

    def _read_event(
        self,
        session_fd: int,
        name: str,
        *,
        expected_session_id: str,
    ) -> TransactionJournalRecord:
        match = EVENT_FILE_RE.fullmatch(name)
        if match is None or match.group(2) not in STATE_SET:
            raise _error(
                "transaction_journal_session_entry_invalid"
            )
        try:
            descriptor = os.open(
                name,
                _read_file_flags(),
                dir_fd=session_fd,
            )
        except OSError as exc:
            raise _error(
                "transaction_journal_record_unreadable"
            ) from exc
        os.set_inheritable(descriptor, False)
        try:
            before = _validate_regular_file(
                descriptor,
                owner_uid=self._owner_uid,
                owner_gid=self._owner_gid,
                modes=frozenset({RECORD_FILE_MODE}),
                maximum_bytes=MAX_RECORD_BYTES,
                field="transaction_journal_record",
            )
            _validate_named_fd_binding(
                session_fd,
                name,
                descriptor,
                directory=False,
                field="transaction_journal_record",
            )
            raw = _read_bounded(
                descriptor,
                expected_size=before.st_size,
                maximum=MAX_RECORD_BYTES,
            )
            after = os.fstat(descriptor)
            rebound = os.stat(
                name,
                dir_fd=session_fd,
                follow_symlinks=False,
            )
            if (
                _full_stat_tuple(before) != _full_stat_tuple(after)
                or _stable_object_tuple(after)
                != _stable_object_tuple(rebound)
            ):
                raise _error(
                    "transaction_journal_record_changed"
                )
        finally:
            os.close(descriptor)
        record = TransactionJournalRecord(
            _normalize_record(_decode_record(raw))
        )
        if (
            record.revision != int(match.group(1))
            or record.state != match.group(2)
            or record.record_sha256 != match.group(3)
            or record.to_dict()["session_id"] != expected_session_id
        ):
            raise _error(
                "transaction_journal_record_filename_mismatch"
            )
        return record

    def _validate_stale_temp(
        self,
        session_fd: int,
        name: str,
    ) -> int:
        if TEMP_FILE_RE.fullmatch(name) is None:
            raise _error(
                "transaction_journal_session_entry_invalid"
            )
        try:
            descriptor = os.open(
                name,
                _read_file_flags(),
                dir_fd=session_fd,
            )
        except OSError as exc:
            raise _error(
                "transaction_journal_stale_temp_unsafe"
            ) from exc
        os.set_inheritable(descriptor, False)
        try:
            _validate_regular_file(
                descriptor,
                owner_uid=self._owner_uid,
                owner_gid=self._owner_gid,
                modes=frozenset(
                    {TEMP_FILE_MODE, RECORD_FILE_MODE}
                ),
                maximum_bytes=MAX_RECORD_BYTES,
                field="transaction_journal_stale_temp",
            )
            _validate_named_fd_binding(
                session_fd,
                name,
                descriptor,
                directory=False,
                field="transaction_journal_stale_temp",
            )
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def _scan_session(
        self,
        directory_name: str,
        session_fd: int,
        *,
        clean_stale_temps: bool,
    ) -> tuple[TransactionJournalRecord, ...]:
        match = SESSION_DIRECTORY_RE.fullmatch(directory_name)
        if match is None:
            raise _error(
                "transaction_journal_session_directory_name_invalid"
            )
        expected_session_id = match.group(1)
        entries = _bounded_entries(
            session_fd,
            maximum=(
                MAX_EVENTS_PER_SESSION + MAX_STALE_TEMP_FILES
            ),
            field="transaction_journal_session_inventory",
        )
        event_names: list[str] = []
        temp_names: list[str] = []
        for name in entries:
            if EVENT_FILE_RE.fullmatch(name):
                event_names.append(name)
            elif TEMP_FILE_RE.fullmatch(name):
                temp_names.append(name)
            else:
                raise _error(
                    "transaction_journal_session_entry_invalid"
                )
        if len(event_names) > MAX_EVENTS_PER_SESSION:
            raise _error("transaction_journal_event_limit_exceeded")
        if len(temp_names) > MAX_STALE_TEMP_FILES:
            raise _error(
                "transaction_journal_stale_temp_limit_exceeded"
            )
        records = tuple(
            sorted(
                (
                    self._read_event(
                        session_fd,
                        name,
                        expected_session_id=expected_session_id,
                    )
                    for name in event_names
                ),
                key=lambda record: record.revision,
            )
        )
        if records:
            _validate_history(
                records,
                expected_session_id=expected_session_id,
            )
        if temp_names:
            descriptors: list[tuple[str, int]] = []
            try:
                for name in temp_names:
                    descriptors.append(
                        (
                            name,
                            self._validate_stale_temp(
                                session_fd, name
                            ),
                        )
                    )
                if clean_stale_temps:
                    for name, descriptor in descriptors:
                        _validate_named_fd_binding(
                            session_fd,
                            name,
                            descriptor,
                            directory=False,
                            field="transaction_journal_stale_temp",
                        )
                        try:
                            os.unlink(name, dir_fd=session_fd)
                        except OSError as exc:
                            raise _error(
                                "transaction_journal_"
                                "stale_temp_remove_failed"
                            ) from exc
                    try:
                        os.fsync(session_fd)
                    except OSError as exc:
                        raise _error(
                            "transaction_journal_"
                            "stale_temp_fsync_failed"
                        ) from exc
            finally:
                for _name, descriptor in descriptors:
                    os.close(descriptor)
        return records

    def _archive_terminal_session(
        self,
        directory_name: str,
        session_fd: int,
        records: tuple[TransactionJournalRecord, ...],
        *,
        completed_count: int,
        completed_bytes: int,
    ) -> None:
        if not records or records[-1].state not in TERMINAL_STATES:
            raise _error(
                "transaction_journal_archive_state_invalid"
            )
        source_bytes = self._session_record_bytes(session_fd)
        if (
            completed_count >= MAX_COMPLETED_SESSION_DIRECTORIES
            or completed_bytes + source_bytes
            > MAX_COMPLETED_ARCHIVE_BYTES
        ):
            raise _error(
                "transaction_journal_completed_archive_capacity_exceeded"
            )
        store_fd = self._require_active()
        _validate_named_fd_binding(
            store_fd,
            directory_name,
            session_fd,
            directory=True,
            field="transaction_journal_archive_source",
        )
        _validate_named_fd_binding(
            store_fd,
            ".completed",
            self._completed_fd,
            directory=True,
            field="transaction_journal_completed_directory",
        )
        _exclusive_rename(
            store_fd,
            directory_name,
            self._completed_fd,
            directory_name,
            destination_exists_code=(
                "transaction_journal_archive_destination_exists"
            ),
        )
        _validate_named_fd_binding(
            self._completed_fd,
            directory_name,
            session_fd,
            directory=True,
            field="transaction_journal_archive_destination",
        )
        try:
            os.fsync(self._completed_fd)
            os.fsync(store_fd)
        except OSError as exc:
            raise _error(
                "transaction_journal_archive_fsync_failed"
            ) from exc

    def _scan_store(
        self,
        *,
        create_leases: bool,
        reject_incomplete: bool = False,
        archive_terminal: bool = False,
    ) -> tuple[
        tuple[TransactionJournalSession, ...],
        int,
        int,
    ]:
        store_fd = self._require_active()
        completed_count, completed_bytes = (
            self._validate_completed_archive()
        )
        entries = _bounded_entries(
            store_fd,
            maximum=MAX_SESSION_DIRECTORIES + 2,
            field="transaction_journal_store_inventory",
        )
        if ".lock" not in entries:
            raise _error("transaction_journal_lock_file_missing")
        if ".completed" not in entries:
            raise _error(
                "transaction_journal_completed_directory_missing"
            )
        session_names = [
            name
            for name in entries
            if name not in {".lock", ".completed"}
        ]
        if len(session_names) > MAX_SESSION_DIRECTORIES:
            raise _error(
                "transaction_journal_session_directory_limit_exceeded"
            )
        for name in session_names:
            if SESSION_DIRECTORY_RE.fullmatch(name) is None:
                raise _error(
                    "transaction_journal_store_entry_invalid"
                )
        loaded: list[TransactionJournalSession] = []
        for name in sorted(session_names):
            descriptor = self._open_session_directory(name)
            keep_descriptor = False
            try:
                records = self._scan_session(
                    name,
                    descriptor,
                    clean_stale_temps=True,
                )
                if not records:
                    _validate_named_fd_binding(
                        store_fd,
                        name,
                        descriptor,
                        directory=True,
                        field="transaction_journal_empty_session",
                    )
                    try:
                        os.rmdir(name, dir_fd=store_fd)
                        os.fsync(store_fd)
                    except OSError as exc:
                        raise _error(
                            "transaction_journal_empty_session_remove_failed"
                        ) from exc
                    continue
                if (
                    archive_terminal
                    and records[-1].state in TERMINAL_STATES
                ):
                    self._archive_terminal_session(
                        name,
                        descriptor,
                        records,
                        completed_count=completed_count,
                        completed_bytes=completed_bytes,
                    )
                    completed_count += 1
                    completed_bytes += self._session_record_bytes(
                        descriptor
                    )
                    continue
                if (
                    reject_incomplete
                    and records[-1].state not in TERMINAL_STATES
                ):
                    raise _error(
                        "transaction_journal_incomplete_session_exists"
                    )
                if (
                    create_leases
                    and records[-1].state not in TERMINAL_STATES
                ):
                    first = records[0].to_dict()
                    session = TransactionJournalSession(
                        _token=_SESSION_TOKEN,
                        store=self,
                        directory_fd=descriptor,
                        directory_name=name,
                        records=records,
                        instance_slug=first["instance_slug"],
                        session_id=first["session_id"],
                        control_sha256=first["control_sha256"],
                        handoff_policy_sha256=first[
                            "handoff_policy_sha256"
                        ],
                        recovery_required=(
                            _history_requires_lifecycle_recovery(
                                records
                            )
                        ),
                    )
                    self._sessions.append(session)
                    loaded.append(session)
                    keep_descriptor = True
            finally:
                if not keep_descriptor:
                    os.close(descriptor)
        return tuple(loaded), completed_count, completed_bytes

    def reserve_session(
        self,
        *,
        instance_slug: str,
        control_sha256: str,
        handoff_policy_sha256: str,
        recorded_at_unix: int,
    ) -> TransactionJournalSession:
        """Create and durably reserve a root-generated session namespace."""

        with self._operation_lock:
            return self._reserve_session(
                instance_slug=instance_slug,
                control_sha256=control_sha256,
                handoff_policy_sha256=handoff_policy_sha256,
                recorded_at_unix=recorded_at_unix,
                selected_session_id=secrets.token_hex(32),
                fault_hook=None,
            )

    def _reserve_session_for_test(
        self,
        *,
        instance_slug: str,
        control_sha256: str,
        handoff_policy_sha256: str,
        recorded_at_unix: int,
        session_id: str,
        fault_hook: Callable[[str], None] | None = None,
    ) -> TransactionJournalSession:
        with self._operation_lock:
            if fault_hook is not None and not callable(fault_hook):
                raise _error(
                    "transaction_journal_fault_hook_invalid"
                )
            return self._reserve_session(
                instance_slug=instance_slug,
                control_sha256=control_sha256,
                handoff_policy_sha256=handoff_policy_sha256,
                recorded_at_unix=recorded_at_unix,
                selected_session_id=_session_id(session_id),
                fault_hook=fault_hook,
            )

    def _reserve_session(
        self,
        *,
        instance_slug: str,
        control_sha256: str,
        handoff_policy_sha256: str,
        recorded_at_unix: int,
        selected_session_id: str,
        fault_hook: Callable[[str], None] | None,
    ) -> TransactionJournalSession:
        store_fd = self._require_active()
        (
            _loaded,
            completed_count,
            completed_bytes,
        ) = self._scan_store(
            create_leases=False,
            reject_incomplete=True,
            archive_terminal=True,
        )
        if (
            completed_count >= MAX_COMPLETED_SESSION_DIRECTORIES
            or completed_bytes + MAX_SESSION_ARCHIVE_BYTES
            > MAX_COMPLETED_ARCHIVE_BYTES
        ):
            raise _error(
                "transaction_journal_completed_archive_admission_closed"
            )
        entries = _bounded_entries(
            store_fd,
            maximum=MAX_SESSION_DIRECTORIES + 2,
            field="transaction_journal_store_inventory",
        )
        active_count = sum(
            1 for name in entries if SESSION_DIRECTORY_RE.fullmatch(name)
        )
        if active_count >= MAX_SESSION_DIRECTORIES:
            raise _error(
                "transaction_journal_session_capacity_exceeded"
            )
        slug = _instance_slug(instance_slug)
        control_digest = _digest(
            control_sha256,
            field="transaction_journal_control_sha256",
        )
        handoff_digest = _digest(
            handoff_policy_sha256,
            field="transaction_journal_handoff_policy_sha256",
        )
        timestamp = _integer(
            recorded_at_unix,
            field="transaction_journal_recorded_at_unix",
            minimum=1,
        )
        selected_session_id = _session_id(selected_session_id)
        directory_name = f"session-{selected_session_id}"
        try:
            os.mkdir(
                directory_name,
                SESSION_DIRECTORY_MODE,
                dir_fd=store_fd,
            )
        except FileExistsError as exc:
            raise _error(
                "transaction_journal_session_exists"
            ) from exc
        except OSError as exc:
            raise _error(
                "transaction_journal_session_create_failed"
            ) from exc
        _call_fault(fault_hook, "after_session_mkdir")
        descriptor = self._open_session_directory(directory_name)
        session: TransactionJournalSession | None = None
        try:
            try:
                os.fsync(descriptor)
            except OSError as exc:
                raise _error(
                    "transaction_journal_new_session_fsync_failed"
                ) from exc
            _call_fault(
                fault_hook,
                "after_new_session_directory_fsync",
            )
            try:
                os.fsync(store_fd)
            except OSError as exc:
                raise _error(
                    "transaction_journal_store_fsync_failed"
                ) from exc
            _call_fault(
                fault_hook,
                "after_store_directory_fsync",
            )
            session = TransactionJournalSession(
                _token=_SESSION_TOKEN,
                store=self,
                directory_fd=descriptor,
                directory_name=directory_name,
                records=(),
                instance_slug=slug,
                session_id=selected_session_id,
                control_sha256=control_digest,
                handoff_policy_sha256=handoff_digest,
            )
            reserved = session._append(
                next_state="reserved",
                details={},
                recorded_at_unix=timestamp,
                fault_hook=fault_hook,
            )
            if reserved.state != "reserved":
                raise AssertionError("reservation state mismatch")
        except BaseException:
            if session is not None:
                session.close()
            else:
                os.close(descriptor)
            raise
        self._sessions.append(session)
        return session

    def load_incomplete_sessions(
        self,
    ) -> tuple[TransactionJournalSession, ...]:
        """Load all non-complete sessions after full-store validation.

        Pending quarantine and operator-attention sessions are returned.
        Safely quarantined, cleanup-complete, and operator-resolved histories
        are terminal and remain in the bounded validated archive tier.
        """

        with self._operation_lock:
            if any(session.active for session in self._sessions):
                raise _error(
                    "transaction_journal_sessions_already_open"
                )
            loaded, _completed_count, _completed_bytes = (
                self._scan_store(create_leases=True)
            )
            return loaded

    def close(self) -> None:
        with self._operation_lock:
            for session in reversed(self._sessions):
                session.close()
            self._sessions.clear()
            for field in (
                "_lock_fd",
                "_completed_fd",
                "_anchor_fd",
                "_store_fd",
            ):
                descriptor = getattr(self, field)
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    finally:
                        setattr(self, field, -1)

    def __enter__(self) -> TransactionJournalStore:
        self._require_active()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        del exc_type, exc, traceback
        self.close()
        return False

    def __reduce__(self) -> Any:
        raise TypeError("TransactionJournalStore is not serializable")

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError("TransactionJournalStore is not serializable")


def _open_transaction_store(
    store_path: Path | str,
    filesystem_anchor: Path | str,
    *,
    owner_uid: int,
    owner_gid: int,
    strict_parent_chain: bool,
) -> TransactionJournalStore:
    selected_store = _absolute_path(
        store_path,
        field="transaction_journal_store_path",
    )
    selected_anchor = _absolute_path(
        filesystem_anchor,
        field="transaction_journal_filesystem_anchor",
    )
    if strict_parent_chain:
        _validate_trusted_parent_chain(
            selected_store,
            owner_uid=owner_uid,
        )
        _validate_trusted_parent_chain(
            selected_anchor,
            owner_uid=owner_uid,
        )
    store_fd = -1
    anchor_fd = -1
    completed_fd = -1
    lock_fd = -1
    lease: TransactionJournalStore | None = None
    try:
        try:
            store_fd = os.open(selected_store, _directory_flags())
            anchor_fd = os.open(selected_anchor, _directory_flags())
        except OSError as exc:
            raise _error(
                "transaction_journal_store_unreadable"
            ) from exc
        store_info = _validate_directory(
            store_fd,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            mode=STORE_MODE,
            field="transaction_journal_store",
        )
        anchor_info = _validate_directory(
            anchor_fd,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            mode=None,
            field="transaction_journal_filesystem_anchor",
        )
        _validate_path_fd_binding(
            selected_store,
            store_fd,
            field="transaction_journal_store",
        )
        _validate_path_fd_binding(
            selected_anchor,
            anchor_fd,
            field="transaction_journal_filesystem_anchor",
        )
        if store_info.st_dev != anchor_info.st_dev:
            raise _error(
                "transaction_journal_cross_device_forbidden"
            )
        try:
            completed_fd = os.open(
                ".completed",
                _directory_flags(),
                dir_fd=store_fd,
            )
        except OSError as exc:
            raise _error(
                "transaction_journal_completed_directory_unreadable"
            ) from exc
        completed_info = _validate_directory(
            completed_fd,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            mode=COMPLETED_DIRECTORY_MODE,
            field="transaction_journal_completed_directory",
        )
        _validate_named_fd_binding(
            store_fd,
            ".completed",
            completed_fd,
            directory=True,
            field="transaction_journal_completed_directory",
        )
        if completed_info.st_dev != store_info.st_dev:
            raise _error(
                "transaction_journal_cross_device_forbidden"
            )
        try:
            lock_fd = os.open(
                ".lock",
                _lock_file_flags(),
                dir_fd=store_fd,
            )
        except OSError as exc:
            raise _error(
                "transaction_journal_lock_file_unreadable"
            ) from exc
        _validate_regular_file(
            lock_fd,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            modes=frozenset({LOCK_FILE_MODE}),
            maximum_bytes=0,
            field="transaction_journal_lock_file",
        )
        _validate_named_fd_binding(
            store_fd,
            ".lock",
            lock_fd,
            directory=False,
            field="transaction_journal_lock_file",
        )
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise _error("transaction_journal_store_busy") from exc
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise _error("transaction_journal_store_busy") from exc
            raise _error("transaction_journal_store_lock_failed") from exc
        _validate_named_fd_binding(
            store_fd,
            ".lock",
            lock_fd,
            directory=False,
            field="transaction_journal_lock_file",
        )
        lease = TransactionJournalStore(
            _token=_STORE_TOKEN,
            store_path=selected_store,
            store_fd=store_fd,
            anchor_fd=anchor_fd,
            completed_fd=completed_fd,
            lock_fd=lock_fd,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        store_fd = -1
        anchor_fd = -1
        completed_fd = -1
        lock_fd = -1
        lease._scan_store(create_leases=False)
        return lease
    except BaseException:
        if lease is not None:
            lease.close()
        raise
    finally:
        for descriptor in (
            lock_fd,
            completed_fd,
            anchor_fd,
            store_fd,
        ):
            if descriptor >= 0:
                os.close(descriptor)


def open_transaction_store(
    store_path: Path | str,
    filesystem_anchor: Path | str,
) -> TransactionJournalStore:
    """Open the production root-owned store and acquire its instance lock."""

    if os.geteuid() != 0:
        raise _error("transaction_journal_requires_root")
    return _open_transaction_store(
        store_path,
        filesystem_anchor,
        owner_uid=0,
        owner_gid=0,
        strict_parent_chain=True,
    )


def _open_transaction_store_for_test(
    store_path: Path | str,
    filesystem_anchor: Path | str,
) -> TransactionJournalStore:
    """Exercise the production filesystem contract as the test identity."""

    return _open_transaction_store(
        store_path,
        filesystem_anchor,
        owner_uid=os.geteuid(),
        owner_gid=os.getegid(),
        strict_parent_chain=False,
    )


__all__ = [
    "CAPTURE_STAGING_JOURNAL_SCHEMA",
    "CLEANUP_PHASES",
    "CLEANUP_RESULTS",
    "JOURNAL_RECORD_SCHEMA",
    "LIFECYCLE_CAPTURE_EVENT_EVIDENCE_SCHEMA",
    "LIFECYCLE_OPERATION_BINDING_FIELDS",
    "LIFECYCLE_OPERATION_BINDING_SCHEMA",
    "LIFECYCLE_OPERATION_OUTCOMES",
    "LIFECYCLE_OPERATIONS",
    "LIFECYCLE_SUPERVISOR_EVENTS",
    "MAX_EVENTS_PER_SESSION",
    "MAX_RECOVERED_VERIFIER_OUTPUT_BYTES",
    "MAX_RECORD_BYTES",
    "PRODUCTION_ACTIVATION",
    "RECOVERED_ADOPTION_CONTINUATION_FIELDS",
    "RECOVERED_ADOPTION_CONTINUATION_SCHEMA",
    "RECOVERED_ADOPTION_JOURNAL_BINDING_FIELDS",
    "RECOVERED_ADOPTION_JOURNAL_BINDING_SCHEMA",
    "RECOVERED_ADOPTION_LEASE_BINDING_V2_FIELDS",
    "RECOVERED_ADOPTION_LEASE_BINDING_V2_SCHEMA",
    "RECOVERED_REVALIDATION_STATE_SEMANTICS",
    "RECOVERED_VERIFIER_SOURCE_EVIDENCE_FIELDS",
    "RECOVERED_VERIFIER_SOURCE_EVIDENCE_SCHEMA",
    "STAGING_ABSENCE_RECEIPT_SCHEMA",
    "STAGING_ABSENCE_STATUS",
    "STAGING_EXPOSED_LEAF_MODE",
    "STAGING_EXPOSURE_JOURNAL_SEQUENCE",
    "STAGING_EXPOSURE_RECEIPT_FIELDS",
    "STAGING_EXPOSURE_RECEIPT_SCHEMA",
    "STAGING_EXPOSURE_STATUS",
    "STAGING_QUARANTINE_RECEIPT_SCHEMA",
    "STAGING_QUARANTINE_STATUS",
    "STAGING_TOMBSTONE_ACK_RECEIPT_SCHEMA",
    "STAGING_TOMBSTONE_ACK_STATUS",
    "STATES",
    "TERMINAL_STATES",
    "VERIFIED_EVIDENCE_V6_FIELDS",
    "VERIFIER_EVIDENCE_V4_FIELDS",
    "VERIFIER_OUTPUT_V4_FIELDS",
    "VERIFIER_OUTPUT_V4_SCHEMA",
    "VERIFIER_REQUEST_V5_FIELDS",
    "VERIFIER_REQUEST_V5_SCHEMA",
    "VERIFIER_V5_VERSION",
    "CaptureTransactionRecorder",
    "RecoveredAdoptionContinuationClearance",
    "RecoveredAdoptionJournalContext",
    "RecoveredAdoptionTombstoneAckOperation",
    "RecoveredVerifiedEvidenceV6Clearance",
    "RecoveredVerifierSourceEvidenceMaterial",
    "RecoveredVerifierSourceEvidenceOperation",
    "TransactionJournalError",
    "TransactionJournalLiveSnapshot",
    "TransactionJournalOperationLease",
    "TransactionJournalOuterSuccessorPermit",
    "TransactionJournalRecord",
    "TransactionJournalSession",
    "TransactionJournalStore",
    "adoption_reconciliation_receipt_sha256",
    "normalize_adoption_reconciliation_receipt",
    "normalize_lifecycle_operation_binding",
    "normalize_recovered_adoption_continuation",
    "normalize_recovered_adoption_journal_binding",
    "normalize_recovered_adoption_lease_binding_v2",
    "normalize_recovered_verified_evidence_v6",
    "normalize_recovered_verifier_source_evidence",
    "normalize_staging_absence_receipt",
    "normalize_staging_exposure_receipt",
    "normalize_staging_quarantine_receipt",
    "normalize_staging_tombstone_ack_receipt",
    "open_transaction_store",
    "recovered_adoption_continuation_sha256",
    "recovered_adoption_journal_binding_sha256",
    "recovered_adoption_lease_binding_v2_sha256",
    "recovered_verified_evidence_v6_sha256",
    "recovered_verifier_source_evidence_sha256",
    "lifecycle_operation_binding_sha256",
    "staging_absence_receipt_sha256",
    "staging_exposure_receipt_sha256",
    "staging_quarantine_receipt_sha256",
    "staging_tombstone_ack_receipt_sha256",
    "verifier_output_v4_sha256",
]
