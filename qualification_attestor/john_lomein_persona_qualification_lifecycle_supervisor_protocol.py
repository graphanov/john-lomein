#!/usr/bin/env python3
"""Bounded, authority-minimizing wire contract for lifecycle supervision.

The root lifecycle supervisor and its unprivileged client share this module,
but no lifecycle implementation.  The protocol carries content identities and
root-owned journal coordinates only.  It deliberately has no representation
for a process identifier, signal, path, executable, argument vector,
environment, or arbitrary command.

Peer credentials and socket ownership are transport properties and therefore
must be verified by the future client/daemon before using this protocol.  The
client and server nonces below bind that authenticated transport exchange to a
specific transcript; they are not a substitute for peer authentication.

Production remains disabled.  Activating the supervisor requires a new,
measured implementation route and must not be inferred from a valid frame.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import struct
from collections.abc import Mapping
from typing import Any

from qualification_attestor import (
    john_lomein_persona_qualification_lifecycle_receipts
    as lifecycle_receipts,
)


PRODUCTION_ACTIVATION = False

CLIENT_HELLO_SCHEMA = (
    "john-lomein.persona-qualification-lifecycle-supervisor-client-hello.v1"
)
SERVER_HELLO_SCHEMA = (
    "john-lomein.persona-qualification-lifecycle-supervisor-server-hello.v1"
)
REQUEST_SCHEMA = (
    "john-lomein.persona-qualification-lifecycle-supervisor-request.v1"
)
RESPONSE_SCHEMA = (
    "john-lomein.persona-qualification-lifecycle-supervisor-response.v3"
)
CAPTURE_EVENT_EVIDENCE_SCHEMA = (
    "john-lomein.persona-qualification-lifecycle-"
    "capture-event-evidence.v1"
)
SCOPE_INCARNATION_DERIVATION_SCHEMA = (
    "john-lomein.persona-qualification-lifecycle-scope-"
    "incarnation-derivation.v1"
)
SCOPE_START_AUTHORIZATION_SCHEMA = (
    "john-lomein.persona-qualification-lifecycle-scope-"
    "start-authorization.v1"
)

ACTIVATION_RECEIPT_SCHEMA = (
    lifecycle_receipts.ACTIVATION_RECEIPT_SCHEMA
)
SCOPE_STARTED_RECEIPT_SCHEMA = (
    lifecycle_receipts.SCOPE_STARTED_RECEIPT_SCHEMA
)
CLEARANCE_INTENT_RECEIPT_SCHEMA = (
    lifecycle_receipts.CLEARANCE_INTENT_RECEIPT_SCHEMA
)
SCOPE_EMPTY_RECEIPT_SCHEMA = (
    lifecycle_receipts.SCOPE_EMPTY_RECEIPT_SCHEMA
)
CLEARANCE_BUNDLE_SCHEMA = lifecycle_receipts.CLEARANCE_BUNDLE_SCHEMA

MAX_FRAME_BYTES = 64 * 1024
MAX_FRAMES_PER_FEED = 64
MAX_TIMEOUT_SECONDS = 900
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_IDENTITY = (1 << 31) - 1
ZERO_SHA256 = "0" * 64
LIFECYCLE_PROVIDERS = frozenset(
    provider
    for providers in lifecycle_receipts.PROVIDERS_BY_SYSTEM.values()
    for provider in providers
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
INSTANCE_SLUG_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$"
)
REQUEST_ID_RE = re.compile(r"^jlqreq-[0-9a-f]{32}$")
SCOPE_ID_RE = re.compile(
    r"^jlq-root_supervisor-([0-9a-f]{64})$"
)
ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

OPERATIONS = frozenset(
    {
        "get_activation",
        "start_scope",
        "await_capture_event",
        "request_clearance",
        "recover_scope",
    }
)
EFFECT_ORIGIN_STATES = frozenset(
    {"child_launch_intent", "child_running", "capture_ready"}
)
OUTER_RECORD_STATES = frozenset(
    {
        "child_launch_intent",
        "child_running",
        "capture_ready",
        "lifecycle_clearance_intent",
        "lifecycle_scope_empty",
        "operator_attention",
        "operator_resolved",
    }
)
CLEARANCE_MODES = frozenset(
    {
        "wait_clean_then_terminate_on_deadline",
        "terminate_and_clear",
    }
)
CAPTURE_EVENTS = frozenset(
    {
        "capture_ready",
        "child_exited",
        "capture_deadline_exceeded",
    }
)
RECOVERY_REASONS = frozenset(
    {
        "client_restart",
        "supervisor_restart",
        "host_reboot",
        "request_outcome_unknown",
    }
)
RECOVERY_STATES = frozenset(
    {
        "start_intent",
        "scope_started",
        "capture_event",
        "clearance_intent",
        "provider_observation",
        "settled_bundle",
    }
)

ERROR_OUTCOME_FINAL_NO_EFFECT = "final_no_effect"
ERROR_OUTCOME_RETRYABLE_NO_EFFECT = "retryable_no_effect"
ERROR_OUTCOME_RECOVER_SCOPE_REQUIRED = "recover_scope_required"
ERROR_OUTCOME_OPERATOR_ATTENTION_REQUIRED = (
    "operator_attention_required"
)
ERROR_OUTCOMES = frozenset(
    {
        ERROR_OUTCOME_FINAL_NO_EFFECT,
        ERROR_OUTCOME_RETRYABLE_NO_EFFECT,
        ERROR_OUTCOME_RECOVER_SCOPE_REQUIRED,
        ERROR_OUTCOME_OPERATOR_ATTENTION_REQUIRED,
    }
)

_F = frozenset({ERROR_OUTCOME_FINAL_NO_EFFECT})
_T = frozenset({ERROR_OUTCOME_RETRYABLE_NO_EFFECT})
_R = frozenset({ERROR_OUTCOME_RECOVER_SCOPE_REQUIRED})
_A = frozenset({ERROR_OUTCOME_OPERATOR_ATTENTION_REQUIRED})
_TR = _T | _R
_FR = _F | _R
_FA = _F | _A
_RA = _R | _A

# Error codes describe the failure observed by the supervisor.  Outcomes
# describe the only safe next action the client may take.  The same failure
# can therefore have different outcomes depending on whether the supervisor
# durably proved that no effect occurred.  This operation-specific table
# prevents a server from laundering an uncertain effect into a retry.
_ERROR_OUTCOMES_BY_OPERATION_CODE = {
    "get_activation": {
        "activation_mismatch": _F,
        "activation_unavailable": _T,
        "deadline_exceeded": _T,
        "instance_unknown": _F,
        "operation_unsupported": _F,
        "peer_unauthorized": _F,
        "production_disabled": _F,
        "provider_failure": _T,
        "provider_unavailable": _T,
        "replay_rejected": _F,
        "request_out_of_order": _F,
        "supervisor_restarting": _T,
    },
    "start_scope": {
        "activation_mismatch": _F,
        "activation_unavailable": _T,
        "deadline_exceeded": _TR,
        "instance_unknown": _F,
        "journal_binding_mismatch": _A,
        "operation_unsupported": _F,
        "peer_unauthorized": _F,
        "production_disabled": _F,
        "provider_failure": _R,
        "provider_unavailable": _TR,
        "recovery_attention_required": _A,
        "replay_rejected": _FR,
        "request_out_of_order": _F,
        "scope_incarnation_mismatch": _F,
        "scope_not_found": _R,
        "scope_state_conflict": _RA,
        "session_conflict": _RA,
        "supervisor_restarting": _TR,
    },
    "await_capture_event": {
        "activation_mismatch": _A,
        "activation_unavailable": _T,
        "deadline_exceeded": _TR,
        "instance_unknown": _A,
        "journal_binding_mismatch": _A,
        "operation_unsupported": _A,
        "peer_unauthorized": _A,
        "production_disabled": _A,
        "provider_failure": _R,
        "provider_unavailable": _TR,
        "recovery_attention_required": _A,
        "replay_rejected": _R,
        "request_out_of_order": _R,
        "scope_incarnation_mismatch": _A,
        "scope_not_found": _R,
        "scope_state_conflict": _RA,
        "session_conflict": _RA,
        "supervisor_restarting": _TR,
    },
    "request_clearance": {
        "activation_mismatch": _A,
        "activation_unavailable": _T,
        "deadline_exceeded": _TR,
        "instance_unknown": _A,
        "journal_binding_mismatch": _A,
        "operation_unsupported": _A,
        "peer_unauthorized": _A,
        "production_disabled": _A,
        "provider_failure": _R,
        "provider_unavailable": _TR,
        "recovery_attention_required": _A,
        "replay_rejected": _R,
        "request_out_of_order": _R,
        "scope_incarnation_mismatch": _A,
        "scope_not_found": _R,
        "scope_state_conflict": _RA,
        "session_conflict": _RA,
        "supervisor_restarting": _TR,
    },
    "recover_scope": {
        "activation_mismatch": _A,
        "activation_unavailable": _T,
        "deadline_exceeded": _TR,
        "instance_unknown": _A,
        "journal_binding_mismatch": _A,
        "operation_unsupported": _A,
        "peer_unauthorized": _A,
        "production_disabled": _A,
        "provider_failure": _R,
        "provider_unavailable": _TR,
        "recovery_attention_required": _A,
        "replay_rejected": _R,
        "request_out_of_order": _R,
        "scope_incarnation_mismatch": _A,
        "scope_not_found": _FA,
        "scope_state_conflict": _RA,
        "session_conflict": _RA,
        "supervisor_restarting": _TR,
    },
}
_REMOTE_ERROR_CODES = frozenset(
    code
    for outcomes_by_code in _ERROR_OUTCOMES_BY_OPERATION_CODE.values()
    for code in outcomes_by_code
)

# Exact field sets also keep future implementations from smuggling a richer
# process-control API through otherwise innocuous JSON.
CLIENT_HELLO_FIELDS = frozenset(
    {
        "schema_version",
        "message_type",
        "operation",
        "instance_slug",
        "request_id",
        "client_incarnation_id",
        "client_nonce",
        "expected_supervisor_policy_sha256",
        "expected_supervisor_bundle_sha256",
        "expected_helper_activation_policy_sha256",
        "expected_lifecycle_canary_sha256",
    }
)
SERVER_HELLO_FIELDS = frozenset(
    {
        "schema_version",
        "message_type",
        "operation",
        "status",
        "instance_slug",
        "request_id",
        "client_incarnation_id",
        "client_nonce",
        "client_hello_sha256",
        "server_nonce",
        "protocol_session_id",
        "supervisor_incarnation_id",
        "supervisor_epoch_id",
        "host_boot_id_sha256",
        "supervisor_policy_sha256",
        "supervisor_bundle_sha256",
        "helper_activation_policy_sha256",
        "lifecycle_canary_sha256",
        "activation_receipt_sha256",
        "production_activation",
    }
)
REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "message_type",
        "instance_slug",
        "protocol_session_id",
        "client_incarnation_id",
        "supervisor_incarnation_id",
        "client_nonce",
        "server_nonce",
        "server_hello_sha256",
        "supervisor_epoch_id",
        "host_boot_id_sha256",
        "request_id",
        "sequence",
        "operation",
        "payload",
    }
)
RESPONSE_FIELDS = frozenset(
    {
        "schema_version",
        "message_type",
        "instance_slug",
        "protocol_session_id",
        "client_incarnation_id",
        "supervisor_incarnation_id",
        "client_nonce",
        "server_nonce",
        "server_hello_sha256",
        "supervisor_epoch_id",
        "host_boot_id_sha256",
        "request_id",
        "sequence",
        "operation",
        "request_sha256",
        "status",
        "result",
        "error_code",
        "error_outcome",
        "observed_ledger_head_sha256",
    }
)

GET_ACTIVATION_FIELDS = frozenset(
    {
        "expected_activation_receipt_sha256",
        "expected_supervisor_policy_sha256",
        "expected_supervisor_bundle_sha256",
        "expected_helper_activation_policy_sha256",
        "expected_lifecycle_canary_sha256",
    }
)
START_SCOPE_FIELDS = frozenset(
    {
        "capture_session_id",
        "lifecycle_scope_id",
        "scope_incarnation_id",
        "child_launch_intent_record_revision",
        "child_launch_intent_record_sha256",
        "staging_transaction_intent_sha256",
        "staging_exposure_receipt_sha256",
        "handoff_policy_sha256",
        "helper_activation_policy_sha256",
        "lifecycle_provider",
        "capture_uid",
        "export_gid",
        "lifecycle_activation_receipt_sha256",
    }
)
AWAIT_CAPTURE_EVENT_FIELDS = frozenset(
    {
        "capture_session_id",
        "lifecycle_scope_id",
        "scope_incarnation_id",
        "scope_started_receipt_sha256",
        "child_launch_intent_record_sha256",
        "outer_journal_record_state",
        "outer_journal_record_revision",
        "outer_journal_record_sha256",
        "expected_ledger_head_sha256",
        "after_event_sequence",
        "timeout_seconds",
    }
)
REQUEST_CLEARANCE_FIELDS = frozenset(
    {
        "capture_session_id",
        "lifecycle_scope_id",
        "scope_incarnation_id",
        "lifecycle_activation_receipt_sha256",
        "child_launch_intent_record_sha256",
        "effect_origin_state",
        "effect_origin_record_revision",
        "effect_origin_record_sha256",
        "scope_started_receipt_sha256",
        "clearance_mode",
        "lifecycle_clearance_intent_record_revision",
        "lifecycle_clearance_intent_record_sha256",
        "expected_ledger_head_sha256",
        "timeout_seconds",
    }
)
RECOVER_SCOPE_FIELDS = frozenset(
    {
        "capture_session_id",
        "lifecycle_scope_id",
        "scope_incarnation_id",
        "lifecycle_activation_receipt_sha256",
        "child_launch_intent_record_revision",
        "child_launch_intent_record_sha256",
        "outer_journal_record_state",
        "outer_journal_record_revision",
        "outer_journal_record_sha256",
        "expected_scope_started_receipt_sha256",
        "expected_scope_start_authorization_sha256",
        "expected_effect_origin_state",
        "expected_effect_origin_record_revision",
        "expected_effect_origin_record_sha256",
        "expected_clearance_intent_record_revision",
        "expected_clearance_intent_record_sha256",
        "expected_clearance_mode",
        "expected_ledger_head_sha256",
        "recovery_reason",
    }
)

GET_ACTIVATION_RESULT_FIELDS = frozenset(
    {"activation_receipt", "activation_receipt_sha256"}
)
START_SCOPE_RESULT_FIELDS = frozenset(
    {
        "scope_started_receipt",
        "scope_started_receipt_sha256",
        "ledger_head_sha256",
    }
)
AWAIT_CAPTURE_EVENT_RESULT_FIELDS = frozenset(
    {
        "capture_session_id",
        "lifecycle_scope_id",
        "scope_incarnation_id",
        "scope_started_receipt_sha256",
        "event_sequence",
        "event",
        "event_record_sha256",
        "event_evidence_sha256",
        "ledger_head_sha256",
    }
)
REQUEST_CLEARANCE_RESULT_FIELDS = frozenset(
    {
        "clearance_bundle",
        "clearance_bundle_sha256",
        "ledger_head_sha256",
    }
)
RECOVER_SCOPE_RESULT_FIELDS = frozenset(
    {
        "recovery_state",
        "capture_session_id",
        "lifecycle_scope_id",
        "scope_incarnation_id",
        "ledger_head_sha256",
        "scope_started_receipt",
        "scope_started_receipt_sha256",
        "effect_origin_state",
        "effect_origin_record_revision",
        "effect_origin_record_sha256",
        "event_sequence",
        "event",
        "event_record_sha256",
        "event_evidence_sha256",
        "clearance_bundle",
        "clearance_bundle_sha256",
    }
)

CAPTURE_EVENT_EVIDENCE_FIELDS = frozenset(
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

FORBIDDEN_AUTHORITY_FIELD_PARTS = frozenset(
    {
        "argv",
        "command",
        "cwd",
        "env",
        "environment",
        "executable",
        "fd",
        "path",
        "pgid",
        "pid",
        "signal",
    }
)


class LifecycleSupervisorProtocolError(ValueError):
    """Stable, public-safe wire rejection."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _error(code: str) -> LifecycleSupervisorProtocolError:
    return LifecycleSupervisorProtocolError(code)


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise _error("lifecycle_supervisor_json_invalid") from exc


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _error("lifecycle_supervisor_json_duplicate_key")
        result[key] = value
    return result


def parse_canonical_json(raw: bytes) -> Any:
    if (
        not isinstance(raw, bytes)
        or not raw
        or len(raw) > MAX_FRAME_BYTES
        or b"\x00" in raw
    ):
        raise _error("lifecycle_supervisor_json_size_invalid")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite")
            ),
        )
    except LifecycleSupervisorProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _error("lifecycle_supervisor_json_invalid") from exc
    if canonical_json(value) != raw:
        raise _error("lifecycle_supervisor_json_noncanonical")
    return value


def encode_frame(value: Mapping[str, Any]) -> bytes:
    if not isinstance(value, Mapping):
        raise _error("lifecycle_supervisor_message_invalid")
    payload = canonical_json(dict(value))
    if len(payload) < 2 or len(payload) > MAX_FRAME_BYTES:
        raise _error("lifecycle_supervisor_frame_size_invalid")
    return struct.pack("!I", len(payload)) + payload


def decode_frame(raw: bytes) -> dict[str, Any]:
    if (
        not isinstance(raw, bytes)
        or len(raw) < 6
        or len(raw) > MAX_FRAME_BYTES + 4
    ):
        raise _error("lifecycle_supervisor_frame_size_invalid")
    (length,) = struct.unpack("!I", raw[:4])
    if length < 2 or length > MAX_FRAME_BYTES:
        raise _error("lifecycle_supervisor_frame_size_invalid")
    if len(raw) != length + 4:
        raise _error("lifecycle_supervisor_frame_length_mismatch")
    value = parse_canonical_json(raw[4:])
    if not isinstance(value, dict):
        raise _error("lifecycle_supervisor_message_invalid")
    _reject_authority_fields(value)
    return value


class FrameDecoder:
    """Incremental bounded decoder for an authenticated byte stream."""

    __slots__ = ("_buffer", "_expected", "_failed")

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._expected: int | None = None
        self._failed = False

    def feed(self, raw: bytes) -> list[dict[str, Any]]:
        if self._failed:
            raise _error("lifecycle_supervisor_frame_decoder_failed")
        if (
            not isinstance(raw, bytes)
            or not raw
            or len(raw) > MAX_FRAME_BYTES + 4
        ):
            self._failed = True
            raise _error("lifecycle_supervisor_frame_chunk_invalid")
        self._buffer.extend(raw)
        messages: list[dict[str, Any]] = []
        try:
            while True:
                if self._expected is None:
                    if len(self._buffer) < 4:
                        break
                    (length,) = struct.unpack("!I", self._buffer[:4])
                    if length < 2 or length > MAX_FRAME_BYTES:
                        raise _error(
                            "lifecycle_supervisor_frame_size_invalid"
                        )
                    del self._buffer[:4]
                    self._expected = length
                if len(self._buffer) < self._expected:
                    break
                payload = bytes(self._buffer[: self._expected])
                del self._buffer[: self._expected]
                self._expected = None
                value = parse_canonical_json(payload)
                if not isinstance(value, dict):
                    raise _error("lifecycle_supervisor_message_invalid")
                _reject_authority_fields(value)
                messages.append(value)
                if len(messages) > MAX_FRAMES_PER_FEED:
                    raise _error(
                        "lifecycle_supervisor_frame_batch_too_large"
                    )
        except LifecycleSupervisorProtocolError:
            self._failed = True
            self._buffer.clear()
            self._expected = None
            raise
        return messages

    def finish(self) -> None:
        if self._failed:
            raise _error("lifecycle_supervisor_frame_decoder_failed")
        if self._expected is not None or self._buffer:
            self._failed = True
            self._buffer.clear()
            self._expected = None
            raise _error("lifecycle_supervisor_frame_truncated")


def _reject_authority_fields(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise _error(
                    "lifecycle_supervisor_field_name_invalid"
                )
            parts = frozenset(key.lower().split("_"))
            if parts & FORBIDDEN_AUTHORITY_FIELD_PARTS:
                raise _error(
                    "lifecycle_supervisor_forbidden_authority_field"
                )
            _reject_authority_fields(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reject_authority_fields(child)


def _strict_mapping(
    value: Any,
    fields: frozenset[str],
    *,
    code: str,
) -> dict[str, Any]:
    _reject_authority_fields(value)
    if not isinstance(value, Mapping) or set(value) != fields:
        raise _error(code)
    return {field: value[field] for field in fields}


def _exact(value: Any, expected: Any, *, code: str) -> Any:
    if value != expected or type(value) is not type(expected):
        raise _error(code)
    return expected


def _digest(value: Any, *, code: str) -> str:
    if (
        not isinstance(value, str)
        or not SHA256_RE.fullmatch(value)
        or value == ZERO_SHA256
    ):
        raise _error(code)
    return value


def _nullable_digest(value: Any, *, code: str) -> str | None:
    if value is None:
        return None
    return _digest(value, code=code)


def _component(value: Any, *, code: str) -> str:
    if (
        not isinstance(value, str)
        or not COMPONENT_RE.fullmatch(value)
        or value in {".", ".."}
    ):
        raise _error(code)
    return value


def capture_event_evidence_sha256(value: Any) -> str:
    """Digest the exact local evidence bound to ``capture_ready``.

    The input grammar intentionally matches the eight durable
    ``capture_ready`` detail fields in the outer transaction journal.  The
    schema wrapper domain-separates this digest from both that journal record
    and every individual capture artifact digest.
    """

    selected = _strict_mapping(
        value,
        CAPTURE_EVENT_EVIDENCE_FIELDS,
        code=(
            "lifecycle_supervisor_capture_event_evidence_fields_invalid"
        ),
    )
    normalized = {
        "provisional_name": _component(
            selected["provisional_name"],
            code=(
                "lifecycle_supervisor_capture_event_"
                "provisional_name_invalid"
            ),
        )
    }
    for field in CAPTURE_EVENT_EVIDENCE_FIELDS - {"provisional_name"}:
        normalized[field] = _digest(
            selected[field],
            code=f"lifecycle_supervisor_capture_event_{field}_invalid",
        )
    return sha256_json(
        {
            "schema_version": CAPTURE_EVENT_EVIDENCE_SCHEMA,
            "capture_ready": normalized,
        }
    )


def _positive_integer(value: Any, *, code: str) -> int:
    if (
        type(value) is not int
        or value < 1
        or value > MAX_SAFE_INTEGER
    ):
        raise _error(code)
    return value


def _bounded_integer(
    value: Any,
    *,
    minimum: int,
    maximum: int,
    code: str,
) -> int:
    if (
        type(value) is not int
        or value < minimum
        or value > maximum
    ):
        raise _error(code)
    return value


def _token(
    value: Any,
    *,
    permitted: frozenset[str],
    code: str,
) -> str:
    if not isinstance(value, str) or value not in permitted:
        raise _error(code)
    return value


def _instance_slug(value: Any) -> str:
    if not isinstance(value, str) or not INSTANCE_SLUG_RE.fullmatch(value):
        raise _error("lifecycle_supervisor_instance_slug_invalid")
    return value


def _request_id(value: Any) -> str:
    if not isinstance(value, str) or not REQUEST_ID_RE.fullmatch(value):
        raise _error("lifecycle_supervisor_request_id_invalid")
    return value


def _session_id(value: Any) -> str:
    return _digest(
        value,
        code="lifecycle_supervisor_capture_session_id_invalid",
    )


def _scope_id(value: Any, *, capture_session_id: str) -> str:
    expected = f"jlq-root_supervisor-{capture_session_id}"
    if (
        not isinstance(value, str)
        or not SCOPE_ID_RE.fullmatch(value)
        or value != expected
    ):
        raise _error("lifecycle_supervisor_scope_id_invalid")
    return value


def _scope_common(
    selected: Mapping[str, Any],
) -> tuple[str, str, str]:
    session_id = _session_id(selected["capture_session_id"])
    scope_id = _scope_id(
        selected["lifecycle_scope_id"],
        capture_session_id=session_id,
    )
    incarnation = _digest(
        selected["scope_incarnation_id"],
        code="lifecycle_supervisor_scope_incarnation_id_invalid",
    )
    return session_id, scope_id, incarnation


def derive_scope_incarnation_id(
    *,
    instance_slug: str,
    capture_session_id: str,
    child_launch_intent_record_sha256: str,
    lifecycle_activation_receipt_sha256: str,
) -> str:
    """Derive the restart-stable identity for one supervised launch.

    The identity is recoverable from durable outer-journal and activation
    coordinates.  It is deliberately not random client process state: a
    client that loses a start response can derive the same identity after a
    restart and ask the authenticated supervisor to recover the scope.
    """

    return sha256_json(
        {
            "schema_version": SCOPE_INCARNATION_DERIVATION_SCHEMA,
            "instance_slug": _instance_slug(instance_slug),
            "capture_session_id": _session_id(capture_session_id),
            "child_launch_intent_record_sha256": _digest(
                child_launch_intent_record_sha256,
                code=(
                    "lifecycle_supervisor_launch_intent_sha256_invalid"
                ),
            ),
            "lifecycle_activation_receipt_sha256": _digest(
                lifecycle_activation_receipt_sha256,
                code=(
                    "lifecycle_supervisor_activation_receipt_sha256_invalid"
                ),
            ),
        }
    )


def derive_scope_start_authorization_sha256(
    *,
    instance_slug: str,
    capture_session_id: str,
    scope_incarnation_id: str,
    child_launch_intent_record_revision: int,
    child_launch_intent_record_sha256: str,
    staging_transaction_intent_sha256: str,
    staging_exposure_receipt_sha256: str,
    handoff_policy_sha256: str,
    helper_activation_policy_sha256: str,
    lifecycle_provider: str,
    capture_uid: int,
    export_gid: int,
    lifecycle_activation_receipt_sha256: str,
    activation_host_boot_id_sha256: str,
) -> str:
    """Digest the durable inputs that authorize a scope start receipt."""

    session_id = _session_id(capture_session_id)
    return sha256_json(
        {
            "schema_version": SCOPE_START_AUTHORIZATION_SCHEMA,
            "instance_slug": _instance_slug(instance_slug),
            "capture_session_id": session_id,
            "lifecycle_scope_id": _scope_id(
                f"jlq-root_supervisor-{session_id}",
                capture_session_id=session_id,
            ),
            "scope_incarnation_id": _digest(
                scope_incarnation_id,
                code=(
                    "lifecycle_supervisor_scope_incarnation_id_invalid"
                ),
            ),
            "child_launch_intent_record_revision": _positive_integer(
                child_launch_intent_record_revision,
                code=(
                    "lifecycle_supervisor_launch_intent_revision_invalid"
                ),
            ),
            "child_launch_intent_record_sha256": _digest(
                child_launch_intent_record_sha256,
                code=(
                    "lifecycle_supervisor_launch_intent_sha256_invalid"
                ),
            ),
            "staging_transaction_intent_sha256": _digest(
                staging_transaction_intent_sha256,
                code=(
                    "lifecycle_supervisor_staging_intent_sha256_invalid"
                ),
            ),
            "staging_exposure_receipt_sha256": _digest(
                staging_exposure_receipt_sha256,
                code=(
                    "lifecycle_supervisor_staging_exposure_sha256_invalid"
                ),
            ),
            "handoff_policy_sha256": _digest(
                handoff_policy_sha256,
                code="lifecycle_supervisor_handoff_policy_sha256_invalid",
            ),
            "helper_activation_policy_sha256": _digest(
                helper_activation_policy_sha256,
                code="lifecycle_supervisor_helper_policy_sha256_invalid",
            ),
            "lifecycle_provider": _token(
                lifecycle_provider,
                permitted=LIFECYCLE_PROVIDERS,
                code="lifecycle_supervisor_lifecycle_provider_invalid",
            ),
            "capture_uid": _bounded_integer(
                capture_uid,
                minimum=1,
                maximum=MAX_IDENTITY,
                code="lifecycle_supervisor_capture_uid_invalid",
            ),
            "export_gid": _bounded_integer(
                export_gid,
                minimum=1,
                maximum=MAX_IDENTITY,
                code="lifecycle_supervisor_export_gid_invalid",
            ),
            "lifecycle_activation_receipt_sha256": _digest(
                lifecycle_activation_receipt_sha256,
                code=(
                    "lifecycle_supervisor_activation_receipt_sha256_invalid"
                ),
            ),
            "activation_host_boot_id_sha256": _digest(
                activation_host_boot_id_sha256,
                code=(
                    "lifecycle_supervisor_activation_host_boot_id_invalid"
                ),
            ),
        }
    )


def normalize_client_hello(value: Any) -> dict[str, Any]:
    selected = _strict_mapping(
        value,
        CLIENT_HELLO_FIELDS,
        code="lifecycle_supervisor_client_hello_fields_invalid",
    )
    client_incarnation = _digest(
        selected["client_incarnation_id"],
        code="lifecycle_supervisor_client_incarnation_id_invalid",
    )
    client_nonce = _digest(
        selected["client_nonce"],
        code="lifecycle_supervisor_client_nonce_invalid",
    )
    if hmac.compare_digest(client_incarnation, client_nonce):
        raise _error(
            "lifecycle_supervisor_client_nonce_domain_collision"
        )
    return {
        "schema_version": _exact(
            selected["schema_version"],
            CLIENT_HELLO_SCHEMA,
            code="lifecycle_supervisor_client_hello_schema_invalid",
        ),
        "message_type": _exact(
            selected["message_type"],
            "client_hello",
            code="lifecycle_supervisor_client_hello_type_invalid",
        ),
        "operation": _exact(
            selected["operation"],
            "handshake",
            code="lifecycle_supervisor_client_hello_operation_invalid",
        ),
        "instance_slug": _instance_slug(selected["instance_slug"]),
        "request_id": _request_id(selected["request_id"]),
        "client_incarnation_id": client_incarnation,
        "client_nonce": client_nonce,
        "expected_supervisor_policy_sha256": _digest(
            selected["expected_supervisor_policy_sha256"],
            code="lifecycle_supervisor_expected_policy_sha256_invalid",
        ),
        "expected_supervisor_bundle_sha256": _digest(
            selected["expected_supervisor_bundle_sha256"],
            code="lifecycle_supervisor_expected_bundle_sha256_invalid",
        ),
        "expected_helper_activation_policy_sha256": _digest(
            selected["expected_helper_activation_policy_sha256"],
            code=(
                "lifecycle_supervisor_expected_helper_policy_sha256_invalid"
            ),
        ),
        "expected_lifecycle_canary_sha256": _digest(
            selected["expected_lifecycle_canary_sha256"],
            code="lifecycle_supervisor_expected_canary_sha256_invalid",
        ),
    }


def build_client_hello(
    *,
    instance_slug: str,
    request_id: str,
    client_incarnation_id: str,
    client_nonce: str,
    expected_supervisor_policy_sha256: str,
    expected_supervisor_bundle_sha256: str,
    expected_helper_activation_policy_sha256: str,
    expected_lifecycle_canary_sha256: str,
) -> dict[str, Any]:
    return normalize_client_hello(
        {
            "schema_version": CLIENT_HELLO_SCHEMA,
            "message_type": "client_hello",
            "operation": "handshake",
            "instance_slug": instance_slug,
            "request_id": request_id,
            "client_incarnation_id": client_incarnation_id,
            "client_nonce": client_nonce,
            "expected_supervisor_policy_sha256": (
                expected_supervisor_policy_sha256
            ),
            "expected_supervisor_bundle_sha256": (
                expected_supervisor_bundle_sha256
            ),
            "expected_helper_activation_policy_sha256": (
                expected_helper_activation_policy_sha256
            ),
            "expected_lifecycle_canary_sha256": (
                expected_lifecycle_canary_sha256
            ),
        }
    )


def client_hello_sha256(value: Any) -> str:
    return sha256_json(normalize_client_hello(value))


def normalize_server_hello(value: Any) -> dict[str, Any]:
    selected = _strict_mapping(
        value,
        SERVER_HELLO_FIELDS,
        code="lifecycle_supervisor_server_hello_fields_invalid",
    )
    client_incarnation = _digest(
        selected["client_incarnation_id"],
        code="lifecycle_supervisor_client_incarnation_id_invalid",
    )
    client_nonce = _digest(
        selected["client_nonce"],
        code="lifecycle_supervisor_client_nonce_invalid",
    )
    server_nonce = _digest(
        selected["server_nonce"],
        code="lifecycle_supervisor_server_nonce_invalid",
    )
    protocol_session = _digest(
        selected["protocol_session_id"],
        code="lifecycle_supervisor_protocol_session_id_invalid",
    )
    supervisor_incarnation = _digest(
        selected["supervisor_incarnation_id"],
        code="lifecycle_supervisor_incarnation_id_invalid",
    )
    supervisor_epoch = _digest(
        selected["supervisor_epoch_id"],
        code="lifecycle_supervisor_epoch_id_invalid",
    )
    host_boot = _digest(
        selected["host_boot_id_sha256"],
        code="lifecycle_supervisor_host_boot_id_sha256_invalid",
    )
    domain_values = (
        client_incarnation,
        client_nonce,
        server_nonce,
        protocol_session,
        supervisor_incarnation,
        supervisor_epoch,
        host_boot,
    )
    if len(set(domain_values)) != len(domain_values):
        raise _error(
            "lifecycle_supervisor_handshake_domain_collision"
        )
    if selected["production_activation"] is not False:
        raise _error(
            "lifecycle_supervisor_production_activation_forbidden"
        )
    return {
        "schema_version": _exact(
            selected["schema_version"],
            SERVER_HELLO_SCHEMA,
            code="lifecycle_supervisor_server_hello_schema_invalid",
        ),
        "message_type": _exact(
            selected["message_type"],
            "server_hello",
            code="lifecycle_supervisor_server_hello_type_invalid",
        ),
        "operation": _exact(
            selected["operation"],
            "handshake",
            code="lifecycle_supervisor_server_hello_operation_invalid",
        ),
        "status": _exact(
            selected["status"],
            "accepted",
            code="lifecycle_supervisor_server_hello_status_invalid",
        ),
        "instance_slug": _instance_slug(selected["instance_slug"]),
        "request_id": _request_id(selected["request_id"]),
        "client_incarnation_id": client_incarnation,
        "client_nonce": client_nonce,
        "client_hello_sha256": _digest(
            selected["client_hello_sha256"],
            code="lifecycle_supervisor_client_hello_sha256_invalid",
        ),
        "server_nonce": server_nonce,
        "protocol_session_id": protocol_session,
        "supervisor_incarnation_id": supervisor_incarnation,
        "supervisor_epoch_id": supervisor_epoch,
        "host_boot_id_sha256": host_boot,
        "supervisor_policy_sha256": _digest(
            selected["supervisor_policy_sha256"],
            code="lifecycle_supervisor_policy_sha256_invalid",
        ),
        "supervisor_bundle_sha256": _digest(
            selected["supervisor_bundle_sha256"],
            code="lifecycle_supervisor_bundle_sha256_invalid",
        ),
        "helper_activation_policy_sha256": _digest(
            selected["helper_activation_policy_sha256"],
            code="lifecycle_supervisor_helper_policy_sha256_invalid",
        ),
        "lifecycle_canary_sha256": _digest(
            selected["lifecycle_canary_sha256"],
            code="lifecycle_supervisor_canary_sha256_invalid",
        ),
        "activation_receipt_sha256": _nullable_digest(
            selected["activation_receipt_sha256"],
            code="lifecycle_supervisor_activation_receipt_sha256_invalid",
        ),
        "production_activation": False,
    }


def validate_server_hello(
    client_hello: Any,
    server_hello: Any,
) -> dict[str, Any]:
    client = normalize_client_hello(client_hello)
    server = normalize_server_hello(server_hello)
    expected_pairs = (
        ("instance_slug", "instance_slug"),
        ("request_id", "request_id"),
        ("client_incarnation_id", "client_incarnation_id"),
        ("client_nonce", "client_nonce"),
    )
    if any(
        server[server_field] != client[client_field]
        for server_field, client_field in expected_pairs
    ):
        raise _error(
            "lifecycle_supervisor_handshake_correlation_mismatch"
        )
    if not hmac.compare_digest(
        server["client_hello_sha256"],
        client_hello_sha256(client),
    ):
        raise _error(
            "lifecycle_supervisor_client_hello_digest_mismatch"
        )
    measurement_pairs = (
        (
            "supervisor_policy_sha256",
            "expected_supervisor_policy_sha256",
        ),
        (
            "supervisor_bundle_sha256",
            "expected_supervisor_bundle_sha256",
        ),
        (
            "helper_activation_policy_sha256",
            "expected_helper_activation_policy_sha256",
        ),
        (
            "lifecycle_canary_sha256",
            "expected_lifecycle_canary_sha256",
        ),
    )
    if any(
        not hmac.compare_digest(
            server[server_field], client[client_field]
        )
        for server_field, client_field in measurement_pairs
    ):
        raise _error(
            "lifecycle_supervisor_handshake_measurement_mismatch"
        )
    return server


def build_server_hello(
    client_hello: Any,
    *,
    server_nonce: str,
    protocol_session_id: str,
    supervisor_incarnation_id: str,
    supervisor_epoch_id: str,
    host_boot_id_sha256: str,
    supervisor_policy_sha256: str,
    supervisor_bundle_sha256: str,
    helper_activation_policy_sha256: str,
    lifecycle_canary_sha256: str,
    activation_receipt_sha256: str | None,
) -> dict[str, Any]:
    client = normalize_client_hello(client_hello)
    value = {
        "schema_version": SERVER_HELLO_SCHEMA,
        "message_type": "server_hello",
        "operation": "handshake",
        "status": "accepted",
        "instance_slug": client["instance_slug"],
        "request_id": client["request_id"],
        "client_incarnation_id": client["client_incarnation_id"],
        "client_nonce": client["client_nonce"],
        "client_hello_sha256": client_hello_sha256(client),
        "server_nonce": server_nonce,
        "protocol_session_id": protocol_session_id,
        "supervisor_incarnation_id": supervisor_incarnation_id,
        "supervisor_epoch_id": supervisor_epoch_id,
        "host_boot_id_sha256": host_boot_id_sha256,
        "supervisor_policy_sha256": supervisor_policy_sha256,
        "supervisor_bundle_sha256": supervisor_bundle_sha256,
        "helper_activation_policy_sha256": (
            helper_activation_policy_sha256
        ),
        "lifecycle_canary_sha256": lifecycle_canary_sha256,
        "activation_receipt_sha256": activation_receipt_sha256,
        "production_activation": False,
    }
    return validate_server_hello(client, value)


def server_hello_sha256(value: Any) -> str:
    return sha256_json(normalize_server_hello(value))


def _normalize_get_activation_payload(value: Any) -> dict[str, Any]:
    selected = _strict_mapping(
        value,
        GET_ACTIVATION_FIELDS,
        code="lifecycle_supervisor_get_activation_fields_invalid",
    )
    return {
        "expected_activation_receipt_sha256": _nullable_digest(
            selected["expected_activation_receipt_sha256"],
            code=(
                "lifecycle_supervisor_expected_activation_receipt_invalid"
            ),
        ),
        "expected_supervisor_policy_sha256": _digest(
            selected["expected_supervisor_policy_sha256"],
            code="lifecycle_supervisor_expected_policy_sha256_invalid",
        ),
        "expected_supervisor_bundle_sha256": _digest(
            selected["expected_supervisor_bundle_sha256"],
            code="lifecycle_supervisor_expected_bundle_sha256_invalid",
        ),
        "expected_helper_activation_policy_sha256": _digest(
            selected["expected_helper_activation_policy_sha256"],
            code=(
                "lifecycle_supervisor_expected_helper_policy_sha256_invalid"
            ),
        ),
        "expected_lifecycle_canary_sha256": _digest(
            selected["expected_lifecycle_canary_sha256"],
            code="lifecycle_supervisor_expected_canary_sha256_invalid",
        ),
    }


def _normalize_start_scope_payload(value: Any) -> dict[str, Any]:
    selected = _strict_mapping(
        value,
        START_SCOPE_FIELDS,
        code="lifecycle_supervisor_start_scope_fields_invalid",
    )
    session_id, scope_id, incarnation = _scope_common(selected)
    return {
        "capture_session_id": session_id,
        "lifecycle_scope_id": scope_id,
        "scope_incarnation_id": incarnation,
        "child_launch_intent_record_revision": _positive_integer(
            selected["child_launch_intent_record_revision"],
            code=(
                "lifecycle_supervisor_launch_intent_revision_invalid"
            ),
        ),
        "child_launch_intent_record_sha256": _digest(
            selected["child_launch_intent_record_sha256"],
            code=(
                "lifecycle_supervisor_launch_intent_sha256_invalid"
            ),
        ),
        "staging_transaction_intent_sha256": _digest(
            selected["staging_transaction_intent_sha256"],
            code=(
                "lifecycle_supervisor_staging_intent_sha256_invalid"
            ),
        ),
        "staging_exposure_receipt_sha256": _digest(
            selected["staging_exposure_receipt_sha256"],
            code=(
                "lifecycle_supervisor_staging_exposure_sha256_invalid"
            ),
        ),
        "handoff_policy_sha256": _digest(
            selected["handoff_policy_sha256"],
            code="lifecycle_supervisor_handoff_policy_sha256_invalid",
        ),
        "helper_activation_policy_sha256": _digest(
            selected["helper_activation_policy_sha256"],
            code="lifecycle_supervisor_helper_policy_sha256_invalid",
        ),
        "lifecycle_provider": _token(
            selected["lifecycle_provider"],
            permitted=LIFECYCLE_PROVIDERS,
            code="lifecycle_supervisor_lifecycle_provider_invalid",
        ),
        "capture_uid": _bounded_integer(
            selected["capture_uid"],
            minimum=1,
            maximum=MAX_IDENTITY,
            code="lifecycle_supervisor_capture_uid_invalid",
        ),
        "export_gid": _bounded_integer(
            selected["export_gid"],
            minimum=1,
            maximum=MAX_IDENTITY,
            code="lifecycle_supervisor_export_gid_invalid",
        ),
        "lifecycle_activation_receipt_sha256": _digest(
            selected["lifecycle_activation_receipt_sha256"],
            code=(
                "lifecycle_supervisor_activation_receipt_sha256_invalid"
            ),
        ),
    }


def _normalize_await_capture_event_payload(
    value: Any,
) -> dict[str, Any]:
    selected = _strict_mapping(
        value,
        AWAIT_CAPTURE_EVENT_FIELDS,
        code=(
            "lifecycle_supervisor_await_capture_event_fields_invalid"
        ),
    )
    session_id, scope_id, incarnation = _scope_common(selected)
    outer_state = _token(
        selected["outer_journal_record_state"],
        permitted=frozenset({"child_running", "capture_ready"}),
        code="lifecycle_supervisor_outer_record_state_invalid",
    )
    return {
        "capture_session_id": session_id,
        "lifecycle_scope_id": scope_id,
        "scope_incarnation_id": incarnation,
        "scope_started_receipt_sha256": _digest(
            selected["scope_started_receipt_sha256"],
            code=(
                "lifecycle_supervisor_scope_started_receipt_sha256_invalid"
            ),
        ),
        "child_launch_intent_record_sha256": _digest(
            selected["child_launch_intent_record_sha256"],
            code=(
                "lifecycle_supervisor_launch_intent_sha256_invalid"
            ),
        ),
        "outer_journal_record_state": outer_state,
        "outer_journal_record_revision": _positive_integer(
            selected["outer_journal_record_revision"],
            code="lifecycle_supervisor_outer_record_revision_invalid",
        ),
        "outer_journal_record_sha256": _digest(
            selected["outer_journal_record_sha256"],
            code="lifecycle_supervisor_outer_record_sha256_invalid",
        ),
        "expected_ledger_head_sha256": _digest(
            selected["expected_ledger_head_sha256"],
            code=(
                "lifecycle_supervisor_expected_ledger_head_sha256_invalid"
            ),
        ),
        "after_event_sequence": _bounded_integer(
            selected["after_event_sequence"],
            minimum=0,
            maximum=MAX_SAFE_INTEGER,
            code="lifecycle_supervisor_event_sequence_invalid",
        ),
        "timeout_seconds": _bounded_integer(
            selected["timeout_seconds"],
            minimum=1,
            maximum=MAX_TIMEOUT_SECONDS,
            code="lifecycle_supervisor_timeout_seconds_invalid",
        ),
    }


def _normalize_request_clearance_payload(
    value: Any,
) -> dict[str, Any]:
    selected = _strict_mapping(
        value,
        REQUEST_CLEARANCE_FIELDS,
        code="lifecycle_supervisor_request_clearance_fields_invalid",
    )
    session_id, scope_id, incarnation = _scope_common(selected)
    origin = _token(
        selected["effect_origin_state"],
        permitted=EFFECT_ORIGIN_STATES,
        code="lifecycle_supervisor_effect_origin_state_invalid",
    )
    mode = _token(
        selected["clearance_mode"],
        permitted=CLEARANCE_MODES,
        code="lifecycle_supervisor_clearance_mode_invalid",
    )
    start_digest = _nullable_digest(
        selected["scope_started_receipt_sha256"],
        code=(
            "lifecycle_supervisor_scope_started_receipt_sha256_invalid"
        ),
    )
    if origin == "child_launch_intent" and start_digest is not None:
        raise _error(
            "lifecycle_supervisor_recovered_start_must_be_deferred"
        )
    if origin != "child_launch_intent" and start_digest is None:
        raise _error("lifecycle_supervisor_scope_started_receipt_missing")
    if (
        origin in {"child_launch_intent", "child_running"}
        and mode != "terminate_and_clear"
    ):
        raise _error(
            "lifecycle_supervisor_clearance_mode_origin_mismatch"
        )
    effect_revision = _positive_integer(
        selected["effect_origin_record_revision"],
        code="lifecycle_supervisor_effect_origin_revision_invalid",
    )
    clearance_revision = _positive_integer(
        selected["lifecycle_clearance_intent_record_revision"],
        code=(
            "lifecycle_supervisor_clearance_intent_revision_invalid"
        ),
    )
    if effect_revision >= clearance_revision:
        raise _error(
            "lifecycle_supervisor_clearance_revision_order_invalid"
        )
    return {
        "capture_session_id": session_id,
        "lifecycle_scope_id": scope_id,
        "scope_incarnation_id": incarnation,
        "lifecycle_activation_receipt_sha256": _digest(
            selected["lifecycle_activation_receipt_sha256"],
            code=(
                "lifecycle_supervisor_activation_receipt_sha256_invalid"
            ),
        ),
        "child_launch_intent_record_sha256": _digest(
            selected["child_launch_intent_record_sha256"],
            code=(
                "lifecycle_supervisor_launch_intent_sha256_invalid"
            ),
        ),
        "effect_origin_state": origin,
        "effect_origin_record_revision": effect_revision,
        "effect_origin_record_sha256": _digest(
            selected["effect_origin_record_sha256"],
            code=(
                "lifecycle_supervisor_effect_origin_sha256_invalid"
            ),
        ),
        "scope_started_receipt_sha256": start_digest,
        "clearance_mode": mode,
        "lifecycle_clearance_intent_record_revision": clearance_revision,
        "lifecycle_clearance_intent_record_sha256": _digest(
            selected["lifecycle_clearance_intent_record_sha256"],
            code=(
                "lifecycle_supervisor_clearance_intent_sha256_invalid"
            ),
        ),
        "expected_ledger_head_sha256": _digest(
            selected["expected_ledger_head_sha256"],
            code=(
                "lifecycle_supervisor_expected_ledger_head_sha256_invalid"
            ),
        ),
        "timeout_seconds": _bounded_integer(
            selected["timeout_seconds"],
            minimum=1,
            maximum=MAX_TIMEOUT_SECONDS,
            code="lifecycle_supervisor_timeout_seconds_invalid",
        ),
    }


def _normalize_recover_scope_payload(value: Any) -> dict[str, Any]:
    selected = _strict_mapping(
        value,
        RECOVER_SCOPE_FIELDS,
        code="lifecycle_supervisor_recover_scope_fields_invalid",
    )
    session_id, scope_id, incarnation = _scope_common(selected)
    outer_state = _token(
        selected["outer_journal_record_state"],
        permitted=OUTER_RECORD_STATES,
        code="lifecycle_supervisor_outer_record_state_invalid",
    )
    launch_revision = _positive_integer(
        selected["child_launch_intent_record_revision"],
        code="lifecycle_supervisor_launch_intent_revision_invalid",
    )
    outer_revision = _positive_integer(
        selected["outer_journal_record_revision"],
        code="lifecycle_supervisor_outer_record_revision_invalid",
    )
    if (
        outer_state == "child_launch_intent"
        and outer_revision != launch_revision
    ):
        raise _error(
            "lifecycle_supervisor_recovery_launch_revision_mismatch"
        )
    launch_digest = _digest(
        selected["child_launch_intent_record_sha256"],
        code="lifecycle_supervisor_launch_intent_sha256_invalid",
    )
    outer_digest = _digest(
        selected["outer_journal_record_sha256"],
        code="lifecycle_supervisor_outer_record_sha256_invalid",
    )
    if (
        outer_state == "child_launch_intent"
        and not hmac.compare_digest(outer_digest, launch_digest)
    ):
        raise _error(
            "lifecycle_supervisor_recovery_launch_digest_mismatch"
        )
    expected_origin = _token(
        selected["expected_effect_origin_state"],
        permitted=EFFECT_ORIGIN_STATES,
        code="lifecycle_supervisor_effect_origin_state_invalid",
    )
    expected_origin_revision = _positive_integer(
        selected["expected_effect_origin_record_revision"],
        code="lifecycle_supervisor_effect_origin_revision_invalid",
    )
    expected_origin_digest = _digest(
        selected["expected_effect_origin_record_sha256"],
        code="lifecycle_supervisor_effect_origin_sha256_invalid",
    )
    if expected_origin_revision > outer_revision:
        raise _error(
            "lifecycle_supervisor_recovery_future_effect_origin"
        )
    if expected_origin == "child_launch_intent" and (
        expected_origin_revision != launch_revision
        or not hmac.compare_digest(
            expected_origin_digest, launch_digest
        )
    ):
        raise _error(
            "lifecycle_supervisor_recovery_launch_origin_mismatch"
        )
    if outer_state in EFFECT_ORIGIN_STATES and (
        expected_origin != outer_state
        or expected_origin_revision != outer_revision
        or not hmac.compare_digest(
            expected_origin_digest, outer_digest
        )
    ):
        raise _error(
            "lifecycle_supervisor_recovery_outer_origin_mismatch"
        )
    clearance_required = outer_state in {
        "lifecycle_clearance_intent",
        "lifecycle_scope_empty",
    }
    clearance_forbidden = outer_state in EFFECT_ORIGIN_STATES
    raw_clearance_revision = selected[
        "expected_clearance_intent_record_revision"
    ]
    raw_clearance_digest = selected[
        "expected_clearance_intent_record_sha256"
    ]
    raw_clearance_mode = selected["expected_clearance_mode"]
    clearance_supplied = any(
        value is not None
        for value in (
            raw_clearance_revision,
            raw_clearance_digest,
            raw_clearance_mode,
        )
    )
    if clearance_required and not clearance_supplied:
        raise _error(
            "lifecycle_supervisor_recovery_clearance_required"
        )
    if clearance_forbidden and clearance_supplied:
        raise _error(
            "lifecycle_supervisor_recovery_clearance_unexpected"
        )
    if clearance_supplied:
        if (
            raw_clearance_revision is None
            or raw_clearance_digest is None
            or raw_clearance_mode is None
        ):
            raise _error(
                "lifecycle_supervisor_recovery_clearance_pair_invalid"
            )
        expected_clearance_revision = _positive_integer(
            raw_clearance_revision,
            code=(
                "lifecycle_supervisor_expected_clearance_revision_invalid"
            ),
        )
        expected_clearance_digest = _digest(
            raw_clearance_digest,
            code=(
                "lifecycle_supervisor_expected_clearance_sha256_invalid"
            ),
        )
        expected_clearance_mode = _token(
            raw_clearance_mode,
            permitted=CLEARANCE_MODES,
            code=(
                "lifecycle_supervisor_expected_clearance_mode_invalid"
            ),
        )
        if expected_clearance_revision > outer_revision:
            raise _error(
                "lifecycle_supervisor_recovery_future_clearance_intent"
            )
        if outer_state == "lifecycle_clearance_intent" and (
            expected_clearance_revision != outer_revision
            or not hmac.compare_digest(
                expected_clearance_digest, outer_digest
            )
        ):
            raise _error(
                "lifecycle_supervisor_recovery_outer_clearance_mismatch"
            )
    else:
        expected_clearance_revision = None
        expected_clearance_digest = None
        expected_clearance_mode = None
    return {
        "capture_session_id": session_id,
        "lifecycle_scope_id": scope_id,
        "scope_incarnation_id": incarnation,
        "lifecycle_activation_receipt_sha256": _digest(
            selected["lifecycle_activation_receipt_sha256"],
            code=(
                "lifecycle_supervisor_activation_receipt_sha256_invalid"
            ),
        ),
        "child_launch_intent_record_revision": launch_revision,
        "child_launch_intent_record_sha256": launch_digest,
        "outer_journal_record_state": outer_state,
        "outer_journal_record_revision": outer_revision,
        "outer_journal_record_sha256": outer_digest,
        "expected_scope_started_receipt_sha256": _nullable_digest(
            selected["expected_scope_started_receipt_sha256"],
            code=(
                "lifecycle_supervisor_expected_started_receipt_invalid"
            ),
        ),
        "expected_scope_start_authorization_sha256": _digest(
            selected["expected_scope_start_authorization_sha256"],
            code=(
                "lifecycle_supervisor_expected_start_authorization_invalid"
            ),
        ),
        "expected_effect_origin_state": expected_origin,
        "expected_effect_origin_record_revision": (
            expected_origin_revision
        ),
        "expected_effect_origin_record_sha256": (
            expected_origin_digest
        ),
        "expected_clearance_intent_record_revision": (
            expected_clearance_revision
        ),
        "expected_clearance_intent_record_sha256": (
            expected_clearance_digest
        ),
        "expected_clearance_mode": expected_clearance_mode,
        "expected_ledger_head_sha256": _nullable_digest(
            selected["expected_ledger_head_sha256"],
            code=(
                "lifecycle_supervisor_expected_ledger_head_sha256_invalid"
            ),
        ),
        "recovery_reason": _token(
            selected["recovery_reason"],
            permitted=RECOVERY_REASONS,
            code="lifecycle_supervisor_recovery_reason_invalid",
        ),
    }


_PAYLOAD_NORMALIZERS = {
    "get_activation": _normalize_get_activation_payload,
    "start_scope": _normalize_start_scope_payload,
    "await_capture_event": _normalize_await_capture_event_payload,
    "request_clearance": _normalize_request_clearance_payload,
    "recover_scope": _normalize_recover_scope_payload,
}


def normalize_operation_payload(
    operation: Any,
    value: Any,
) -> dict[str, Any]:
    selected_operation = _token(
        operation,
        permitted=OPERATIONS,
        code="lifecycle_supervisor_operation_invalid",
    )
    return _PAYLOAD_NORMALIZERS[selected_operation](value)


def _normalize_lifecycle_receipt(
    value: Any,
    *,
    normalizer: Any,
) -> dict[str, Any]:
    """Delegate the canonical receipt grammar to its sole owner."""

    try:
        return normalizer(value)
    except lifecycle_receipts.LifecycleReceiptError as exc:
        raise _error(
            "lifecycle_supervisor_lifecycle_receipt_invalid"
        ) from exc


def _normalize_activation_receipt(value: Any) -> dict[str, Any]:
    return _normalize_lifecycle_receipt(
        value,
        normalizer=lifecycle_receipts.normalize_activation_receipt,
    )


def _normalize_scope_started_receipt(value: Any) -> dict[str, Any]:
    return _normalize_lifecycle_receipt(
        value,
        normalizer=lifecycle_receipts.normalize_scope_started_receipt,
    )


def _normalize_clearance_bundle(value: Any) -> dict[str, Any]:
    return _normalize_lifecycle_receipt(
        value,
        normalizer=lifecycle_receipts.normalize_clearance_bundle,
    )


def _receipt_pair(
    receipt: Any,
    claimed_digest: Any,
    *,
    normalizer: Any,
    digestor: Any,
    digest_code: str,
    mismatch_code: str,
) -> tuple[dict[str, Any], str]:
    normalized = normalizer(receipt)
    observed = _digest(claimed_digest, code=digest_code)
    try:
        expected = digestor(normalized)
    except lifecycle_receipts.LifecycleReceiptError as exc:
        raise _error(
            "lifecycle_supervisor_lifecycle_receipt_invalid"
        ) from exc
    if not hmac.compare_digest(observed, expected):
        raise _error(mismatch_code)
    return normalized, expected


def _normalize_get_activation_result(value: Any) -> dict[str, Any]:
    selected = _strict_mapping(
        value,
        GET_ACTIVATION_RESULT_FIELDS,
        code=(
            "lifecycle_supervisor_get_activation_result_fields_invalid"
        ),
    )
    receipt, receipt_digest = _receipt_pair(
        selected["activation_receipt"],
        selected["activation_receipt_sha256"],
        normalizer=_normalize_activation_receipt,
        digestor=lifecycle_receipts.activation_receipt_sha256,
        digest_code=(
            "lifecycle_supervisor_activation_receipt_sha256_invalid"
        ),
        mismatch_code=(
            "lifecycle_supervisor_activation_receipt_digest_mismatch"
        ),
    )
    return {
        "activation_receipt": receipt,
        "activation_receipt_sha256": receipt_digest,
    }


def _normalize_start_scope_result(value: Any) -> dict[str, Any]:
    selected = _strict_mapping(
        value,
        START_SCOPE_RESULT_FIELDS,
        code="lifecycle_supervisor_start_scope_result_fields_invalid",
    )
    receipt, receipt_digest = _receipt_pair(
        selected["scope_started_receipt"],
        selected["scope_started_receipt_sha256"],
        normalizer=_normalize_scope_started_receipt,
        digestor=lifecycle_receipts.scope_started_receipt_sha256,
        digest_code=(
            "lifecycle_supervisor_scope_started_receipt_sha256_invalid"
        ),
        mismatch_code=(
            "lifecycle_supervisor_scope_started_digest_mismatch"
        ),
    )
    return {
        "scope_started_receipt": receipt,
        "scope_started_receipt_sha256": receipt_digest,
        "ledger_head_sha256": _digest(
            selected["ledger_head_sha256"],
            code="lifecycle_supervisor_ledger_head_sha256_invalid",
        ),
    }


def _normalize_event_evidence_sha256(
    event: str,
    value: Any,
) -> str | None:
    evidence = _nullable_digest(
        value,
        code=(
            "lifecycle_supervisor_capture_event_"
            "evidence_sha256_invalid"
        ),
    )
    if (event == "capture_ready") is not (evidence is not None):
        raise _error(
            "lifecycle_supervisor_capture_event_evidence_shape_invalid"
        )
    return evidence


def _normalize_await_capture_event_result(
    value: Any,
) -> dict[str, Any]:
    selected = _strict_mapping(
        value,
        AWAIT_CAPTURE_EVENT_RESULT_FIELDS,
        code=(
            "lifecycle_supervisor_await_capture_event_result_fields_invalid"
        ),
    )
    session_id, scope_id, incarnation = _scope_common(selected)
    event = _token(
        selected["event"],
        permitted=CAPTURE_EVENTS,
        code="lifecycle_supervisor_capture_event_invalid",
    )
    return {
        "capture_session_id": session_id,
        "lifecycle_scope_id": scope_id,
        "scope_incarnation_id": incarnation,
        "scope_started_receipt_sha256": _digest(
            selected["scope_started_receipt_sha256"],
            code=(
                "lifecycle_supervisor_scope_started_receipt_sha256_invalid"
            ),
        ),
        "event_sequence": _positive_integer(
            selected["event_sequence"],
            code="lifecycle_supervisor_event_sequence_invalid",
        ),
        "event": event,
        "event_record_sha256": _digest(
            selected["event_record_sha256"],
            code="lifecycle_supervisor_event_record_sha256_invalid",
        ),
        "event_evidence_sha256": _normalize_event_evidence_sha256(
            event,
            selected["event_evidence_sha256"],
        ),
        "ledger_head_sha256": _digest(
            selected["ledger_head_sha256"],
            code="lifecycle_supervisor_ledger_head_sha256_invalid",
        ),
    }


def _normalize_request_clearance_result(
    value: Any,
) -> dict[str, Any]:
    selected = _strict_mapping(
        value,
        REQUEST_CLEARANCE_RESULT_FIELDS,
        code=(
            "lifecycle_supervisor_request_clearance_result_fields_invalid"
        ),
    )
    bundle, bundle_digest = _receipt_pair(
        selected["clearance_bundle"],
        selected["clearance_bundle_sha256"],
        normalizer=_normalize_clearance_bundle,
        digestor=lifecycle_receipts.clearance_bundle_sha256,
        digest_code=(
            "lifecycle_supervisor_clearance_bundle_sha256_invalid"
        ),
        mismatch_code=(
            "lifecycle_supervisor_clearance_bundle_digest_mismatch"
        ),
    )
    return {
        "clearance_bundle": bundle,
        "clearance_bundle_sha256": bundle_digest,
        "ledger_head_sha256": _digest(
            selected["ledger_head_sha256"],
            code="lifecycle_supervisor_ledger_head_sha256_invalid",
        ),
    }


def _normalize_recover_scope_result(value: Any) -> dict[str, Any]:
    selected = _strict_mapping(
        value,
        RECOVER_SCOPE_RESULT_FIELDS,
        code="lifecycle_supervisor_recover_scope_result_fields_invalid",
    )
    session_id, scope_id, incarnation = _scope_common(selected)
    recovery_state = _token(
        selected["recovery_state"],
        permitted=RECOVERY_STATES,
        code="lifecycle_supervisor_recovery_state_invalid",
    )
    raw_event_values = (
        selected["event_sequence"],
        selected["event"],
        selected["event_record_sha256"],
        selected["event_evidence_sha256"],
    )
    if recovery_state == "capture_event":
        if any(value is None for value in raw_event_values[:3]):
            raise _error(
                "lifecycle_supervisor_recovery_event_shape_invalid"
            )
        event_sequence = _positive_integer(
            selected["event_sequence"],
            code="lifecycle_supervisor_event_sequence_invalid",
        )
        event = _token(
            selected["event"],
            permitted=CAPTURE_EVENTS,
            code="lifecycle_supervisor_capture_event_invalid",
        )
        event_record_sha256 = _digest(
            selected["event_record_sha256"],
            code="lifecycle_supervisor_event_record_sha256_invalid",
        )
        event_evidence_sha256 = _normalize_event_evidence_sha256(
            event,
            selected["event_evidence_sha256"],
        )
    else:
        if any(value is not None for value in raw_event_values):
            raise _error(
                "lifecycle_supervisor_recovery_event_shape_invalid"
            )
        event_sequence = None
        event = None
        event_record_sha256 = None
        event_evidence_sha256 = None
    raw_started = selected["scope_started_receipt"]
    raw_started_digest = selected["scope_started_receipt_sha256"]
    if raw_started is None:
        if raw_started_digest is not None:
            raise _error(
                "lifecycle_supervisor_scope_started_pair_invalid"
            )
        started = None
        started_digest = None
    else:
        started, started_digest = _receipt_pair(
            raw_started,
            raw_started_digest,
            normalizer=_normalize_scope_started_receipt,
            digestor=lifecycle_receipts.scope_started_receipt_sha256,
            digest_code=(
                "lifecycle_supervisor_scope_started_receipt_sha256_invalid"
            ),
            mismatch_code=(
                "lifecycle_supervisor_scope_started_digest_mismatch"
            ),
        )
    raw_bundle = selected["clearance_bundle"]
    raw_bundle_digest = selected["clearance_bundle_sha256"]
    if raw_bundle is None:
        if raw_bundle_digest is not None:
            raise _error(
                "lifecycle_supervisor_clearance_bundle_pair_invalid"
            )
        bundle = None
        bundle_digest = None
    else:
        bundle, bundle_digest = _receipt_pair(
            raw_bundle,
            raw_bundle_digest,
            normalizer=_normalize_clearance_bundle,
            digestor=lifecycle_receipts.clearance_bundle_sha256,
            digest_code=(
                "lifecycle_supervisor_clearance_bundle_sha256_invalid"
            ),
            mismatch_code=(
                "lifecycle_supervisor_clearance_bundle_digest_mismatch"
            ),
        )
    if recovery_state == "start_intent" and (
        started is not None or bundle is not None
    ):
        raise _error(
            "lifecycle_supervisor_recovery_start_intent_shape_invalid"
        )
    if recovery_state in {"scope_started", "capture_event"} and (
        started is None or bundle is not None
    ):
        raise _error(
            "lifecycle_supervisor_recovery_running_shape_invalid"
        )
    if recovery_state in {
        "clearance_intent",
        "provider_observation",
    } and bundle is not None:
        raise _error(
            "lifecycle_supervisor_recovery_pending_shape_invalid"
        )
    if (recovery_state == "settled_bundle") is not (bundle is not None):
        raise _error(
            "lifecycle_supervisor_recovery_settled_shape_invalid"
        )
    if started is not None and (
        started["capture_session_id"] != session_id
        or started["lifecycle_scope_id"] != scope_id
        or started["scope_incarnation_id"] != incarnation
    ):
        raise _error(
            "lifecycle_supervisor_recovery_started_binding_changed"
        )
    origin = _token(
        selected["effect_origin_state"],
        permitted=EFFECT_ORIGIN_STATES,
        code="lifecycle_supervisor_effect_origin_state_invalid",
    )
    origin_digest = _digest(
        selected["effect_origin_record_sha256"],
        code="lifecycle_supervisor_effect_origin_sha256_invalid",
    )
    if bundle is not None:
        intent = bundle["clearance_intent_receipt"]
        if (
            intent["capture_session_id"] != session_id
            or intent["lifecycle_scope_id"] != scope_id
            or intent["scope_incarnation_id"] != incarnation
            or intent["effect_origin_state"] != origin
            or intent["effect_origin_record_sha256"] != origin_digest
        ):
            raise _error(
                "lifecycle_supervisor_recovery_bundle_binding_changed"
            )
        bundle_started = bundle["scope_started_receipt"]
        bundle_started_digest = bundle[
            "scope_started_receipt_sha256"
        ]
        if started is None:
            started = bundle_started
            started_digest = bundle_started_digest
        elif (
            bundle_started_digest != started_digest
            or bundle_started != started
        ):
            raise _error(
                "lifecycle_supervisor_recovery_started_binding_changed"
            )
    return {
        "recovery_state": recovery_state,
        "capture_session_id": session_id,
        "lifecycle_scope_id": scope_id,
        "scope_incarnation_id": incarnation,
        "ledger_head_sha256": _digest(
            selected["ledger_head_sha256"],
            code="lifecycle_supervisor_ledger_head_sha256_invalid",
        ),
        "scope_started_receipt": started,
        "scope_started_receipt_sha256": started_digest,
        "effect_origin_state": origin,
        "effect_origin_record_revision": _positive_integer(
            selected["effect_origin_record_revision"],
            code=(
                "lifecycle_supervisor_effect_origin_revision_invalid"
            ),
        ),
        "effect_origin_record_sha256": origin_digest,
        "event_sequence": event_sequence,
        "event": event,
        "event_record_sha256": event_record_sha256,
        "event_evidence_sha256": event_evidence_sha256,
        "clearance_bundle": bundle,
        "clearance_bundle_sha256": bundle_digest,
    }


_RESULT_NORMALIZERS = {
    "get_activation": _normalize_get_activation_result,
    "start_scope": _normalize_start_scope_result,
    "await_capture_event": _normalize_await_capture_event_result,
    "request_clearance": _normalize_request_clearance_result,
    "recover_scope": _normalize_recover_scope_result,
}


def normalize_operation_result(
    operation: Any,
    value: Any,
) -> dict[str, Any]:
    selected_operation = _token(
        operation,
        permitted=OPERATIONS,
        code="lifecycle_supervisor_operation_invalid",
    )
    return _RESULT_NORMALIZERS[selected_operation](value)


def normalize_request(value: Any) -> dict[str, Any]:
    selected = _strict_mapping(
        value,
        REQUEST_FIELDS,
        code="lifecycle_supervisor_request_fields_invalid",
    )
    operation = _token(
        selected["operation"],
        permitted=OPERATIONS,
        code="lifecycle_supervisor_operation_invalid",
    )
    return {
        "schema_version": _exact(
            selected["schema_version"],
            REQUEST_SCHEMA,
            code="lifecycle_supervisor_request_schema_invalid",
        ),
        "message_type": _exact(
            selected["message_type"],
            "request",
            code="lifecycle_supervisor_request_type_invalid",
        ),
        "instance_slug": _instance_slug(selected["instance_slug"]),
        "protocol_session_id": _digest(
            selected["protocol_session_id"],
            code="lifecycle_supervisor_protocol_session_id_invalid",
        ),
        "client_incarnation_id": _digest(
            selected["client_incarnation_id"],
            code="lifecycle_supervisor_client_incarnation_id_invalid",
        ),
        "supervisor_incarnation_id": _digest(
            selected["supervisor_incarnation_id"],
            code="lifecycle_supervisor_incarnation_id_invalid",
        ),
        "client_nonce": _digest(
            selected["client_nonce"],
            code="lifecycle_supervisor_client_nonce_invalid",
        ),
        "server_nonce": _digest(
            selected["server_nonce"],
            code="lifecycle_supervisor_server_nonce_invalid",
        ),
        "server_hello_sha256": _digest(
            selected["server_hello_sha256"],
            code="lifecycle_supervisor_server_hello_sha256_invalid",
        ),
        "supervisor_epoch_id": _digest(
            selected["supervisor_epoch_id"],
            code="lifecycle_supervisor_epoch_id_invalid",
        ),
        "host_boot_id_sha256": _digest(
            selected["host_boot_id_sha256"],
            code="lifecycle_supervisor_host_boot_id_sha256_invalid",
        ),
        "request_id": _request_id(selected["request_id"]),
        "sequence": _positive_integer(
            selected["sequence"],
            code="lifecycle_supervisor_request_sequence_invalid",
        ),
        "operation": operation,
        "payload": normalize_operation_payload(
            operation, selected["payload"]
        ),
    }


def request_sha256(value: Any) -> str:
    return sha256_json(normalize_request(value))


def _request_envelope_from_hello(
    server_hello: Mapping[str, Any],
) -> dict[str, Any]:
    server = normalize_server_hello(server_hello)
    return {
        "instance_slug": server["instance_slug"],
        "protocol_session_id": server["protocol_session_id"],
        "client_incarnation_id": server["client_incarnation_id"],
        "supervisor_incarnation_id": server[
            "supervisor_incarnation_id"
        ],
        "client_nonce": server["client_nonce"],
        "server_nonce": server["server_nonce"],
        "server_hello_sha256": server_hello_sha256(server),
        "supervisor_epoch_id": server["supervisor_epoch_id"],
        "host_boot_id_sha256": server["host_boot_id_sha256"],
    }


def build_request(
    server_hello: Any,
    *,
    request_id: str,
    sequence: int,
    operation: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    envelope = _request_envelope_from_hello(
        normalize_server_hello(server_hello)
    )
    return normalize_request(
        {
            "schema_version": REQUEST_SCHEMA,
            "message_type": "request",
            **envelope,
            "request_id": request_id,
            "sequence": sequence,
            "operation": operation,
            "payload": dict(payload),
        }
    )


def _validate_request_measurements(
    request: Mapping[str, Any],
    server: Mapping[str, Any],
) -> None:
    operation = request["operation"]
    payload = request["payload"]
    activation_digest = server["activation_receipt_sha256"]
    if activation_digest is None:
        if operation != "get_activation" or request["sequence"] != 1:
            raise _error(
                "lifecycle_supervisor_activation_discovery_required"
            )
    if operation == "get_activation":
        expected_pairs = (
            (
                "expected_supervisor_policy_sha256",
                "supervisor_policy_sha256",
            ),
            (
                "expected_supervisor_bundle_sha256",
                "supervisor_bundle_sha256",
            ),
            (
                "expected_helper_activation_policy_sha256",
                "helper_activation_policy_sha256",
            ),
            (
                "expected_lifecycle_canary_sha256",
                "lifecycle_canary_sha256",
            ),
        )
        if any(
            payload[payload_field] != server[server_field]
            for payload_field, server_field in expected_pairs
        ) or (
            payload["expected_activation_receipt_sha256"]
            != activation_digest
        ):
            raise _error(
                "lifecycle_supervisor_request_measurement_mismatch"
            )
    elif operation == "start_scope":
        if (
            payload["helper_activation_policy_sha256"]
            != server["helper_activation_policy_sha256"]
            or payload["lifecycle_activation_receipt_sha256"]
            != activation_digest
        ):
            raise _error(
                "lifecycle_supervisor_request_measurement_mismatch"
            )
    # Clearance and recovery carry the activation digest that authorized the
    # durable scope, which can legitimately differ from the current
    # authenticated server activation after a host reboot.  The current
    # activation remains handshake-bound; the old scope activation is bound
    # to the incarnation here and must be checked against the durable ledger
    # by the supervisor implementation.


def validate_request_for_handshake(
    client_hello: Any,
    server_hello: Any,
    request: Any,
) -> dict[str, Any]:
    server = validate_server_hello(client_hello, server_hello)
    normalized = normalize_request(request)
    expected = _request_envelope_from_hello(server)
    if any(normalized[field] != value for field, value in expected.items()):
        raise _error(
            "lifecycle_supervisor_request_handshake_binding_mismatch"
        )
    _validate_request_measurements(normalized, server)
    if normalized["operation"] != "get_activation":
        payload = normalized["payload"]
        scope_activation_digest = (
            payload["lifecycle_activation_receipt_sha256"]
            if normalized["operation"]
            in {"start_scope", "request_clearance", "recover_scope"}
            else server["activation_receipt_sha256"]
        )
        expected_incarnation = derive_scope_incarnation_id(
            instance_slug=normalized["instance_slug"],
            capture_session_id=payload["capture_session_id"],
            child_launch_intent_record_sha256=payload[
                "child_launch_intent_record_sha256"
            ],
            lifecycle_activation_receipt_sha256=scope_activation_digest,
        )
        if not hmac.compare_digest(
            payload["scope_incarnation_id"],
            expected_incarnation,
        ):
            raise _error(
                "lifecycle_supervisor_scope_incarnation_"
                "derivation_mismatch"
            )
    return normalized


def _normalize_error_outcome(value: Any) -> str:
    return _token(
        value,
        permitted=ERROR_OUTCOMES,
        code="lifecycle_supervisor_remote_error_outcome_invalid",
    )


def error_outcome_retryable(value: Any) -> bool:
    """Return whether an error outcome permits replaying the request."""

    return (
        _normalize_error_outcome(value)
        == ERROR_OUTCOME_RETRYABLE_NO_EFFECT
    )


def error_outcome_is_no_effect(value: Any) -> bool:
    """Return whether the supervisor proved the request had no effect."""

    return _normalize_error_outcome(value) in {
        ERROR_OUTCOME_FINAL_NO_EFFECT,
        ERROR_OUTCOME_RETRYABLE_NO_EFFECT,
    }


def error_outcome_requires_recovery(value: Any) -> bool:
    """Return whether the scope must be recovered before proceeding."""

    return (
        _normalize_error_outcome(value)
        == ERROR_OUTCOME_RECOVER_SCOPE_REQUIRED
    )


def error_outcome_requires_operator_attention(value: Any) -> bool:
    """Return whether automated progress must stop for an operator."""

    return (
        _normalize_error_outcome(value)
        == ERROR_OUTCOME_OPERATOR_ATTENTION_REQUIRED
    )


def normalize_response(value: Any) -> dict[str, Any]:
    selected = _strict_mapping(
        value,
        RESPONSE_FIELDS,
        code="lifecycle_supervisor_response_fields_invalid",
    )
    operation = _token(
        selected["operation"],
        permitted=OPERATIONS,
        code="lifecycle_supervisor_operation_invalid",
    )
    status = _token(
        selected["status"],
        permitted=frozenset({"ok", "error"}),
        code="lifecycle_supervisor_response_status_invalid",
    )
    if status == "ok":
        if (
            selected["error_code"] is not None
            or selected["error_outcome"] is not None
            or selected["observed_ledger_head_sha256"] is not None
        ):
            raise _error(
                "lifecycle_supervisor_success_error_fields_invalid"
            )
        result = normalize_operation_result(
            operation, selected["result"]
        )
        error_code = None
        error_outcome = None
        observed_ledger_head_sha256 = None
    else:
        if selected["result"] is not None:
            raise _error(
                "lifecycle_supervisor_error_result_must_be_null"
            )
        error_code_raw = selected["error_code"]
        if (
            not isinstance(error_code_raw, str)
            or not ERROR_CODE_RE.fullmatch(error_code_raw)
            or error_code_raw not in _REMOTE_ERROR_CODES
        ):
            raise _error(
                "lifecycle_supervisor_remote_error_code_invalid"
            )
        error_code = error_code_raw
        permitted_outcomes = _ERROR_OUTCOMES_BY_OPERATION_CODE[
            operation
        ].get(error_code)
        if permitted_outcomes is None:
            raise _error(
                "lifecycle_supervisor_remote_error_operation_invalid"
            )
        error_outcome = _normalize_error_outcome(
            selected["error_outcome"]
        )
        if error_outcome not in permitted_outcomes:
            raise _error(
                "lifecycle_supervisor_remote_error_outcome_invalid"
            )
        observed_ledger_head_sha256 = _nullable_digest(
            selected["observed_ledger_head_sha256"],
            code=(
                "lifecycle_supervisor_observed_ledger_"
                "head_sha256_invalid"
            ),
        )
        if (
            operation in {"get_activation", "start_scope"}
            and error_outcome
            in {
                ERROR_OUTCOME_FINAL_NO_EFFECT,
                ERROR_OUTCOME_RETRYABLE_NO_EFFECT,
            }
            and observed_ledger_head_sha256 is not None
        ):
            raise _error(
                "lifecycle_supervisor_remote_error_ledger_head_invalid"
            )
        result = None
    return {
        "schema_version": _exact(
            selected["schema_version"],
            RESPONSE_SCHEMA,
            code="lifecycle_supervisor_response_schema_invalid",
        ),
        "message_type": _exact(
            selected["message_type"],
            "response",
            code="lifecycle_supervisor_response_type_invalid",
        ),
        "instance_slug": _instance_slug(selected["instance_slug"]),
        "protocol_session_id": _digest(
            selected["protocol_session_id"],
            code="lifecycle_supervisor_protocol_session_id_invalid",
        ),
        "client_incarnation_id": _digest(
            selected["client_incarnation_id"],
            code="lifecycle_supervisor_client_incarnation_id_invalid",
        ),
        "supervisor_incarnation_id": _digest(
            selected["supervisor_incarnation_id"],
            code="lifecycle_supervisor_incarnation_id_invalid",
        ),
        "client_nonce": _digest(
            selected["client_nonce"],
            code="lifecycle_supervisor_client_nonce_invalid",
        ),
        "server_nonce": _digest(
            selected["server_nonce"],
            code="lifecycle_supervisor_server_nonce_invalid",
        ),
        "server_hello_sha256": _digest(
            selected["server_hello_sha256"],
            code="lifecycle_supervisor_server_hello_sha256_invalid",
        ),
        "supervisor_epoch_id": _digest(
            selected["supervisor_epoch_id"],
            code="lifecycle_supervisor_epoch_id_invalid",
        ),
        "host_boot_id_sha256": _digest(
            selected["host_boot_id_sha256"],
            code="lifecycle_supervisor_host_boot_id_sha256_invalid",
        ),
        "request_id": _request_id(selected["request_id"]),
        "sequence": _positive_integer(
            selected["sequence"],
            code="lifecycle_supervisor_request_sequence_invalid",
        ),
        "operation": operation,
        "request_sha256": _digest(
            selected["request_sha256"],
            code="lifecycle_supervisor_request_sha256_invalid",
        ),
        "status": status,
        "result": result,
        "error_code": error_code,
        "error_outcome": error_outcome,
        "observed_ledger_head_sha256": (
            observed_ledger_head_sha256
        ),
    }


def _response_envelope_from_request(
    request: Mapping[str, Any],
) -> dict[str, Any]:
    normalized = normalize_request(request)
    return {
        field: normalized[field]
        for field in (
            "instance_slug",
            "protocol_session_id",
            "client_incarnation_id",
            "supervisor_incarnation_id",
            "client_nonce",
            "server_nonce",
            "server_hello_sha256",
            "supervisor_epoch_id",
            "host_boot_id_sha256",
            "request_id",
            "sequence",
            "operation",
        )
    }


def build_success_response(
    request: Any,
    *,
    result: Mapping[str, Any],
) -> dict[str, Any]:
    normalized_request = normalize_request(request)
    return normalize_response(
        {
            "schema_version": RESPONSE_SCHEMA,
            "message_type": "response",
            **_response_envelope_from_request(normalized_request),
            "request_sha256": request_sha256(normalized_request),
            "status": "ok",
            "result": dict(result),
            "error_code": None,
            "error_outcome": None,
            "observed_ledger_head_sha256": None,
        }
    )


def _validate_error_response_for_request(
    request: Mapping[str, Any],
    response: Mapping[str, Any],
) -> None:
    operation = request["operation"]
    error_outcome = response["error_outcome"]
    if (
        operation == "recover_scope"
        and response["error_code"] == "scope_not_found"
    ):
        expected_head = request["payload"][
            "expected_ledger_head_sha256"
        ]
        if expected_head is None:
            if error_outcome != ERROR_OUTCOME_FINAL_NO_EFFECT:
                raise _error(
                    "lifecycle_supervisor_remote_error_outcome_invalid"
                )
        else:
            if (
                error_outcome
                != ERROR_OUTCOME_OPERATOR_ATTENTION_REQUIRED
            ):
                raise _error(
                    "lifecycle_supervisor_remote_error_outcome_invalid"
                )
            return

    if error_outcome not in {
        ERROR_OUTCOME_FINAL_NO_EFFECT,
        ERROR_OUTCOME_RETRYABLE_NO_EFFECT,
    }:
        return

    if operation in {"get_activation", "start_scope"}:
        expected_head = None
    else:
        expected_head = request["payload"][
            "expected_ledger_head_sha256"
        ]
    observed_head = response["observed_ledger_head_sha256"]
    if expected_head is None or observed_head is None:
        head_matches = expected_head is observed_head
    else:
        head_matches = hmac.compare_digest(
            expected_head, observed_head
        )
    if not head_matches:
        raise _error(
            "lifecycle_supervisor_remote_error_ledger_head_mismatch"
        )


def build_error_response(
    request: Any,
    *,
    error_code: str,
    error_outcome: str,
    observed_ledger_head_sha256: str | None,
) -> dict[str, Any]:
    normalized_request = normalize_request(request)
    response = normalize_response(
        {
            "schema_version": RESPONSE_SCHEMA,
            "message_type": "response",
            **_response_envelope_from_request(normalized_request),
            "request_sha256": request_sha256(normalized_request),
            "status": "error",
            "result": None,
            "error_code": error_code,
            "error_outcome": error_outcome,
            "observed_ledger_head_sha256": (
                observed_ledger_head_sha256
            ),
        }
    )
    _validate_error_response_for_request(
        normalized_request, response
    )
    return response


def _validate_scope_result_binding(
    payload: Mapping[str, Any],
    result: Mapping[str, Any],
) -> None:
    for field in (
        "capture_session_id",
        "lifecycle_scope_id",
        "scope_incarnation_id",
    ):
        if result[field] != payload[field]:
            raise _error(
                "lifecycle_supervisor_response_scope_binding_mismatch"
            )


def _validate_success_result_for_request(
    request: Mapping[str, Any],
    result: Mapping[str, Any],
    server: Mapping[str, Any],
) -> None:
    operation = request["operation"]
    payload = request["payload"]
    if operation == "get_activation":
        receipt = result["activation_receipt"]
        digest = result["activation_receipt_sha256"]
        expected = payload["expected_activation_receipt_sha256"]
        if expected is not None and digest != expected:
            raise _error(
                "lifecycle_supervisor_activation_receipt_changed"
            )
        fields = (
            ("supervisor_policy_sha256", "supervisor_policy_sha256"),
            ("supervisor_bundle_sha256", "supervisor_bundle_sha256"),
            (
                "helper_activation_policy_sha256",
                "helper_activation_policy_sha256",
            ),
            ("lifecycle_canary_sha256", "lifecycle_canary_sha256"),
            ("host_boot_id_sha256", "host_boot_id_sha256"),
        )
        if any(
            receipt[receipt_field] != server[server_field]
            for receipt_field, server_field in fields
        ) or (
            server["activation_receipt_sha256"] is not None
            and digest != server["activation_receipt_sha256"]
        ):
            raise _error(
                "lifecycle_supervisor_activation_binding_mismatch"
            )
    elif operation == "start_scope":
        receipt = result["scope_started_receipt"]
        _validate_scope_result_binding(payload, receipt)
        pairs = (
            "staging_transaction_intent_sha256",
            "staging_exposure_receipt_sha256",
            "child_launch_intent_record_sha256",
            "handoff_policy_sha256",
            "helper_activation_policy_sha256",
            "lifecycle_provider",
            "capture_uid",
            "export_gid",
            "lifecycle_activation_receipt_sha256",
        )
        if any(receipt[field] != payload[field] for field in pairs) or (
            receipt["supervisor_epoch_id"]
            != server["supervisor_epoch_id"]
        ) or (
            receipt["host_boot_id_sha256"]
            != server["host_boot_id_sha256"]
        ):
            raise _error(
                "lifecycle_supervisor_scope_started_binding_mismatch"
            )
    elif operation == "await_capture_event":
        _validate_scope_result_binding(payload, result)
        if (
            result["scope_started_receipt_sha256"]
            != payload["scope_started_receipt_sha256"]
            or result["event_sequence"]
            <= payload["after_event_sequence"]
        ):
            raise _error(
                "lifecycle_supervisor_capture_event_binding_mismatch"
            )
    elif operation == "request_clearance":
        bundle = result["clearance_bundle"]
        intent = bundle["clearance_intent_receipt"]
        _validate_scope_result_binding(payload, intent)
        request_to_intent = (
            (
                "lifecycle_activation_receipt_sha256",
                "lifecycle_activation_receipt_sha256",
            ),
            (
                "child_launch_intent_record_sha256",
                "child_launch_intent_record_sha256",
            ),
            ("effect_origin_state", "effect_origin_state"),
            (
                "effect_origin_record_sha256",
                "effect_origin_record_sha256",
            ),
            (
                "scope_started_receipt_sha256",
                "scope_started_receipt_sha256",
            ),
            ("clearance_mode", "clearance_mode"),
            (
                "lifecycle_clearance_intent_record_sha256",
                "outer_clearance_intent_record_sha256",
            ),
        )
        if any(
            payload[payload_field] != intent[intent_field]
            for payload_field, intent_field in request_to_intent
        ):
            raise _error(
                "lifecycle_supervisor_clearance_binding_mismatch"
            )
    else:
        _validate_scope_result_binding(payload, result)
        started_receipt = result["scope_started_receipt"]
        expected_started = payload[
            "expected_scope_started_receipt_sha256"
        ]
        if expected_started is not None and (
            started_receipt is None
            or result["scope_started_receipt_sha256"]
            != expected_started
        ):
            raise _error(
                "lifecycle_supervisor_recovery_started_binding_mismatch"
            )
        if started_receipt is not None:
            observed_start_authorization = (
                derive_scope_start_authorization_sha256(
                    instance_slug=request["instance_slug"],
                    capture_session_id=started_receipt[
                        "capture_session_id"
                    ],
                    scope_incarnation_id=started_receipt[
                        "scope_incarnation_id"
                    ],
                    child_launch_intent_record_revision=payload[
                        "child_launch_intent_record_revision"
                    ],
                    child_launch_intent_record_sha256=started_receipt[
                        "child_launch_intent_record_sha256"
                    ],
                    staging_transaction_intent_sha256=started_receipt[
                        "staging_transaction_intent_sha256"
                    ],
                    staging_exposure_receipt_sha256=started_receipt[
                        "staging_exposure_receipt_sha256"
                    ],
                    handoff_policy_sha256=started_receipt[
                        "handoff_policy_sha256"
                    ],
                    helper_activation_policy_sha256=started_receipt[
                        "helper_activation_policy_sha256"
                    ],
                    lifecycle_provider=started_receipt[
                        "lifecycle_provider"
                    ],
                    capture_uid=started_receipt["capture_uid"],
                    export_gid=started_receipt["export_gid"],
                    lifecycle_activation_receipt_sha256=started_receipt[
                        "lifecycle_activation_receipt_sha256"
                    ],
                    activation_host_boot_id_sha256=started_receipt[
                        "host_boot_id_sha256"
                    ],
                )
            )
            if not hmac.compare_digest(
                observed_start_authorization,
                payload[
                    "expected_scope_start_authorization_sha256"
                ],
            ):
                raise _error(
                    "lifecycle_supervisor_recovery_start_"
                    "authorization_mismatch"
                )
        if (
            result["effect_origin_record_revision"]
            > payload["outer_journal_record_revision"]
        ):
            raise _error(
                "lifecycle_supervisor_recovery_future_outer_record"
            )
        if (
            result["effect_origin_state"]
            != payload["expected_effect_origin_state"]
            or result["effect_origin_record_revision"]
            != payload["expected_effect_origin_record_revision"]
            or result["effect_origin_record_sha256"]
            != payload["expected_effect_origin_record_sha256"]
        ):
            raise _error(
                "lifecycle_supervisor_recovery_outer_binding_mismatch"
            )
        bundle = result["clearance_bundle"]
        if bundle is not None:
            # The authenticated current server can replay a bundle settled by
            # an earlier supervisor epoch or host boot.  The historical
            # clearance coordinates are immutable evidence inside the bundle;
            # they must not be rewritten to match this handshake.
            intent = bundle["clearance_intent_receipt"]
            expected_clearance_digest = payload[
                "expected_clearance_intent_record_sha256"
            ]
            expected_intent_started = (
                None
                if payload["expected_effect_origin_state"]
                == "child_launch_intent"
                else result["scope_started_receipt_sha256"]
            )
            if (
                expected_clearance_digest is None
                or bundle["activation_receipt_sha256"]
                != payload["lifecycle_activation_receipt_sha256"]
                or intent["lifecycle_activation_receipt_sha256"]
                != payload["lifecycle_activation_receipt_sha256"]
                or intent["child_launch_intent_record_sha256"]
                != payload["child_launch_intent_record_sha256"]
                or intent["effect_origin_state"]
                != payload["expected_effect_origin_state"]
                or intent["effect_origin_record_sha256"]
                != payload["expected_effect_origin_record_sha256"]
                or intent["scope_started_receipt_sha256"]
                != expected_intent_started
                or intent["outer_clearance_intent_record_sha256"]
                != expected_clearance_digest
                or intent["clearance_mode"]
                != payload["expected_clearance_mode"]
            ):
                raise _error(
                    "lifecycle_supervisor_recovery_bundle_"
                    "authorization_mismatch"
                )


def validate_response_for_request(
    client_hello: Any,
    server_hello: Any,
    request: Any,
    response: Any,
) -> dict[str, Any]:
    server = validate_server_hello(client_hello, server_hello)
    normalized_request = validate_request_for_handshake(
        client_hello, server, request
    )
    normalized_response = normalize_response(response)
    expected_envelope = _response_envelope_from_request(
        normalized_request
    )
    if any(
        normalized_response[field] != value
        for field, value in expected_envelope.items()
    ) or not hmac.compare_digest(
        normalized_response["request_sha256"],
        request_sha256(normalized_request),
    ):
        raise _error(
            "lifecycle_supervisor_response_correlation_mismatch"
        )
    if normalized_response["status"] == "ok":
        _validate_success_result_for_request(
            normalized_request,
            normalized_response["result"],
            server,
        )
    else:
        _validate_error_response_for_request(
            normalized_request,
            normalized_response,
        )
    return normalized_response


class ServerRequestGuard:
    """Stateful, monotonically sequenced request replay guard."""

    __slots__ = (
        "_client_hello",
        "_server_hello",
        "_next_sequence",
        "_discovery_only",
        "_closed",
    )

    def __init__(self, client_hello: Any, server_hello: Any) -> None:
        self._client_hello = normalize_client_hello(client_hello)
        self._server_hello = validate_server_hello(
            self._client_hello, server_hello
        )
        self._next_sequence = 1
        self._discovery_only = (
            self._server_hello["activation_receipt_sha256"] is None
        )
        self._closed = False

    def accept(self, request: Any) -> dict[str, Any]:
        if self._closed:
            raise _error("lifecycle_supervisor_session_closed")
        normalized = validate_request_for_handshake(
            self._client_hello,
            self._server_hello,
            request,
        )
        if normalized["sequence"] != self._next_sequence:
            raise _error(
                "lifecycle_supervisor_request_sequence_replayed"
            )
        self._next_sequence += 1
        if self._discovery_only:
            self._closed = True
        return normalized


class ClientExchangeGuard:
    """One-in-flight client correlation guard with replay rejection."""

    __slots__ = (
        "_client_hello",
        "_server_hello",
        "_next_sequence",
        "_pending",
        "_discovery_only",
        "_closed",
    )

    def __init__(self, client_hello: Any, server_hello: Any) -> None:
        self._client_hello = normalize_client_hello(client_hello)
        self._server_hello = validate_server_hello(
            self._client_hello, server_hello
        )
        self._next_sequence = 1
        self._pending: dict[str, Any] | None = None
        self._discovery_only = (
            self._server_hello["activation_receipt_sha256"] is None
        )
        self._closed = False

    def build_request(
        self,
        *,
        request_id: str,
        operation: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        if self._closed:
            raise _error("lifecycle_supervisor_session_closed")
        if self._pending is not None:
            raise _error(
                "lifecycle_supervisor_request_already_in_flight"
            )
        request = build_request(
            self._server_hello,
            request_id=request_id,
            sequence=self._next_sequence,
            operation=operation,
            payload=payload,
        )
        request = validate_request_for_handshake(
            self._client_hello,
            self._server_hello,
            request,
        )
        self._pending = request
        return request

    def accept_response(self, response: Any) -> dict[str, Any]:
        if self._pending is None:
            raise _error(
                "lifecycle_supervisor_response_without_request"
            )
        normalized = validate_response_for_request(
            self._client_hello,
            self._server_hello,
            self._pending,
            response,
        )
        self._pending = None
        self._next_sequence += 1
        if self._discovery_only:
            self._closed = True
        return normalized


__all__ = [
    "ACTIVATION_RECEIPT_SCHEMA",
    "CAPTURE_EVENT_EVIDENCE_FIELDS",
    "CAPTURE_EVENT_EVIDENCE_SCHEMA",
    "CAPTURE_EVENTS",
    "CLEARANCE_BUNDLE_SCHEMA",
    "CLEARANCE_INTENT_RECEIPT_SCHEMA",
    "CLEARANCE_MODES",
    "CLIENT_HELLO_SCHEMA",
    "ClientExchangeGuard",
    "EFFECT_ORIGIN_STATES",
    "ERROR_OUTCOMES",
    "ERROR_OUTCOME_FINAL_NO_EFFECT",
    "ERROR_OUTCOME_OPERATOR_ATTENTION_REQUIRED",
    "ERROR_OUTCOME_RECOVER_SCOPE_REQUIRED",
    "ERROR_OUTCOME_RETRYABLE_NO_EFFECT",
    "FrameDecoder",
    "LifecycleSupervisorProtocolError",
    "MAX_FRAME_BYTES",
    "MAX_TIMEOUT_SECONDS",
    "OPERATIONS",
    "OUTER_RECORD_STATES",
    "PRODUCTION_ACTIVATION",
    "RECOVERY_REASONS",
    "RECOVERY_STATES",
    "REQUEST_SCHEMA",
    "RESPONSE_SCHEMA",
    "SCOPE_INCARNATION_DERIVATION_SCHEMA",
    "SCOPE_START_AUTHORIZATION_SCHEMA",
    "SCOPE_EMPTY_RECEIPT_SCHEMA",
    "SCOPE_STARTED_RECEIPT_SCHEMA",
    "SERVER_HELLO_SCHEMA",
    "ServerRequestGuard",
    "build_client_hello",
    "build_error_response",
    "build_request",
    "build_server_hello",
    "build_success_response",
    "canonical_json",
    "capture_event_evidence_sha256",
    "client_hello_sha256",
    "decode_frame",
    "derive_scope_incarnation_id",
    "derive_scope_start_authorization_sha256",
    "encode_frame",
    "error_outcome_is_no_effect",
    "error_outcome_requires_operator_attention",
    "error_outcome_requires_recovery",
    "error_outcome_retryable",
    "normalize_client_hello",
    "normalize_operation_payload",
    "normalize_operation_result",
    "normalize_request",
    "normalize_response",
    "normalize_server_hello",
    "parse_canonical_json",
    "request_sha256",
    "server_hello_sha256",
    "sha256_json",
    "validate_request_for_handshake",
    "validate_response_for_request",
    "validate_server_hello",
]
