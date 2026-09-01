#!/usr/bin/env python3
"""Role-neutral wire contract for protected qualification capture.

This module is the complete dependency shared by the privileged coordinator
and the sandboxed capture child.  It deliberately imports only Python's
standard library and has no knowledge of capture plans, opaque evidence,
sandbox construction, identities, signing, or adoption.

The contract is a length-prefixed canonical-JSON stream with one strict state
machine.  Keeping it in a separate module lets an installed native bundle
measure the coordinator and child dependency closures independently without
silently giving either role the other's implementation.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import select
import struct
import time
from collections.abc import Callable, Mapping
from typing import Any


# V1 is retained only for the existing dormant, long-lived-child compatibility
# path.  New capture/adoption work must use HANDOFF_PROTOCOL_SCHEMA: unlike v1,
# the child emits one sealed provisional object and exits before root adopts
# it.  Keeping both constants explicit prevents an old parser from silently
# accepting new identity semantics.
LEGACY_PROTOCOL_SCHEMA = (
    "john-lomein.persona.capture-helper-protocol.v1"
)
PROTOCOL_SCHEMA = LEGACY_PROTOCOL_SCHEMA
HANDOFF_PROTOCOL_SCHEMA = (
    "john-lomein.persona.capture-helper-protocol.v2"
)

MAX_CONTROL_FRAME_BYTES = 4 * 1024
MAX_EVENT_FRAME_BYTES = 4 * 1024
# The plan contract currently permits 256 KiB.  The wire cap is deliberately
# fixed here rather than imported from the plan implementation: changing the
# plan limit must not silently change an already-versioned protocol.
MAX_INITIALIZATION_FRAME_BYTES = (256 * 1024) + (32 * 1024)
MAX_TIMEOUT_SECONDS = 900
POLL_INTERVAL_SECONDS = 0.01

SESSION_ID_RE = re.compile(r"^[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REASON_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,95}$")

INIT_FIELDS = frozenset(
    {
        "schema_version",
        "session_id",
        "sequence",
        "command",
        "capture_plan",
        "capture_plan_sha256",
        "destination_parent",
        "helper_uid",
        "helper_gid",
        "timeout_seconds",
    }
)
COMMAND_FIELDS = frozenset(
    {
        "schema_version",
        "session_id",
        "sequence",
        "command",
        "artifact_sha256",
        "reason_code",
    }
)
READY_FIELDS = frozenset(
    {
        "schema_version",
        "session_id",
        "sequence",
        "event",
        "capture_root",
        "capture_plan_sha256",
        "capture_manifest_sha256",
    }
)
EVENT_FIELDS = frozenset(
    {
        "schema_version",
        "session_id",
        "sequence",
        "event",
        "artifact_sha256",
    }
)
ERROR_FIELDS = frozenset(
    {
        "schema_version",
        "session_id",
        "sequence",
        "event",
        "error_code",
    }
)

HANDOFF_INIT_FIELDS = frozenset(
    {
        "schema_version",
        "session_id",
        "sequence",
        "command",
        "capture_plan",
        "capture_plan_sha256",
        "capture_selection_sha256",
        "capture_boundary_policy_sha256",
        "helper_activation_policy_sha256",
        "destination_parent",
        "evidence_uid",
        "capture_uid",
        "export_gid",
        "verifier_uid",
        "verifier_gid",
        "timeout_seconds",
        "request_sha256",
    }
)
HANDOFF_READY_FIELDS = frozenset(
    {
        "schema_version",
        "session_id",
        "sequence",
        "event",
        "provisional_name",
        "capture_plan_sha256",
        "capture_selection_sha256",
        "capture_manifest_sha256",
        "capture_boundary_policy_sha256",
        "helper_activation_policy_sha256",
        "request_sha256",
        "object_identity_sha256",
    }
)
HANDOFF_ERROR_FIELDS = frozenset(
    {
        "schema_version",
        "session_id",
        "sequence",
        "event",
        "request_sha256",
        "error_code",
    }
)
HANDOFF_REQUEST_DIGEST_FIELDS = (
    HANDOFF_INIT_FIELDS - {"request_sha256"}
)

COMMAND_TRANSITIONS: dict[str, tuple[str, str, str, bool]] = {
    # command: (required state, next state, event, digest required)
    "begin_verification": (
        "capture_ready",
        "verification_active",
        "verification_authorized",
        False,
    ),
    "complete_verification": (
        "verification_active",
        "signing_authorized",
        "signing_authorized",
        True,
    ),
    "complete_signing": (
        "signing_authorized",
        "publication_authorized",
        "publication_authorized",
        True,
    ),
    "complete_publication": (
        "publication_authorized",
        "cleaned",
        "cleaned",
        True,
    ),
}


class CaptureHelperError(RuntimeError):
    """Stable, public-safe protocol rejection."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


CaptureProtocolError = CaptureHelperError


def error(code: str) -> CaptureHelperError:
    return CaptureHelperError(code)


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise error("capture_helper_json_invalid") from exc


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise error("capture_helper_json_duplicate_key")
        result[key] = value
    return result


def parse_canonical_json(
    raw: bytes,
    *,
    maximum_bytes: int,
    field: str,
) -> Any:
    if (
        not isinstance(raw, bytes)
        or not raw
        or len(raw) > maximum_bytes
        or b"\x00" in raw
    ):
        raise error(f"{field}_invalid")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite")
            ),
        )
    except CaptureHelperError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise error(f"{field}_invalid") from exc
    if canonical_json(value) != raw:
        raise error(f"{field}_noncanonical")
    return value


def _write_all(
    descriptor: int,
    raw: bytes,
    *,
    deadline: float,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    offset = 0
    try:
        original_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        fcntl.fcntl(
            descriptor,
            fcntl.F_SETFL,
            original_flags | os.O_NONBLOCK,
        )
    except OSError as exc:
        raise error("capture_helper_protocol_write_failed") from exc
    try:
        while offset < len(raw):
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise error("capture_helper_protocol_deadline_exceeded")
            try:
                _, writable, _ = select.select(
                    [],
                    [descriptor],
                    [],
                    min(POLL_INTERVAL_SECONDS, remaining),
                )
            except InterruptedError:
                continue
            except OSError as exc:
                raise error(
                    "capture_helper_protocol_write_failed"
                ) from exc
            if not writable:
                continue
            try:
                written = os.write(
                    descriptor,
                    raw[offset : offset + 64 * 1024],
                )
            except (InterruptedError, BlockingIOError):
                continue
            except OSError as exc:
                raise error(
                    "capture_helper_protocol_write_failed"
                ) from exc
            if written <= 0:
                raise error("capture_helper_protocol_write_failed")
            offset += written
    finally:
        try:
            fcntl.fcntl(descriptor, fcntl.F_SETFL, original_flags)
        except OSError:
            pass


def encode_frame(
    value: Mapping[str, Any],
    *,
    maximum_bytes: int,
) -> bytes:
    if not isinstance(value, Mapping):
        raise error("capture_helper_protocol_message_invalid")
    payload = canonical_json(dict(value))
    if not payload or len(payload) > maximum_bytes:
        raise error("capture_helper_protocol_message_too_large")
    return struct.pack("!I", len(payload)) + payload


def write_frame(
    descriptor: int,
    value: Mapping[str, Any],
    *,
    maximum_bytes: int,
    deadline: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    _write_all(
        descriptor,
        encode_frame(value, maximum_bytes=maximum_bytes),
        deadline=(
            monotonic() + MAX_TIMEOUT_SECONDS
            if deadline is None
            else deadline
        ),
        monotonic=monotonic,
    )


def _read_exact(
    descriptor: int,
    length: int,
    *,
    deadline: float,
    monotonic: Callable[[], float],
) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        timeout = deadline - monotonic()
        if timeout <= 0:
            raise error("capture_helper_protocol_deadline_exceeded")
        try:
            readable, _, _ = select.select(
                [descriptor],
                [],
                [],
                min(POLL_INTERVAL_SECONDS, timeout),
            )
        except InterruptedError:
            continue
        except OSError as exc:
            raise error("capture_helper_protocol_read_failed") from exc
        if not readable:
            continue
        try:
            chunk = os.read(descriptor, remaining)
        except InterruptedError:
            continue
        except OSError as exc:
            raise error("capture_helper_protocol_read_failed") from exc
        if not chunk:
            raise error("capture_helper_protocol_eof")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(
    descriptor: int,
    *,
    maximum_bytes: int,
    deadline: float,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    prefix = _read_exact(
        descriptor,
        4,
        deadline=deadline,
        monotonic=monotonic,
    )
    (length,) = struct.unpack("!I", prefix)
    if length < 2 or length > maximum_bytes:
        raise error("capture_helper_protocol_frame_size_invalid")
    raw = _read_exact(
        descriptor,
        length,
        deadline=deadline,
        monotonic=monotonic,
    )
    value = parse_canonical_json(
        raw,
        maximum_bytes=maximum_bytes,
        field="capture_helper_protocol_message",
    )
    if not isinstance(value, dict):
        raise error("capture_helper_protocol_message_invalid")
    return value


def integer(
    value: Any,
    *,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise error(f"{field}_invalid")
    return value


def digest(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise error(f"{field}_invalid")
    return value


def handoff_request_sha256(value: Any) -> str:
    """Digest every v2 initialization field except the digest itself."""

    if (
        not isinstance(value, Mapping)
        or set(value) != HANDOFF_REQUEST_DIGEST_FIELDS
        or value.get("schema_version") != HANDOFF_PROTOCOL_SCHEMA
    ):
        raise error("capture_handoff_request_fields_invalid")
    return sha256(canonical_json(dict(value)))


def bind_handoff_request(value: Any) -> dict[str, Any]:
    """Return one exact v2 request with its self-binding digest."""

    request_digest = handoff_request_sha256(value)
    return {**dict(value), "request_sha256": request_digest}


def verify_handoff_request_digest(value: Any) -> str:
    """Validate exact v2 fields and return the bound request digest."""

    if not isinstance(value, Mapping) or set(value) != HANDOFF_INIT_FIELDS:
        raise error("capture_handoff_request_fields_invalid")
    observed = digest(
        value.get("request_sha256"),
        field="capture_handoff_request_sha256",
    )
    core = {
        key: item
        for key, item in value.items()
        if key != "request_sha256"
    }
    expected = handoff_request_sha256(core)
    if observed != expected:
        raise error("capture_handoff_request_digest_mismatch")
    return observed


def session_id(value: Any) -> str:
    if not isinstance(value, str) or not SESSION_ID_RE.fullmatch(value):
        raise error("capture_helper_session_id_invalid")
    return value


def handoff_error_record(
    *,
    session: str,
    request_sha256: str,
    error_code: str,
) -> dict[str, Any]:
    if not REASON_CODE_RE.fullmatch(error_code):
        raise error("capture_handoff_error_code_invalid")
    return {
        "schema_version": HANDOFF_PROTOCOL_SCHEMA,
        "session_id": session_id(session),
        "sequence": 0,
        "event": "error",
        "request_sha256": digest(
            request_sha256,
            field="capture_handoff_error_request_sha256",
        ),
        "error_code": error_code,
    }


def event_record(
    *,
    session: str,
    sequence: int,
    name: str,
    artifact_sha256: str | None,
) -> dict[str, Any]:
    return {
        "schema_version": PROTOCOL_SCHEMA,
        "session_id": session,
        "sequence": sequence,
        "event": name,
        "artifact_sha256": artifact_sha256,
    }


def error_record(
    *,
    session: str,
    sequence: int,
    error_code: str,
) -> dict[str, Any]:
    return {
        "schema_version": PROTOCOL_SCHEMA,
        "session_id": session,
        "sequence": sequence,
        "event": "error",
        "error_code": error_code,
    }


class ProtocolMachine:
    """Strict sandbox-child command state and sequence validator."""

    __slots__ = ("session_id", "sequence", "state")

    def __init__(self, session: str) -> None:
        self.session_id = session_id(session)
        self.sequence = 0
        self.state = "capture_ready"

    def accept(self, value: Any) -> tuple[str, str | None, str | None]:
        if not isinstance(value, Mapping) or set(value) != COMMAND_FIELDS:
            raise error("capture_helper_command_fields_invalid")
        if value.get("schema_version") != PROTOCOL_SCHEMA:
            raise error("capture_helper_command_schema_invalid")
        if value.get("session_id") != self.session_id:
            raise error("capture_helper_command_session_mismatch")
        sequence = integer(
            value.get("sequence"),
            field="capture_helper_command_sequence",
            minimum=1,
            maximum=(1 << 53) - 1,
        )
        if sequence != self.sequence + 1:
            raise error("capture_helper_command_sequence_invalid")
        command = value.get("command")
        artifact = value.get("artifact_sha256")
        reason = value.get("reason_code")
        if command == "abort":
            if (
                self.state in {"cleaned", "aborted"}
                or artifact is not None
                or not isinstance(reason, str)
                or not REASON_CODE_RE.fullmatch(reason)
            ):
                raise error("capture_helper_abort_invalid")
            self.sequence = sequence
            self.state = "aborted"
            return command, None, reason
        transition = COMMAND_TRANSITIONS.get(command)
        if transition is None:
            raise error("capture_helper_command_invalid")
        required, next_state, _event, digest_required = transition
        if self.state != required:
            raise error("capture_helper_command_out_of_order")
        if reason is not None:
            raise error("capture_helper_command_reason_unexpected")
        if digest_required:
            artifact = digest(
                artifact,
                field="capture_helper_command_artifact_sha256",
            )
        elif artifact is not None:
            raise error("capture_helper_command_artifact_unexpected")
        self.sequence = sequence
        self.state = next_state
        return command, artifact, None
