#!/usr/bin/env python3
"""Crash-durable core ledger for the protected lifecycle supervisor.

This module is intentionally *not* a daemon, launcher, process reaper, or IPC
endpoint.  It owns only a root-controlled, append-only decision ledger and the
pure state transitions needed to turn trusted provider observations into the
path-free receipt grammar defined by ``lifecycle_receipts``.

No record contains a process identifier, signal, executable, argument vector,
or filesystem path.  The store path is deployment configuration supplied when
the root service opens its private state directory; it is never session
authority.  Production activation remains disabled until a separately
measured daemon, authenticated protocol, and privileged canary exist.

Settled histories remain exact-replayable and are deliberately not deleted.
Safe retirement requires a one-shot authority minted from the durable outer
transaction journal after it has accepted the lifecycle bundle.  Until that
cross-process capability exists, admission closes at the bounded session
limit instead of trusting a caller-supplied acknowledgement digest.
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
import unicodedata
from collections.abc import Callable, Mapping
from functools import wraps
from pathlib import Path
from typing import Any

from qualification_attestor import (
    john_lomein_persona_qualification_lifecycle_receipts
    as lifecycle_receipts,
)


PRODUCTION_ACTIVATION = False

LEDGER_RECORD_SCHEMA = (
    "john-lomein.persona-qualification-lifecycle-supervisor-ledger.v1"
)
SCOPE_INCARNATION_ID_CONTRACT = "protocol_derived_stable_digest"
PRODUCTION_BLOCKERS = frozenset(
    {
        "lifecycle_terminal_retirement_authority_missing",
        "lifecycle_privileged_provider_adapter_missing",
        "lifecycle_privileged_canary_missing",
    }
)

STORE_MODE = 0o700
LOCK_FILE_MODE = 0o600
SESSION_DIRECTORY_MODE = 0o700
TEMP_FILE_MODE = 0o600
RECORD_FILE_MODE = 0o400

MAX_RECORD_BYTES = 128 * 1024
MAX_RECORDS_PER_SESSION = 8
MAX_SESSION_DIRECTORIES = 4_096
MAX_STALE_TEMP_FILES = 8
MAX_STDERR_BYTES = lifecycle_receipts.MAX_STDERR_BYTES

ZERO_SHA256 = "0" * 64
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SESSION_DIRECTORY_RE = re.compile(
    r"^session-([0-9a-f]{64})-([0-9a-f]{64})$"
)
TEMP_FILE_RE = re.compile(r"^\.tmp-([0-9a-f]{32})$")
EVENT_FILE_RE = re.compile(
    r"^([0-9]{6})-([a-z][a-z0-9_]*)-([0-9a-f]{64})\.json$"
)
REASON_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
INSTANCE_SLUG_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$"
)

STATES = (
    "start_intent",
    "scope_started",
    "capture_event",
    "clearance_intent",
    "provider_observation",
    "settled_bundle",
    "operator_attention",
)
STATE_SET = frozenset(STATES)
TERMINAL_STATES = frozenset({"settled_bundle", "operator_attention"})

CAPTURE_EVENT_ORIGINS = frozenset({"child_running", "capture_ready"})
PROVIDER_OBSERVATION_KINDS = frozenset(
    {
        "scope_absent",
        "clean_exit",
        "abnormal_exit",
        "forced_scope_empty",
        "scope_empty_unobserved",
    }
)
STDERR_OBSERVATION_KINDS = frozenset(
    {"clean_exit", "abnormal_exit", "forced_scope_empty"}
)
RECOVERY_ACTIONS = frozenset(
    {
        "request_clearance",
        "observe_provider",
        "settle_bundle",
        "complete",
        "operator_attention",
    }
)

DIRECT_WAIT_RESTART_REASON = (
    "direct_wait_same_boot_restart_authority_lost"
)
HOST_EPOCH_INCOHERENT_REASON = "host_boot_changed_epoch_unchanged"
REBOOT_OBSERVATION_REASON = "host_reboot_observation_incompatible"
EXIT_EPOCH_REASON = "exit_observation_after_supervisor_restart"
ABSENCE_EPOCH_REASON = "scope_absence_without_restart_evidence"

FORBIDDEN_FIELD_PARTS = frozenset(
    {
        "argv",
        "command",
        "executable",
        "key",
        "path",
        "pgid",
        "pid",
        "signal",
    }
)

RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "capture_session_id",
        "scope_incarnation_id",
        "revision",
        "previous_record_sha256",
        "state",
        "recorded_at_unix",
        "operation_request_sha256",
        "operation_id_sha256",
        "details",
        "record_sha256",
    }
)

START_INTENT_FIELDS = frozenset(
    {
        "activation_receipt",
        "activation_receipt_sha256",
        "instance_slug",
        "instance_control_sha256",
        "lifecycle_provider",
        "lifecycle_scope_id",
        "start_supervisor_epoch_id",
        "start_host_boot_id_sha256",
        "staging_transaction_intent_sha256",
        "staging_exposure_receipt_sha256",
        "child_launch_intent_record_revision",
        "child_launch_intent_record_sha256",
        "handoff_policy_sha256",
        "helper_activation_policy_sha256",
        "capture_uid",
        "export_gid",
    }
)
SCOPE_STARTED_FIELDS = frozenset(
    {
        "provider_start_observation_sha256",
        "scope_started_receipt",
        "scope_started_receipt_sha256",
    }
)
CAPTURE_EVENT_FIELDS = frozenset(
    {
        "effect_origin_state",
        "effect_origin_record_revision",
        "effect_origin_record_sha256",
        "scope_started_receipt_sha256",
    }
)
CLEARANCE_INTENT_FIELDS = frozenset(
    {
        "clearance_intent_receipt",
        "clearance_intent_receipt_sha256",
        "effect_origin_record_revision",
        "outer_clearance_intent_record_revision",
    }
)
OBSERVATION_FIELDS = frozenset(
    {
        "observation_kind",
        "provider_observation_sha256",
        "observed_supervisor_epoch_id",
        "observed_host_boot_id_sha256",
        "stderr_bytes",
        "stderr_sha256",
    }
)
PROVIDER_OBSERVATION_FIELDS = frozenset(
    {
        "observation",
        "scope_empty_receipt",
        "scope_empty_receipt_sha256",
    }
)
SETTLED_BUNDLE_FIELDS = frozenset(
    {
        "provider_observation_record_sha256",
        "clearance_bundle",
        "clearance_bundle_sha256",
    }
)
OPERATOR_ATTENTION_FIELDS = frozenset(
    {
        "reason_code",
        "clearance_intent_record_sha256",
        "provider_observation",
        "observed_supervisor_epoch_id",
        "observed_host_boot_id_sha256",
    }
)

_RENAME_NOREPLACE = 1
_DARWIN_RENAME_EXCL = 0x00000004


class LifecycleSupervisorError(ValueError):
    """Stable, public-safe rejection from the supervisor core boundary."""

    def __init__(self, code: str, *, operator_attention: bool = False):
        super().__init__(code)
        self.code = code
        self.operator_attention = operator_attention


def _error(
    code: str, *, operator_attention: bool = False
) -> LifecycleSupervisorError:
    return LifecycleSupervisorError(
        code, operator_attention=operator_attention
    )


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
        raise _error("lifecycle_supervisor_json_invalid") from exc


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_forbidden_fields(value: Any) -> None:
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            if not isinstance(raw_key, str):
                raise _error(
                    "lifecycle_supervisor_field_name_invalid"
                )
            parts = frozenset(raw_key.lower().split("_"))
            if parts & FORBIDDEN_FIELD_PARTS:
                raise _error(
                    "lifecycle_supervisor_forbidden_authority_field"
                )
            _reject_forbidden_fields(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reject_forbidden_fields(child)


def _strict_mapping(
    value: Any,
    fields: frozenset[str] | set[str],
    *,
    code: str,
) -> dict[str, Any]:
    _reject_forbidden_fields(value)
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise _error(code)
    return {field: value[field] for field in fields}


def _digest(
    value: Any, *, field: str, allow_zero: bool = False
) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise _error(f"{field}_invalid")
    if not allow_zero and value == ZERO_SHA256:
        raise _error(f"{field}_invalid")
    return value


def _integer(
    value: Any,
    *,
    field: str,
    minimum: int = 0,
    maximum: int = (1 << 53) - 1,
) -> int:
    if (
        type(value) is not int
        or value < minimum
        or value > maximum
    ):
        raise _error(f"{field}_invalid")
    return value


def _reason(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or unicodedata.normalize("NFC", value) != value
        or REASON_RE.fullmatch(value) is None
    ):
        raise _error(f"{field}_invalid")
    return value


def _instance_slug(value: Any) -> str:
    if (
        not isinstance(value, str)
        or unicodedata.normalize("NFC", value) != value
        or INSTANCE_SLUG_RE.fullmatch(value) is None
    ):
        raise _error("lifecycle_supervisor_instance_slug_invalid")
    return value


def _session_id(value: Any) -> str:
    return _digest(value, field="lifecycle_supervisor_session_id")


def _incarnation_id(value: Any) -> str:
    return _digest(
        value, field="lifecycle_supervisor_scope_incarnation_id"
    )


def _absolute_path(value: Path | str) -> Path:
    text = str(value)
    selected = Path(text)
    if (
        not text
        or len(text) > 4_096
        or "\x00" in text
        or any(ord(character) < 32 for character in text)
        or unicodedata.normalize("NFC", text) != text
        or not selected.is_absolute()
        or "." in selected.parts
        or ".." in selected.parts
        or text != str(selected)
    ):
        raise _error("lifecycle_supervisor_store_path_invalid")
    return selected


def _scope_id(session_id: str) -> str:
    return f"jlq-{lifecycle_receipts.LIFECYCLE_BACKEND}-{session_id}"


def _bound_operation_id(
    operation_id_sha256: Any,
    *,
    state: str,
    session_id: str,
    incarnation_id: str,
) -> str:
    request_id = _digest(
        operation_id_sha256,
        field="lifecycle_supervisor_operation_id_sha256",
    )
    if state not in STATE_SET:
        raise _error("lifecycle_supervisor_operation_state_invalid")
    return _sha256(
        _canonical_json(
            {
                "domain": (
                    "john-lomein.lifecycle-supervisor."
                    f"{state}.operation.v1"
                ),
                "capture_session_id": session_id,
                "scope_incarnation_id": incarnation_id,
                "request_id_sha256": request_id,
            }
        )
    )


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
        raise _error("lifecycle_supervisor_nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _read_file_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("lifecycle_supervisor_nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _write_file_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("lifecycle_supervisor_nofollow_unsupported")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
    )
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _lock_file_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("lifecycle_supervisor_nofollow_unsupported")
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
            item
            for item in bytes(buffer.raw[:observed]).split(b"\x00")
            if item
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
                "lifecycle_supervisor_parent_unreadable"
            ) from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != owner_uid
            or info.st_mode & 0o022
        ):
            raise _error("lifecycle_supervisor_parent_unsafe")


def _validate_directory(
    descriptor: int,
    *,
    owner_uid: int,
    owner_gid: int,
    mode: int,
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
        or stat.S_IMODE(info.st_mode) != mode
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
    selected_path: Path, descriptor: int, *, field: str
) -> None:
    try:
        named = selected_path.lstat()
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
            name, dir_fd=parent_fd, follow_symlinks=False
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
    descriptor: int, *, maximum: int, field: str
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
            raise _error(
                "lifecycle_supervisor_record_write_failed"
            ) from exc
        if written <= 0:
            raise _error("lifecycle_supervisor_record_write_failed")
        offset += written


def _read_bounded(
    descriptor: int, *, expected_size: int, maximum: int
) -> bytes:
    if expected_size < 1 or expected_size > maximum:
        raise _error("lifecycle_supervisor_record_size_invalid")
    chunks: list[bytes] = []
    remaining = expected_size
    while remaining:
        try:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
        except OSError as exc:
            raise _error(
                "lifecycle_supervisor_record_read_failed"
            ) from exc
        if not chunk:
            raise _error("lifecycle_supervisor_record_truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    try:
        extra = os.read(descriptor, 1)
    except OSError as exc:
        raise _error(
            "lifecycle_supervisor_record_read_failed"
        ) from exc
    if extra:
        raise _error("lifecycle_supervisor_record_changed")
    return b"".join(chunks)


def _exclusive_rename(
    parent_fd: int,
    source_name: str,
    destination_name: str,
) -> None:
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
            parent_fd,
            source,
            parent_fd,
            destination,
            _RENAME_NOREPLACE,
        )
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
            parent_fd,
            source,
            parent_fd,
            destination,
            _DARWIN_RENAME_EXCL,
        )
    else:
        raise _error(
            "lifecycle_supervisor_exclusive_rename_unsupported"
        )
    if result != 0:
        observed = ctypes.get_errno()
        if observed in {errno.EEXIST, errno.ENOTEMPTY}:
            raise _error(
                "lifecycle_supervisor_record_revision_exists"
            )
        raise _error(
            "lifecycle_supervisor_record_commit_failed"
        )


def _call_fault(
    fault_hook: Callable[[str], None] | None, phase: str
) -> None:
    if fault_hook is not None:
        if not callable(fault_hook):
            raise _error("lifecycle_supervisor_fault_hook_invalid")
        fault_hook(phase)


class _DuplicateKeyError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    selected: dict[str, Any] = {}
    for key, value in pairs:
        if key in selected:
            raise _DuplicateKeyError(key)
        selected[key] = value
    return selected


def _decode_record(raw: bytes) -> dict[str, Any]:
    if (
        not raw
        or len(raw) > MAX_RECORD_BYTES
        or not raw.endswith(b"\n")
        or raw.endswith(b"\n\n")
    ):
        raise _error(
            "lifecycle_supervisor_record_encoding_invalid",
            operator_attention=True,
        )
    try:
        value = json.loads(
            raw[:-1].decode("ascii"),
            object_pairs_hook=_unique_object,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateKeyError,
    ) as exc:
        raise _error(
            "lifecycle_supervisor_record_encoding_invalid",
            operator_attention=True,
        ) from exc
    if not isinstance(value, dict):
        raise _error(
            "lifecycle_supervisor_record_fields_invalid",
            operator_attention=True,
        )
    if _canonical_json(value) + b"\n" != raw:
        raise _error(
            "lifecycle_supervisor_record_not_canonical",
            operator_attention=True,
        )
    return value


def _normalize_observation(value: Any) -> dict[str, Any]:
    selected = _strict_mapping(
        value,
        OBSERVATION_FIELDS,
        code="lifecycle_supervisor_observation_fields_invalid",
    )
    kind = selected["observation_kind"]
    if kind not in PROVIDER_OBSERVATION_KINDS:
        raise _error(
            "lifecycle_supervisor_observation_kind_invalid"
        )
    stderr_bytes = selected["stderr_bytes"]
    stderr_sha256 = selected["stderr_sha256"]
    if kind in STDERR_OBSERVATION_KINDS:
        stderr_bytes = _integer(
            stderr_bytes,
            field="lifecycle_supervisor_stderr_bytes",
            maximum=MAX_STDERR_BYTES,
        )
        stderr_sha256 = _digest(
            stderr_sha256,
            field="lifecycle_supervisor_stderr_sha256",
        )
    elif stderr_bytes is not None or stderr_sha256 is not None:
        raise _error(
            "lifecycle_supervisor_observation_stderr_invalid"
        )
    return {
        "observation_kind": kind,
        "provider_observation_sha256": _digest(
            selected["provider_observation_sha256"],
            field=(
                "lifecycle_supervisor_provider_observation_sha256"
            ),
        ),
        "observed_supervisor_epoch_id": _digest(
            selected["observed_supervisor_epoch_id"],
            field=(
                "lifecycle_supervisor_observed_supervisor_epoch_id"
            ),
        ),
        "observed_host_boot_id_sha256": _digest(
            selected["observed_host_boot_id_sha256"],
            field=(
                "lifecycle_supervisor_observed_host_boot_id_sha256"
            ),
        ),
        "stderr_bytes": stderr_bytes,
        "stderr_sha256": stderr_sha256,
    }


def _normalize_details(state: str, value: Any) -> dict[str, Any]:
    if state == "start_intent":
        selected = _strict_mapping(
            value,
            START_INTENT_FIELDS,
            code=(
                "lifecycle_supervisor_start_intent_fields_invalid"
            ),
        )
        try:
            activation = lifecycle_receipts.normalize_activation_receipt(
                selected["activation_receipt"]
            )
            activation_digest = (
                lifecycle_receipts.activation_receipt_sha256(
                    activation
                )
            )
        except lifecycle_receipts.LifecycleReceiptError as exc:
            raise _error(
                f"lifecycle_supervisor_{exc.code}"
            ) from exc
        observed_activation_digest = _digest(
            selected["activation_receipt_sha256"],
            field=(
                "lifecycle_supervisor_activation_receipt_sha256"
            ),
        )
        if not hmac.compare_digest(
            activation_digest, observed_activation_digest
        ):
            raise _error(
                "lifecycle_supervisor_activation_digest_mismatch"
            )
        provider = selected["lifecycle_provider"]
        if provider != activation["lifecycle_provider"]:
            raise _error(
                "lifecycle_supervisor_activation_provider_mismatch"
            )
        helper_digest = _digest(
            selected["helper_activation_policy_sha256"],
            field=(
                "lifecycle_supervisor_helper_activation_policy_sha256"
            ),
        )
        if helper_digest != activation[
            "helper_activation_policy_sha256"
        ]:
            raise _error(
                "lifecycle_supervisor_helper_policy_mismatch"
            )
        return {
            "activation_receipt": activation,
            "activation_receipt_sha256": activation_digest,
            "instance_slug": _instance_slug(
                selected["instance_slug"]
            ),
            "instance_control_sha256": _digest(
                selected["instance_control_sha256"],
                field=(
                    "lifecycle_supervisor_instance_control_sha256"
                ),
            ),
            "lifecycle_provider": provider,
            "lifecycle_scope_id": selected["lifecycle_scope_id"],
            "start_supervisor_epoch_id": _digest(
                selected["start_supervisor_epoch_id"],
                field=(
                    "lifecycle_supervisor_start_supervisor_epoch_id"
                ),
            ),
            "start_host_boot_id_sha256": _digest(
                selected["start_host_boot_id_sha256"],
                field=(
                    "lifecycle_supervisor_start_host_boot_id_sha256"
                ),
            ),
            "staging_transaction_intent_sha256": _digest(
                selected["staging_transaction_intent_sha256"],
                field=(
                    "lifecycle_supervisor_staging_transaction_"
                    "intent_sha256"
                ),
            ),
            "staging_exposure_receipt_sha256": _digest(
                selected["staging_exposure_receipt_sha256"],
                field=(
                    "lifecycle_supervisor_staging_exposure_"
                    "receipt_sha256"
                ),
            ),
            "child_launch_intent_record_sha256": _digest(
                selected["child_launch_intent_record_sha256"],
                field=(
                    "lifecycle_supervisor_child_launch_intent_"
                    "record_sha256"
                ),
            ),
            "child_launch_intent_record_revision": _integer(
                selected["child_launch_intent_record_revision"],
                field=(
                    "lifecycle_supervisor_child_launch_intent_"
                    "record_revision"
                ),
                minimum=1,
            ),
            "handoff_policy_sha256": _digest(
                selected["handoff_policy_sha256"],
                field=(
                    "lifecycle_supervisor_handoff_policy_sha256"
                ),
            ),
            "helper_activation_policy_sha256": helper_digest,
            "capture_uid": _integer(
                selected["capture_uid"],
                field="lifecycle_supervisor_capture_uid",
                minimum=1,
                maximum=lifecycle_receipts.MAX_IDENTITY,
            ),
            "export_gid": _integer(
                selected["export_gid"],
                field="lifecycle_supervisor_export_gid",
                minimum=1,
                maximum=lifecycle_receipts.MAX_IDENTITY,
            ),
        }
    if state == "scope_started":
        selected = _strict_mapping(
            value,
            SCOPE_STARTED_FIELDS,
            code=(
                "lifecycle_supervisor_scope_started_fields_invalid"
            ),
        )
        try:
            receipt = lifecycle_receipts.normalize_scope_started_receipt(
                selected["scope_started_receipt"]
            )
            expected = lifecycle_receipts.scope_started_receipt_sha256(
                receipt
            )
        except lifecycle_receipts.LifecycleReceiptError as exc:
            raise _error(
                f"lifecycle_supervisor_{exc.code}"
            ) from exc
        observed = _digest(
            selected["scope_started_receipt_sha256"],
            field=(
                "lifecycle_supervisor_scope_started_receipt_sha256"
            ),
        )
        if not hmac.compare_digest(expected, observed):
            raise _error(
                "lifecycle_supervisor_scope_started_digest_mismatch"
            )
        return {
            "provider_start_observation_sha256": _digest(
                selected["provider_start_observation_sha256"],
                field=(
                    "lifecycle_supervisor_provider_start_"
                    "observation_sha256"
                ),
            ),
            "scope_started_receipt": receipt,
            "scope_started_receipt_sha256": expected,
        }
    if state == "capture_event":
        selected = _strict_mapping(
            value,
            CAPTURE_EVENT_FIELDS,
            code=(
                "lifecycle_supervisor_capture_event_fields_invalid"
            ),
        )
        origin = selected["effect_origin_state"]
        if origin not in CAPTURE_EVENT_ORIGINS:
            raise _error(
                "lifecycle_supervisor_capture_event_origin_invalid"
            )
        return {
            "effect_origin_state": origin,
            "effect_origin_record_revision": _integer(
                selected["effect_origin_record_revision"],
                field=(
                    "lifecycle_supervisor_effect_origin_record_revision"
                ),
                minimum=1,
            ),
            "effect_origin_record_sha256": _digest(
                selected["effect_origin_record_sha256"],
                field=(
                    "lifecycle_supervisor_effect_origin_record_sha256"
                ),
            ),
            "scope_started_receipt_sha256": _digest(
                selected["scope_started_receipt_sha256"],
                field=(
                    "lifecycle_supervisor_scope_started_receipt_sha256"
                ),
            ),
        }
    if state == "clearance_intent":
        selected = _strict_mapping(
            value,
            CLEARANCE_INTENT_FIELDS,
            code=(
                "lifecycle_supervisor_clearance_intent_fields_invalid"
            ),
        )
        try:
            receipt = (
                lifecycle_receipts.normalize_clearance_intent_receipt(
                    selected["clearance_intent_receipt"]
                )
            )
            expected = (
                lifecycle_receipts.clearance_intent_receipt_sha256(
                    receipt
                )
            )
        except lifecycle_receipts.LifecycleReceiptError as exc:
            raise _error(
                f"lifecycle_supervisor_{exc.code}"
            ) from exc
        observed = _digest(
            selected["clearance_intent_receipt_sha256"],
            field=(
                "lifecycle_supervisor_clearance_intent_"
                "receipt_sha256"
            ),
        )
        if not hmac.compare_digest(expected, observed):
            raise _error(
                "lifecycle_supervisor_clearance_intent_digest_mismatch"
            )
        return {
            "clearance_intent_receipt": receipt,
            "clearance_intent_receipt_sha256": expected,
            "effect_origin_record_revision": _integer(
                selected["effect_origin_record_revision"],
                field=(
                    "lifecycle_supervisor_effect_origin_record_revision"
                ),
                minimum=1,
            ),
            "outer_clearance_intent_record_revision": _integer(
                selected["outer_clearance_intent_record_revision"],
                field=(
                    "lifecycle_supervisor_outer_clearance_intent_"
                    "record_revision"
                ),
                minimum=1,
            ),
        }
    if state == "provider_observation":
        selected = _strict_mapping(
            value,
            PROVIDER_OBSERVATION_FIELDS,
            code=(
                "lifecycle_supervisor_provider_observation_fields_invalid"
            ),
        )
        observation = _normalize_observation(
            selected["observation"]
        )
        try:
            receipt = lifecycle_receipts.normalize_scope_empty_receipt(
                selected["scope_empty_receipt"]
            )
            expected = lifecycle_receipts.scope_empty_receipt_sha256(
                receipt
            )
        except lifecycle_receipts.LifecycleReceiptError as exc:
            raise _error(
                f"lifecycle_supervisor_{exc.code}"
            ) from exc
        observed = _digest(
            selected["scope_empty_receipt_sha256"],
            field=(
                "lifecycle_supervisor_scope_empty_receipt_sha256"
            ),
        )
        if not hmac.compare_digest(expected, observed):
            raise _error(
                "lifecycle_supervisor_scope_empty_digest_mismatch"
            )
        return {
            "observation": observation,
            "scope_empty_receipt": receipt,
            "scope_empty_receipt_sha256": expected,
        }
    if state == "settled_bundle":
        selected = _strict_mapping(
            value,
            SETTLED_BUNDLE_FIELDS,
            code=(
                "lifecycle_supervisor_settled_bundle_fields_invalid"
            ),
        )
        try:
            bundle = lifecycle_receipts.normalize_clearance_bundle(
                selected["clearance_bundle"]
            )
            expected = lifecycle_receipts.clearance_bundle_sha256(
                bundle
            )
        except lifecycle_receipts.LifecycleReceiptError as exc:
            raise _error(
                f"lifecycle_supervisor_{exc.code}"
            ) from exc
        observed = _digest(
            selected["clearance_bundle_sha256"],
            field=(
                "lifecycle_supervisor_clearance_bundle_sha256"
            ),
        )
        if not hmac.compare_digest(expected, observed):
            raise _error(
                "lifecycle_supervisor_clearance_bundle_digest_mismatch"
            )
        return {
            "provider_observation_record_sha256": _digest(
                selected["provider_observation_record_sha256"],
                field=(
                    "lifecycle_supervisor_provider_observation_"
                    "record_sha256"
                ),
            ),
            "clearance_bundle": bundle,
            "clearance_bundle_sha256": expected,
        }
    if state == "operator_attention":
        selected = _strict_mapping(
            value,
            OPERATOR_ATTENTION_FIELDS,
            code=(
                "lifecycle_supervisor_operator_attention_fields_invalid"
            ),
        )
        return {
            "reason_code": _reason(
                selected["reason_code"],
                field=(
                    "lifecycle_supervisor_operator_attention_reason"
                ),
            ),
            "clearance_intent_record_sha256": _digest(
                selected["clearance_intent_record_sha256"],
                field=(
                    "lifecycle_supervisor_clearance_intent_"
                    "record_sha256"
                ),
            ),
            "provider_observation": _normalize_observation(
                selected["provider_observation"]
            ),
            "observed_supervisor_epoch_id": _digest(
                selected["observed_supervisor_epoch_id"],
                field=(
                    "lifecycle_supervisor_observed_supervisor_epoch_id"
                ),
            ),
            "observed_host_boot_id_sha256": _digest(
                selected["observed_host_boot_id_sha256"],
                field=(
                    "lifecycle_supervisor_observed_host_boot_id_sha256"
                ),
            ),
        }
    raise _error("lifecycle_supervisor_state_invalid")


def _record_without_digest(
    *,
    session_id: str,
    incarnation_id: str,
    revision: int,
    previous_record_sha256: str,
    state: str,
    recorded_at_unix: int,
    operation_request_sha256: str,
    operation_id_sha256: str,
    details: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": LEDGER_RECORD_SCHEMA,
        "capture_session_id": session_id,
        "scope_incarnation_id": incarnation_id,
        "revision": revision,
        "previous_record_sha256": previous_record_sha256,
        "state": state,
        "recorded_at_unix": recorded_at_unix,
        "operation_request_sha256": operation_request_sha256,
        "operation_id_sha256": operation_id_sha256,
        "details": dict(details),
    }


def _build_record(
    *,
    session_id: str,
    incarnation_id: str,
    revision: int,
    previous_record_sha256: str,
    state: str,
    recorded_at_unix: int,
    operation_request_sha256: str,
    operation_id_sha256: str,
    details: Mapping[str, Any],
) -> dict[str, Any]:
    payload = _record_without_digest(
        session_id=session_id,
        incarnation_id=incarnation_id,
        revision=revision,
        previous_record_sha256=previous_record_sha256,
        state=state,
        recorded_at_unix=recorded_at_unix,
        operation_request_sha256=operation_request_sha256,
        operation_id_sha256=operation_id_sha256,
        details=details,
    )
    return {
        **payload,
        "record_sha256": _sha256(_canonical_json(payload)),
    }


def _normalize_record(value: Any) -> dict[str, Any]:
    selected = _strict_mapping(
        value,
        RECORD_FIELDS,
        code="lifecycle_supervisor_record_fields_invalid",
    )
    if selected["schema_version"] != LEDGER_RECORD_SCHEMA:
        raise _error(
            "lifecycle_supervisor_record_schema_unsupported"
        )
    state = selected["state"]
    if state not in STATE_SET:
        raise _error("lifecycle_supervisor_state_invalid")
    session_id = _session_id(selected["capture_session_id"])
    incarnation_id = _incarnation_id(
        selected["scope_incarnation_id"]
    )
    operation_request = _digest(
        selected["operation_request_sha256"],
        field=(
            "lifecycle_supervisor_operation_request_sha256"
        ),
    )
    expected_operation = _bound_operation_id(
        operation_request,
        state=state,
        session_id=session_id,
        incarnation_id=incarnation_id,
    )
    observed_operation = _digest(
        selected["operation_id_sha256"],
        field=(
            "lifecycle_supervisor_bound_operation_id_sha256"
        ),
    )
    if not hmac.compare_digest(
        expected_operation, observed_operation
    ):
        raise _error(
            "lifecycle_supervisor_operation_domain_binding_invalid",
            operator_attention=True,
        )
    normalized = _record_without_digest(
        session_id=session_id,
        incarnation_id=incarnation_id,
        revision=_integer(
            selected["revision"],
            field="lifecycle_supervisor_revision",
            minimum=1,
            maximum=MAX_RECORDS_PER_SESSION,
        ),
        previous_record_sha256=_digest(
            selected["previous_record_sha256"],
            field=(
                "lifecycle_supervisor_previous_record_sha256"
            ),
            allow_zero=True,
        ),
        state=state,
        recorded_at_unix=_integer(
            selected["recorded_at_unix"],
            field="lifecycle_supervisor_recorded_at_unix",
            minimum=1,
        ),
        operation_request_sha256=operation_request,
        operation_id_sha256=observed_operation,
        details=_normalize_details(state, selected["details"]),
    )
    observed = _digest(
        selected["record_sha256"],
        field="lifecycle_supervisor_record_sha256",
    )
    expected = _sha256(_canonical_json(normalized))
    if not hmac.compare_digest(observed, expected):
        raise _error(
            "lifecycle_supervisor_record_digest_mismatch",
            operator_attention=True,
        )
    return {**normalized, "record_sha256": observed}


class LifecycleSupervisorRecord:
    """Immutable canonical ledger record."""

    __slots__ = ("_canonical",)

    def __init__(self, value: Mapping[str, Any]) -> None:
        self._canonical = _canonical_json(_normalize_record(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self._canonical.decode("ascii"))
        if not isinstance(value, dict):
            raise AssertionError("canonical ledger record is not an object")
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
    def operation_id_sha256(self) -> str:
        return self.to_dict()["operation_id_sha256"]

    @property
    def operation_request_sha256(self) -> str:
        return self.to_dict()["operation_request_sha256"]

    @property
    def recorded_at_unix(self) -> int:
        return self.to_dict()["recorded_at_unix"]

    @property
    def details(self) -> dict[str, Any]:
        return self.to_dict()["details"]


def _allowed_transition(previous: str | None, next_state: str) -> bool:
    if previous is None:
        return next_state == "start_intent"
    permitted = {
        "start_intent": frozenset(
            {"scope_started", "clearance_intent"}
        ),
        "scope_started": frozenset(
            {"capture_event", "clearance_intent"}
        ),
        "capture_event": frozenset({"clearance_intent"}),
        "clearance_intent": frozenset(
            {"provider_observation", "operator_attention"}
        ),
        "provider_observation": frozenset({"settled_bundle"}),
    }
    return next_state in permitted.get(previous, frozenset())


def _record_for_state(
    records: tuple[LifecycleSupervisorRecord, ...], state: str
) -> LifecycleSupervisorRecord | None:
    for record in records:
        if record.state == state:
            return record
    return None


def _stable_start_bindings(
    start: LifecycleSupervisorRecord,
    *,
    session_id: str,
    incarnation_id: str,
) -> dict[str, Any]:
    details = start.details
    return {
        "capture_session_id": session_id,
        "lifecycle_backend": lifecycle_receipts.LIFECYCLE_BACKEND,
        "lifecycle_provider": details["lifecycle_provider"],
        "lifecycle_scope_id": _scope_id(session_id),
        "scope_incarnation_id": incarnation_id,
        "lifecycle_activation_receipt_sha256": details[
            "activation_receipt_sha256"
        ],
        "child_launch_intent_record_sha256": details[
            "child_launch_intent_record_sha256"
        ],
    }


def _derive_scope_empty_receipt(
    records: tuple[LifecycleSupervisorRecord, ...],
    observation: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, str | None]:
    start = records[0]
    start_details = start.details
    started = _record_for_state(records, "scope_started")
    clearance = _record_for_state(records, "clearance_intent")
    if clearance is None:
        raise _error(
            "lifecycle_supervisor_clearance_intent_missing"
        )
    selected_observation = _normalize_observation(observation)
    observed_boot = selected_observation[
        "observed_host_boot_id_sha256"
    ]
    observed_epoch = selected_observation[
        "observed_supervisor_epoch_id"
    ]
    activation_boot = start_details["activation_receipt"][
        "host_boot_id_sha256"
    ]
    kind = selected_observation["observation_kind"]
    provider = start_details["lifecycle_provider"]

    if started is None:
        if kind != "scope_absent":
            return None, REBOOT_OBSERVATION_REASON
        if observed_boot == activation_boot:
            disposition = "never_started"
            basis = lifecycle_receipts.NO_EFFECT_CLEARANCE_BASIS
        else:
            if observed_epoch == start_details[
                "start_supervisor_epoch_id"
            ]:
                return None, HOST_EPOCH_INCOHERENT_REASON
            disposition = "never_started_after_reboot"
            basis = lifecycle_receipts.REBOOT_CLEARANCE_BASIS
        start_digest = None
        start_epoch = None
        start_boot = None
    else:
        started_receipt = started.details["scope_started_receipt"]
        start_digest = started.details[
            "scope_started_receipt_sha256"
        ]
        start_epoch = started_receipt["supervisor_epoch_id"]
        start_boot = started_receipt["host_boot_id_sha256"]
        same_boot = hmac.compare_digest(start_boot, observed_boot)
        same_epoch = hmac.compare_digest(start_epoch, observed_epoch)
        if not same_boot:
            if same_epoch:
                return None, HOST_EPOCH_INCOHERENT_REASON
            if kind != "scope_absent":
                return None, REBOOT_OBSERVATION_REASON
            disposition = "host_reboot"
            basis = lifecycle_receipts.REBOOT_CLEARANCE_BASIS
        else:
            if (
                provider == "direct_waitid_deny_fork"
                and not same_epoch
            ):
                return None, DIRECT_WAIT_RESTART_REASON
            basis = lifecycle_receipts.NORMAL_CLEARANCE_BASIS_BY_PROVIDER[
                provider
            ]
            if kind == "clean_exit":
                if not same_epoch:
                    return None, EXIT_EPOCH_REASON
                disposition = "clean_exit"
            elif kind == "abnormal_exit":
                if not same_epoch:
                    return None, EXIT_EPOCH_REASON
                disposition = "abnormal_exit"
            elif kind == "forced_scope_empty":
                disposition = "forced_termination"
            elif kind in {"scope_absent", "scope_empty_unobserved"}:
                if same_epoch:
                    return None, ABSENCE_EPOCH_REASON
                disposition = "exit_unobserved_after_restart"
            else:
                raise AssertionError("normalized observation kind missing")

    clearance_details = clearance.details
    intent = clearance_details["clearance_intent_receipt"]
    stderr_bytes = selected_observation["stderr_bytes"]
    stderr_sha256 = selected_observation["stderr_sha256"]
    if disposition not in {
        "clean_exit",
        "abnormal_exit",
        "forced_termination",
    }:
        stderr_bytes = None
        stderr_sha256 = None
    adoption_eligible = (
        disposition == "clean_exit"
        and intent["effect_origin_state"] == "capture_ready"
        and intent["clearance_mode"]
        == "wait_clean_then_terminate_on_deadline"
        and stderr_bytes == 0
        and stderr_sha256 == lifecycle_receipts.EMPTY_SHA256
    )
    receipt = {
        "schema_version": lifecycle_receipts.SCOPE_EMPTY_RECEIPT_SCHEMA,
        "status": lifecycle_receipts.SCOPE_EMPTY_STATUS,
        **_stable_start_bindings(
            start,
            session_id=start.to_dict()["capture_session_id"],
            incarnation_id=start.to_dict()["scope_incarnation_id"],
        ),
        "effect_origin_state": intent["effect_origin_state"],
        "effect_origin_record_sha256": intent[
            "effect_origin_record_sha256"
        ],
        "scope_started_receipt_sha256": start_digest,
        "clearance_intent_receipt_sha256": clearance_details[
            "clearance_intent_receipt_sha256"
        ],
        "outer_clearance_intent_record_sha256": intent[
            "outer_clearance_intent_record_sha256"
        ],
        "clearance_mode": intent["clearance_mode"],
        "start_supervisor_epoch_id": start_epoch,
        "clearance_supervisor_epoch_id": observed_epoch,
        "start_host_boot_id_sha256": start_boot,
        "clearance_host_boot_id_sha256": observed_boot,
        "clearance_basis": basis,
        "completion_disposition": disposition,
        "stderr_bytes": stderr_bytes,
        "stderr_sha256": stderr_sha256,
        "adoption_eligible": adoption_eligible,
    }
    try:
        return (
            lifecycle_receipts.normalize_scope_empty_receipt(receipt),
            None,
        )
    except lifecycle_receipts.LifecycleReceiptError as exc:
        raise _error(
            f"lifecycle_supervisor_{exc.code}"
        ) from exc


def _validate_history(
    records: tuple[LifecycleSupervisorRecord, ...],
    *,
    expected_session_id: str,
    expected_incarnation_id: str,
) -> None:
    if not records:
        return
    seen_operations: set[str] = set()
    previous: LifecycleSupervisorRecord | None = None
    for index, record in enumerate(records, start=1):
        value = record.to_dict()
        if (
            value["capture_session_id"] != expected_session_id
            or value["scope_incarnation_id"]
            != expected_incarnation_id
        ):
            raise _error(
                "lifecycle_supervisor_history_identity_changed",
                operator_attention=True,
            )
        if (
            record.revision != index
            or value["previous_record_sha256"]
            != (
                ZERO_SHA256
                if previous is None
                else previous.record_sha256
            )
            or not _allowed_transition(
                None if previous is None else previous.state,
                record.state,
            )
        ):
            raise _error(
                "lifecycle_supervisor_history_chain_invalid",
                operator_attention=True,
            )
        if (
            previous is not None
            and record.recorded_at_unix < previous.recorded_at_unix
        ):
            raise _error(
                "lifecycle_supervisor_history_clock_rollback",
                operator_attention=True,
            )
        if record.operation_id_sha256 in seen_operations:
            raise _error(
                "lifecycle_supervisor_operation_reused",
                operator_attention=True,
            )
        seen_operations.add(record.operation_id_sha256)
        previous = record

    start = records[0]
    start_value = start.to_dict()
    start_details = start.details
    if (
        start.state != "start_intent"
        or start_details["lifecycle_scope_id"]
        != _scope_id(expected_session_id)
        or start_details["start_host_boot_id_sha256"]
        != start_details["activation_receipt"][
            "host_boot_id_sha256"
        ]
    ):
        raise _error(
            "lifecycle_supervisor_start_binding_invalid",
            operator_attention=True,
        )
    expected_start_operation = start_value["operation_id_sha256"]
    if expected_start_operation == ZERO_SHA256:
        raise _error(
            "lifecycle_supervisor_operation_id_invalid",
            operator_attention=True,
        )

    started = _record_for_state(records, "scope_started")
    if started is not None:
        receipt = started.details["scope_started_receipt"]
        expected = {
            **_stable_start_bindings(
                start,
                session_id=expected_session_id,
                incarnation_id=expected_incarnation_id,
            ),
            "supervisor_epoch_id": start_details[
                "start_supervisor_epoch_id"
            ],
            "host_boot_id_sha256": start_details[
                "start_host_boot_id_sha256"
            ],
            "staging_transaction_intent_sha256": start_details[
                "staging_transaction_intent_sha256"
            ],
            "staging_exposure_receipt_sha256": start_details[
                "staging_exposure_receipt_sha256"
            ],
            "handoff_policy_sha256": start_details[
                "handoff_policy_sha256"
            ],
            "helper_activation_policy_sha256": start_details[
                "helper_activation_policy_sha256"
            ],
            "capture_uid": start_details["capture_uid"],
            "export_gid": start_details["export_gid"],
        }
        if any(receipt[field] != value for field, value in expected.items()):
            raise _error(
                "lifecycle_supervisor_scope_started_binding_changed",
                operator_attention=True,
            )

    capture = _record_for_state(records, "capture_event")
    if capture is not None:
        if (
            started is None
            or capture.details["scope_started_receipt_sha256"]
            != started.details["scope_started_receipt_sha256"]
            or capture.details["effect_origin_record_revision"]
            <= start_details["child_launch_intent_record_revision"]
        ):
            raise _error(
                "lifecycle_supervisor_capture_start_binding_changed",
                operator_attention=True,
            )

    clearance = _record_for_state(records, "clearance_intent")
    if clearance is not None:
        intent = clearance.details["clearance_intent_receipt"]
        stable = _stable_start_bindings(
            start,
            session_id=expected_session_id,
            incarnation_id=expected_incarnation_id,
        )
        if any(intent[field] != value for field, value in stable.items()):
            raise _error(
                "lifecycle_supervisor_clearance_scope_binding_changed",
                operator_attention=True,
            )
        if (
            clearance.details[
                "outer_clearance_intent_record_revision"
            ]
            <= clearance.details["effect_origin_record_revision"]
        ):
            raise _error(
                "lifecycle_supervisor_clearance_revision_order_invalid",
                operator_attention=True,
            )
        if capture is None:
            if (
                intent["effect_origin_state"]
                != "child_launch_intent"
                or intent["effect_origin_record_sha256"]
                != start_details[
                    "child_launch_intent_record_sha256"
                ]
                or intent["scope_started_receipt_sha256"] is not None
                or clearance.details[
                    "effect_origin_record_revision"
                ]
                != start_details[
                    "child_launch_intent_record_revision"
                ]
            ):
                raise _error(
                    "lifecycle_supervisor_no_effect_clearance_invalid",
                    operator_attention=True,
                )
        elif (
            intent["effect_origin_state"]
            != capture.details["effect_origin_state"]
            or intent["effect_origin_record_sha256"]
            != capture.details["effect_origin_record_sha256"]
            or clearance.details["effect_origin_record_revision"]
            != capture.details["effect_origin_record_revision"]
            or intent["scope_started_receipt_sha256"]
            != started.details["scope_started_receipt_sha256"]
        ):
            raise _error(
                "lifecycle_supervisor_clearance_origin_changed",
                operator_attention=True,
            )

    observation_record = _record_for_state(
        records, "provider_observation"
    )
    if observation_record is not None:
        expected_receipt, reason = _derive_scope_empty_receipt(
            records[: observation_record.revision - 1],
            observation_record.details["observation"],
        )
        if reason is not None or expected_receipt is None:
            raise _error(
                "lifecycle_supervisor_provider_observation_invalid",
                operator_attention=True,
            )
        expected_digest = (
            lifecycle_receipts.scope_empty_receipt_sha256(
                expected_receipt
            )
        )
        if (
            observation_record.details["scope_empty_receipt"]
            != expected_receipt
            or observation_record.details[
                "scope_empty_receipt_sha256"
            ]
            != expected_digest
        ):
            raise _error(
                "lifecycle_supervisor_provider_observation_changed",
                operator_attention=True,
            )

    attention = _record_for_state(records, "operator_attention")
    if attention is not None:
        expected_receipt, reason = _derive_scope_empty_receipt(
            records[: attention.revision - 1],
            attention.details["provider_observation"],
        )
        del expected_receipt
        if (
            reason is None
            or attention.details["reason_code"] != reason
            or clearance is None
            or attention.details[
                "clearance_intent_record_sha256"
            ]
            != clearance.record_sha256
            or attention.details[
                "observed_supervisor_epoch_id"
            ]
            != attention.details["provider_observation"][
                "observed_supervisor_epoch_id"
            ]
            or attention.details["observed_host_boot_id_sha256"]
            != attention.details["provider_observation"][
                "observed_host_boot_id_sha256"
            ]
        ):
            raise _error(
                "lifecycle_supervisor_operator_attention_binding_changed",
                operator_attention=True,
            )

    settled = _record_for_state(records, "settled_bundle")
    if settled is not None:
        if (
            observation_record is None
            or clearance is None
            or settled.details[
                "provider_observation_record_sha256"
            ]
            != observation_record.record_sha256
        ):
            raise _error(
                "lifecycle_supervisor_settled_predecessor_changed",
                operator_attention=True,
            )
        bundle = settled.details["clearance_bundle"]
        expected_bundle = {
            "schema_version": (
                lifecycle_receipts.CLEARANCE_BUNDLE_SCHEMA
            ),
            "status": lifecycle_receipts.CLEARANCE_BUNDLE_STATUS,
            "activation_receipt": start_details[
                "activation_receipt"
            ],
            "activation_receipt_sha256": start_details[
                "activation_receipt_sha256"
            ],
            "scope_started_receipt": (
                None
                if started is None
                else started.details["scope_started_receipt"]
            ),
            "scope_started_receipt_sha256": (
                None
                if started is None
                else started.details[
                    "scope_started_receipt_sha256"
                ]
            ),
            "clearance_intent_receipt": clearance.details[
                "clearance_intent_receipt"
            ],
            "clearance_intent_receipt_sha256": clearance.details[
                "clearance_intent_receipt_sha256"
            ],
            "scope_empty_receipt": observation_record.details[
                "scope_empty_receipt"
            ],
            "scope_empty_receipt_sha256": observation_record.details[
                "scope_empty_receipt_sha256"
            ],
        }
        try:
            expected_bundle = (
                lifecycle_receipts.normalize_clearance_bundle(
                    expected_bundle
                )
            )
        except lifecycle_receipts.LifecycleReceiptError as exc:
            raise _error(
                f"lifecycle_supervisor_{exc.code}",
                operator_attention=True,
            ) from exc
        if bundle != expected_bundle:
            raise _error(
                "lifecycle_supervisor_settled_bundle_changed",
                operator_attention=True,
            )


def _event_filename(record: LifecycleSupervisorRecord) -> str:
    return (
        f"{record.revision:06d}-{record.state}-"
        f"{record.record_sha256}.json"
    )


_STORE_TOKEN = object()
_SESSION_TOKEN = object()

# Lock order is store admission before scope.  Scope operations deliberately
# never acquire admission, so store shutdown may wait for an in-flight scope
# operation without deadlocking that operation's immutable store reads.


def _scope_serialized(method: Callable[..., Any]) -> Callable[..., Any]:
    """Serialize one complete scope operation, including its proof reads."""

    @wraps(method)
    def serialized(
        self: LifecycleSupervisorSession, *args: Any, **kwargs: Any
    ) -> Any:
        with self._scope_lock:
            return method(self, *args, **kwargs)

    return serialized


def _store_serialized(method: Callable[..., Any]) -> Callable[..., Any]:
    """Serialize store inventory admission and lease bookkeeping."""

    @wraps(method)
    def serialized(
        self: LifecycleSupervisorStore, *args: Any, **kwargs: Any
    ) -> Any:
        with self._admission_lock:
            return method(self, *args, **kwargs)

    return serialized


class LifecycleSupervisorSession:
    """Descriptor-bound append capability for one lifecycle incarnation."""

    __slots__ = (
        "_store",
        "_directory_fd",
        "_directory_name",
        "_records",
        "_session_id",
        "_incarnation_id",
        "_scope_lock",
    )

    def __init__(
        self,
        *,
        _token: object,
        store: LifecycleSupervisorStore,
        directory_fd: int,
        directory_name: str,
        records: tuple[LifecycleSupervisorRecord, ...],
        session_id: str,
        incarnation_id: str,
    ) -> None:
        if _token is not _SESSION_TOKEN:
            raise TypeError(
                "LifecycleSupervisorSession cannot be constructed directly"
            )
        os.set_inheritable(directory_fd, False)
        self._store = store
        self._directory_fd = directory_fd
        self._directory_name = directory_name
        self._records = records
        self._session_id = session_id
        self._incarnation_id = incarnation_id
        self._scope_lock = store._scope_lock_for(directory_name)

    @property
    @_scope_serialized
    def active(self) -> bool:
        return (
            self._directory_fd >= 0
            and self._store._store_fd >= 0
            and self._store._lock_fd >= 0
        )

    @property
    def capture_session_id(self) -> str:
        return self._session_id

    @property
    def scope_incarnation_id(self) -> str:
        return self._incarnation_id

    @property
    def lifecycle_scope_id(self) -> str:
        return _scope_id(self._session_id)

    @property
    @_scope_serialized
    def records(self) -> tuple[LifecycleSupervisorRecord, ...]:
        self._require_active()
        return self._records

    @property
    @_scope_serialized
    def latest_record(self) -> LifecycleSupervisorRecord:
        self._require_active()
        if not self._records:
            raise _error("lifecycle_supervisor_session_empty")
        return self._records[-1]

    @property
    def state(self) -> str:
        return self.latest_record.state

    @_scope_serialized
    def _require_active(self) -> int:
        if not self.active:
            raise _error("lifecycle_supervisor_session_closed")
        return self._directory_fd

    def _operation_record(
        self, operation_id_sha256: str
    ) -> LifecycleSupervisorRecord | None:
        for record in self._records:
            if record.operation_id_sha256 == operation_id_sha256:
                return record
        return None

    @_scope_serialized
    def _append(
        self,
        *,
        state: str,
        details: Mapping[str, Any],
        operation_id_sha256: str,
        recorded_at_unix: int,
        fault_hook: Callable[[str], None] | None = None,
    ) -> LifecycleSupervisorRecord:
        descriptor = self._require_active()
        on_disk = self._store._scan_session(
            self._directory_name,
            descriptor,
            clean_stale_temps=False,
        )
        if tuple(
            record.record_sha256 for record in on_disk
        ) != tuple(record.record_sha256 for record in self._records):
            raise _error(
                "lifecycle_supervisor_session_changed",
                operator_attention=True,
            )
        normalized_details = _normalize_details(state, details)
        operation_request = _digest(
            operation_id_sha256,
            field=(
                "lifecycle_supervisor_operation_request_sha256"
            ),
        )
        bound_operation = _bound_operation_id(
            operation_request,
            state=state,
            session_id=self._session_id,
            incarnation_id=self._incarnation_id,
        )
        existing = self._operation_record(bound_operation)
        if existing is not None:
            if (
                existing.state == state
                and existing.details == normalized_details
            ):
                return existing
            raise _error(
                "lifecycle_supervisor_idempotency_conflict",
                operator_attention=True,
            )
        previous = self._records[-1] if self._records else None
        if not _allowed_transition(
            None if previous is None else previous.state,
            state,
        ):
            raise _error(
                "lifecycle_supervisor_transition_conflict",
                operator_attention=True,
            )
        timestamp = _integer(
            recorded_at_unix,
            field="lifecycle_supervisor_recorded_at_unix",
            minimum=1,
        )
        if previous is not None and timestamp < previous.recorded_at_unix:
            raise _error("lifecycle_supervisor_clock_rollback")
        candidate = LifecycleSupervisorRecord(
            _build_record(
                session_id=self._session_id,
                incarnation_id=self._incarnation_id,
                revision=len(self._records) + 1,
                previous_record_sha256=(
                    ZERO_SHA256
                    if previous is None
                    else previous.record_sha256
                ),
                state=state,
                recorded_at_unix=timestamp,
                operation_request_sha256=operation_request,
                operation_id_sha256=bound_operation,
                details=normalized_details,
            )
        )
        proposed = (*self._records, candidate)
        _validate_history(
            proposed,
            expected_session_id=self._session_id,
            expected_incarnation_id=self._incarnation_id,
        )
        raw = _canonical_json(candidate.to_dict()) + b"\n"
        if len(raw) > MAX_RECORD_BYTES:
            raise _error("lifecycle_supervisor_record_too_large")
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
                    "lifecycle_supervisor_temp_create_failed"
                ) from exc
            os.set_inheritable(temp_fd, False)
            _call_fault(fault_hook, "after_temp_open")
            _write_all(temp_fd, raw)
            _call_fault(fault_hook, "after_temp_write")
            try:
                os.fsync(temp_fd)
            except OSError as exc:
                raise _error(
                    "lifecycle_supervisor_record_fsync_failed"
                ) from exc
            _call_fault(fault_hook, "after_temp_file_fsync")
            try:
                os.fchmod(temp_fd, RECORD_FILE_MODE)
            except OSError as exc:
                raise _error(
                    "lifecycle_supervisor_record_chmod_failed"
                ) from exc
            _call_fault(fault_hook, "after_temp_chmod")
            try:
                os.fsync(temp_fd)
            except OSError as exc:
                raise _error(
                    "lifecycle_supervisor_record_metadata_fsync_failed"
                ) from exc
            _call_fault(fault_hook, "after_temp_metadata_fsync")
            _validate_regular_file(
                temp_fd,
                owner_uid=self._store._owner_uid,
                owner_gid=self._store._owner_gid,
                modes=frozenset({RECORD_FILE_MODE}),
                maximum_bytes=MAX_RECORD_BYTES,
                field="lifecycle_supervisor_temp_record",
            )
            _validate_named_fd_binding(
                descriptor,
                temp_name,
                temp_fd,
                directory=False,
                field="lifecycle_supervisor_temp_record",
            )
            _exclusive_rename(
                descriptor, temp_name, _event_filename(candidate)
            )
            _call_fault(fault_hook, "after_noreplace_commit")
            try:
                os.fsync(descriptor)
            except OSError as exc:
                raise _error(
                    "lifecycle_supervisor_directory_fsync_failed"
                ) from exc
            _call_fault(fault_hook, "after_session_directory_fsync")
        finally:
            if temp_fd >= 0:
                os.close(temp_fd)
        self._records = proposed
        return candidate

    def record_scope_started(
        self,
        *,
        provider_start_observation_sha256: str,
        operation_id_sha256: str,
        recorded_at_unix: int,
    ) -> LifecycleSupervisorRecord:
        """Durably record contained-before-exec provider evidence."""

        return self._record_scope_started(
            provider_start_observation_sha256=(
                provider_start_observation_sha256
            ),
            operation_id_sha256=operation_id_sha256,
            recorded_at_unix=recorded_at_unix,
            fault_hook=None,
        )

    @_scope_serialized
    def _record_scope_started(
        self,
        *,
        provider_start_observation_sha256: str,
        operation_id_sha256: str,
        recorded_at_unix: int,
        fault_hook: Callable[[str], None] | None,
    ) -> LifecycleSupervisorRecord:
        start = self._records[0]
        details = start.details
        existing = _record_for_state(self._records, "scope_started")
        if existing is None:
            if (
                details["start_host_boot_id_sha256"]
                != self._store.host_boot_id_sha256
            ):
                raise _error(
                    "lifecycle_supervisor_start_boot_changed",
                    operator_attention=True,
                )
            if (
                details["start_supervisor_epoch_id"]
                != self._store.supervisor_epoch_id
            ):
                raise _error(
                    "lifecycle_supervisor_start_epoch_changed",
                    operator_attention=True,
                )
        receipt = {
            "schema_version": (
                lifecycle_receipts.SCOPE_STARTED_RECEIPT_SCHEMA
            ),
            "status": lifecycle_receipts.SCOPE_STARTED_STATUS,
            **_stable_start_bindings(
                start,
                session_id=self._session_id,
                incarnation_id=self._incarnation_id,
            ),
            "supervisor_epoch_id": details[
                "start_supervisor_epoch_id"
            ],
            "host_boot_id_sha256": details[
                "start_host_boot_id_sha256"
            ],
            "staging_transaction_intent_sha256": details[
                "staging_transaction_intent_sha256"
            ],
            "staging_exposure_receipt_sha256": details[
                "staging_exposure_receipt_sha256"
            ],
            "handoff_policy_sha256": details[
                "handoff_policy_sha256"
            ],
            "helper_activation_policy_sha256": details[
                "helper_activation_policy_sha256"
            ],
            "capture_uid": details["capture_uid"],
            "export_gid": details["export_gid"],
        }
        receipt = lifecycle_receipts.normalize_scope_started_receipt(
            receipt
        )
        return self._append(
            state="scope_started",
            details={
                "provider_start_observation_sha256": (
                    provider_start_observation_sha256
                ),
                "scope_started_receipt": receipt,
                "scope_started_receipt_sha256": (
                    lifecycle_receipts.scope_started_receipt_sha256(
                        receipt
                    )
                ),
            },
            operation_id_sha256=operation_id_sha256,
            recorded_at_unix=recorded_at_unix,
            fault_hook=fault_hook,
        )

    @_scope_serialized
    def record_capture_event(
        self,
        *,
        effect_origin_state: str,
        effect_origin_record_revision: int,
        effect_origin_record_sha256: str,
        expected_scope_started_receipt_sha256: str,
        operation_id_sha256: str,
        recorded_at_unix: int,
    ) -> LifecycleSupervisorRecord:
        """Bind the durable outer event immediately before clearance.

        A raw READY/helper event is not itself an outer-journal coordinate and
        must not call this method.  The coordinator first durably records
        ``capture_ready`` (or selects its durable ``child_running`` failure
        origin), then supplies that exact revision and digest here.
        """

        started = _record_for_state(self._records, "scope_started")
        if started is None:
            raise _error(
                "lifecycle_supervisor_scope_started_missing"
            )
        expected = _digest(
            expected_scope_started_receipt_sha256,
            field=(
                "lifecycle_supervisor_expected_scope_started_"
                "receipt_sha256"
            ),
        )
        if expected != started.details[
            "scope_started_receipt_sha256"
        ]:
            raise _error(
                "lifecycle_supervisor_scope_started_expectation_mismatch"
            )
        return self._append(
            state="capture_event",
            details={
                "effect_origin_state": effect_origin_state,
                "effect_origin_record_revision": (
                    effect_origin_record_revision
                ),
                "effect_origin_record_sha256": (
                    effect_origin_record_sha256
                ),
                "scope_started_receipt_sha256": expected,
            },
            operation_id_sha256=operation_id_sha256,
            recorded_at_unix=recorded_at_unix,
        )

    @_scope_serialized
    def record_clearance_intent(
        self,
        *,
        effect_origin_state: str,
        effect_origin_record_revision: int,
        effect_origin_record_sha256: str,
        expected_scope_started_receipt_sha256: str | None,
        clearance_mode: str,
        outer_clearance_intent_record_revision: int,
        outer_clearance_intent_record_sha256: str,
        operation_id_sha256: str,
        recorded_at_unix: int,
    ) -> LifecycleSupervisorRecord:
        """Bind the durable outer clearance request before observation."""

        start = self._records[0]
        start_details = start.details
        capture = _record_for_state(self._records, "capture_event")
        started = _record_for_state(self._records, "scope_started")
        if capture is None:
            expected_start = None
        else:
            if started is None:
                raise AssertionError("capture event without start")
            expected_start = started.details[
                "scope_started_receipt_sha256"
            ]
        if expected_scope_started_receipt_sha256 is None:
            observed_start = None
        else:
            observed_start = _digest(
                expected_scope_started_receipt_sha256,
                field=(
                    "lifecycle_supervisor_expected_scope_started_"
                    "receipt_sha256"
                ),
            )
        if observed_start != expected_start:
            raise _error(
                "lifecycle_supervisor_scope_started_expectation_mismatch"
            )
        if capture is None:
            expected_origin = "child_launch_intent"
            expected_origin_revision = start_details[
                "child_launch_intent_record_revision"
            ]
            expected_origin_digest = start_details[
                "child_launch_intent_record_sha256"
            ]
        else:
            expected_origin = capture.details["effect_origin_state"]
            expected_origin_revision = capture.details[
                "effect_origin_record_revision"
            ]
            expected_origin_digest = capture.details[
                "effect_origin_record_sha256"
            ]
        if (
            effect_origin_state != expected_origin
            or effect_origin_record_revision
            != expected_origin_revision
            or effect_origin_record_sha256 != expected_origin_digest
        ):
            raise _error(
                "lifecycle_supervisor_effect_origin_expectation_mismatch"
            )
        receipt = {
            "schema_version": (
                lifecycle_receipts.CLEARANCE_INTENT_RECEIPT_SCHEMA
            ),
            "status": lifecycle_receipts.CLEARANCE_INTENT_STATUS,
            **_stable_start_bindings(
                start,
                session_id=self._session_id,
                incarnation_id=self._incarnation_id,
            ),
            "effect_origin_state": expected_origin,
            "effect_origin_record_sha256": expected_origin_digest,
            "scope_started_receipt_sha256": expected_start,
            "clearance_mode": clearance_mode,
            "outer_clearance_intent_record_sha256": (
                outer_clearance_intent_record_sha256
            ),
        }
        try:
            receipt = (
                lifecycle_receipts.normalize_clearance_intent_receipt(
                    receipt
                )
            )
        except lifecycle_receipts.LifecycleReceiptError as exc:
            raise _error(
                f"lifecycle_supervisor_{exc.code}"
            ) from exc
        return self._append(
            state="clearance_intent",
            details={
                "clearance_intent_receipt": receipt,
                "clearance_intent_receipt_sha256": (
                    lifecycle_receipts.clearance_intent_receipt_sha256(
                        receipt
                    )
                ),
                "effect_origin_record_revision": (
                    expected_origin_revision
                ),
                "outer_clearance_intent_record_revision": (
                    outer_clearance_intent_record_revision
                ),
            },
            operation_id_sha256=operation_id_sha256,
            recorded_at_unix=recorded_at_unix,
        )

    @_scope_serialized
    def record_provider_observation(
        self,
        *,
        observation_kind: str,
        provider_observation_sha256: str,
        stderr_bytes: int | None,
        stderr_sha256: str | None,
        operation_id_sha256: str,
        recorded_at_unix: int,
    ) -> LifecycleSupervisorRecord:
        """Derive and record a clearance result or durable attention exit."""

        observation = _normalize_observation(
            {
                "observation_kind": observation_kind,
                "provider_observation_sha256": (
                    provider_observation_sha256
                ),
                "observed_supervisor_epoch_id": (
                    self._store.supervisor_epoch_id
                ),
                "observed_host_boot_id_sha256": (
                    self._store.host_boot_id_sha256
                ),
                "stderr_bytes": stderr_bytes,
                "stderr_sha256": stderr_sha256,
            }
        )
        receipt, reason = _derive_scope_empty_receipt(
            self._records, observation
        )
        if reason is not None:
            clearance = _record_for_state(
                self._records, "clearance_intent"
            )
            if clearance is None:
                raise _error(
                    "lifecycle_supervisor_clearance_intent_missing"
                )
            return self._append(
                state="operator_attention",
                details={
                    "reason_code": reason,
                    "clearance_intent_record_sha256": (
                        clearance.record_sha256
                    ),
                    "provider_observation": observation,
                    "observed_supervisor_epoch_id": (
                        self._store.supervisor_epoch_id
                    ),
                    "observed_host_boot_id_sha256": (
                        self._store.host_boot_id_sha256
                    ),
                },
                operation_id_sha256=operation_id_sha256,
                recorded_at_unix=recorded_at_unix,
            )
        if receipt is None:
            raise AssertionError("derived receipt missing")
        return self._append(
            state="provider_observation",
            details={
                "observation": observation,
                "scope_empty_receipt": receipt,
                "scope_empty_receipt_sha256": (
                    lifecycle_receipts.scope_empty_receipt_sha256(
                        receipt
                    )
                ),
            },
            operation_id_sha256=operation_id_sha256,
            recorded_at_unix=recorded_at_unix,
        )

    @_scope_serialized
    def record_settled_bundle(
        self,
        *,
        expected_provider_observation_record_sha256: str,
        operation_id_sha256: str,
        recorded_at_unix: int,
    ) -> LifecycleSupervisorRecord:
        """Assemble the final bundle from durable predecessor records only."""

        expected = _digest(
            expected_provider_observation_record_sha256,
            field=(
                "lifecycle_supervisor_expected_provider_observation_"
                "record_sha256"
            ),
        )
        start = self._records[0]
        started = _record_for_state(self._records, "scope_started")
        clearance = _record_for_state(
            self._records, "clearance_intent"
        )
        observation = _record_for_state(
            self._records, "provider_observation"
        )
        if (
            clearance is None
            or observation is None
            or observation.record_sha256 != expected
        ):
            raise _error(
                "lifecycle_supervisor_provider_observation_"
                "expectation_mismatch"
            )
        bundle = {
            "schema_version": lifecycle_receipts.CLEARANCE_BUNDLE_SCHEMA,
            "status": lifecycle_receipts.CLEARANCE_BUNDLE_STATUS,
            "activation_receipt": start.details[
                "activation_receipt"
            ],
            "activation_receipt_sha256": start.details[
                "activation_receipt_sha256"
            ],
            "scope_started_receipt": (
                None
                if started is None
                else started.details["scope_started_receipt"]
            ),
            "scope_started_receipt_sha256": (
                None
                if started is None
                else started.details[
                    "scope_started_receipt_sha256"
                ]
            ),
            "clearance_intent_receipt": clearance.details[
                "clearance_intent_receipt"
            ],
            "clearance_intent_receipt_sha256": clearance.details[
                "clearance_intent_receipt_sha256"
            ],
            "scope_empty_receipt": observation.details[
                "scope_empty_receipt"
            ],
            "scope_empty_receipt_sha256": observation.details[
                "scope_empty_receipt_sha256"
            ],
        }
        try:
            bundle = lifecycle_receipts.normalize_clearance_bundle(
                bundle
            )
        except lifecycle_receipts.LifecycleReceiptError as exc:
            raise _error(
                f"lifecycle_supervisor_{exc.code}"
            ) from exc
        return self._append(
            state="settled_bundle",
            details={
                "provider_observation_record_sha256": expected,
                "clearance_bundle": bundle,
                "clearance_bundle_sha256": (
                    lifecycle_receipts.clearance_bundle_sha256(bundle)
                ),
            },
            operation_id_sha256=operation_id_sha256,
            recorded_at_unix=recorded_at_unix,
        )

    @_scope_serialized
    def recovery_status(self) -> dict[str, Any]:
        """Classify the durable resume point without synthesizing evidence."""

        latest = self.latest_record
        start = self._records[0]
        provider = start.details["lifecycle_provider"]
        started = _record_for_state(self._records, "scope_started")
        if latest.state == "settled_bundle":
            action = "complete"
        elif latest.state == "operator_attention":
            action = "operator_attention"
        elif latest.state == "provider_observation":
            action = "settle_bundle"
        elif latest.state == "clearance_intent":
            if (
                started is not None
                and provider == "direct_waitid_deny_fork"
                and started.details["scope_started_receipt"][
                    "host_boot_id_sha256"
                ]
                == self._store.host_boot_id_sha256
                and started.details["scope_started_receipt"][
                    "supervisor_epoch_id"
                ]
                != self._store.supervisor_epoch_id
            ):
                action = "operator_attention"
            else:
                action = "observe_provider"
        else:
            action = "request_clearance"
        if action not in RECOVERY_ACTIONS:
            raise AssertionError("recovery action invalid")
        return {
            "instance_slug": start.details["instance_slug"],
            "instance_control_sha256": start.details[
                "instance_control_sha256"
            ],
            "capture_session_id": self._session_id,
            "scope_incarnation_id": self._incarnation_id,
            "lifecycle_scope_id": self.lifecycle_scope_id,
            "lifecycle_provider": provider,
            "state": latest.state,
            "ledger_head_sha256": latest.record_sha256,
            "current_supervisor_epoch_id": (
                self._store.supervisor_epoch_id
            ),
            "current_host_boot_id_sha256": (
                self._store.host_boot_id_sha256
            ),
            "action": action,
        }

    def _record_scope_started_for_test(
        self,
        *,
        provider_start_observation_sha256: str,
        operation_id_sha256: str,
        recorded_at_unix: int,
        fault_hook: Callable[[str], None],
    ) -> LifecycleSupervisorRecord:
        return self._record_scope_started(
            provider_start_observation_sha256=(
                provider_start_observation_sha256
            ),
            operation_id_sha256=operation_id_sha256,
            recorded_at_unix=recorded_at_unix,
            fault_hook=fault_hook,
        )

    @_scope_serialized
    def close(self) -> None:
        if self._directory_fd >= 0:
            try:
                os.close(self._directory_fd)
            finally:
                self._directory_fd = -1

    def __enter__(self) -> LifecycleSupervisorSession:
        self._require_active()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        del exc_type, exc, traceback
        self.close()
        return False

    def __reduce__(self) -> Any:
        raise TypeError(
            "LifecycleSupervisorSession is not serializable"
        )

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError(
            "LifecycleSupervisorSession is not serializable"
        )


class LifecycleSupervisorStore:
    """Exclusive lease over one root-owned lifecycle supervisor store."""

    __slots__ = (
        "_store_path",
        "_store_fd",
        "_lock_fd",
        "_owner_uid",
        "_owner_gid",
        "_instance_slug",
        "_instance_control_sha256",
        "_host_boot_id_sha256",
        "_supervisor_epoch_id",
        "_sessions",
        "_admission_lock",
        "_scope_locks",
    )

    def __init__(
        self,
        *,
        _token: object,
        store_path: Path,
        store_fd: int,
        lock_fd: int,
        owner_uid: int,
        owner_gid: int,
        instance_slug: str,
        instance_control_sha256: str,
        host_boot_id_sha256: str,
        supervisor_epoch_id: str,
    ) -> None:
        if _token is not _STORE_TOKEN:
            raise TypeError(
                "LifecycleSupervisorStore cannot be constructed directly"
            )
        os.set_inheritable(store_fd, False)
        os.set_inheritable(lock_fd, False)
        self._store_path = store_path
        self._store_fd = store_fd
        self._lock_fd = lock_fd
        self._owner_uid = owner_uid
        self._owner_gid = owner_gid
        self._instance_slug = instance_slug
        self._instance_control_sha256 = instance_control_sha256
        self._host_boot_id_sha256 = host_boot_id_sha256
        self._supervisor_epoch_id = supervisor_epoch_id
        self._sessions: list[LifecycleSupervisorSession] = []
        self._admission_lock = threading.RLock()
        self._scope_locks: dict[str, threading.RLock] = {}

    def _scope_lock_for(self, directory_name: str) -> threading.RLock:
        """Return the store-owned lock shared by every lease for a scope."""

        with self._admission_lock:
            selected = self._scope_locks.get(directory_name)
            if selected is None:
                selected = threading.RLock()
                self._scope_locks[directory_name] = selected
            return selected

    @property
    def active(self) -> bool:
        return self._store_fd >= 0 and self._lock_fd >= 0

    @property
    def host_boot_id_sha256(self) -> str:
        self._require_active()
        return self._host_boot_id_sha256

    @property
    def instance_slug(self) -> str:
        self._require_active()
        return self._instance_slug

    @property
    def instance_control_sha256(self) -> str:
        self._require_active()
        return self._instance_control_sha256

    @property
    def supervisor_epoch_id(self) -> str:
        self._require_active()
        return self._supervisor_epoch_id

    def _require_active(self) -> int:
        if not self.active:
            raise _error("lifecycle_supervisor_store_closed")
        return self._store_fd

    def _open_session_directory(self, name: str) -> int:
        store_fd = self._require_active()
        try:
            descriptor = os.open(
                name, _directory_flags(), dir_fd=store_fd
            )
        except OSError as exc:
            raise _error(
                "lifecycle_supervisor_session_directory_unreadable",
                operator_attention=True,
            ) from exc
        os.set_inheritable(descriptor, False)
        try:
            _validate_directory(
                descriptor,
                owner_uid=self._owner_uid,
                owner_gid=self._owner_gid,
                mode=SESSION_DIRECTORY_MODE,
                field="lifecycle_supervisor_session_directory",
            )
            _validate_named_fd_binding(
                store_fd,
                name,
                descriptor,
                directory=True,
                field="lifecycle_supervisor_session_directory",
            )
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def _read_event(
        self,
        session_fd: int,
        name: str,
        *,
        expected_session_id: str,
        expected_incarnation_id: str,
    ) -> LifecycleSupervisorRecord:
        match = EVENT_FILE_RE.fullmatch(name)
        if match is None or match.group(2) not in STATE_SET:
            raise _error(
                "lifecycle_supervisor_session_entry_invalid",
                operator_attention=True,
            )
        try:
            descriptor = os.open(
                name, _read_file_flags(), dir_fd=session_fd
            )
        except OSError as exc:
            raise _error(
                "lifecycle_supervisor_record_unreadable",
                operator_attention=True,
            ) from exc
        os.set_inheritable(descriptor, False)
        try:
            before = _validate_regular_file(
                descriptor,
                owner_uid=self._owner_uid,
                owner_gid=self._owner_gid,
                modes=frozenset({RECORD_FILE_MODE}),
                maximum_bytes=MAX_RECORD_BYTES,
                field="lifecycle_supervisor_record",
            )
            _validate_named_fd_binding(
                session_fd,
                name,
                descriptor,
                directory=False,
                field="lifecycle_supervisor_record",
            )
            raw = _read_bounded(
                descriptor,
                expected_size=before.st_size,
                maximum=MAX_RECORD_BYTES,
            )
            after = os.fstat(descriptor)
            rebound = os.stat(
                name, dir_fd=session_fd, follow_symlinks=False
            )
            if (
                _full_stat_tuple(before) != _full_stat_tuple(after)
                or _stable_object_tuple(after)
                != _stable_object_tuple(rebound)
            ):
                raise _error(
                    "lifecycle_supervisor_record_changed",
                    operator_attention=True,
                )
        finally:
            os.close(descriptor)
        record = LifecycleSupervisorRecord(
            _normalize_record(_decode_record(raw))
        )
        value = record.to_dict()
        if (
            record.revision != int(match.group(1))
            or record.state != match.group(2)
            or record.record_sha256 != match.group(3)
            or value["capture_session_id"] != expected_session_id
            or value["scope_incarnation_id"]
            != expected_incarnation_id
        ):
            raise _error(
                "lifecycle_supervisor_record_filename_mismatch",
                operator_attention=True,
            )
        return record

    def _validate_stale_temp(
        self, session_fd: int, name: str
    ) -> int:
        if TEMP_FILE_RE.fullmatch(name) is None:
            raise _error(
                "lifecycle_supervisor_session_entry_invalid",
                operator_attention=True,
            )
        try:
            descriptor = os.open(
                name, _read_file_flags(), dir_fd=session_fd
            )
        except OSError as exc:
            raise _error(
                "lifecycle_supervisor_stale_temp_unsafe",
                operator_attention=True,
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
                field="lifecycle_supervisor_stale_temp",
            )
            _validate_named_fd_binding(
                session_fd,
                name,
                descriptor,
                directory=False,
                field="lifecycle_supervisor_stale_temp",
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
    ) -> tuple[LifecycleSupervisorRecord, ...]:
        match = SESSION_DIRECTORY_RE.fullmatch(directory_name)
        if match is None:
            raise _error(
                "lifecycle_supervisor_session_directory_name_invalid",
                operator_attention=True,
            )
        session_id, incarnation_id = match.groups()
        entries = _bounded_entries(
            session_fd,
            maximum=(
                MAX_RECORDS_PER_SESSION + MAX_STALE_TEMP_FILES
            ),
            field="lifecycle_supervisor_session_inventory",
        )
        event_names = [
            name for name in entries if EVENT_FILE_RE.fullmatch(name)
        ]
        temp_names = [
            name for name in entries if TEMP_FILE_RE.fullmatch(name)
        ]
        if len(event_names) + len(temp_names) != len(entries):
            raise _error(
                "lifecycle_supervisor_session_entry_invalid",
                operator_attention=True,
            )
        if len(event_names) > MAX_RECORDS_PER_SESSION:
            raise _error(
                "lifecycle_supervisor_record_limit_exceeded",
                operator_attention=True,
            )
        if len(temp_names) > MAX_STALE_TEMP_FILES:
            raise _error(
                "lifecycle_supervisor_stale_temp_limit_exceeded",
                operator_attention=True,
            )
        records = tuple(
            sorted(
                (
                    self._read_event(
                        session_fd,
                        name,
                        expected_session_id=session_id,
                        expected_incarnation_id=incarnation_id,
                    )
                    for name in event_names
                ),
                key=lambda record: record.revision,
            )
        )
        if records:
            _validate_history(
                records,
                expected_session_id=session_id,
                expected_incarnation_id=incarnation_id,
            )
            start_details = records[0].details
            if (
                start_details["instance_slug"]
                != self._instance_slug
                or start_details["instance_control_sha256"]
                != self._instance_control_sha256
            ):
                raise _error(
                    "lifecycle_supervisor_instance_control_mismatch",
                    operator_attention=True,
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
                            field="lifecycle_supervisor_stale_temp",
                        )
                        try:
                            os.unlink(name, dir_fd=session_fd)
                        except OSError as exc:
                            raise _error(
                                "lifecycle_supervisor_stale_temp_"
                                "remove_failed",
                                operator_attention=True,
                            ) from exc
                    try:
                        os.fsync(session_fd)
                    except OSError as exc:
                        raise _error(
                            "lifecycle_supervisor_stale_temp_fsync_failed",
                            operator_attention=True,
                        ) from exc
            finally:
                for _name, descriptor in descriptors:
                    os.close(descriptor)
        return records

    @_store_serialized
    def _scan_store(
        self, *, create_leases: bool
    ) -> tuple[LifecycleSupervisorSession, ...]:
        store_fd = self._require_active()
        entries = _bounded_entries(
            store_fd,
            maximum=MAX_SESSION_DIRECTORIES + 1,
            field="lifecycle_supervisor_store_inventory",
        )
        if ".lock" not in entries:
            raise _error("lifecycle_supervisor_lock_file_missing")
        session_names = [name for name in entries if name != ".lock"]
        if (
            len(session_names) > MAX_SESSION_DIRECTORIES
            or any(
                SESSION_DIRECTORY_RE.fullmatch(name) is None
                for name in session_names
            )
        ):
            raise _error(
                "lifecycle_supervisor_store_entry_invalid",
                operator_attention=True,
            )
        seen_sessions: set[str] = set()
        loaded: list[LifecycleSupervisorSession] = []
        for name in sorted(session_names):
            match = SESSION_DIRECTORY_RE.fullmatch(name)
            if match is None:
                raise AssertionError("validated session name missing")
            session_id, incarnation_id = match.groups()
            if session_id in seen_sessions:
                raise _error(
                    "lifecycle_supervisor_session_reused",
                    operator_attention=True,
                )
            seen_sessions.add(session_id)
            descriptor = self._open_session_directory(name)
            keep = False
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
                        field=(
                            "lifecycle_supervisor_empty_session"
                        ),
                    )
                    try:
                        os.rmdir(name, dir_fd=store_fd)
                        os.fsync(store_fd)
                    except OSError as exc:
                        raise _error(
                            "lifecycle_supervisor_empty_session_"
                            "remove_failed"
                        ) from exc
                    continue
                if (
                    create_leases
                    and records[-1].state not in TERMINAL_STATES
                ):
                    lease = LifecycleSupervisorSession(
                        _token=_SESSION_TOKEN,
                        store=self,
                        directory_fd=descriptor,
                        directory_name=name,
                        records=records,
                        session_id=session_id,
                        incarnation_id=incarnation_id,
                    )
                    self._sessions.append(lease)
                    loaded.append(lease)
                    keep = True
            finally:
                if not keep:
                    os.close(descriptor)
        return tuple(loaded)

    def start_session(
        self,
        *,
        capture_session_id: str,
        scope_incarnation_id: str,
        activation_receipt: Mapping[str, Any],
        activation_receipt_sha256: str,
        staging_transaction_intent_sha256: str,
        staging_exposure_receipt_sha256: str,
        child_launch_intent_record_revision: int,
        child_launch_intent_record_sha256: str,
        handoff_policy_sha256: str,
        helper_activation_policy_sha256: str,
        capture_uid: int,
        export_gid: int,
        operation_id_sha256: str,
        recorded_at_unix: int,
    ) -> LifecycleSupervisorSession:
        """Durably authorize one exact scope incarnation before launch.

        ``scope_incarnation_id`` is supplied by the authenticated protocol
        after deterministic derivation from its durable request coordinate.
        This core validates and persists it verbatim; it never invents or
        regenerates an incarnation during retry or recovery.
        """

        return self._start_session(
            capture_session_id=capture_session_id,
            scope_incarnation_id=scope_incarnation_id,
            activation_receipt=activation_receipt,
            activation_receipt_sha256=activation_receipt_sha256,
            staging_transaction_intent_sha256=(
                staging_transaction_intent_sha256
            ),
            staging_exposure_receipt_sha256=(
                staging_exposure_receipt_sha256
            ),
            child_launch_intent_record_revision=(
                child_launch_intent_record_revision
            ),
            child_launch_intent_record_sha256=(
                child_launch_intent_record_sha256
            ),
            handoff_policy_sha256=handoff_policy_sha256,
            helper_activation_policy_sha256=(
                helper_activation_policy_sha256
            ),
            capture_uid=capture_uid,
            export_gid=export_gid,
            operation_id_sha256=operation_id_sha256,
            recorded_at_unix=recorded_at_unix,
            fault_hook=None,
        )

    @_store_serialized
    def _start_session(
        self,
        *,
        capture_session_id: str,
        scope_incarnation_id: str,
        activation_receipt: Mapping[str, Any],
        activation_receipt_sha256: str,
        staging_transaction_intent_sha256: str,
        staging_exposure_receipt_sha256: str,
        child_launch_intent_record_revision: int,
        child_launch_intent_record_sha256: str,
        handoff_policy_sha256: str,
        helper_activation_policy_sha256: str,
        capture_uid: int,
        export_gid: int,
        operation_id_sha256: str,
        recorded_at_unix: int,
        fault_hook: Callable[[str], None] | None,
    ) -> LifecycleSupervisorSession:
        store_fd = self._require_active()
        session_id = _session_id(capture_session_id)
        incarnation_id = _incarnation_id(scope_incarnation_id)
        try:
            normalized_activation = (
                lifecycle_receipts.normalize_activation_receipt(
                    activation_receipt
                )
            )
        except lifecycle_receipts.LifecycleReceiptError as exc:
            raise _error(
                f"lifecycle_supervisor_{exc.code}"
            ) from exc
        activation_digest = _digest(
            activation_receipt_sha256,
            field=(
                "lifecycle_supervisor_activation_receipt_sha256"
            ),
        )
        expected_activation_digest = (
            lifecycle_receipts.activation_receipt_sha256(
                normalized_activation
            )
        )
        if activation_digest != expected_activation_digest:
            raise _error(
                "lifecycle_supervisor_activation_digest_mismatch"
            )
        if (
            normalized_activation["host_boot_id_sha256"]
            != self._host_boot_id_sha256
        ):
            raise _error(
                "lifecycle_supervisor_activation_boot_mismatch"
            )
        details = _normalize_details(
            "start_intent",
            {
                "activation_receipt": normalized_activation,
                "activation_receipt_sha256": activation_digest,
                "instance_slug": self._instance_slug,
                "instance_control_sha256": (
                    self._instance_control_sha256
                ),
                "lifecycle_provider": normalized_activation[
                    "lifecycle_provider"
                ],
                "lifecycle_scope_id": _scope_id(session_id),
                "start_supervisor_epoch_id": (
                    self._supervisor_epoch_id
                ),
                "start_host_boot_id_sha256": (
                    self._host_boot_id_sha256
                ),
                "staging_transaction_intent_sha256": (
                    staging_transaction_intent_sha256
                ),
                "staging_exposure_receipt_sha256": (
                    staging_exposure_receipt_sha256
                ),
                "child_launch_intent_record_revision": (
                    child_launch_intent_record_revision
                ),
                "child_launch_intent_record_sha256": (
                    child_launch_intent_record_sha256
                ),
                "handoff_policy_sha256": handoff_policy_sha256,
                "helper_activation_policy_sha256": (
                    helper_activation_policy_sha256
                ),
                "capture_uid": capture_uid,
                "export_gid": export_gid,
            },
        )
        bound_start_operation = _bound_operation_id(
            operation_id_sha256,
            state="start_intent",
            session_id=session_id,
            incarnation_id=incarnation_id,
        )
        for active_session in self._sessions:
            if (
                active_session.active
                and active_session.capture_session_id == session_id
            ):
                if (
                    active_session.scope_incarnation_id
                    != incarnation_id
                ):
                    raise _error(
                        "lifecycle_supervisor_session_"
                        "incarnation_conflict",
                        operator_attention=True,
                    )
                first = active_session.records[0]
                if (
                    first.operation_id_sha256
                    == bound_start_operation
                    and first.details == details
                ):
                    return active_session
                raise _error(
                    "lifecycle_supervisor_start_"
                    "idempotency_conflict",
                    operator_attention=True,
                )
        directory_name = f"session-{session_id}-{incarnation_id}"
        entries = _bounded_entries(
            store_fd,
            maximum=MAX_SESSION_DIRECTORIES + 1,
            field="lifecycle_supervisor_store_inventory",
        )
        same_session = [
            name
            for name in entries
            if (
                (match := SESSION_DIRECTORY_RE.fullmatch(name))
                and match.group(1) == session_id
            )
        ]
        if same_session:
            if same_session != [directory_name]:
                raise _error(
                    "lifecycle_supervisor_session_incarnation_conflict",
                    operator_attention=True,
                )
            descriptor = self._open_session_directory(directory_name)
            keep = False
            try:
                records = self._scan_session(
                    directory_name,
                    descriptor,
                    clean_stale_temps=True,
                )
                if not records:
                    raise _error(
                        "lifecycle_supervisor_existing_session_empty",
                        operator_attention=True,
                    )
                first = records[0]
                if (
                    first.operation_id_sha256
                    != bound_start_operation
                    or first.details != details
                ):
                    raise _error(
                        "lifecycle_supervisor_start_idempotency_conflict",
                        operator_attention=True,
                    )
                session = LifecycleSupervisorSession(
                    _token=_SESSION_TOKEN,
                    store=self,
                    directory_fd=descriptor,
                    directory_name=directory_name,
                    records=records,
                    session_id=session_id,
                    incarnation_id=incarnation_id,
                )
                self._sessions.append(session)
                keep = True
                return session
            finally:
                if not keep:
                    os.close(descriptor)
        if len(entries) - 1 >= MAX_SESSION_DIRECTORIES:
            raise _error(
                "lifecycle_supervisor_session_capacity_exceeded"
            )
        try:
            os.mkdir(
                directory_name,
                SESSION_DIRECTORY_MODE,
                dir_fd=store_fd,
            )
        except FileExistsError as exc:
            raise _error(
                "lifecycle_supervisor_session_exists",
                operator_attention=True,
            ) from exc
        except OSError as exc:
            raise _error(
                "lifecycle_supervisor_session_create_failed"
            ) from exc
        _call_fault(fault_hook, "after_session_mkdir")
        descriptor = self._open_session_directory(directory_name)
        session: LifecycleSupervisorSession | None = None
        try:
            try:
                os.fsync(descriptor)
            except OSError as exc:
                raise _error(
                    "lifecycle_supervisor_new_session_fsync_failed"
                ) from exc
            _call_fault(fault_hook, "after_new_session_fsync")
            try:
                os.fsync(store_fd)
            except OSError as exc:
                raise _error(
                    "lifecycle_supervisor_store_fsync_failed"
                ) from exc
            _call_fault(fault_hook, "after_store_fsync")
            session = LifecycleSupervisorSession(
                _token=_SESSION_TOKEN,
                store=self,
                directory_fd=descriptor,
                directory_name=directory_name,
                records=(),
                session_id=session_id,
                incarnation_id=incarnation_id,
            )
            session._append(
                state="start_intent",
                details=details,
                operation_id_sha256=operation_id_sha256,
                recorded_at_unix=recorded_at_unix,
                fault_hook=fault_hook,
            )
        except BaseException:
            if session is not None:
                session.close()
            else:
                os.close(descriptor)
            raise
        self._sessions.append(session)
        return session

    def _start_session_for_test(
        self,
        *,
        fault_hook: Callable[[str], None],
        **kwargs: Any,
    ) -> LifecycleSupervisorSession:
        if not callable(fault_hook):
            raise _error("lifecycle_supervisor_fault_hook_invalid")
        return self._start_session(
            fault_hook=fault_hook,
            **kwargs,
        )

    @_store_serialized
    def load_incomplete_sessions(
        self,
    ) -> tuple[LifecycleSupervisorSession, ...]:
        """Replay and lease every nonterminal durable incarnation."""

        if any(session.active for session in self._sessions):
            raise _error(
                "lifecycle_supervisor_sessions_already_open"
            )
        return self._scan_store(create_leases=True)

    @_store_serialized
    def close(self) -> None:
        for session in reversed(self._sessions):
            session.close()
        self._sessions.clear()
        for field in ("_lock_fd", "_store_fd"):
            descriptor = getattr(self, field)
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                finally:
                    setattr(self, field, -1)

    def __enter__(self) -> LifecycleSupervisorStore:
        self._require_active()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        del exc_type, exc, traceback
        self.close()
        return False

    def __reduce__(self) -> Any:
        raise TypeError("LifecycleSupervisorStore is not serializable")

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError("LifecycleSupervisorStore is not serializable")


def _open_lifecycle_supervisor_store(
    store_path: Path | str,
    *,
    instance_slug: str,
    instance_control_sha256: str,
    host_boot_id_sha256: str,
    supervisor_epoch_id: str,
    owner_uid: int,
    owner_gid: int,
    strict_parent_chain: bool,
) -> LifecycleSupervisorStore:
    selected_path = _absolute_path(store_path)
    selected_instance = _instance_slug(instance_slug)
    instance_control = _digest(
        instance_control_sha256,
        field="lifecycle_supervisor_instance_control_sha256",
    )
    boot = _digest(
        host_boot_id_sha256,
        field="lifecycle_supervisor_host_boot_id_sha256",
    )
    epoch = _digest(
        supervisor_epoch_id,
        field="lifecycle_supervisor_epoch_id",
    )
    if strict_parent_chain:
        _validate_trusted_parent_chain(
            selected_path, owner_uid=owner_uid
        )
    store_fd = -1
    lock_fd = -1
    lease: LifecycleSupervisorStore | None = None
    try:
        try:
            store_fd = os.open(selected_path, _directory_flags())
        except OSError as exc:
            raise _error(
                "lifecycle_supervisor_store_unreadable"
            ) from exc
        _validate_directory(
            store_fd,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            mode=STORE_MODE,
            field="lifecycle_supervisor_store",
        )
        _validate_path_fd_binding(
            selected_path,
            store_fd,
            field="lifecycle_supervisor_store",
        )
        try:
            lock_fd = os.open(
                ".lock", _lock_file_flags(), dir_fd=store_fd
            )
        except OSError as exc:
            raise _error(
                "lifecycle_supervisor_lock_file_unreadable"
            ) from exc
        _validate_regular_file(
            lock_fd,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            modes=frozenset({LOCK_FILE_MODE}),
            maximum_bytes=0,
            field="lifecycle_supervisor_lock_file",
        )
        _validate_named_fd_binding(
            store_fd,
            ".lock",
            lock_fd,
            directory=False,
            field="lifecycle_supervisor_lock_file",
        )
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise _error("lifecycle_supervisor_store_busy") from exc
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise _error(
                    "lifecycle_supervisor_store_busy"
                ) from exc
            raise _error(
                "lifecycle_supervisor_store_lock_failed"
            ) from exc
        _validate_named_fd_binding(
            store_fd,
            ".lock",
            lock_fd,
            directory=False,
            field="lifecycle_supervisor_lock_file",
        )
        lease = LifecycleSupervisorStore(
            _token=_STORE_TOKEN,
            store_path=selected_path,
            store_fd=store_fd,
            lock_fd=lock_fd,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            instance_slug=selected_instance,
            instance_control_sha256=instance_control,
            host_boot_id_sha256=boot,
            supervisor_epoch_id=epoch,
        )
        store_fd = -1
        lock_fd = -1
        lease._scan_store(create_leases=False)
        return lease
    except BaseException:
        if lease is not None:
            lease.close()
        raise
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)
        if store_fd >= 0:
            os.close(store_fd)


def open_lifecycle_supervisor_store(
    store_path: Path | str,
    *,
    instance_slug: str,
    instance_control_sha256: str,
    host_boot_id_sha256: str,
    supervisor_epoch_id: str,
) -> LifecycleSupervisorStore:
    """Open the production root-owned store and acquire its lock."""

    if os.geteuid() != 0:
        raise _error("lifecycle_supervisor_requires_root")
    return _open_lifecycle_supervisor_store(
        store_path,
        instance_slug=instance_slug,
        instance_control_sha256=instance_control_sha256,
        host_boot_id_sha256=host_boot_id_sha256,
        supervisor_epoch_id=supervisor_epoch_id,
        owner_uid=0,
        owner_gid=0,
        strict_parent_chain=True,
    )


def _open_lifecycle_supervisor_store_for_test(
    store_path: Path | str,
    *,
    instance_slug: str,
    instance_control_sha256: str,
    host_boot_id_sha256: str,
    supervisor_epoch_id: str,
) -> LifecycleSupervisorStore:
    """Exercise the filesystem contract as the unprivileged test identity."""

    return _open_lifecycle_supervisor_store(
        store_path,
        instance_slug=instance_slug,
        instance_control_sha256=instance_control_sha256,
        host_boot_id_sha256=host_boot_id_sha256,
        supervisor_epoch_id=supervisor_epoch_id,
        owner_uid=os.geteuid(),
        owner_gid=os.getegid(),
        strict_parent_chain=False,
    )


__all__ = [
    "DIRECT_WAIT_RESTART_REASON",
    "LEDGER_RECORD_SCHEMA",
    "LifecycleSupervisorError",
    "LifecycleSupervisorRecord",
    "LifecycleSupervisorSession",
    "LifecycleSupervisorStore",
    "PRODUCTION_ACTIVATION",
    "PRODUCTION_BLOCKERS",
    "PROVIDER_OBSERVATION_KINDS",
    "RECOVERY_ACTIONS",
    "SCOPE_INCARNATION_ID_CONTRACT",
    "STATES",
    "TERMINAL_STATES",
    "open_lifecycle_supervisor_store",
]
