#!/usr/bin/env python3
"""Root-managed, crash-safe staging leaves for capture handoff v2.

This module owns no model, verifier, signing, network, or process-signalling
authority.  It creates one unpredictable capture-owned leaf beneath a
root-owned shared staging root, retains exact descriptor authority for that
leaf, and records append-only filesystem intents on the same device.

Recovery never reads or signals a serialized PID or PGID.  A pre-adoption
leaf whose in-memory process-death proof was lost is moved whole, without
replacement, into a root-only quarantine and left sealed.  Only the live
coordinator may remove an empty leaf after directly containing and reaping
the process scope.
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
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from qualification_attestor import (
    john_lomein_persona_qualification_capture_staging_receipts
    as staging_receipts,
)


PRODUCTION_ACTIVATION = False

STAGING_JOURNAL_SCHEMA = (
    staging_receipts.CAPTURE_STAGING_JOURNAL_SCHEMA
)
SHARED_ROOT_MODE = 0o711
RECOVERY_NAMESPACE_MODE = 0o711
CONTROL_NAMESPACE_MODE = 0o700
LOCK_FILE_MODE = 0o600
JOURNAL_FILE_MODE = 0o600
EXPOSED_LEAF_MODE = 0o700
REVOKED_LEAF_MODE = 0o500

RECOVERY_NAMESPACE = "recovery"
QUARANTINE_NAMESPACE = "quarantine"
QUARANTINE_STAGING_NAMESPACE = "staging"
TRANSACTIONS_NAMESPACE = "transactions"
LOCK_NAME = ".lock"
COMPLETED_NAMESPACE = ".completed"
STAGING_TOMBSTONE_SCHEMA = (
    "john-lomein.persona-qualification-capture-staging-tombstone.v1"
)
COMPLETED_TOMBSTONE_SCHEMA = (
    "john-lomein.persona-qualification-capture-staging-completed.v1"
)

SESSION_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
SESSION_NAME_RE = re.compile(r"^session-[0-9a-f]{64}$")
JOURNAL_NAME_RE = re.compile(r"^session-[0-9a-f]{64}\.jsonl$")
TOMBSTONE_NAME_RE = re.compile(r"^session-[0-9a-f]{64}\.json$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_NAMESPACE_ENTRIES = 4_096
MAX_JOURNAL_BYTES = 128 * 1024
MAX_JOURNAL_RECORD_BYTES = 16 * 1024
MAX_OPERATOR_REMOVAL_ENTRIES = 8_192
MAX_OPERATOR_REMOVAL_DEPTH = 64
MAX_OPERATOR_REMOVAL_BYTES = 128 * 1024 * 1024
MAX_CREATE_ATTEMPTS = 8
MAX_COMPLETED_TOMBSTONES = 4_096
MAX_TOMBSTONE_BYTES = 16 * 1024

JOURNAL_FIELDS = {
    "schema_version",
    "session_name",
    "sequence",
    "event",
    "leaf_identity_sha256",
    "staging_transaction_intent_sha256",
    "rename_primitive",
    "quarantine_reason_code",
    "lifecycle_scope_empty_receipt_sha256",
    "outer_ack_pending_record_sha256",
    "outer_quarantine_intent_record_sha256",
    "outer_staging_tombstone_acked_record_sha256",
    "outer_lifecycle_clearance_record_sha256",
    "terminal_receipt_sha256",
    "tombstone_sha256",
    "terminal_disposition",
    "previous_record_sha256",
    "record_sha256",
}
JOURNAL_EVENTS = {
    "create_intent",
    "leaf_created",
    "staging_exposure_intent",
    "staging_exposed",
    "spawn_intent",
    "spawn_failed",
    "spawned",
    "ready_bound",
    "process_scope_dead",
    "cleanup_intent",
    "removed",
    "quarantine_intent",
    "quarantined",
    "quarantine_remove_intent",
    "quarantine_removed",
    "startup_identity_observed",
    "startup_quarantine_intent",
    "startup_quarantined",
    "startup_absent",
    "operator_attention",
    "outer_tombstone_acknowledged",
    "operator_resolution_intent",
    "operator_removed",
}
TERMINAL_JOURNAL_EVENTS = frozenset(
    {
        "removed",
        "quarantine_removed",
        "startup_absent",
        "operator_removed",
    }
)

_RENAME_NOREPLACE = 1
_DARWIN_RENAME_EXCL = 0x00000004
_LEASE_TOKEN = object()
_INSTALLED_CONTROL_TOKEN = object()
_RECOVERED_ADOPTION_ACK_CALL_TOKEN = object()


class CaptureStagingError(RuntimeError):
    """Stable, public-safe staging lifecycle rejection."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _error(code: str) -> CaptureStagingError:
    return CaptureStagingError(code)


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise _error("capture_staging_json_invalid") from exc


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _error("capture_staging_journal_duplicate_field")
        value[key] = item
    return value


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
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


def _absolute_path(value: Path | str, *, field: str) -> Path:
    if not isinstance(value, (Path, str)):
        raise _error(f"{field}_invalid")
    text = unicodedata.normalize("NFC", str(value))
    path = Path(text)
    if (
        not path.is_absolute()
        or "\x00" in text
        or "\n" in text
        or "\r" in text
        or "." in path.parts
        or ".." in path.parts
        or str(path) != text
    ):
        raise _error(f"{field}_invalid")
    return path


def _session_token(value: Any) -> str:
    if not isinstance(value, str) or not SESSION_TOKEN_RE.fullmatch(value):
        raise _error("capture_staging_session_token_invalid")
    return value


def _stable_identity(info: os.stat_result) -> tuple[int, int, int]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(stat.S_IFMT(info.st_mode)),
    )


def _identity_sha256(info: os.stat_result) -> str:
    return _sha256(_canonical_json(list(_stable_identity(info))))


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


def _stat_sha256(info: os.stat_result) -> str:
    return _sha256(_canonical_json(list(_full_stat_tuple(info))))


def _directory_flags() -> int:
    required = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW")
    if not all(hasattr(os, name) for name in required):
        raise _error("capture_staging_descriptor_flags_unsupported")
    return os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW


def _journal_flags(*, create: bool) -> int:
    required = ("O_CLOEXEC", "O_NOFOLLOW")
    if not all(hasattr(os, name) for name in required):
        raise _error("capture_staging_descriptor_flags_unsupported")
    flags = os.O_RDWR | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    return flags


def _reject_fd_metadata(descriptor: int, *, field: str) -> None:
    """Reject authorizing extended metadata and Darwin ACL grants."""

    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        if not hasattr(libc, "flistxattr"):
            raise _error(f"{field}_fd_metadata_unsupported")
        libc.flistxattr.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_int,
        ]
        libc.flistxattr.restype = ctypes.c_ssize_t
        size = libc.flistxattr(descriptor, None, 0, 0)
    elif sys.platform.startswith("linux"):
        if not hasattr(libc, "flistxattr"):
            raise _error(f"{field}_fd_metadata_unsupported")
        libc.flistxattr.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        libc.flistxattr.restype = ctypes.c_ssize_t
        size = libc.flistxattr(descriptor, None, 0)
    else:
        raise _error(f"{field}_fd_metadata_unsupported")
    if size < 0:
        raise _error(f"{field}_metadata_unreadable")
    attributes: set[bytes] = set()
    if size:
        buffer = ctypes.create_string_buffer(size)
        if sys.platform == "darwin":
            observed = libc.flistxattr(descriptor, buffer, size, 0)
        else:
            observed = libc.flistxattr(descriptor, buffer, size)
        if observed != size:
            raise _error(f"{field}_metadata_changed")
        attributes = {
            name
            for name in bytes(buffer.raw[:observed]).split(b"\x00")
            if name
        }
    permitted = (
        {b"com.apple.provenance"}
        if sys.platform == "darwin"
        else {b"security.selinux"}
    )
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


def _validate_trusted_parent_chain(path: Path, *, root_uid: int) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise _error("capture_staging_parent_chain_unreadable") from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != root_uid
            or info.st_mode & 0o022
        ):
            raise _error("capture_staging_parent_chain_unsafe")


def _validate_directory(
    descriptor: int,
    *,
    owner_uid: int,
    group_gid: int,
    mode: int,
    device: int | None,
    field: str,
) -> os.stat_result:
    try:
        info = os.fstat(descriptor)
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != owner_uid
        or info.st_gid != group_gid
        or stat.S_IMODE(info.st_mode) != mode
        or (device is not None and info.st_dev != device)
    ):
        raise _error(f"{field}_unsafe")
    if os.get_inheritable(descriptor):
        raise _error(f"{field}_inheritable")
    _reject_fd_metadata(descriptor, field=field)
    return info


def _open_bound_directory(
    parent_fd: int,
    name: str,
    *,
    field: str,
) -> tuple[int, os.stat_result]:
    try:
        named = os.stat(
            name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        descriptor = os.open(
            name,
            _directory_flags(),
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(named.st_mode)
            or _stable_identity(named) != _stable_identity(opened)
        ):
            raise _error(f"{field}_inode_mismatch")
        if os.get_inheritable(descriptor):
            raise _error(f"{field}_inheritable")
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _bound_name_matches(
    parent_fd: int,
    name: str,
    descriptor: int,
) -> bool:
    try:
        named = os.stat(
            name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        opened = os.fstat(descriptor)
    except OSError:
        return False
    return (
        stat.S_ISDIR(named.st_mode)
        and _stable_identity(named) == _stable_identity(opened)
    )


def _bounded_entries(
    descriptor: int,
    *,
    field: str,
) -> list[str]:
    try:
        with os.scandir(descriptor) as iterator:
            entries: list[str] = []
            for entry in iterator:
                entries.append(entry.name)
                if len(entries) > MAX_NAMESPACE_ENTRIES:
                    raise _error(f"{field}_inventory_exceeded")
    except CaptureStagingError:
        raise
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    return sorted(entries)


def _ensure_namespace(
    parent_fd: int,
    name: str,
    *,
    owner_uid: int,
    group_gid: int,
    mode: int,
    device: int,
    field: str,
) -> int:
    created = False
    try:
        os.mkdir(name, mode, dir_fd=parent_fd)
        created = True
    except FileExistsError:
        pass
    except OSError as exc:
        raise _error(f"{field}_create_failed") from exc
    descriptor = -1
    try:
        descriptor, _info = _open_bound_directory(
            parent_fd,
            name,
            field=field,
        )
        if created:
            os.fchmod(descriptor, 0)
            os.fchown(descriptor, owner_uid, group_gid)
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
            os.fsync(parent_fd)
        _validate_directory(
            descriptor,
            owner_uid=owner_uid,
            group_gid=group_gid,
            mode=mode,
            device=device,
            field=field,
        )
        return descriptor
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _open_shared_root(
    path: Path,
    *,
    root_uid: int,
    root_gid: int,
    strict_parent_chain: bool,
    required_device: int | None,
) -> tuple[int, int]:
    root = _absolute_path(path, field="capture_staging_shared_root")
    if strict_parent_chain:
        _validate_trusted_parent_chain(root.parent, root_uid=root_uid)
    try:
        named = os.lstat(root)
        descriptor = os.open(root, _directory_flags())
    except OSError as exc:
        raise _error("capture_staging_shared_root_unreadable") from exc
    try:
        opened = _validate_directory(
            descriptor,
            owner_uid=root_uid,
            group_gid=root_gid,
            mode=SHARED_ROOT_MODE,
            device=required_device,
            field="capture_staging_shared_root",
        )
        if _stable_identity(named) != _stable_identity(opened):
            raise _error("capture_staging_shared_root_inode_mismatch")
        return descriptor, int(opened.st_dev)
    except BaseException:
        os.close(descriptor)
        raise


def _validate_regular_control_file(
    descriptor: int,
    *,
    root_uid: int,
    root_gid: int,
    mode: int,
    device: int,
    field: str,
) -> os.stat_result:
    try:
        info = os.fstat(descriptor)
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != root_uid
        or info.st_gid != root_gid
        or stat.S_IMODE(info.st_mode) != mode
        or info.st_nlink != 1
        or info.st_dev != device
        or os.get_inheritable(descriptor)
    ):
        raise _error(f"{field}_unsafe")
    _reject_fd_metadata(descriptor, field=field)
    return info


def _open_lock(
    transactions_fd: int,
    *,
    root_uid: int,
    root_gid: int,
    device: int,
) -> int:
    required = ("O_CLOEXEC", "O_NOFOLLOW")
    if not all(hasattr(os, name) for name in required):
        raise _error("capture_staging_descriptor_flags_unsupported")
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(
            LOCK_NAME,
            flags,
            LOCK_FILE_MODE,
            dir_fd=transactions_fd,
        )
    except OSError as exc:
        raise _error("capture_staging_lock_unreadable") from exc
    try:
        os.fchown(descriptor, root_uid, root_gid)
        os.fchmod(descriptor, LOCK_FILE_MODE)
        _validate_regular_control_file(
            descriptor,
            root_uid=root_uid,
            root_gid=root_gid,
            mode=LOCK_FILE_MODE,
            device=device,
            field="capture_staging_lock",
        )
        try:
            fcntl.flock(
                descriptor,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError as exc:
            raise _error("capture_staging_session_busy") from exc
        os.fsync(descriptor)
        os.fsync(transactions_fd)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _journal_name(session_name: str) -> str:
    if not SESSION_NAME_RE.fullmatch(session_name):
        raise _error("capture_staging_session_name_invalid")
    return f"{session_name}.jsonl"


def _append_all(descriptor: int, raw: bytes) -> None:
    try:
        starting_size = int(os.fstat(descriptor).st_size)
    except OSError as exc:
        raise _error("capture_staging_journal_write_failed") from exc
    if (
        starting_size < 0
        or starting_size + len(raw) > MAX_JOURNAL_BYTES
    ):
        raise _error("capture_staging_journal_too_large")
    offset = 0
    try:
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise OSError(errno.EIO, "short journal write")
            offset += written
        os.fsync(descriptor)
    except OSError as exc:
        # A live coordinator still owns the exclusive transaction lock.  Roll
        # a failed append back to the exact pre-write size so a second record
        # can never be appended after a known partial frame.  SIGKILL can
        # bypass this block; startup performs the separately constrained
        # final-tail repair below.
        try:
            os.ftruncate(descriptor, starting_size)
            os.fsync(descriptor)
        except OSError:
            pass
        code = (
            "capture_staging_journal_fsync_failed"
            if offset == len(raw)
            else "capture_staging_journal_write_failed"
        )
        raise _error(code) from exc


def _append_record(
    descriptor: int,
    *,
    session_name: str,
    sequence: int,
    event: str,
    identity_sha256: str | None,
    staging_transaction_intent_sha256: str,
    rename_primitive: str | None = None,
    quarantine_reason_code: str | None = None,
    lifecycle_scope_empty_receipt_sha256: str | None = None,
    outer_ack_pending_record_sha256: str | None = None,
    outer_quarantine_intent_record_sha256: str | None = None,
    outer_staging_tombstone_acked_record_sha256: str | None = None,
    outer_lifecycle_clearance_record_sha256: str | None = None,
    terminal_receipt_sha256: str | None = None,
    tombstone_sha256: str | None = None,
    terminal_disposition: str | None = None,
) -> None:
    if event not in JOURNAL_EVENTS:
        raise _error("capture_staging_journal_event_invalid")
    if (
        identity_sha256 is not None
        and not SHA256_RE.fullmatch(identity_sha256)
    ):
        raise _error("capture_staging_journal_identity_invalid")
    transaction_intent = _digest(
        staging_transaction_intent_sha256,
        field="capture_staging_transaction_intent_sha256",
    )
    state = _parse_journal(
        _read_descriptor(
            descriptor,
            maximum_bytes=MAX_JOURNAL_BYTES,
        ),
        session_name=session_name,
        allow_torn_tail=False,
    )
    if state.next_sequence != sequence:
        raise _error("capture_staging_journal_sequence_invalid")
    if (
        state.staging_transaction_intent_sha256 is not None
        and state.staging_transaction_intent_sha256
        != transaction_intent
    ):
        raise _error(
            "capture_staging_journal_transaction_intent_changed"
        )
    selected_rename_primitive = (
        state.rename_primitive
        if state.rename_primitive is not None
        else rename_primitive
    )
    if selected_rename_primitive is not None and (
        selected_rename_primitive
        not in staging_receipts.RENAME_PRIMITIVES
    ):
        raise _error(
            "capture_staging_journal_rename_primitive_invalid"
        )
    if (
        state.rename_primitive is not None
        and rename_primitive is not None
        and rename_primitive != state.rename_primitive
    ):
        raise _error(
            "capture_staging_journal_rename_primitive_changed"
        )
    selected_quarantine_reason = (
        state.quarantine_reason_code
        if state.quarantine_reason_code is not None
        else quarantine_reason_code
    )
    if (
        selected_quarantine_reason is not None
        and selected_quarantine_reason
        not in {"capture_failed", "coordinator_restarted"}
    ):
        raise _error(
            "capture_staging_journal_quarantine_reason_invalid"
        )
    if (
        state.quarantine_reason_code is None
        and quarantine_reason_code is not None
        and event
        not in {"quarantine_intent", "startup_quarantine_intent"}
    ):
        raise _error(
            "capture_staging_journal_quarantine_reason_event_invalid"
        )
    if (
        state.quarantine_reason_code is not None
        and quarantine_reason_code is not None
        and quarantine_reason_code != state.quarantine_reason_code
    ):
        raise _error(
            "capture_staging_journal_quarantine_reason_changed"
        )
    supplied_lifecycle_values = (
        lifecycle_scope_empty_receipt_sha256,
        outer_lifecycle_clearance_record_sha256,
    )
    if any(
        value is not None for value in supplied_lifecycle_values
    ) and not all(
        value is not None for value in supplied_lifecycle_values
    ):
        raise _error(
            "capture_staging_journal_lifecycle_binding_incomplete"
        )
    if state.lifecycle_scope_empty_receipt_sha256 is None:
        if any(
            value is not None for value in supplied_lifecycle_values
        ):
            if event != "process_scope_dead":
                raise _error(
                    "capture_staging_journal_"
                    "lifecycle_binding_event_invalid"
                )
            selected_scope_empty = _digest(
                lifecycle_scope_empty_receipt_sha256,
                field=(
                    "capture_staging_lifecycle_"
                    "scope_empty_receipt_sha256"
                ),
            )
            selected_lifecycle_clearance = _digest(
                outer_lifecycle_clearance_record_sha256,
                field=(
                    "capture_staging_outer_lifecycle_"
                    "clearance_record_sha256"
                ),
            )
        else:
            if event == "process_scope_dead":
                raise _error(
                    "capture_staging_journal_"
                    "lifecycle_binding_missing"
                )
            selected_scope_empty = None
            selected_lifecycle_clearance = None
    else:
        if any(
            value is not None for value in supplied_lifecycle_values
        ) and supplied_lifecycle_values != (
            state.lifecycle_scope_empty_receipt_sha256,
            state.outer_lifecycle_clearance_record_sha256,
        ):
            raise _error(
                "capture_staging_journal_lifecycle_binding_changed"
            )
        selected_scope_empty = (
            state.lifecycle_scope_empty_receipt_sha256
        )
        selected_lifecycle_clearance = (
            state.outer_lifecycle_clearance_record_sha256
        )
    if state.outer_staging_tombstone_acked_record_sha256 is None:
        if outer_staging_tombstone_acked_record_sha256 is not None:
            if event != "operator_resolution_intent":
                raise _error(
                    "capture_staging_journal_outer_acked_event_invalid"
                )
            selected_outer_acked = _digest(
                outer_staging_tombstone_acked_record_sha256,
                field=(
                    "capture_staging_outer_staging_"
                    "tombstone_acked_record_sha256"
                ),
            )
        else:
            if event == "operator_resolution_intent":
                raise _error(
                    "capture_staging_journal_outer_acked_missing"
                )
            selected_outer_acked = None
    else:
        if (
            outer_staging_tombstone_acked_record_sha256 is not None
            and outer_staging_tombstone_acked_record_sha256
            != state.outer_staging_tombstone_acked_record_sha256
        ):
            raise _error(
                "capture_staging_journal_outer_acked_changed"
            )
        selected_outer_acked = (
            state.outer_staging_tombstone_acked_record_sha256
        )
    supplied_ack_values = (
        outer_ack_pending_record_sha256,
        terminal_receipt_sha256,
        tombstone_sha256,
        terminal_disposition,
    )
    if any(value is not None for value in supplied_ack_values) and not all(
        value is not None for value in supplied_ack_values
    ):
        raise _error("capture_staging_journal_ack_binding_incomplete")
    if state.ack_record_sha256 is None:
        if event == staging_receipts.STAGING_TOMBSTONE_ACK_EVENT:
            if not all(value is not None for value in supplied_ack_values):
                raise _error(
                    "capture_staging_journal_ack_binding_missing"
                )
            selected_outer_ack = _digest(
                outer_ack_pending_record_sha256,
                field=(
                    "capture_staging_outer_ack_pending_record_sha256"
                ),
            )
            selected_outer_quarantine = (
                None
                if outer_quarantine_intent_record_sha256 is None
                else _digest(
                    outer_quarantine_intent_record_sha256,
                    field=(
                        "capture_staging_outer_"
                        "quarantine_intent_record_sha256"
                    ),
                )
            )
            selected_terminal_receipt = _digest(
                terminal_receipt_sha256,
                field="capture_staging_terminal_receipt_sha256",
            )
            selected_tombstone = _digest(
                tombstone_sha256,
                field="capture_staging_tombstone_sha256",
            )
            if terminal_disposition not in (
                staging_receipts.TERMINAL_DISPOSITIONS
            ):
                raise _error(
                    "capture_staging_terminal_disposition_invalid"
                )
            selected_terminal_disposition = terminal_disposition
            requires_outer_quarantine_intent = (
                selected_terminal_disposition == "quarantined"
                or (
                    selected_terminal_disposition == "absent"
                    and state.quarantine_reason_code is not None
                )
            )
            if (
                requires_outer_quarantine_intent
                and selected_outer_quarantine is None
            ):
                raise _error(
                    "capture_staging_journal_"
                    "outer_quarantine_intent_missing"
                )
            if (
                not requires_outer_quarantine_intent
                and selected_outer_quarantine is not None
            ):
                raise _error(
                    "capture_staging_journal_"
                    "outer_quarantine_intent_unexpected"
                )
            if (
                outer_lifecycle_clearance_record_sha256
                != state.outer_lifecycle_clearance_record_sha256
            ):
                raise _error(
                    "capture_staging_journal_ack_"
                    "lifecycle_clearance_mismatch"
                )
        else:
            if (
                any(value is not None for value in supplied_ack_values)
                or outer_quarantine_intent_record_sha256 is not None
            ):
                raise _error(
                    "capture_staging_journal_ack_binding_event_invalid"
                )
            selected_outer_ack = None
            selected_outer_quarantine = None
            selected_terminal_receipt = None
            selected_tombstone = None
            selected_terminal_disposition = None
    else:
        if event == staging_receipts.STAGING_TOMBSTONE_ACK_EVENT:
            raise _error("capture_staging_journal_ack_duplicate")
        expected = (
            state.outer_ack_pending_record_sha256,
            state.terminal_receipt_sha256,
            state.tombstone_sha256,
            state.terminal_disposition,
        )
        if any(value is not None for value in supplied_ack_values) and (
            supplied_ack_values != expected
        ):
            raise _error("capture_staging_journal_ack_binding_changed")
        if (
            outer_quarantine_intent_record_sha256 is not None
            and outer_quarantine_intent_record_sha256
            != state.outer_quarantine_intent_record_sha256
        ):
            raise _error(
                "capture_staging_journal_"
                "outer_quarantine_intent_changed"
            )
        selected_outer_ack = state.outer_ack_pending_record_sha256
        selected_outer_quarantine = (
            state.outer_quarantine_intent_record_sha256
        )
        selected_terminal_receipt = state.terminal_receipt_sha256
        selected_tombstone = state.tombstone_sha256
        selected_terminal_disposition = state.terminal_disposition
    _validate_journal_event_transition(
        event=event,
        last_event=state.last_event,
        observed_identity_sha256=identity_sha256,
        observed_rename_primitive=selected_rename_primitive,
        spawned=state.spawned,
        ready_bound=state.ready_bound,
        process_scope_dead=state.process_scope_dead,
        ack_record_sha256=state.ack_record_sha256,
        terminal_disposition=selected_terminal_disposition,
        operator_attention_predecessor=(
            state.operator_attention_predecessor
        ),
    )
    payload = {
        "schema_version": STAGING_JOURNAL_SCHEMA,
        "session_name": session_name,
        "sequence": sequence,
        "event": event,
        "leaf_identity_sha256": identity_sha256,
        "staging_transaction_intent_sha256": transaction_intent,
        "rename_primitive": selected_rename_primitive,
        "quarantine_reason_code": selected_quarantine_reason,
        "lifecycle_scope_empty_receipt_sha256": (
            selected_scope_empty
        ),
        "outer_ack_pending_record_sha256": selected_outer_ack,
        "outer_quarantine_intent_record_sha256": (
            selected_outer_quarantine
        ),
        "outer_staging_tombstone_acked_record_sha256": (
            selected_outer_acked
        ),
        "outer_lifecycle_clearance_record_sha256": (
            selected_lifecycle_clearance
        ),
        "terminal_receipt_sha256": selected_terminal_receipt,
        "tombstone_sha256": selected_tombstone,
        "terminal_disposition": selected_terminal_disposition,
        "previous_record_sha256": state.last_record_sha256,
    }
    record = dict(payload)
    record["record_sha256"] = _sha256(_canonical_json(payload))
    _append_all(descriptor, _canonical_json(record) + b"\n")


@dataclass(frozen=True)
class _JournalState:
    next_sequence: int
    identity_sha256: str | None
    staging_transaction_intent_sha256: str | None
    rename_primitive: str | None
    quarantine_reason_code: str | None
    lifecycle_scope_empty_receipt_sha256: str | None
    outer_lifecycle_clearance_record_sha256: str | None
    outer_staging_tombstone_acked_record_sha256: str | None
    outer_ack_pending_record_sha256: str | None
    outer_quarantine_intent_record_sha256: str | None
    terminal_receipt_sha256: str | None
    tombstone_sha256: str | None
    terminal_disposition: str | None
    ack_sequence: int | None
    ack_previous_record_sha256: str | None
    ack_record_sha256: str | None
    operator_attention_predecessor: str | None
    last_event: str
    last_record_sha256: str | None
    valid_bytes: int
    torn_tail: bool
    spawned: bool
    ready_bound: bool
    process_scope_dead: bool


_JOURNAL_PREDECESSORS = {
    "create_intent": frozenset({""}),
    "leaf_created": frozenset({"create_intent"}),
    "staging_exposure_intent": frozenset({"leaf_created"}),
    "staging_exposed": frozenset({"staging_exposure_intent"}),
    "spawn_intent": frozenset({"staging_exposed", "spawn_failed"}),
    "spawn_failed": frozenset({"spawn_intent"}),
    "spawned": frozenset({"spawn_intent"}),
    "ready_bound": frozenset({"spawned"}),
    "process_scope_dead": frozenset({"spawned", "ready_bound"}),
    "cleanup_intent": frozenset(
        {"staging_exposed", "spawn_failed", "process_scope_dead"}
    ),
    "removed": frozenset({"cleanup_intent"}),
    "quarantine_intent": frozenset(
        {
            "leaf_created",
            "staging_exposure_intent",
            "staging_exposed",
            "spawn_failed",
            "process_scope_dead",
        }
    ),
    "quarantined": frozenset({"quarantine_intent"}),
    "quarantine_remove_intent": frozenset({"quarantined"}),
    "quarantine_removed": frozenset(
        {"quarantine_remove_intent", "operator_attention"}
    ),
    "startup_identity_observed": frozenset({"create_intent"}),
    "startup_quarantine_intent": frozenset(
        {
            "startup_identity_observed",
            "leaf_created",
            "staging_exposure_intent",
            "staging_exposed",
            "spawn_intent",
            "spawn_failed",
            "spawned",
            "ready_bound",
            "process_scope_dead",
            "cleanup_intent",
            "quarantine_intent",
            "operator_attention",
        }
    ),
    "startup_quarantined": frozenset(
        {
            "startup_quarantine_intent",
            "quarantine_intent",
            "operator_attention",
        }
    ),
    "startup_absent": frozenset(
        {
            "create_intent",
            "leaf_created",
            "staging_exposure_intent",
            "staging_exposed",
            "spawn_intent",
            "spawn_failed",
            "process_scope_dead",
            "cleanup_intent",
            "quarantine_intent",
            "quarantine_remove_intent",
            "operator_resolution_intent",
            "operator_attention",
        }
    ),
    "operator_attention": frozenset(
        {
            "leaf_created",
            "staging_exposure_intent",
            "staging_exposed",
            "spawn_intent",
            "spawn_failed",
            "spawned",
            "ready_bound",
            "process_scope_dead",
            "cleanup_intent",
            "quarantine_intent",
            "quarantine_remove_intent",
            "startup_identity_observed",
            "startup_quarantine_intent",
            "operator_resolution_intent",
        }
    ),
    "operator_removed": frozenset({"operator_resolution_intent"}),
}


def _validate_journal_event_transition(
    *,
    event: str,
    last_event: str,
    observed_identity_sha256: str | None,
    observed_rename_primitive: str | None,
    spawned: bool,
    ready_bound: bool,
    process_scope_dead: bool,
    ack_record_sha256: str | None,
    terminal_disposition: str | None,
    operator_attention_predecessor: str | None,
) -> None:
    """Reject hash-valid records that do not form a valid staging flow."""

    ack_event = staging_receipts.STAGING_TOMBSTONE_ACK_EVENT
    if event == ack_event:
        expected = (
            staging_receipts.ABSENCE_TERMINAL_EVENTS
            if terminal_disposition == "absent"
            else staging_receipts.QUARANTINE_TERMINAL_EVENTS
            if terminal_disposition == "quarantined"
            else frozenset()
        )
        if ack_record_sha256 is not None or last_event not in expected:
            raise _error(
                "capture_staging_journal_event_transition_invalid"
            )
    elif event == "operator_resolution_intent":
        if (
            ack_record_sha256 is None
            or terminal_disposition != "quarantined"
            or last_event != ack_event
        ):
            raise _error(
                "capture_staging_journal_event_transition_invalid"
            )
    elif last_event not in _JOURNAL_PREDECESSORS.get(
        event,
        frozenset(),
    ):
        raise _error(
            "capture_staging_journal_event_transition_invalid"
        )
    if (
        event == "startup_absent"
        and last_event == "operator_attention"
        and operator_attention_predecessor
        not in {
            "cleanup_intent",
            "quarantine_remove_intent",
            "operator_resolution_intent",
        }
    ):
        raise _error(
            "capture_staging_journal_event_transition_invalid"
        )
    if (
        event == "quarantine_removed"
        and last_event == "operator_attention"
        and operator_attention_predecessor
        != "quarantine_remove_intent"
    ):
        raise _error(
            "capture_staging_journal_event_transition_invalid"
        )
    if event == "create_intent":
        if observed_identity_sha256 is not None:
            raise _error(
                "capture_staging_journal_event_identity_invalid"
            )
    elif (
        event != "startup_absent"
        and not (
            event == ack_event
            and terminal_disposition == "absent"
        )
        and observed_identity_sha256 is None
    ):
        raise _error(
            "capture_staging_journal_event_identity_invalid"
        )
    if event == "ready_bound" and (
        not spawned or ready_bound or process_scope_dead
    ):
        raise _error(
            "capture_staging_journal_event_transition_invalid"
        )
    if event == "process_scope_dead" and (
        not spawned or process_scope_dead
    ):
        raise _error(
            "capture_staging_journal_event_transition_invalid"
        )
    if observed_rename_primitive is not None and event in {
        "create_intent",
        "leaf_created",
        "staging_exposure_intent",
        "staging_exposed",
        "spawn_intent",
        "spawn_failed",
        "spawned",
        "ready_bound",
        "process_scope_dead",
        "cleanup_intent",
    }:
        raise _error(
            "capture_staging_journal_rename_primitive_early"
        )
    if event in {
        "quarantined",
        "startup_quarantined",
    } and observed_rename_primitive is None:
        raise _error(
            "capture_staging_journal_rename_primitive_missing"
        )


def _safe_torn_journal_tail(raw: bytes) -> bool:
    if (
        not raw
        or len(raw) > MAX_JOURNAL_RECORD_BYTES
        or raw[:1] != b"{"
        or b"\n" in raw
        or b"\r" in raw
        or b"\x00" in raw
    ):
        return False
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        return False
    return all(0x20 <= ord(character) <= 0x7E for character in text)


def _parse_journal(
    raw: bytes,
    *,
    session_name: str,
    allow_torn_tail: bool = False,
) -> _JournalState:
    if len(raw) > MAX_JOURNAL_BYTES:
        raise _error("capture_staging_journal_invalid")
    valid = raw
    torn_tail = False
    if raw and not raw.endswith(b"\n"):
        final_newline = raw.rfind(b"\n")
        tail = raw[final_newline + 1 :]
        if (
            not allow_torn_tail
            or not _safe_torn_journal_tail(tail)
        ):
            raise _error("capture_staging_journal_invalid")
        valid = raw[: final_newline + 1]
        torn_tail = True
    identity: str | None = None
    transaction_intent: str | None = None
    rename_primitive: str | None = None
    quarantine_reason_code: str | None = None
    lifecycle_scope_empty_receipt_sha256: str | None = None
    outer_lifecycle_clearance_record_sha256: str | None = None
    outer_staging_tombstone_acked_record_sha256: str | None = None
    outer_ack_pending_record_sha256: str | None = None
    outer_quarantine_intent_record_sha256: str | None = None
    terminal_receipt_sha256: str | None = None
    tombstone_sha256: str | None = None
    terminal_disposition: str | None = None
    ack_sequence: int | None = None
    ack_previous_record_sha256: str | None = None
    ack_record_sha256: str | None = None
    operator_attention_predecessor: str | None = None
    last_event = ""
    last_record_sha256: str | None = None
    spawned = False
    ready_bound = False
    process_scope_dead = False
    lines = valid.splitlines()
    for sequence, line in enumerate(lines):
        try:
            value = json.loads(
                line.decode("ascii"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=lambda _value: (_ for _ in ()).throw(
                    _error("capture_staging_journal_nonfinite")
                ),
            )
        except CaptureStagingError:
            raise
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise _error("capture_staging_journal_invalid") from exc
        if (
            not isinstance(value, Mapping)
            or set(value) != JOURNAL_FIELDS
            or _canonical_json(value) != line
            or value.get("schema_version") != STAGING_JOURNAL_SCHEMA
            or value.get("session_name") != session_name
            or value.get("sequence") != sequence
            or value.get("event") not in JOURNAL_EVENTS
        ):
            raise _error("capture_staging_journal_invalid")
        previous = value.get("previous_record_sha256")
        record_sha256 = value.get("record_sha256")
        if (
            previous != last_record_sha256
            or not isinstance(record_sha256, str)
            or not SHA256_RE.fullmatch(record_sha256)
        ):
            raise _error("capture_staging_journal_digest_invalid")
        payload = {
            key: value[key]
            for key in JOURNAL_FIELDS
            if key != "record_sha256"
        }
        if _sha256(_canonical_json(payload)) != record_sha256:
            raise _error("capture_staging_journal_digest_invalid")
        observed = value.get("leaf_identity_sha256")
        if observed is not None and (
            not isinstance(observed, str)
            or not SHA256_RE.fullmatch(observed)
        ):
            raise _error("capture_staging_journal_invalid")
        if identity is None and observed is not None:
            identity = observed
        elif observed is not None and observed != identity:
            raise _error("capture_staging_journal_identity_changed")
        observed_intent = value.get(
            "staging_transaction_intent_sha256"
        )
        if (
            not isinstance(observed_intent, str)
            or SHA256_RE.fullmatch(observed_intent) is None
        ):
            raise _error("capture_staging_journal_invalid")
        if transaction_intent is None:
            transaction_intent = observed_intent
        elif observed_intent != transaction_intent:
            raise _error(
                "capture_staging_journal_transaction_intent_changed"
            )
        observed_rename = value.get("rename_primitive")
        if observed_rename is not None and (
            not isinstance(observed_rename, str)
            or observed_rename not in staging_receipts.RENAME_PRIMITIVES
        ):
            raise _error("capture_staging_journal_invalid")
        if rename_primitive is None and observed_rename is not None:
            rename_primitive = observed_rename
        elif (
            rename_primitive is not None
            and observed_rename != rename_primitive
        ):
            raise _error(
                "capture_staging_journal_rename_primitive_changed"
            )
        observed_reason = value.get("quarantine_reason_code")
        if (
            observed_reason is not None
            and observed_reason
            not in {"capture_failed", "coordinator_restarted"}
        ):
            raise _error(
                "capture_staging_journal_quarantine_reason_invalid"
            )
        if quarantine_reason_code is None:
            if observed_reason is not None:
                if value["event"] not in {
                    "quarantine_intent",
                    "startup_quarantine_intent",
                }:
                    raise _error(
                        "capture_staging_journal_"
                        "quarantine_reason_event_invalid"
                    )
                quarantine_reason_code = observed_reason
        elif observed_reason != quarantine_reason_code:
            raise _error(
                "capture_staging_journal_quarantine_reason_changed"
            )
        if (
            value["event"]
            in {"quarantined", "startup_quarantined"}
            and observed_reason is None
        ):
            raise _error(
                "capture_staging_journal_quarantine_reason_missing"
            )
        observed_scope_empty = value.get(
            "lifecycle_scope_empty_receipt_sha256"
        )
        observed_lifecycle_clearance = value.get(
            "outer_lifecycle_clearance_record_sha256"
        )
        observed_lifecycle = (
            observed_scope_empty,
            observed_lifecycle_clearance,
        )
        if (
            value["event"] == "process_scope_dead"
            and observed_scope_empty is None
        ):
            raise _error(
                "capture_staging_journal_lifecycle_binding_missing"
            )
        if any(
            item is not None for item in observed_lifecycle
        ) and not all(
            isinstance(item, str)
            and SHA256_RE.fullmatch(item) is not None
            for item in observed_lifecycle
        ):
            raise _error(
                "capture_staging_journal_lifecycle_binding_invalid"
            )
        if lifecycle_scope_empty_receipt_sha256 is None:
            if observed_scope_empty is not None:
                if value["event"] != "process_scope_dead" or not spawned:
                    raise _error(
                        "capture_staging_journal_"
                        "lifecycle_binding_event_invalid"
                    )
                lifecycle_scope_empty_receipt_sha256 = (
                    observed_scope_empty
                )
                outer_lifecycle_clearance_record_sha256 = (
                    observed_lifecycle_clearance
                )
        elif observed_lifecycle != (
            lifecycle_scope_empty_receipt_sha256,
            outer_lifecycle_clearance_record_sha256,
        ):
            raise _error(
                "capture_staging_journal_lifecycle_binding_changed"
            )
        observed_outer_acked = value.get(
            "outer_staging_tombstone_acked_record_sha256"
        )
        if outer_staging_tombstone_acked_record_sha256 is None:
            if observed_outer_acked is not None:
                if (
                    value["event"] != "operator_resolution_intent"
                    or not isinstance(observed_outer_acked, str)
                    or SHA256_RE.fullmatch(observed_outer_acked)
                    is None
                ):
                    raise _error(
                        "capture_staging_journal_"
                        "outer_acked_binding_invalid"
                    )
                outer_staging_tombstone_acked_record_sha256 = (
                    observed_outer_acked
                )
            elif value["event"] == "operator_resolution_intent":
                raise _error(
                    "capture_staging_journal_outer_acked_missing"
                )
        elif (
            observed_outer_acked
            != outer_staging_tombstone_acked_record_sha256
        ):
            raise _error(
                "capture_staging_journal_outer_acked_changed"
            )
        prior_ack_record_sha256 = ack_record_sha256
        observed_ack = (
            value.get("outer_ack_pending_record_sha256"),
            value.get("terminal_receipt_sha256"),
            value.get("tombstone_sha256"),
            value.get("terminal_disposition"),
        )
        observed_outer_quarantine = value.get(
            "outer_quarantine_intent_record_sha256"
        )
        if (
            observed_outer_quarantine is not None
            and (
                not isinstance(observed_outer_quarantine, str)
                or SHA256_RE.fullmatch(observed_outer_quarantine)
                is None
            )
        ):
            raise _error(
                "capture_staging_journal_"
                "outer_quarantine_intent_invalid"
            )
        if any(item is not None for item in observed_ack) and not all(
            item is not None for item in observed_ack
        ):
            raise _error(
                "capture_staging_journal_ack_binding_invalid"
            )
        if ack_record_sha256 is None:
            if observed_ack[0] is not None:
                if (
                    value["event"]
                    != staging_receipts.STAGING_TOMBSTONE_ACK_EVENT
                    or not all(
                        isinstance(item, str)
                        and SHA256_RE.fullmatch(item) is not None
                        for item in observed_ack[:3]
                    )
                    or observed_ack[3]
                    not in staging_receipts.TERMINAL_DISPOSITIONS
                ):
                    raise _error(
                        "capture_staging_journal_ack_binding_invalid"
                    )
                if (
                    observed_ack[3] == "absent"
                    and last_event
                    not in staging_receipts.ABSENCE_TERMINAL_EVENTS
                ) or (
                    observed_ack[3] == "quarantined"
                    and last_event
                    not in staging_receipts.QUARANTINE_TERMINAL_EVENTS
                ):
                    raise _error(
                        "capture_staging_journal_ack_predecessor_invalid"
                    )
                requires_outer_quarantine_intent = (
                    observed_ack[3] == "quarantined"
                    or (
                        observed_ack[3] == "absent"
                        and quarantine_reason_code is not None
                    )
                )
                if (
                    requires_outer_quarantine_intent
                    and observed_outer_quarantine is None
                ):
                    raise _error(
                        "capture_staging_journal_"
                        "outer_quarantine_intent_missing"
                    )
                if (
                    not requires_outer_quarantine_intent
                    and observed_outer_quarantine is not None
                ):
                    raise _error(
                        "capture_staging_journal_"
                        "outer_quarantine_intent_unexpected"
                    )
                outer_ack_pending_record_sha256 = observed_ack[0]
                outer_quarantine_intent_record_sha256 = (
                    observed_outer_quarantine
                )
                terminal_receipt_sha256 = observed_ack[1]
                tombstone_sha256 = observed_ack[2]
                terminal_disposition = observed_ack[3]
                ack_sequence = sequence
                ack_previous_record_sha256 = previous
                ack_record_sha256 = record_sha256
            elif (
                value["event"]
                == staging_receipts.STAGING_TOMBSTONE_ACK_EVENT
            ):
                raise _error(
                    "capture_staging_journal_ack_binding_missing"
                )
            elif observed_outer_quarantine is not None:
                raise _error(
                    "capture_staging_journal_"
                    "outer_quarantine_intent_event_invalid"
                )
        else:
            if (
                observed_ack
                != (
                    outer_ack_pending_record_sha256,
                    terminal_receipt_sha256,
                    tombstone_sha256,
                    terminal_disposition,
                )
                or value["event"]
                == staging_receipts.STAGING_TOMBSTONE_ACK_EVENT
                or observed_outer_quarantine
                != outer_quarantine_intent_record_sha256
            ):
                raise _error(
                    "capture_staging_journal_ack_binding_changed"
                )
        _validate_journal_event_transition(
            event=value["event"],
            last_event=last_event,
            observed_identity_sha256=observed,
            observed_rename_primitive=observed_rename,
            spawned=spawned,
            ready_bound=ready_bound,
            process_scope_dead=process_scope_dead,
            ack_record_sha256=prior_ack_record_sha256,
            terminal_disposition=terminal_disposition,
            operator_attention_predecessor=(
                operator_attention_predecessor
            ),
        )
        if value["event"] == "operator_attention":
            operator_attention_predecessor = last_event
        last_event = value["event"]
        if last_event == "spawned":
            spawned = True
        elif last_event == "ready_bound":
            ready_bound = True
        elif last_event == "process_scope_dead":
            process_scope_dead = True
        last_record_sha256 = record_sha256
    return _JournalState(
        next_sequence=len(lines),
        identity_sha256=identity,
        staging_transaction_intent_sha256=transaction_intent,
        rename_primitive=rename_primitive,
        quarantine_reason_code=quarantine_reason_code,
        lifecycle_scope_empty_receipt_sha256=(
            lifecycle_scope_empty_receipt_sha256
        ),
        outer_lifecycle_clearance_record_sha256=(
            outer_lifecycle_clearance_record_sha256
        ),
        outer_staging_tombstone_acked_record_sha256=(
            outer_staging_tombstone_acked_record_sha256
        ),
        outer_ack_pending_record_sha256=(
            outer_ack_pending_record_sha256
        ),
        outer_quarantine_intent_record_sha256=(
            outer_quarantine_intent_record_sha256
        ),
        terminal_receipt_sha256=terminal_receipt_sha256,
        tombstone_sha256=tombstone_sha256,
        terminal_disposition=terminal_disposition,
        ack_sequence=ack_sequence,
        ack_previous_record_sha256=ack_previous_record_sha256,
        ack_record_sha256=ack_record_sha256,
        operator_attention_predecessor=(
            operator_attention_predecessor
        ),
        last_event=last_event,
        last_record_sha256=last_record_sha256,
        valid_bytes=len(valid),
        torn_tail=torn_tail,
        spawned=spawned,
        ready_bound=ready_bound,
        process_scope_dead=process_scope_dead,
    )


def _read_descriptor(
    descriptor: int,
    *,
    maximum_bytes: int,
) -> bytes:
    try:
        info = os.fstat(descriptor)
        if info.st_size < 0 or info.st_size > maximum_bytes:
            raise _error("capture_staging_journal_too_large")
        if hasattr(os, "pread"):
            raw = os.pread(descriptor, info.st_size + 1, 0)
        else:
            position = os.lseek(descriptor, 0, os.SEEK_CUR)
            os.lseek(descriptor, 0, os.SEEK_SET)
            raw = os.read(descriptor, info.st_size + 1)
            os.lseek(descriptor, position, os.SEEK_SET)
    except CaptureStagingError:
        raise
    except OSError as exc:
        raise _error("capture_staging_journal_read_failed") from exc
    if len(raw) != info.st_size:
        raise _error("capture_staging_journal_changed")
    return raw


def _open_existing_journal(
    transactions_fd: int,
    *,
    session_name: str,
    root_uid: int,
    root_gid: int,
    device: int,
    repair_torn_tail: bool = True,
) -> tuple[int, _JournalState]:
    try:
        descriptor = os.open(
            _journal_name(session_name),
            _journal_flags(create=False),
            dir_fd=transactions_fd,
        )
    except OSError as exc:
        raise _error("capture_staging_journal_missing") from exc
    try:
        _validate_regular_control_file(
            descriptor,
            root_uid=root_uid,
            root_gid=root_gid,
            mode=JOURNAL_FILE_MODE,
            device=device,
            field="capture_staging_journal",
        )
        raw = _read_descriptor(
            descriptor,
            maximum_bytes=MAX_JOURNAL_BYTES,
        )
        state = _parse_journal(
            raw,
            session_name=session_name,
            allow_torn_tail=repair_torn_tail,
        )
        if state.torn_tail:
            try:
                os.ftruncate(descriptor, state.valid_bytes)
                os.fsync(descriptor)
                os.fsync(transactions_fd)
            except OSError as exc:
                raise _error(
                    "capture_staging_journal_tail_repair_failed"
                ) from exc
            repaired = _read_descriptor(
                descriptor,
                maximum_bytes=MAX_JOURNAL_BYTES,
            )
            if len(repaired) != state.valid_bytes:
                raise _error(
                    "capture_staging_journal_tail_repair_changed"
                )
            state = _parse_journal(
                repaired,
                session_name=session_name,
                allow_torn_tail=False,
            )
        return descriptor, state
    except BaseException:
        os.close(descriptor)
        raise


def _namespace_name_absent(parent_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError as exc:
        raise _error(
            "capture_staging_leaf_disposition_unreadable"
        ) from exc
    return False


def _journal_name_matches(
    transactions_fd: int,
    *,
    session_name: str,
    journal_fd: int,
) -> bool:
    try:
        named = os.stat(
            _journal_name(session_name),
            dir_fd=transactions_fd,
            follow_symlinks=False,
        )
        opened = os.fstat(journal_fd)
    except OSError:
        return False
    return (
        stat.S_ISREG(named.st_mode)
        and _stable_identity(named) == _stable_identity(opened)
    )


def _retire_terminal_journal(
    *,
    recovery_fd: int,
    quarantine_fd: int,
    transactions_fd: int,
    session_name: str,
    journal_fd: int,
    fault_hook: Callable[[str], None] | None = None,
) -> None:
    """Remove one terminal journal only after exact leaf disposition proof."""

    state = _parse_journal(
        _read_descriptor(
            journal_fd,
            maximum_bytes=MAX_JOURNAL_BYTES,
        ),
        session_name=session_name,
        allow_torn_tail=False,
    )
    if (
        state.last_event != "operator_removed"
        or state.ack_record_sha256 is None
        or state.terminal_disposition != "quarantined"
    ):
        raise _error("capture_staging_journal_not_terminal")
    if (
        not _namespace_name_absent(recovery_fd, session_name)
        or not _namespace_name_absent(quarantine_fd, session_name)
    ):
        raise _error("capture_staging_leaf_disposition_incomplete")
    if not _journal_name_matches(
        transactions_fd,
        session_name=session_name,
        journal_fd=journal_fd,
    ):
        raise _error("capture_staging_journal_name_rebound")
    if fault_hook is not None:
        fault_hook("before_terminal_journal_unlink")
    try:
        os.unlink(
            _journal_name(session_name),
            dir_fd=transactions_fd,
        )
    except OSError as exc:
        raise _error(
            "capture_staging_journal_retire_failed"
        ) from exc
    if fault_hook is not None:
        fault_hook("after_terminal_journal_unlink")
    try:
        os.fsync(transactions_fd)
    except OSError as exc:
        raise _error(
            "capture_staging_journal_retire_fsync_failed"
        ) from exc


def _exclusive_rename(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
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
        raise _error("capture_staging_exclusive_rename_unsupported")
    if result != 0:
        observed = ctypes.get_errno()
        if observed in {errno.EEXIST, errno.ENOTEMPTY}:
            raise _error("capture_staging_quarantine_destination_exists")
        if observed == errno.EXDEV:
            raise _error("capture_staging_cross_device_forbidden")
        raise _error("capture_staging_quarantine_rename_failed")
    return primitive


@dataclass(frozen=True)
class _StagingIdentities:
    root_uid: int
    root_gid: int
    capture_uid: int
    export_gid: int


def _validate_leaf(
    descriptor: int,
    *,
    identities: _StagingIdentities,
    device: int,
    expected_identity_sha256: str | None,
    allow_exposed: bool,
    allow_revoked: bool,
    allow_root_created: bool,
    field: str,
) -> os.stat_result:
    try:
        info = os.fstat(descriptor)
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    permitted: set[tuple[int, int, int]] = set()
    if allow_root_created:
        permitted.add(
            (
                identities.root_uid,
                identities.root_gid,
                EXPOSED_LEAF_MODE,
            )
        )
    if allow_exposed:
        permitted.add(
            (
                identities.capture_uid,
                identities.export_gid,
                EXPOSED_LEAF_MODE,
            )
        )
    if allow_revoked:
        permitted.add(
            (
                identities.root_uid,
                identities.root_gid,
                REVOKED_LEAF_MODE,
            )
        )
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_dev != device
        or (
            info.st_uid,
            info.st_gid,
            stat.S_IMODE(info.st_mode),
        )
        not in permitted
        or os.get_inheritable(descriptor)
    ):
        raise _error(f"{field}_unsafe")
    observed_identity = _identity_sha256(info)
    if (
        expected_identity_sha256 is not None
        and observed_identity != expected_identity_sha256
    ):
        raise _error(f"{field}_identity_mismatch")
    _reject_fd_metadata(descriptor, field=field)
    return info


def _revoke_leaf(
    descriptor: int,
    *,
    identities: _StagingIdentities,
    device: int,
    expected_identity_sha256: str,
    field: str,
) -> None:
    before = _validate_leaf(
        descriptor,
        identities=identities,
        device=device,
        expected_identity_sha256=expected_identity_sha256,
        allow_exposed=True,
        allow_revoked=True,
        allow_root_created=True,
        field=field,
    )
    if (
        before.st_uid,
        before.st_gid,
        stat.S_IMODE(before.st_mode),
    ) != (
        identities.root_uid,
        identities.root_gid,
        REVOKED_LEAF_MODE,
    ):
        try:
            os.fchmod(descriptor, 0)
            os.fchown(
                descriptor,
                identities.root_uid,
                identities.root_gid,
            )
            os.fchmod(descriptor, REVOKED_LEAF_MODE)
            os.fsync(descriptor)
        except OSError as exc:
            raise _error("capture_staging_leaf_revoke_failed") from exc
    _validate_leaf(
        descriptor,
        identities=identities,
        device=device,
        expected_identity_sha256=expected_identity_sha256,
        allow_exposed=False,
        allow_revoked=True,
        allow_root_created=False,
        field=field,
    )


def _leaf_empty(descriptor: int) -> bool:
    return not _bounded_entries(
        descriptor,
        field="capture_staging_leaf",
    )


def _move_to_quarantine(
    *,
    recovery_fd: int,
    quarantine_fd: int,
    session_name: str,
    leaf_fd: int,
    identities: _StagingIdentities,
    device: int,
    identity_sha256: str,
    staging_transaction_intent_sha256: str,
    journal_fd: int,
    next_sequence: int,
    event_prefix: str,
    reason_code: str,
    remove_if_empty: bool,
    fault_hook: Callable[[str], None] | None = None,
) -> tuple[int, str]:
    if not _bound_name_matches(recovery_fd, session_name, leaf_fd):
        raise _error("capture_staging_recovery_name_rebound")
    intent_event = (
        "startup_quarantine_intent"
        if event_prefix == "startup"
        else "quarantine_intent"
    )
    finished_event = (
        "startup_quarantined"
        if event_prefix == "startup"
        else "quarantined"
    )
    before = _parse_journal(
        _read_descriptor(
            journal_fd,
            maximum_bytes=MAX_JOURNAL_BYTES,
        ),
        session_name=session_name,
    )
    if before.last_event != intent_event:
        _append_record(
            journal_fd,
            session_name=session_name,
            sequence=next_sequence,
            event=intent_event,
            identity_sha256=identity_sha256,
            staging_transaction_intent_sha256=(
                staging_transaction_intent_sha256
            ),
            quarantine_reason_code=reason_code,
        )
        next_sequence += 1
    if fault_hook is not None:
        fault_hook(f"after_{intent_event}")
    rename_primitive = _exclusive_rename(
        recovery_fd,
        session_name,
        quarantine_fd,
        session_name,
    )
    if fault_hook is not None:
        fault_hook("after_quarantine_rename")
    if not _bound_name_matches(quarantine_fd, session_name, leaf_fd):
        raise _error("capture_staging_quarantine_name_rebound")
    try:
        os.fsync(recovery_fd)
    except OSError as exc:
        raise _error(
            "capture_staging_quarantine_source_parent_fsync_failed"
        ) from exc
    if fault_hook is not None:
        fault_hook("after_quarantine_source_parent_fsync")
    try:
        os.fsync(quarantine_fd)
    except OSError as exc:
        raise _error(
            "capture_staging_quarantine_destination_parent_fsync_failed"
        ) from exc
    if fault_hook is not None:
        fault_hook("after_quarantine_destination_parent_fsync")
    _revoke_leaf(
        leaf_fd,
        identities=identities,
        device=device,
        expected_identity_sha256=identity_sha256,
        field="capture_staging_quarantined_leaf",
    )
    _append_record(
        journal_fd,
        session_name=session_name,
        sequence=next_sequence,
        event=finished_event,
        identity_sha256=identity_sha256,
        staging_transaction_intent_sha256=(
            staging_transaction_intent_sha256
        ),
        rename_primitive=rename_primitive,
    )
    next_sequence += 1
    outcome = "quarantined"
    if remove_if_empty and _leaf_empty(leaf_fd):
        _append_record(
            journal_fd,
            session_name=session_name,
            sequence=next_sequence,
            event="quarantine_remove_intent",
            identity_sha256=identity_sha256,
            staging_transaction_intent_sha256=(
                staging_transaction_intent_sha256
            ),
        )
        next_sequence += 1
        if fault_hook is not None:
            fault_hook("after_quarantine_remove_intent")
        try:
            os.rmdir(session_name, dir_fd=quarantine_fd)
            os.fsync(quarantine_fd)
        except OSError as exc:
            raise _error(
                "capture_staging_quarantine_remove_failed"
            ) from exc
        if fault_hook is not None:
            fault_hook("after_quarantine_leaf_removed")
        _append_record(
            journal_fd,
            session_name=session_name,
            sequence=next_sequence,
            event="quarantine_removed",
            identity_sha256=identity_sha256,
            staging_transaction_intent_sha256=(
                staging_transaction_intent_sha256
            ),
        )
        next_sequence += 1
        outcome = "removed"
    return next_sequence, outcome


def _recover_one(
    *,
    recovery_fd: int,
    quarantine_fd: int,
    transactions_fd: int,
    session_name: str,
    identities: _StagingIdentities,
    device: int,
) -> None:
    journal_fd, journal = _open_existing_journal(
        transactions_fd,
        session_name=session_name,
        root_uid=identities.root_uid,
        root_gid=identities.root_gid,
        device=device,
    )
    leaf_fd = -1
    try:
        if journal.staging_transaction_intent_sha256 is None:
            raise _error(
                "capture_staging_recovery_journal_intent_missing"
            )
        if journal.last_event in TERMINAL_JOURNAL_EVENTS:
            raise _error(
                "capture_staging_terminal_journal_leaf_present"
            )
        leaf_fd, info = _open_bound_directory(
            recovery_fd,
            session_name,
            field="capture_staging_recovery_leaf",
        )
        identity = _identity_sha256(info)
        if journal.identity_sha256 is None:
            _validate_leaf(
                leaf_fd,
                identities=identities,
                device=device,
                expected_identity_sha256=None,
                allow_exposed=False,
                allow_revoked=False,
                allow_root_created=True,
                field="capture_staging_recovery_leaf",
            )
            _append_record(
                journal_fd,
                session_name=session_name,
                sequence=journal.next_sequence,
                event="startup_identity_observed",
                identity_sha256=identity,
                staging_transaction_intent_sha256=(
                    journal.staging_transaction_intent_sha256
                ),
            )
            next_sequence = journal.next_sequence + 1
        else:
            identity = journal.identity_sha256
            _validate_leaf(
                leaf_fd,
                identities=identities,
                device=device,
                expected_identity_sha256=identity,
                allow_exposed=True,
                allow_revoked=True,
                allow_root_created=True,
                field="capture_staging_recovery_leaf",
            )
            next_sequence = journal.next_sequence
        _move_to_quarantine(
            recovery_fd=recovery_fd,
            quarantine_fd=quarantine_fd,
            session_name=session_name,
            leaf_fd=leaf_fd,
            identities=identities,
            device=device,
            identity_sha256=identity,
            staging_transaction_intent_sha256=(
                journal.staging_transaction_intent_sha256
            ),
            journal_fd=journal_fd,
            next_sequence=next_sequence,
            event_prefix="startup",
            reason_code=(
                journal.quarantine_reason_code
                or "coordinator_restarted"
            ),
            remove_if_empty=False,
        )
    finally:
        if leaf_fd >= 0:
            os.close(leaf_fd)
        os.close(journal_fd)


def _validate_quarantine(
    *,
    quarantine_fd: int,
    transactions_fd: int,
    session_name: str,
    identities: _StagingIdentities,
    device: int,
) -> None:
    journal_fd, journal = _open_existing_journal(
        transactions_fd,
        session_name=session_name,
        root_uid=identities.root_uid,
        root_gid=identities.root_gid,
        device=device,
    )
    leaf_fd = -1
    try:
        if journal.staging_transaction_intent_sha256 is None:
            raise _error(
                "capture_staging_quarantine_journal_intent_missing"
            )
        if journal.last_event in TERMINAL_JOURNAL_EVENTS:
            raise _error(
                "capture_staging_terminal_journal_leaf_present"
            )
        leaf_fd, info = _open_bound_directory(
            quarantine_fd,
            session_name,
            field="capture_staging_quarantine_leaf",
        )
        identity = _identity_sha256(info)
        if (
            journal.identity_sha256 is not None
            and identity != journal.identity_sha256
        ):
            raise _error(
                "capture_staging_quarantine_leaf_identity_mismatch"
            )
        if journal.identity_sha256 is None:
            raise _error("capture_staging_quarantine_journal_unbound")
        _validate_leaf(
            leaf_fd,
            identities=identities,
            device=device,
            expected_identity_sha256=identity,
            allow_exposed=True,
            allow_revoked=True,
            allow_root_created=True,
            field="capture_staging_quarantine_leaf",
        )
        _revoke_leaf(
            leaf_fd,
            identities=identities,
            device=device,
            expected_identity_sha256=identity,
            field="capture_staging_quarantine_leaf",
        )
    finally:
        if leaf_fd >= 0:
            os.close(leaf_fd)
        os.close(journal_fd)


def _recover_namespaces(
    *,
    recovery_fd: int,
    quarantine_fd: int,
    transactions_fd: int,
    identities: _StagingIdentities,
    device: int,
) -> None:
    del (
        recovery_fd,
        quarantine_fd,
        transactions_fd,
        identities,
        device,
    )
    raise _error("capture_staging_global_recovery_disabled")

    # Kept below only as historical context until the ACK-aware operator
    # resolver replaces this retired global sweep.  Selected-ID recovery is
    # the sole live path.
    recovery_names = _bounded_entries(
        recovery_fd,
        field="capture_staging_recovery_namespace",
    )
    for name in recovery_names:
        if not SESSION_NAME_RE.fullmatch(name):
            raise _error("capture_staging_recovery_name_invalid")
        _recover_one(
            recovery_fd=recovery_fd,
            quarantine_fd=quarantine_fd,
            transactions_fd=transactions_fd,
            session_name=name,
            identities=identities,
            device=device,
        )
    quarantine_names = _bounded_entries(
        quarantine_fd,
        field="capture_staging_quarantine_namespace",
    )
    for name in quarantine_names:
        if not SESSION_NAME_RE.fullmatch(name):
            raise _error("capture_staging_quarantine_name_invalid")
        _validate_quarantine(
            quarantine_fd=quarantine_fd,
            transactions_fd=transactions_fd,
            session_name=name,
            identities=identities,
            device=device,
        )
    managed_names = set(quarantine_names)

    # Completed/abandoned journals are not a lifetime quota.  Scan in constant
    # memory and retire every exact journal whose leaf is proven absent from
    # both namespaces.  Repeating handles directory iteration across unlink
    # on platforms where readdir may skip a just-shifted entry.
    while True:
        retired = 0
        observed_managed: set[str] = set()
        try:
            iterator_context = os.scandir(transactions_fd)
            with iterator_context as iterator:
                for entry in iterator:
                    name = entry.name
                    if name == LOCK_NAME:
                        continue
                    if not JOURNAL_NAME_RE.fullmatch(name):
                        raise _error(
                            "capture_staging_transaction_name_invalid"
                        )
                    session_name = name[:-6]
                    journal_fd, journal = _open_existing_journal(
                        transactions_fd,
                        session_name=session_name,
                        root_uid=identities.root_uid,
                        root_gid=identities.root_gid,
                        device=device,
                    )
                    try:
                        if session_name in managed_names:
                            observed_managed.add(session_name)
                            continue
                        if journal.last_event not in (
                            TERMINAL_JOURNAL_EVENTS
                        ):
                            if (
                                journal
                                .staging_transaction_intent_sha256
                                is None
                            ):
                                raise _error(
                                    "capture_staging_journal_intent_missing"
                                )
                            _append_record(
                                journal_fd,
                                session_name=session_name,
                                sequence=journal.next_sequence,
                                event="startup_absent",
                                identity_sha256=(
                                    journal.identity_sha256
                                ),
                                staging_transaction_intent_sha256=(
                                    journal
                                    .staging_transaction_intent_sha256
                                ),
                            )
                        _retire_terminal_journal(
                            recovery_fd=recovery_fd,
                            quarantine_fd=quarantine_fd,
                            transactions_fd=transactions_fd,
                            session_name=session_name,
                            journal_fd=journal_fd,
                        )
                        retired += 1
                    finally:
                        os.close(journal_fd)
        except CaptureStagingError:
            raise
        except OSError as exc:
            raise _error(
                "capture_staging_transactions_namespace_unreadable"
            ) from exc
        if retired == 0:
            if observed_managed != managed_names:
                raise _error(
                    "capture_staging_quarantine_journal_missing"
                )
            break


_RECOVERY_OUTCOME_TOKEN = object()


class CaptureStagingRecoveryOutcome:
    """Path-free terminal staging result retained for outer-journal ACK."""

    __slots__ = (
        "_disposition",
        "_session_id",
        "_transaction_intent_sha256",
        "_terminal_receipt",
        "_terminal_receipt_sha256",
    )

    def __init__(
        self,
        *,
        _token: object,
        disposition: str,
        session_id: str,
        staging_transaction_intent_sha256: str,
        terminal_receipt: Mapping[str, Any],
    ) -> None:
        if _token is not _RECOVERY_OUTCOME_TOKEN:
            raise TypeError(
                "CaptureStagingRecoveryOutcome cannot be constructed directly"
            )
        if disposition == "absent":
            normalized = (
                staging_receipts.normalize_staging_absence_receipt(
                    terminal_receipt
                )
            )
            receipt_sha256 = (
                staging_receipts.staging_absence_receipt_sha256(
                    normalized
                )
            )
        elif disposition == "quarantined":
            normalized = (
                staging_receipts.normalize_staging_quarantine_receipt(
                    terminal_receipt
                )
            )
            receipt_sha256 = (
                staging_receipts.staging_quarantine_receipt_sha256(
                    normalized
                )
            )
        else:
            raise _error(
                "capture_staging_recovery_disposition_invalid"
            )
        selected_session = _session_token(session_id)
        selected_intent = _digest(
            staging_transaction_intent_sha256,
            field="capture_staging_transaction_intent_sha256",
        )
        if (
            normalized["capture_session_id"] != selected_session
            or normalized["staging_transaction_intent_sha256"]
            != selected_intent
        ):
            raise _error(
                "capture_staging_recovery_receipt_binding_invalid"
            )
        self._disposition = disposition
        self._session_id = selected_session
        self._transaction_intent_sha256 = selected_intent
        self._terminal_receipt = normalized
        self._terminal_receipt_sha256 = receipt_sha256

    @property
    def disposition(self) -> str:
        return self._disposition

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def staging_transaction_intent_sha256(self) -> str:
        return self._transaction_intent_sha256

    @property
    def terminal_receipt(self) -> dict[str, Any]:
        return dict(self._terminal_receipt)

    @property
    def terminal_receipt_sha256(self) -> str:
        return self._terminal_receipt_sha256

    @property
    def tombstone_sha256(self) -> str:
        return self._terminal_receipt["tombstone_sha256"]

    def __reduce__(self) -> Any:
        raise TypeError(
            "CaptureStagingRecoveryOutcome is not serializable"
        )

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError(
            "CaptureStagingRecoveryOutcome is not serializable"
        )


def _terminal_namespace_binding(
    *,
    root_fd: int,
    recovery_fd: int,
    quarantine_fd: int,
    transactions_fd: int,
) -> dict[str, Any]:
    try:
        root_info = os.fstat(root_fd)
        recovery_info = os.fstat(recovery_fd)
        quarantine_info = os.fstat(quarantine_fd)
        transactions_info = os.fstat(transactions_fd)
    except OSError as exc:
        raise _error(
            "capture_staging_terminal_namespace_unreadable"
        ) from exc
    device = int(root_info.st_dev)
    if any(
        not stat.S_ISDIR(info.st_mode) or int(info.st_dev) != device
        for info in (
            root_info,
            recovery_info,
            quarantine_info,
            transactions_info,
        )
    ):
        raise _error("capture_staging_terminal_namespace_changed")
    return {
        "filesystem_device": device,
        "shared_root_identity_sha256": _identity_sha256(root_info),
        "recovery_namespace_identity_sha256": (
            _identity_sha256(recovery_info)
        ),
        "quarantine_namespace_identity_sha256": (
            _identity_sha256(quarantine_info)
        ),
        "transactions_namespace_identity_sha256": (
            _identity_sha256(transactions_info)
        ),
    }


def _inspection_lock_epoch_sha256(
    lock_fd: int,
    *,
    session_name: str,
    transaction_intent_sha256: str,
    terminal_record_sha256: str,
) -> str:
    try:
        info = os.fstat(lock_fd)
    except OSError as exc:
        raise _error(
            "capture_staging_inspection_lock_unreadable"
        ) from exc
    return _sha256(
        _canonical_json(
            {
                "schema_version": (
                    "john-lomein.persona-qualification-"
                    "capture-staging-lock-epoch.v1"
                ),
                "lock_identity_sha256": _identity_sha256(info),
                "session_name": session_name,
                "staging_transaction_intent_sha256": (
                    transaction_intent_sha256
                ),
                "terminal_record_sha256": terminal_record_sha256,
            }
        )
    )


def _terminal_tombstone_sha256(
    *,
    disposition: str,
    session_name: str,
    transaction_intent_sha256: str,
    identity_sha256: str | None,
    namespace_binding: Mapping[str, Any],
    terminal_state: _JournalState,
    quarantined_stat_sha256: str | None,
) -> str:
    if (
        terminal_state.last_record_sha256 is None
        or terminal_state.next_sequence < 1
    ):
        raise _error("capture_staging_terminal_journal_invalid")
    return _sha256(
        _canonical_json(
            {
                "schema_version": STAGING_TOMBSTONE_SCHEMA,
                "terminal_disposition": disposition,
                "capture_session_id": session_name[len("session-") :],
                "staging_leaf_name": session_name,
                "staging_transaction_intent_sha256": (
                    transaction_intent_sha256
                ),
                "staging_leaf_identity_sha256": identity_sha256,
                **dict(namespace_binding),
                "terminal_event": terminal_state.last_event,
                "terminal_sequence": (
                    terminal_state.next_sequence - 1
                ),
                "terminal_record_sha256": (
                    terminal_state.last_record_sha256
                ),
                "quarantine_reason_code": (
                    terminal_state.quarantine_reason_code
                ),
                "quarantined_stat_sha256": (
                    quarantined_stat_sha256
                ),
            }
        )
    )


def _journal_lifecycle_binding(
    state: _JournalState,
) -> tuple[str, str | None]:
    if not state.spawned:
        return "not_applicable", None
    if (
        state.process_scope_dead
        and state.lifecycle_scope_empty_receipt_sha256 is not None
        and state.outer_lifecycle_clearance_record_sha256 is not None
    ):
        # Staging does not mint supervisor truth.  This is the immutable
        # mechanical binding supplied only after the outer journal durably
        # records the supervisor-issued scope-empty proof.
        return (
            "scope_empty",
            state.lifecycle_scope_empty_receipt_sha256,
        )
    return "scope_not_proven", None


def _terminal_state_from_journal(
    journal_fd: int,
    *,
    session_name: str,
) -> _JournalState:
    """Return the exact terminal prefix, excluding any ACK/successors."""

    raw = _read_descriptor(
        journal_fd,
        maximum_bytes=MAX_JOURNAL_BYTES,
    )
    state = _parse_journal(raw, session_name=session_name)
    if state.ack_sequence is None:
        return state
    lines = raw.splitlines(keepends=True)
    if (
        state.ack_sequence <= 0
        or state.ack_sequence >= len(lines)
        or state.ack_previous_record_sha256 is None
    ):
        raise _error("capture_staging_ack_terminal_prefix_invalid")
    terminal = _parse_journal(
        b"".join(lines[: state.ack_sequence]),
        session_name=session_name,
    )
    if (
        terminal.next_sequence != state.ack_sequence
        or terminal.last_record_sha256
        != state.ack_previous_record_sha256
    ):
        raise _error("capture_staging_ack_terminal_prefix_invalid")
    return terminal


def _build_absence_outcome(
    *,
    root_fd: int,
    recovery_fd: int,
    quarantine_fd: int,
    transactions_fd: int,
    lock_fd: int,
    journal_fd: int,
    session_name: str,
) -> CaptureStagingRecoveryOutcome:
    if (
        not _namespace_name_absent(recovery_fd, session_name)
        or not _namespace_name_absent(quarantine_fd, session_name)
    ):
        raise _error("capture_staging_absence_not_proven")
    try:
        os.fsync(recovery_fd)
        os.fsync(quarantine_fd)
    except OSError as exc:
        raise _error(
            "capture_staging_absence_parent_fsync_failed"
        ) from exc
    if (
        not _namespace_name_absent(recovery_fd, session_name)
        or not _namespace_name_absent(quarantine_fd, session_name)
    ):
        raise _error("capture_staging_absence_binding_changed")
    state = _terminal_state_from_journal(
        journal_fd,
        session_name=session_name,
    )
    if (
        state.last_event
        not in staging_receipts.ABSENCE_TERMINAL_EVENTS
        or state.last_record_sha256 is None
        or state.staging_transaction_intent_sha256 is None
    ):
        raise _error("capture_staging_absence_journal_invalid")
    namespace_binding = _terminal_namespace_binding(
        root_fd=root_fd,
        recovery_fd=recovery_fd,
        quarantine_fd=quarantine_fd,
        transactions_fd=transactions_fd,
    )
    lifecycle_status, lifecycle_receipt = (
        _journal_lifecycle_binding(state)
    )
    tombstone = _terminal_tombstone_sha256(
        disposition="absent",
        session_name=session_name,
        transaction_intent_sha256=(
            state.staging_transaction_intent_sha256
        ),
        identity_sha256=state.identity_sha256,
        namespace_binding=namespace_binding,
        terminal_state=state,
        quarantined_stat_sha256=None,
    )
    receipt = staging_receipts.normalize_staging_absence_receipt(
        {
            "schema_version": (
                staging_receipts.STAGING_ABSENCE_RECEIPT_SCHEMA
            ),
            "status": staging_receipts.STAGING_ABSENCE_STATUS,
            "capture_session_id": session_name[len("session-") :],
            "staging_leaf_name": session_name,
            "staging_transaction_intent_sha256": (
                state.staging_transaction_intent_sha256
            ),
            "staging_leaf_identity_sha256": state.identity_sha256,
            **namespace_binding,
            "staging_journal_schema": STAGING_JOURNAL_SCHEMA,
            "terminal_event": state.last_event,
            "terminal_sequence": state.next_sequence - 1,
            "terminal_record_sha256": state.last_record_sha256,
            "tombstone_sha256": tombstone,
            "quarantine_reason_code": (
                state.quarantine_reason_code
            ),
            "inspection_lock_epoch_sha256": (
                _inspection_lock_epoch_sha256(
                    lock_fd,
                    session_name=session_name,
                    transaction_intent_sha256=(
                        state.staging_transaction_intent_sha256
                    ),
                    terminal_record_sha256=(
                        state.last_record_sha256
                    ),
                )
            ),
            "lifecycle_status": lifecycle_status,
            "lifecycle_scope_empty_receipt_sha256": (
                lifecycle_receipt
            ),
        }
    )
    if (
        not _namespace_name_absent(recovery_fd, session_name)
        or not _namespace_name_absent(quarantine_fd, session_name)
    ):
        raise _error("capture_staging_absence_binding_changed")
    return CaptureStagingRecoveryOutcome(
        _token=_RECOVERY_OUTCOME_TOKEN,
        disposition="absent",
        session_id=session_name[len("session-") :],
        staging_transaction_intent_sha256=(
            state.staging_transaction_intent_sha256
        ),
        terminal_receipt=receipt,
    )


def _build_quarantine_outcome(
    *,
    root_fd: int,
    recovery_fd: int,
    quarantine_fd: int,
    transactions_fd: int,
    lock_fd: int,
    journal_fd: int,
    leaf_fd: int,
    session_name: str,
    reason_code: str,
) -> CaptureStagingRecoveryOutcome:
    if not _namespace_name_absent(recovery_fd, session_name):
        raise _error("capture_staging_quarantine_recovery_not_absent")
    if not _bound_name_matches(
        quarantine_fd,
        session_name,
        leaf_fd,
    ):
        raise _error("capture_staging_quarantine_name_rebound")
    state = _terminal_state_from_journal(
        journal_fd,
        session_name=session_name,
    )
    if (
        state.last_event
        not in staging_receipts.QUARANTINE_TERMINAL_EVENTS
        or state.last_record_sha256 is None
        or state.staging_transaction_intent_sha256 is None
        or state.identity_sha256 is None
        or state.rename_primitive is None
    ):
        raise _error("capture_staging_quarantine_journal_invalid")
    if state.quarantine_reason_code is None:
        raise _error("capture_staging_quarantine_reason_missing")
    reason_code = state.quarantine_reason_code
    try:
        quarantined_info = os.fstat(leaf_fd)
    except OSError as exc:
        raise _error(
            "capture_staging_quarantine_leaf_unreadable"
        ) from exc
    if _identity_sha256(quarantined_info) != state.identity_sha256:
        raise _error(
            "capture_staging_quarantine_leaf_identity_mismatch"
        )
    quarantined_stat = _stat_sha256(quarantined_info)
    namespace_binding = _terminal_namespace_binding(
        root_fd=root_fd,
        recovery_fd=recovery_fd,
        quarantine_fd=quarantine_fd,
        transactions_fd=transactions_fd,
    )
    lifecycle_status, lifecycle_receipt = (
        _journal_lifecycle_binding(state)
    )
    tombstone = _terminal_tombstone_sha256(
        disposition="quarantined",
        session_name=session_name,
        transaction_intent_sha256=(
            state.staging_transaction_intent_sha256
        ),
        identity_sha256=state.identity_sha256,
        namespace_binding=namespace_binding,
        terminal_state=state,
        quarantined_stat_sha256=quarantined_stat,
    )
    receipt = staging_receipts.normalize_staging_quarantine_receipt(
        {
            "schema_version": (
                staging_receipts.STAGING_QUARANTINE_RECEIPT_SCHEMA
            ),
            "status": staging_receipts.STAGING_QUARANTINE_STATUS,
            "capture_session_id": session_name[len("session-") :],
            "staging_leaf_name": session_name,
            "staging_transaction_intent_sha256": (
                state.staging_transaction_intent_sha256
            ),
            "staging_leaf_identity_sha256": state.identity_sha256,
            **namespace_binding,
            "staging_journal_schema": STAGING_JOURNAL_SCHEMA,
            "inspection_lock_epoch_sha256": (
                _inspection_lock_epoch_sha256(
                    lock_fd,
                    session_name=session_name,
                    transaction_intent_sha256=(
                        state.staging_transaction_intent_sha256
                    ),
                    terminal_record_sha256=(
                        state.last_record_sha256
                    ),
                )
            ),
            "quarantine_namespace": (
                staging_receipts.STAGING_QUARANTINE_NAMESPACE
            ),
            "quarantine_name": session_name,
            "quarantined_stat_sha256": quarantined_stat,
            "reason_code": reason_code,
            "lifecycle_status": lifecycle_status,
            "lifecycle_scope_empty_receipt_sha256": (
                lifecycle_receipt
            ),
            "rename_primitive": state.rename_primitive,
            "rename_noreplace": True,
            "parents_fsynced": True,
            "terminal_event": state.last_event,
            "terminal_sequence": state.next_sequence - 1,
            "terminal_record_sha256": state.last_record_sha256,
            "tombstone_sha256": tombstone,
        }
    )
    if (
        not _namespace_name_absent(recovery_fd, session_name)
        or not _bound_name_matches(
            quarantine_fd,
            session_name,
            leaf_fd,
        )
        or _stat_sha256(os.fstat(leaf_fd)) != quarantined_stat
    ):
        raise _error("capture_staging_quarantine_binding_changed")
    return CaptureStagingRecoveryOutcome(
        _token=_RECOVERY_OUTCOME_TOKEN,
        disposition="quarantined",
        session_id=session_name[len("session-") :],
        staging_transaction_intent_sha256=(
            state.staging_transaction_intent_sha256
        ),
        terminal_receipt=receipt,
    )


def _runtime_rename_primitive() -> str:
    libc = ctypes.CDLL(None, use_errno=True)
    system = platform.system()
    if system == "Linux" and hasattr(libc, "renameat2"):
        return "renameat2_noreplace"
    if system == "Darwin" and hasattr(libc, "renameatx_np"):
        return "renameatx_np_excl"
    raise _error("capture_staging_exclusive_rename_unsupported")


def _reconcile_selected_session(
    *,
    root_fd: int,
    recovery_fd: int,
    quarantine_fd: int,
    transactions_fd: int,
    completed_fd: int,
    lock_fd: int,
    session_name: str,
    expected_transaction_intent_sha256: str,
    identities: _StagingIdentities,
    device: int,
    fault_hook: Callable[[str], None] | None,
) -> CaptureStagingRecoveryOutcome | None:
    recovery_present = not _namespace_name_absent(
        recovery_fd,
        session_name,
    )
    quarantine_present = not _namespace_name_absent(
        quarantine_fd,
        session_name,
    )
    if recovery_present and quarantine_present:
        raise _error("capture_staging_session_namespace_ambiguous")
    try:
        os.stat(
            _journal_name(session_name),
            dir_fd=transactions_fd,
            follow_symlinks=False,
        )
        journal_present = True
    except FileNotFoundError:
        journal_present = False
    except OSError as exc:
        raise _error("capture_staging_journal_unreadable") from exc
    try:
        os.stat(
            _journal_name(session_name),
            dir_fd=completed_fd,
            follow_symlinks=False,
        )
        completed_present = True
    except FileNotFoundError:
        completed_present = False
    except OSError as exc:
        raise _error(
            "capture_staging_completed_journal_unreadable"
        ) from exc
    if completed_present:
        if journal_present or recovery_present or quarantine_present:
            raise _error(
                "capture_staging_completed_session_ambiguous"
            )
        completed_journal_fd, completed_state = (
            _open_existing_journal(
                completed_fd,
                session_name=session_name,
                root_uid=identities.root_uid,
                root_gid=identities.root_gid,
                device=device,
                repair_torn_tail=False,
            )
        )
        try:
            if (
                completed_state.staging_transaction_intent_sha256
                != expected_transaction_intent_sha256
            ):
                raise _error(
                    "capture_staging_session_"
                    "transaction_intent_conflict"
                )
            if (
                completed_state.ack_record_sha256 is None
                or completed_state.terminal_disposition != "absent"
                or completed_state.last_event
                != staging_receipts.STAGING_TOMBSTONE_ACK_EVENT
            ):
                raise _error(
                    "capture_staging_completed_journal_invalid"
                )
            return _build_absence_outcome(
                root_fd=root_fd,
                recovery_fd=recovery_fd,
                quarantine_fd=quarantine_fd,
                transactions_fd=transactions_fd,
                lock_fd=lock_fd,
                journal_fd=completed_journal_fd,
                session_name=session_name,
            )
        finally:
            os.close(completed_journal_fd)
    if not journal_present:
        if recovery_present or quarantine_present:
            raise _error("capture_staging_session_journal_missing")
        return None

    journal_fd, journal = _open_existing_journal(
        transactions_fd,
        session_name=session_name,
        root_uid=identities.root_uid,
        root_gid=identities.root_gid,
        device=device,
    )
    leaf_fd = -1
    try:
        if (
            journal.staging_transaction_intent_sha256
            != expected_transaction_intent_sha256
        ):
            raise _error(
                "capture_staging_session_transaction_intent_conflict"
            )
        if recovery_present:
            if journal.last_event in (
                staging_receipts.ABSENCE_TERMINAL_EVENTS
                | staging_receipts.QUARANTINE_TERMINAL_EVENTS
            ):
                raise _error(
                    "capture_staging_terminal_journal_leaf_present"
                )
            leaf_fd, info = _open_bound_directory(
                recovery_fd,
                session_name,
                field="capture_staging_recovery_leaf",
            )
            observed_identity = _identity_sha256(info)
            if journal.identity_sha256 is None:
                _validate_leaf(
                    leaf_fd,
                    identities=identities,
                    device=device,
                    expected_identity_sha256=None,
                    allow_exposed=False,
                    allow_revoked=False,
                    allow_root_created=True,
                    field="capture_staging_recovery_leaf",
                )
                _append_record(
                    journal_fd,
                    session_name=session_name,
                    sequence=journal.next_sequence,
                    event="startup_identity_observed",
                    identity_sha256=observed_identity,
                    staging_transaction_intent_sha256=(
                        expected_transaction_intent_sha256
                    ),
                )
                next_sequence = journal.next_sequence + 1
            else:
                observed_identity = journal.identity_sha256
                _validate_leaf(
                    leaf_fd,
                    identities=identities,
                    device=device,
                    expected_identity_sha256=observed_identity,
                    allow_exposed=True,
                    allow_revoked=True,
                    allow_root_created=True,
                    field="capture_staging_recovery_leaf",
                )
                next_sequence = journal.next_sequence
            _move_to_quarantine(
                recovery_fd=recovery_fd,
                quarantine_fd=quarantine_fd,
                session_name=session_name,
                leaf_fd=leaf_fd,
                identities=identities,
                device=device,
                identity_sha256=observed_identity,
                staging_transaction_intent_sha256=(
                    expected_transaction_intent_sha256
                ),
                journal_fd=journal_fd,
                next_sequence=next_sequence,
                event_prefix="startup",
                reason_code=(
                    journal.quarantine_reason_code
                    or "coordinator_restarted"
                ),
                remove_if_empty=False,
                fault_hook=fault_hook,
            )
            return _build_quarantine_outcome(
                root_fd=root_fd,
                recovery_fd=recovery_fd,
                quarantine_fd=quarantine_fd,
                transactions_fd=transactions_fd,
                lock_fd=lock_fd,
                journal_fd=journal_fd,
                leaf_fd=leaf_fd,
                session_name=session_name,
                reason_code="coordinator_restarted",
            )
        if quarantine_present:
            if journal.identity_sha256 is None:
                raise _error(
                    "capture_staging_quarantine_journal_unbound"
                )
            if journal.last_event in (
                staging_receipts.ABSENCE_TERMINAL_EVENTS
            ):
                raise _error(
                    "capture_staging_terminal_journal_leaf_present"
                )
            leaf_fd, info = _open_bound_directory(
                quarantine_fd,
                session_name,
                field="capture_staging_quarantine_leaf",
            )
            if (
                _identity_sha256(info)
                != journal.identity_sha256
            ):
                raise _error(
                    "capture_staging_quarantine_leaf_identity_mismatch"
                )
            _validate_leaf(
                leaf_fd,
                identities=identities,
                device=device,
                expected_identity_sha256=journal.identity_sha256,
                allow_exposed=True,
                allow_revoked=True,
                allow_root_created=True,
                field="capture_staging_quarantine_leaf",
            )
            _revoke_leaf(
                leaf_fd,
                identities=identities,
                device=device,
                expected_identity_sha256=journal.identity_sha256,
                field="capture_staging_quarantine_leaf",
            )
            try:
                os.fsync(recovery_fd)
            except OSError as exc:
                raise _error(
                    "capture_staging_quarantine_parent_fsync_failed"
                ) from exc
            if fault_hook is not None:
                fault_hook(
                    "after_recovery_quarantine_source_parent_fsync"
                )
            try:
                os.fsync(quarantine_fd)
            except OSError as exc:
                raise _error(
                    "capture_staging_quarantine_parent_fsync_failed"
                ) from exc
            if fault_hook is not None:
                fault_hook(
                    "after_recovery_quarantine_"
                    "destination_parent_fsync"
                )
            if (
                not _namespace_name_absent(
                    recovery_fd,
                    session_name,
                )
                or not _bound_name_matches(
                    quarantine_fd,
                    session_name,
                    leaf_fd,
                )
            ):
                raise _error(
                    "capture_staging_quarantine_binding_changed"
                )
            authorized_empty_removal = (
                journal.last_event == "quarantine_remove_intent"
                or (
                    journal.last_event == "operator_attention"
                    and journal.operator_attention_predecessor
                    == "quarantine_remove_intent"
                )
            )
            if authorized_empty_removal:
                if not _leaf_empty(leaf_fd):
                    raise _error(
                        "capture_staging_quarantine_"
                        "authorized_removal_not_empty"
                    )
                try:
                    os.rmdir(
                        session_name,
                        dir_fd=quarantine_fd,
                    )
                    os.fsync(quarantine_fd)
                except OSError as exc:
                    raise _error(
                        "capture_staging_quarantine_remove_failed"
                    ) from exc
                _append_record(
                    journal_fd,
                    session_name=session_name,
                    sequence=journal.next_sequence,
                    event="quarantine_removed",
                    identity_sha256=journal.identity_sha256,
                    staging_transaction_intent_sha256=(
                        expected_transaction_intent_sha256
                    ),
                )
                return _build_absence_outcome(
                    root_fd=root_fd,
                    recovery_fd=recovery_fd,
                    quarantine_fd=quarantine_fd,
                    transactions_fd=transactions_fd,
                    lock_fd=lock_fd,
                    journal_fd=journal_fd,
                    session_name=session_name,
                )
            if (
                journal.last_event
                == staging_receipts.STAGING_TOMBSTONE_ACK_EVENT
            ):
                if journal.terminal_disposition != "quarantined":
                    raise _error(
                        "capture_staging_ack_leaf_disposition_invalid"
                    )
                return _build_quarantine_outcome(
                    root_fd=root_fd,
                    recovery_fd=recovery_fd,
                    quarantine_fd=quarantine_fd,
                    transactions_fd=transactions_fd,
                    lock_fd=lock_fd,
                    journal_fd=journal_fd,
                    leaf_fd=leaf_fd,
                    session_name=session_name,
                    reason_code="capture_failed",
                )
            if journal.last_event not in (
                staging_receipts.QUARANTINE_TERMINAL_EVENTS
            ):
                _append_record(
                    journal_fd,
                    session_name=session_name,
                    sequence=journal.next_sequence,
                    event="startup_quarantined",
                    identity_sha256=journal.identity_sha256,
                    staging_transaction_intent_sha256=(
                        expected_transaction_intent_sha256
                    ),
                    rename_primitive=(
                        journal.rename_primitive
                        or _runtime_rename_primitive()
                    ),
                )
            return _build_quarantine_outcome(
                root_fd=root_fd,
                recovery_fd=recovery_fd,
                quarantine_fd=quarantine_fd,
                transactions_fd=transactions_fd,
                lock_fd=lock_fd,
                journal_fd=journal_fd,
                leaf_fd=leaf_fd,
                session_name=session_name,
                reason_code="coordinator_restarted",
            )

        if (
            journal.last_event
            == staging_receipts.STAGING_TOMBSTONE_ACK_EVENT
        ):
            if journal.terminal_disposition != "absent":
                raise _error(
                    "capture_staging_ack_leaf_disposition_invalid"
                )
            return _build_absence_outcome(
                root_fd=root_fd,
                recovery_fd=recovery_fd,
                quarantine_fd=quarantine_fd,
                transactions_fd=transactions_fd,
                lock_fd=lock_fd,
                journal_fd=journal_fd,
                session_name=session_name,
            )
        if journal.last_event in (
            staging_receipts.QUARANTINE_TERMINAL_EVENTS
        ):
            raise _error(
                "capture_staging_quarantine_leaf_missing"
            )
        if journal.last_event == "quarantine_remove_intent":
            _append_record(
                journal_fd,
                session_name=session_name,
                sequence=journal.next_sequence,
                event="quarantine_removed",
                identity_sha256=journal.identity_sha256,
                staging_transaction_intent_sha256=(
                    expected_transaction_intent_sha256
                ),
            )
            return _build_absence_outcome(
                root_fd=root_fd,
                recovery_fd=recovery_fd,
                quarantine_fd=quarantine_fd,
                transactions_fd=transactions_fd,
                lock_fd=lock_fd,
                journal_fd=journal_fd,
                session_name=session_name,
            )
        if journal.last_event not in (
            staging_receipts.ABSENCE_TERMINAL_EVENTS
        ):
            _append_record(
                journal_fd,
                session_name=session_name,
                sequence=journal.next_sequence,
                event="startup_absent",
                identity_sha256=journal.identity_sha256,
                staging_transaction_intent_sha256=(
                    expected_transaction_intent_sha256
                ),
            )
        return _build_absence_outcome(
            root_fd=root_fd,
            recovery_fd=recovery_fd,
            quarantine_fd=quarantine_fd,
            transactions_fd=transactions_fd,
            lock_fd=lock_fd,
            journal_fd=journal_fd,
            session_name=session_name,
        )
    finally:
        if leaf_fd >= 0:
            os.close(leaf_fd)
        os.close(journal_fd)


class InstalledCaptureStagingControl:
    """One-shot installed authority retaining one exact shared-root FD."""

    __slots__ = (
        "_root_fd",
        "_root_identity_sha256",
        "_root_stat_sha256",
        "_device",
        "_identities",
        "_owner_pid",
        "_state",
    )

    def __init__(
        self,
        *,
        _token: object,
        root_fd: int,
        root_identity_sha256: str,
        root_stat_sha256: str,
        device: int,
        identities: _StagingIdentities,
    ) -> None:
        if _token is not _INSTALLED_CONTROL_TOKEN:
            raise TypeError(
                "InstalledCaptureStagingControl cannot be "
                "constructed directly"
            )
        os.set_inheritable(root_fd, False)
        self._root_fd = root_fd
        self._root_identity_sha256 = root_identity_sha256
        self._root_stat_sha256 = root_stat_sha256
        self._device = device
        self._identities = identities
        self._owner_pid = os.getpid()
        self._state = "open"
        self._validate_retained_root()

    @property
    def active(self) -> bool:
        return (
            os.getpid() == self._owner_pid
            and self._state == "open"
            and self._root_fd >= 0
        )

    @property
    def filesystem_device(self) -> int:
        self._validate_retained_root()
        return self._device

    @property
    def shared_root_identity_sha256(self) -> str:
        self._validate_retained_root()
        return self._root_identity_sha256

    def _validate_retained_root(self) -> os.stat_result:
        if os.getpid() != self._owner_pid:
            raise _error(
                "capture_staging_control_creator_process_mismatch"
            )
        if (
            self._state != "open"
            or type(self._root_fd) is not int
            or self._root_fd < 0
        ):
            raise _error("capture_staging_control_spent")
        info = _validate_directory(
            self._root_fd,
            owner_uid=self._identities.root_uid,
            group_gid=self._identities.root_gid,
            mode=SHARED_ROOT_MODE,
            device=self._device,
            field="capture_staging_control_shared_root",
        )
        if (
            not hmac.compare_digest(
                _identity_sha256(info),
                self._root_identity_sha256,
            )
            or not hmac.compare_digest(
                _stat_sha256(info), self._root_stat_sha256
            )
        ):
            raise _error("capture_staging_control_shared_root_changed")
        return info

    def _acknowledge_recovered_adoption_tombstone(
        self,
        *,
        _token: object,
        session_id: str,
        staging_transaction_intent_sha256: str,
        terminal_receipt: Mapping[str, Any],
        outer_ack_pending_record_sha256: str,
        outer_quarantine_intent_record_sha256: str | None,
        outer_lifecycle_clearance_record_sha256: str | None,
    ) -> dict[str, Any]:
        if _token is not _RECOVERED_ADOPTION_ACK_CALL_TOKEN:
            raise _error(
                "capture_staging_recovered_ack_authority_required"
            )
        self._validate_retained_root()
        self._state = "committing"
        try:
            receipt = _acknowledge_terminal_impl(
                None,
                session_id=session_id,
                staging_transaction_intent_sha256=(
                    staging_transaction_intent_sha256
                ),
                terminal_receipt=terminal_receipt,
                outer_ack_pending_record_sha256=(
                    outer_ack_pending_record_sha256
                ),
                outer_quarantine_intent_record_sha256=(
                    outer_quarantine_intent_record_sha256
                ),
                outer_lifecycle_clearance_record_sha256=(
                    outer_lifecycle_clearance_record_sha256
                ),
                identities=self._identities,
                required_device=self._device,
                strict_parent_chain=False,
                fault_hook=None,
                retained_root_fd=self._root_fd,
                retained_root_identity_sha256=(
                    self._root_identity_sha256
                ),
                retained_root_stat_sha256=(
                    self._root_stat_sha256
                ),
            )
            # The ACK core duplicates the retained descriptor.  Recheck the
            # installed capability itself after the durable staging effect.
            self._state = "open"
            self._validate_retained_root()
            self._state = "committed"
            return receipt
        except BaseException:
            self._state = "failed"
            raise
        finally:
            if self._root_fd >= 0:
                try:
                    os.close(self._root_fd)
                finally:
                    self._root_fd = -1

    def close(self) -> None:
        if os.getpid() != self._owner_pid:
            raise _error(
                "capture_staging_control_creator_process_mismatch"
            )
        if self._root_fd >= 0:
            try:
                os.close(self._root_fd)
            finally:
                self._root_fd = -1
        if self._state == "open":
            self._state = "closed"

    def _descriptor_number_for_test(self) -> int:
        self._validate_retained_root()
        return self._root_fd

    def __copy__(self) -> Any:
        raise TypeError(
            "InstalledCaptureStagingControl is not copyable"
        )

    def __deepcopy__(self, memo: Any) -> Any:
        del memo
        raise TypeError(
            "InstalledCaptureStagingControl is not copyable"
        )

    def __reduce__(self) -> Any:
        raise TypeError(
            "InstalledCaptureStagingControl is not serializable"
        )

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError(
            "InstalledCaptureStagingControl is not serializable"
        )

    def __del__(self) -> None:
        descriptor = getattr(self, "_root_fd", -1)
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
            try:
                self._root_fd = -1
            except BaseException:
                pass


def _open_installed_capture_staging_control_impl(
    shared_root: Path | str,
    *,
    identities: _StagingIdentities,
    required_device: int | None,
    strict_parent_chain: bool,
) -> InstalledCaptureStagingControl:
    root_fd = -1
    try:
        root_fd, device = _open_shared_root(
            _absolute_path(
                shared_root,
                field="capture_staging_shared_root",
            ),
            root_uid=identities.root_uid,
            root_gid=identities.root_gid,
            strict_parent_chain=strict_parent_chain,
            required_device=required_device,
        )
        info = _validate_directory(
            root_fd,
            owner_uid=identities.root_uid,
            group_gid=identities.root_gid,
            mode=SHARED_ROOT_MODE,
            device=device,
            field="capture_staging_control_shared_root",
        )
        control = InstalledCaptureStagingControl(
            _token=_INSTALLED_CONTROL_TOKEN,
            root_fd=root_fd,
            root_identity_sha256=_identity_sha256(info),
            root_stat_sha256=_stat_sha256(info),
            device=device,
            identities=identities,
        )
        root_fd = -1
        return control
    finally:
        if root_fd >= 0:
            os.close(root_fd)


def _normalize_terminal_receipt_for_ack(
    value: Mapping[str, Any],
) -> tuple[str, dict[str, Any], str]:
    try:
        status = value.get("status")
    except AttributeError as exc:
        raise _error(
            "capture_staging_terminal_receipt_invalid"
        ) from exc
    try:
        if status == staging_receipts.STAGING_ABSENCE_STATUS:
            disposition = "absent"
            normalized = (
                staging_receipts.normalize_staging_absence_receipt(
                    value
                )
            )
            digest = staging_receipts.staging_absence_receipt_sha256(
                normalized
            )
        elif status == staging_receipts.STAGING_QUARANTINE_STATUS:
            disposition = "quarantined"
            normalized = (
                staging_receipts.normalize_staging_quarantine_receipt(
                    value
                )
            )
            digest = (
                staging_receipts.staging_quarantine_receipt_sha256(
                    normalized
                )
            )
        else:
            raise _error(
                "capture_staging_terminal_receipt_status_invalid"
            )
    except CaptureStagingError:
        raise
    except staging_receipts.CaptureStagingReceiptError as exc:
        raise _error(
            "capture_staging_terminal_receipt_invalid"
        ) from exc
    return disposition, normalized, digest


def _acknowledge_terminal_impl(
    shared_root: Path | None,
    *,
    session_id: str,
    staging_transaction_intent_sha256: str,
    terminal_receipt: Mapping[str, Any],
    outer_ack_pending_record_sha256: str,
    outer_quarantine_intent_record_sha256: str | None,
    outer_lifecycle_clearance_record_sha256: str | None,
    identities: _StagingIdentities,
    required_device: int | None,
    strict_parent_chain: bool,
    fault_hook: Callable[[str], None] | None,
    retained_root_fd: int | None = None,
    retained_root_identity_sha256: str | None = None,
    retained_root_stat_sha256: str | None = None,
) -> dict[str, Any]:
    """Durably bind outer authorization to one exact terminal journal."""

    token = _session_token(session_id)
    transaction_intent = _digest(
        staging_transaction_intent_sha256,
        field="capture_staging_transaction_intent_sha256",
    )
    outer_ack_pending = _digest(
        outer_ack_pending_record_sha256,
        field="capture_staging_outer_ack_pending_record_sha256",
    )
    disposition, normalized_terminal, terminal_receipt_sha256 = (
        _normalize_terminal_receipt_for_ack(terminal_receipt)
    )
    requires_outer_quarantine_intent = (
        disposition == "quarantined"
        or (
            disposition == "absent"
            and normalized_terminal["quarantine_reason_code"]
            is not None
        )
    )
    if requires_outer_quarantine_intent:
        if outer_quarantine_intent_record_sha256 is None:
            raise _error(
                "capture_staging_ack_"
                "outer_quarantine_intent_missing"
            )
        outer_quarantine_intent = _digest(
            outer_quarantine_intent_record_sha256,
            field=(
                "capture_staging_outer_"
                "quarantine_intent_record_sha256"
            ),
        )
    else:
        if outer_quarantine_intent_record_sha256 is not None:
            raise _error(
                "capture_staging_ack_"
                "outer_quarantine_intent_unexpected"
            )
        outer_quarantine_intent = None
    if (
        normalized_terminal["capture_session_id"] != token
        or normalized_terminal[
            "staging_transaction_intent_sha256"
        ]
        != transaction_intent
    ):
        raise _error("capture_staging_ack_terminal_binding_invalid")
    lifecycle_status = normalized_terminal["lifecycle_status"]
    if lifecycle_status == "scope_not_proven":
        raise _error("capture_staging_ack_lifecycle_not_cleared")
    if lifecycle_status == "not_applicable":
        if outer_lifecycle_clearance_record_sha256 is not None:
            raise _error(
                "capture_staging_ack_lifecycle_clearance_unexpected"
            )
        lifecycle_clearance = None
    elif lifecycle_status == "scope_empty":
        if outer_lifecycle_clearance_record_sha256 is None:
            raise _error(
                "capture_staging_ack_lifecycle_clearance_missing"
            )
        lifecycle_clearance = _digest(
            outer_lifecycle_clearance_record_sha256,
            field=(
                "capture_staging_outer_lifecycle_"
                "clearance_record_sha256"
            ),
        )
    else:
        raise _error("capture_staging_ack_lifecycle_status_invalid")
    if fault_hook is not None and not callable(fault_hook):
        raise _error("capture_staging_fault_hook_invalid")
    session_name = f"session-{token}"
    if retained_root_fd is None:
        if shared_root is None:
            raise _error("capture_staging_shared_root_invalid")
        root_path: Path | None = _absolute_path(
            shared_root,
            field="capture_staging_shared_root",
        )
        if (
            retained_root_identity_sha256 is not None
            or retained_root_stat_sha256 is not None
        ):
            raise _error(
                "capture_staging_retained_root_binding_unexpected"
            )
    else:
        if shared_root is not None:
            raise _error(
                "capture_staging_retained_root_path_forbidden"
            )
        root_path = None
        retained_root_identity_sha256 = _digest(
            retained_root_identity_sha256,
            field=(
                "capture_staging_retained_root_identity_sha256"
            ),
        )
        retained_root_stat_sha256 = _digest(
            retained_root_stat_sha256,
            field="capture_staging_retained_root_stat_sha256",
        )
    root_fd = -1
    transactions_fd = -1
    completed_fd = -1
    lock_fd = -1
    recovery_fd = -1
    quarantine_root_fd = -1
    quarantine_fd = -1
    journal_fd = -1
    leaf_fd = -1
    try:
        if retained_root_fd is None:
            assert root_path is not None
            root_fd, device = _open_shared_root(
                root_path,
                root_uid=identities.root_uid,
                root_gid=identities.root_gid,
                strict_parent_chain=strict_parent_chain,
                required_device=required_device,
            )
        else:
            try:
                source_info = _validate_directory(
                    retained_root_fd,
                    owner_uid=identities.root_uid,
                    group_gid=identities.root_gid,
                    mode=SHARED_ROOT_MODE,
                    device=required_device,
                    field=(
                        "capture_staging_retained_shared_root"
                    ),
                )
                root_fd = fcntl.fcntl(
                    retained_root_fd,
                    fcntl.F_DUPFD_CLOEXEC,
                    3,
                )
                os.set_inheritable(root_fd, False)
                opened_info = _validate_directory(
                    root_fd,
                    owner_uid=identities.root_uid,
                    group_gid=identities.root_gid,
                    mode=SHARED_ROOT_MODE,
                    device=int(source_info.st_dev),
                    field=(
                        "capture_staging_retained_shared_root"
                    ),
                )
            except CaptureStagingError:
                raise
            except OSError as exc:
                raise _error(
                    "capture_staging_retained_shared_root_unreadable"
                ) from exc
            if (
                _stable_identity(source_info)
                != _stable_identity(opened_info)
                or not hmac.compare_digest(
                    _identity_sha256(opened_info),
                    retained_root_identity_sha256,
                )
                or not hmac.compare_digest(
                    _stat_sha256(opened_info),
                    retained_root_stat_sha256,
                )
            ):
                raise _error(
                    "capture_staging_retained_shared_root_changed"
                )
            device = int(opened_info.st_dev)
        transactions_fd = _ensure_namespace(
            root_fd,
            TRANSACTIONS_NAMESPACE,
            owner_uid=identities.root_uid,
            group_gid=identities.root_gid,
            mode=CONTROL_NAMESPACE_MODE,
            device=device,
            field="capture_staging_transactions_namespace",
        )
        lock_fd = _open_lock(
            transactions_fd,
            root_uid=identities.root_uid,
            root_gid=identities.root_gid,
            device=device,
        )
        completed_fd = _ensure_namespace(
            transactions_fd,
            COMPLETED_NAMESPACE,
            owner_uid=identities.root_uid,
            group_gid=identities.root_gid,
            mode=CONTROL_NAMESPACE_MODE,
            device=device,
            field="capture_staging_completed_namespace",
        )
        recovery_fd = _ensure_namespace(
            root_fd,
            RECOVERY_NAMESPACE,
            owner_uid=identities.root_uid,
            group_gid=identities.root_gid,
            mode=RECOVERY_NAMESPACE_MODE,
            device=device,
            field="capture_staging_recovery_namespace",
        )
        quarantine_root_fd = _ensure_namespace(
            root_fd,
            QUARANTINE_NAMESPACE,
            owner_uid=identities.root_uid,
            group_gid=identities.root_gid,
            mode=CONTROL_NAMESPACE_MODE,
            device=device,
            field="capture_staging_quarantine_namespace",
        )
        quarantine_fd = _ensure_namespace(
            quarantine_root_fd,
            QUARANTINE_STAGING_NAMESPACE,
            owner_uid=identities.root_uid,
            group_gid=identities.root_gid,
            mode=CONTROL_NAMESPACE_MODE,
            device=device,
            field="capture_staging_quarantine_staging_namespace",
        )
        os.close(quarantine_root_fd)
        quarantine_root_fd = -1

        completed_entries = _bounded_entries(
            completed_fd,
            field="capture_staging_completed_namespace",
        )
        if any(
            JOURNAL_NAME_RE.fullmatch(name) is None
            for name in completed_entries
        ):
            raise _error(
                "capture_staging_completed_name_invalid"
            )
        journal_name = _journal_name(session_name)
        active_present = not _namespace_name_absent(
            transactions_fd,
            journal_name,
        )
        completed_present = not _namespace_name_absent(
            completed_fd,
            journal_name,
        )
        if active_present and completed_present:
            raise _error("capture_staging_ack_journal_ambiguous")
        if (
            disposition == "absent"
            and not completed_present
            and len(completed_entries) >= MAX_COMPLETED_TOMBSTONES
        ):
            raise _error(
                "capture_staging_completed_capacity_exceeded"
            )
        if disposition == "quarantined" and completed_present:
            raise _error(
                "capture_staging_quarantine_completed_invalid"
            )
        if not active_present and not completed_present:
            raise _error("capture_staging_ack_journal_missing")
        source_parent_fd = (
            completed_fd if completed_present else transactions_fd
        )
        journal_fd, journal = _open_existing_journal(
            source_parent_fd,
            session_name=session_name,
            root_uid=identities.root_uid,
            root_gid=identities.root_gid,
            device=device,
            repair_torn_tail=not completed_present,
        )
        if (
            journal.staging_transaction_intent_sha256
            != transaction_intent
        ):
            raise _error(
                "capture_staging_session_transaction_intent_conflict"
            )
        if disposition == "absent":
            rebuilt = _build_absence_outcome(
                root_fd=root_fd,
                recovery_fd=recovery_fd,
                quarantine_fd=quarantine_fd,
                transactions_fd=transactions_fd,
                lock_fd=lock_fd,
                journal_fd=journal_fd,
                session_name=session_name,
            )
        else:
            if completed_present:
                raise _error(
                    "capture_staging_quarantine_completed_invalid"
                )
            if not _namespace_name_absent(
                recovery_fd,
                session_name,
            ):
                raise _error(
                    "capture_staging_quarantine_recovery_not_absent"
                )
            leaf_fd, _ = _open_bound_directory(
                quarantine_fd,
                session_name,
                field="capture_staging_quarantine_leaf",
            )
            rebuilt = _build_quarantine_outcome(
                root_fd=root_fd,
                recovery_fd=recovery_fd,
                quarantine_fd=quarantine_fd,
                transactions_fd=transactions_fd,
                lock_fd=lock_fd,
                journal_fd=journal_fd,
                leaf_fd=leaf_fd,
                session_name=session_name,
                reason_code="capture_failed",
            )
        if (
            rebuilt.terminal_receipt != normalized_terminal
            or rebuilt.terminal_receipt_sha256
            != terminal_receipt_sha256
            or rebuilt.tombstone_sha256
            != normalized_terminal["tombstone_sha256"]
        ):
            raise _error(
                "capture_staging_ack_terminal_receipt_mismatch"
            )
        terminal_state = _terminal_state_from_journal(
            journal_fd,
            session_name=session_name,
        )
        if (
            normalized_terminal["terminal_sequence"]
            != terminal_state.next_sequence - 1
            or normalized_terminal["terminal_record_sha256"]
            != terminal_state.last_record_sha256
        ):
            raise _error(
                "capture_staging_ack_terminal_chain_mismatch"
            )
        if lifecycle_status == "not_applicable":
            if (
                terminal_state.spawned
                or terminal_state.lifecycle_scope_empty_receipt_sha256
                is not None
                or terminal_state
                .outer_lifecycle_clearance_record_sha256
                is not None
            ):
                raise _error(
                    "capture_staging_ack_lifecycle_binding_invalid"
                )
            scope_empty_receipt = None
        else:
            scope_empty_receipt = normalized_terminal[
                "lifecycle_scope_empty_receipt_sha256"
            ]
            if (
                terminal_state.lifecycle_scope_empty_receipt_sha256
                != scope_empty_receipt
                or terminal_state
                .outer_lifecycle_clearance_record_sha256
                != lifecycle_clearance
            ):
                raise _error(
                    "capture_staging_ack_lifecycle_binding_invalid"
                )

        if journal.ack_record_sha256 is None:
            if completed_present:
                raise _error(
                    "capture_staging_completed_ack_record_missing"
                )
            if fault_hook is not None:
                fault_hook("before_ack_record")
            _append_record(
                journal_fd,
                session_name=session_name,
                sequence=journal.next_sequence,
                event=(
                    staging_receipts.STAGING_TOMBSTONE_ACK_EVENT
                ),
                identity_sha256=journal.identity_sha256,
                staging_transaction_intent_sha256=transaction_intent,
                lifecycle_scope_empty_receipt_sha256=(
                    scope_empty_receipt
                ),
                outer_lifecycle_clearance_record_sha256=(
                    lifecycle_clearance
                ),
                outer_ack_pending_record_sha256=outer_ack_pending,
                outer_quarantine_intent_record_sha256=(
                    outer_quarantine_intent
                ),
                terminal_receipt_sha256=terminal_receipt_sha256,
                tombstone_sha256=rebuilt.tombstone_sha256,
                terminal_disposition=disposition,
            )
            if fault_hook is not None:
                fault_hook("after_ack_record_fsync")
            journal = _parse_journal(
                _read_descriptor(
                    journal_fd,
                    maximum_bytes=MAX_JOURNAL_BYTES,
                ),
                session_name=session_name,
            )
        if (
            journal.ack_sequence
            != normalized_terminal["terminal_sequence"] + 1
            or journal.ack_previous_record_sha256
            != normalized_terminal["terminal_record_sha256"]
            or journal.outer_ack_pending_record_sha256
            != outer_ack_pending
            or journal.outer_quarantine_intent_record_sha256
            != outer_quarantine_intent
            or journal.terminal_receipt_sha256
            != terminal_receipt_sha256
            or journal.tombstone_sha256
            != rebuilt.tombstone_sha256
            or journal.terminal_disposition != disposition
            or journal.outer_lifecycle_clearance_record_sha256
            != lifecycle_clearance
            or journal.ack_record_sha256 is None
        ):
            raise _error("capture_staging_ack_record_mismatch")

        if disposition == "absent":
            if not completed_present:
                if not _journal_name_matches(
                    transactions_fd,
                    session_name=session_name,
                    journal_fd=journal_fd,
                ):
                    raise _error(
                        "capture_staging_ack_journal_name_rebound"
                    )
                _exclusive_rename(
                    transactions_fd,
                    journal_name,
                    completed_fd,
                    journal_name,
                )
                completed_present = True
                if fault_hook is not None:
                    fault_hook("after_ack_archive_rename")
            if not _journal_name_matches(
                completed_fd,
                session_name=session_name,
                journal_fd=journal_fd,
            ):
                raise _error(
                    "capture_staging_ack_archive_name_rebound"
                )
            try:
                os.fsync(transactions_fd)
            except OSError as exc:
                raise _error(
                    "capture_staging_ack_transactions_fsync_failed"
                ) from exc
            if fault_hook is not None:
                fault_hook("after_ack_transactions_parent_fsync")
            try:
                os.fsync(completed_fd)
            except OSError as exc:
                raise _error(
                    "capture_staging_ack_completed_fsync_failed"
                ) from exc
            if fault_hook is not None:
                fault_hook("after_ack_completed_parent_fsync")
            storage_disposition = "completed_absence_journal"
            completed_parent_fsynced = True
        else:
            if not _journal_name_matches(
                transactions_fd,
                session_name=session_name,
                journal_fd=journal_fd,
            ):
                raise _error(
                    "capture_staging_ack_journal_name_rebound"
                )
            try:
                os.fsync(transactions_fd)
            except OSError as exc:
                raise _error(
                    "capture_staging_ack_transactions_fsync_failed"
                ) from exc
            if fault_hook is not None:
                fault_hook("after_ack_transactions_parent_fsync")
            storage_disposition = "retained_quarantine_journal"
            completed_parent_fsynced = False

        ack_raw = _read_descriptor(
            journal_fd,
            maximum_bytes=MAX_JOURNAL_BYTES,
        )
        readback = _parse_journal(
            ack_raw,
            session_name=session_name,
        )
        if (
            readback.ack_record_sha256
            != journal.ack_record_sha256
            or readback.ack_sequence != journal.ack_sequence
            or readback.ack_previous_record_sha256
            != journal.ack_previous_record_sha256
        ):
            raise _error("capture_staging_ack_readback_changed")
        try:
            journal_identity = _identity_sha256(os.fstat(journal_fd))
        except OSError as exc:
            raise _error(
                "capture_staging_ack_journal_identity_unreadable"
            ) from exc
        ack_receipt = (
            staging_receipts.normalize_staging_tombstone_ack_receipt(
                {
                    "schema_version": (
                        staging_receipts
                        .STAGING_TOMBSTONE_ACK_RECEIPT_SCHEMA
                    ),
                    "status": (
                        staging_receipts
                        .STAGING_TOMBSTONE_ACK_STATUS
                    ),
                    "capture_session_id": token,
                    "staging_transaction_intent_sha256": (
                        transaction_intent
                    ),
                    "terminal_receipt_sha256": (
                        terminal_receipt_sha256
                    ),
                    "tombstone_sha256": rebuilt.tombstone_sha256,
                    "outer_ack_pending_record_sha256": (
                        outer_ack_pending
                    ),
                    "outer_quarantine_intent_record_sha256": (
                        outer_quarantine_intent
                    ),
                    "outer_lifecycle_clearance_record_sha256": (
                        lifecycle_clearance
                    ),
                    "terminal_disposition": disposition,
                    "staging_journal_schema": STAGING_JOURNAL_SCHEMA,
                    "ack_event": (
                        staging_receipts
                        .STAGING_TOMBSTONE_ACK_EVENT
                    ),
                    "ack_sequence": readback.ack_sequence,
                    "ack_previous_record_sha256": (
                        readback.ack_previous_record_sha256
                    ),
                    "ack_record_sha256": (
                        readback.ack_record_sha256
                    ),
                    "inspection_lock_epoch_sha256": (
                        normalized_terminal[
                            "inspection_lock_epoch_sha256"
                        ]
                    ),
                    "journal_storage_disposition": (
                        storage_disposition
                    ),
                    "ack_journal_identity_sha256": journal_identity,
                    "ack_journal_readback_sha256": _sha256(ack_raw),
                    "transactions_parent_fsynced": True,
                    "completed_parent_fsynced": (
                        completed_parent_fsynced
                    ),
                }
            )
        )
        if fault_hook is not None:
            fault_hook("before_ack_receipt_return")
        return ack_receipt
    finally:
        for descriptor in (
            leaf_fd,
            journal_fd,
            quarantine_fd,
            quarantine_root_fd,
            recovery_fd,
            completed_fd,
            lock_fd,
            transactions_fd,
            root_fd,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _open_bound_regular_file(
    parent_fd: int,
    name: str,
    *,
    device: int,
    field: str,
) -> tuple[int, os.stat_result]:
    required = ("O_CLOEXEC", "O_NOFOLLOW")
    if not all(hasattr(os, item) for item in required):
        raise _error("capture_staging_descriptor_flags_unsupported")
    try:
        named = os.stat(
            name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(named.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or named.st_dev != device
            or opened.st_dev != device
            or named.st_nlink != 1
            or opened.st_nlink != 1
            or _stable_identity(named) != _stable_identity(opened)
            or os.get_inheritable(descriptor)
        ):
            raise _error(f"{field}_unsafe")
        _reject_fd_metadata(descriptor, field=field)
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _bound_regular_name_matches(
    parent_fd: int,
    name: str,
    descriptor: int,
) -> bool:
    try:
        named = os.stat(
            name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        opened = os.fstat(descriptor)
    except OSError:
        return False
    return (
        stat.S_ISREG(named.st_mode)
        and named.st_nlink == 1
        and opened.st_nlink == 1
        and _stable_identity(named) == _stable_identity(opened)
    )


def _preflight_quarantined_contents(
    descriptor: int,
    *,
    device: int,
    counters: dict[str, int],
    depth: int,
) -> None:
    """Inventory the full removal tree without mutating any inode."""

    if depth > MAX_OPERATOR_REMOVAL_DEPTH:
        raise _error("capture_staging_operator_remove_depth_exceeded")
    try:
        info = os.fstat(descriptor)
    except OSError as exc:
        raise _error(
            "capture_staging_operator_remove_directory_unreadable"
        ) from exc
    if not stat.S_ISDIR(info.st_mode) or info.st_dev != device:
        raise _error(
            "capture_staging_operator_remove_directory_unsafe"
        )
    _reject_fd_metadata(
        descriptor,
        field="capture_staging_operator_remove_directory",
    )
    entries = _bounded_entries(
        descriptor,
        field="capture_staging_operator_remove_directory",
    )
    for name in entries:
        counters["entries"] += 1
        if counters["entries"] > MAX_OPERATOR_REMOVAL_ENTRIES:
            raise _error(
                "capture_staging_operator_remove_entries_exceeded"
            )
        try:
            entry = os.stat(
                name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise _error(
                "capture_staging_operator_remove_entry_unreadable"
            ) from exc
        if entry.st_dev != device:
            raise _error(
                "capture_staging_operator_remove_cross_device"
            )
        if stat.S_ISDIR(entry.st_mode):
            child_fd, opened = _open_bound_directory(
                descriptor,
                name,
                field="capture_staging_operator_remove_directory",
            )
            try:
                if opened.st_dev != device:
                    raise _error(
                        "capture_staging_operator_remove_cross_device"
                    )
                _preflight_quarantined_contents(
                    child_fd,
                    device=device,
                    counters=counters,
                    depth=depth + 1,
                )
                if not _bound_name_matches(
                    descriptor,
                    name,
                    child_fd,
                ):
                    raise _error(
                        "capture_staging_operator_remove_name_rebound"
                    )
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(entry.st_mode):
            child_fd, opened = _open_bound_regular_file(
                descriptor,
                name,
                device=device,
                field="capture_staging_operator_remove_file",
            )
            try:
                size = int(opened.st_size)
                if size < 0:
                    raise _error(
                        "capture_staging_operator_remove_file_unsafe"
                    )
                counters["bytes"] += size
                if counters["bytes"] > MAX_OPERATOR_REMOVAL_BYTES:
                    raise _error(
                        "capture_staging_operator_remove_bytes_exceeded"
                    )
                if not _bound_regular_name_matches(
                    descriptor,
                    name,
                    child_fd,
                ):
                    raise _error(
                        "capture_staging_operator_remove_name_rebound"
                    )
            finally:
                os.close(child_fd)
        else:
            raise _error(
                "capture_staging_operator_remove_entry_type_unsafe"
            )


def _remove_quarantined_contents(
    descriptor: int,
    *,
    device: int,
    counters: dict[str, int],
    depth: int,
) -> None:
    if depth > MAX_OPERATOR_REMOVAL_DEPTH:
        raise _error("capture_staging_operator_remove_depth_exceeded")
    try:
        info = os.fstat(descriptor)
    except OSError as exc:
        raise _error(
            "capture_staging_operator_remove_directory_unreadable"
        ) from exc
    if not stat.S_ISDIR(info.st_mode) or info.st_dev != device:
        raise _error(
            "capture_staging_operator_remove_directory_unsafe"
        )
    _reject_fd_metadata(
        descriptor,
        field="capture_staging_operator_remove_directory",
    )
    try:
        os.fchmod(descriptor, 0o700)
        os.fsync(descriptor)
    except OSError as exc:
        raise _error(
            "capture_staging_operator_remove_directory_prepare_failed"
        ) from exc
    entries = _bounded_entries(
        descriptor,
        field="capture_staging_operator_remove_directory",
    )
    for name in entries:
        counters["entries"] += 1
        if counters["entries"] > MAX_OPERATOR_REMOVAL_ENTRIES:
            raise _error(
                "capture_staging_operator_remove_entries_exceeded"
            )
        try:
            entry = os.stat(
                name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise _error(
                "capture_staging_operator_remove_entry_unreadable"
            ) from exc
        if entry.st_dev != device:
            raise _error(
                "capture_staging_operator_remove_cross_device"
            )
        if stat.S_ISDIR(entry.st_mode):
            child_fd, opened = _open_bound_directory(
                descriptor,
                name,
                field="capture_staging_operator_remove_directory",
            )
            try:
                if opened.st_dev != device:
                    raise _error(
                        "capture_staging_operator_remove_cross_device"
                    )
                _remove_quarantined_contents(
                    child_fd,
                    device=device,
                    counters=counters,
                    depth=depth + 1,
                )
                if not _bound_name_matches(
                    descriptor,
                    name,
                    child_fd,
                ):
                    raise _error(
                        "capture_staging_operator_remove_name_rebound"
                    )
                try:
                    os.fsync(child_fd)
                    os.rmdir(name, dir_fd=descriptor)
                    os.fsync(descriptor)
                except OSError as exc:
                    raise _error(
                        "capture_staging_operator_remove_directory_failed"
                    ) from exc
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(entry.st_mode):
            child_fd, opened = _open_bound_regular_file(
                descriptor,
                name,
                device=device,
                field="capture_staging_operator_remove_file",
            )
            try:
                size = int(opened.st_size)
                if size < 0:
                    raise _error(
                        "capture_staging_operator_remove_file_unsafe"
                    )
                counters["bytes"] += size
                if counters["bytes"] > MAX_OPERATOR_REMOVAL_BYTES:
                    raise _error(
                        "capture_staging_operator_remove_bytes_exceeded"
                    )
                if not _bound_regular_name_matches(
                    descriptor,
                    name,
                    child_fd,
                ):
                    raise _error(
                        "capture_staging_operator_remove_name_rebound"
                    )
                try:
                    os.unlink(name, dir_fd=descriptor)
                    os.fsync(descriptor)
                except OSError as exc:
                    raise _error(
                        "capture_staging_operator_remove_file_failed"
                    ) from exc
            finally:
                os.close(child_fd)
        else:
            raise _error(
                "capture_staging_operator_remove_entry_type_unsafe"
            )
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise _error(
            "capture_staging_operator_remove_directory_fsync_failed"
        ) from exc


def _resolve_quarantined_impl(
    shared_root: Path,
    *,
    session_id: str,
    staging_transaction_intent_sha256: str,
    outer_staging_tombstone_acked_record_sha256: str,
    expected_identity_sha256: str,
    identities: _StagingIdentities,
    required_device: int | None,
    strict_parent_chain: bool,
    fault_hook: Callable[[str], None] | None,
) -> str:
    """Manually dispose one exact, durably ACKed quarantine."""

    token = _session_token(session_id)
    transaction_intent = _digest(
        staging_transaction_intent_sha256,
        field="capture_staging_transaction_intent_sha256",
    )
    outer_acked_clearance = _digest(
        outer_staging_tombstone_acked_record_sha256,
        field=(
            "capture_staging_outer_staging_"
            "tombstone_acked_record_sha256"
        ),
    )
    if (
        not isinstance(expected_identity_sha256, str)
        or not SHA256_RE.fullmatch(expected_identity_sha256)
    ):
        raise _error(
            "capture_staging_operator_expected_identity_invalid"
        )
    if fault_hook is not None and not callable(fault_hook):
        raise _error("capture_staging_fault_hook_invalid")
    session_name = f"session-{token}"
    root_path = _absolute_path(
        shared_root,
        field="capture_staging_shared_root",
    )
    root_fd = -1
    recovery_fd = -1
    quarantine_root_fd = -1
    quarantine_fd = -1
    transactions_fd = -1
    completed_fd = -1
    lock_fd = -1
    journal_fd = -1
    leaf_fd = -1
    try:
        root_fd, device = _open_shared_root(
            root_path,
            root_uid=identities.root_uid,
            root_gid=identities.root_gid,
            strict_parent_chain=strict_parent_chain,
            required_device=required_device,
        )
        transactions_fd = _ensure_namespace(
            root_fd,
            TRANSACTIONS_NAMESPACE,
            owner_uid=identities.root_uid,
            group_gid=identities.root_gid,
            mode=CONTROL_NAMESPACE_MODE,
            device=device,
            field="capture_staging_transactions_namespace",
        )
        lock_fd = _open_lock(
            transactions_fd,
            root_uid=identities.root_uid,
            root_gid=identities.root_gid,
            device=device,
        )
        completed_fd = _ensure_namespace(
            transactions_fd,
            COMPLETED_NAMESPACE,
            owner_uid=identities.root_uid,
            group_gid=identities.root_gid,
            mode=CONTROL_NAMESPACE_MODE,
            device=device,
            field="capture_staging_completed_namespace",
        )
        recovery_fd = _ensure_namespace(
            root_fd,
            RECOVERY_NAMESPACE,
            owner_uid=identities.root_uid,
            group_gid=identities.root_gid,
            mode=RECOVERY_NAMESPACE_MODE,
            device=device,
            field="capture_staging_recovery_namespace",
        )
        quarantine_root_fd = _ensure_namespace(
            root_fd,
            QUARANTINE_NAMESPACE,
            owner_uid=identities.root_uid,
            group_gid=identities.root_gid,
            mode=CONTROL_NAMESPACE_MODE,
            device=device,
            field="capture_staging_quarantine_namespace",
        )
        quarantine_fd = _ensure_namespace(
            quarantine_root_fd,
            QUARANTINE_STAGING_NAMESPACE,
            owner_uid=identities.root_uid,
            group_gid=identities.root_gid,
            mode=CONTROL_NAMESPACE_MODE,
            device=device,
            field="capture_staging_quarantine_staging_namespace",
        )
        os.close(quarantine_root_fd)
        quarantine_root_fd = -1
        if not _namespace_name_absent(recovery_fd, session_name):
            raise _error(
                "capture_staging_operator_session_not_quarantined"
            )
        completed_entries = _bounded_entries(
            completed_fd,
            field="capture_staging_completed_namespace",
        )
        if any(
            JOURNAL_NAME_RE.fullmatch(name) is None
            for name in completed_entries
        ):
            raise _error(
                "capture_staging_completed_name_invalid"
            )
        journal_name = _journal_name(session_name)
        active_present = not _namespace_name_absent(
            transactions_fd,
            journal_name,
        )
        completed_present = not _namespace_name_absent(
            completed_fd,
            journal_name,
        )
        quarantine_present = not _namespace_name_absent(
            quarantine_fd,
            session_name,
        )
        if active_present and completed_present:
            raise _error(
                "capture_staging_operator_journal_ambiguous"
            )
        if completed_present:
            if active_present or quarantine_present:
                raise _error(
                    "capture_staging_operator_completed_ambiguous"
                )
            journal_fd, completed_state = _open_existing_journal(
                completed_fd,
                session_name=session_name,
                root_uid=identities.root_uid,
                root_gid=identities.root_gid,
                device=device,
                repair_torn_tail=False,
            )
            if (
                completed_state.staging_transaction_intent_sha256
                != transaction_intent
                or completed_state.identity_sha256
                != expected_identity_sha256
                or completed_state.ack_record_sha256 is None
                or completed_state
                .outer_staging_tombstone_acked_record_sha256
                != outer_acked_clearance
                or completed_state.terminal_disposition
                != "quarantined"
                or completed_state.last_event != "operator_removed"
            ):
                raise _error(
                    "capture_staging_operator_completed_invalid"
                )
            try:
                os.fsync(recovery_fd)
                os.fsync(quarantine_fd)
                os.fsync(transactions_fd)
                os.fsync(completed_fd)
            except OSError as exc:
                raise _error(
                    "capture_staging_operator_completed_fsync_failed"
                ) from exc
            if (
                not _namespace_name_absent(
                    recovery_fd,
                    session_name,
                )
                or not _namespace_name_absent(
                    quarantine_fd,
                    session_name,
                )
                or not _journal_name_matches(
                    completed_fd,
                    session_name=session_name,
                    journal_fd=journal_fd,
                )
            ):
                raise _error(
                    "capture_staging_operator_completed_changed"
                )
            return "removed"

        if not active_present:
            raise _error("capture_staging_operator_journal_missing")
        if len(completed_entries) >= MAX_COMPLETED_TOMBSTONES:
            raise _error(
                "capture_staging_completed_capacity_exceeded"
            )
        journal_fd, journal = _open_existing_journal(
            transactions_fd,
            session_name=session_name,
            root_uid=identities.root_uid,
            root_gid=identities.root_gid,
            device=device,
        )
        if (
            journal.staging_transaction_intent_sha256
            != transaction_intent
        ):
            raise _error(
                "capture_staging_session_transaction_intent_conflict"
            )
        if journal.identity_sha256 != expected_identity_sha256:
            raise _error(
                "capture_staging_operator_identity_mismatch"
            )
        if (
            journal.ack_record_sha256 is None
            or journal.terminal_disposition != "quarantined"
            or journal.last_event
            not in {
                staging_receipts.STAGING_TOMBSTONE_ACK_EVENT,
                "operator_resolution_intent",
                "operator_removed",
            }
        ):
            raise _error(
                "capture_staging_operator_ack_required"
            )
        if (
            journal.outer_staging_tombstone_acked_record_sha256
            is not None
            and journal
            .outer_staging_tombstone_acked_record_sha256
            != outer_acked_clearance
        ):
            raise _error(
                "capture_staging_operator_outer_acked_conflict"
            )
        if not _journal_name_matches(
            transactions_fd,
            session_name=session_name,
            journal_fd=journal_fd,
        ):
            raise _error(
                "capture_staging_operator_journal_name_rebound"
            )

        if quarantine_present:
            if journal.last_event == "operator_removed":
                raise _error(
                    "capture_staging_terminal_journal_leaf_present"
                )
            leaf_fd, info = _open_bound_directory(
                quarantine_fd,
                session_name,
                field="capture_staging_operator_quarantine_leaf",
            )
            if _identity_sha256(info) != expected_identity_sha256:
                raise _error(
                    "capture_staging_operator_identity_mismatch"
                )
            if (
                journal.last_event == "operator_resolution_intent"
                and (
                    info.st_uid,
                    info.st_gid,
                    stat.S_IMODE(info.st_mode),
                )
                == (
                    identities.root_uid,
                    identities.root_gid,
                    0o700,
                )
            ):
                try:
                    os.fchmod(leaf_fd, REVOKED_LEAF_MODE)
                    os.fsync(leaf_fd)
                except OSError as exc:
                    raise _error(
                        "capture_staging_operator_"
                        "quarantine_reseal_failed"
                    ) from exc
            _validate_leaf(
                leaf_fd,
                identities=identities,
                device=device,
                expected_identity_sha256=expected_identity_sha256,
                allow_exposed=False,
                allow_revoked=True,
                allow_root_created=False,
                field="capture_staging_operator_quarantine_leaf",
            )
            _preflight_quarantined_contents(
                leaf_fd,
                device=device,
                counters={"entries": 0, "bytes": 0},
                depth=0,
            )
            if not _bound_name_matches(
                quarantine_fd,
                session_name,
                leaf_fd,
            ):
                raise _error(
                    "capture_staging_operator_quarantine_name_rebound"
                )
            if journal.last_event == (
                staging_receipts.STAGING_TOMBSTONE_ACK_EVENT
            ):
                _append_record(
                    journal_fd,
                    session_name=session_name,
                    sequence=journal.next_sequence,
                    event="operator_resolution_intent",
                    identity_sha256=expected_identity_sha256,
                    staging_transaction_intent_sha256=(
                        transaction_intent
                    ),
                    outer_staging_tombstone_acked_record_sha256=(
                        outer_acked_clearance
                    ),
                )
                journal = _parse_journal(
                    _read_descriptor(
                        journal_fd,
                        maximum_bytes=MAX_JOURNAL_BYTES,
                    ),
                    session_name=session_name,
                )
            if fault_hook is not None:
                fault_hook("after_operator_resolution_intent")
            _remove_quarantined_contents(
                leaf_fd,
                device=device,
                counters={"entries": 0, "bytes": 0},
                depth=0,
            )
            if fault_hook is not None:
                fault_hook("after_operator_contents_removed")
            if not _bound_name_matches(
                quarantine_fd,
                session_name,
                leaf_fd,
            ):
                raise _error(
                    "capture_staging_operator_quarantine_name_rebound"
                )
            try:
                os.fsync(leaf_fd)
                os.rmdir(session_name, dir_fd=quarantine_fd)
            except OSError as exc:
                raise _error(
                    "capture_staging_operator_quarantine_remove_failed"
                ) from exc
            if fault_hook is not None:
                fault_hook(
                    "after_operator_quarantine_removed_before_parent_fsync"
                )
            try:
                os.fsync(quarantine_fd)
            except OSError as exc:
                raise _error(
                    "capture_staging_operator_quarantine_fsync_failed"
                ) from exc
            if fault_hook is not None:
                fault_hook("after_operator_quarantine_removed")
            quarantine_present = False
        elif journal.last_event == (
            staging_receipts.STAGING_TOMBSTONE_ACK_EVENT
        ):
            raise _error(
                "capture_staging_operator_quarantine_missing"
            )

        try:
            os.fsync(recovery_fd)
            os.fsync(quarantine_fd)
        except OSError as exc:
            raise _error(
                "capture_staging_operator_absence_fsync_failed"
            ) from exc
        if (
            not _namespace_name_absent(recovery_fd, session_name)
            or not _namespace_name_absent(quarantine_fd, session_name)
        ):
            raise _error(
                "capture_staging_operator_absence_changed"
            )
        journal = _parse_journal(
            _read_descriptor(
                journal_fd,
                maximum_bytes=MAX_JOURNAL_BYTES,
            ),
            session_name=session_name,
        )
        if journal.last_event == "operator_resolution_intent":
            _append_record(
                journal_fd,
                session_name=session_name,
                sequence=journal.next_sequence,
                event="operator_removed",
                identity_sha256=expected_identity_sha256,
                staging_transaction_intent_sha256=transaction_intent,
            )
            journal = _parse_journal(
                _read_descriptor(
                    journal_fd,
                    maximum_bytes=MAX_JOURNAL_BYTES,
                ),
                session_name=session_name,
            )
        if (
            journal.last_event != "operator_removed"
            or journal.ack_record_sha256 is None
            or journal
            .outer_staging_tombstone_acked_record_sha256
            != outer_acked_clearance
            or journal.terminal_disposition != "quarantined"
        ):
            raise _error(
                "capture_staging_operator_terminal_invalid"
            )
        if fault_hook is not None:
            fault_hook("after_operator_removed_record")
        if not _journal_name_matches(
            transactions_fd,
            session_name=session_name,
            journal_fd=journal_fd,
        ):
            raise _error(
                "capture_staging_operator_journal_name_rebound"
            )
        _exclusive_rename(
            transactions_fd,
            journal_name,
            completed_fd,
            journal_name,
        )
        if fault_hook is not None:
            fault_hook("after_operator_archive_rename")
        try:
            os.fsync(transactions_fd)
        except OSError as exc:
            raise _error(
                "capture_staging_operator_transactions_fsync_failed"
            ) from exc
        if fault_hook is not None:
            fault_hook(
                "after_operator_transactions_parent_fsync"
            )
        try:
            os.fsync(completed_fd)
        except OSError as exc:
            raise _error(
                "capture_staging_operator_completed_fsync_failed"
            ) from exc
        if fault_hook is not None:
            fault_hook("after_operator_completed_parent_fsync")
        if not _journal_name_matches(
            completed_fd,
            session_name=session_name,
            journal_fd=journal_fd,
        ):
            raise _error(
                "capture_staging_operator_archive_name_rebound"
            )
        archived = _parse_journal(
            _read_descriptor(
                journal_fd,
                maximum_bytes=MAX_JOURNAL_BYTES,
            ),
            session_name=session_name,
        )
        if (
            archived.last_event != "operator_removed"
            or archived.staging_transaction_intent_sha256
            != transaction_intent
            or archived.identity_sha256
            != expected_identity_sha256
            or archived
            .outer_staging_tombstone_acked_record_sha256
            != outer_acked_clearance
        ):
            raise _error(
                "capture_staging_operator_archive_invalid"
            )
        return "removed"
    finally:
        for descriptor in (
            leaf_fd,
            journal_fd,
            quarantine_fd,
            quarantine_root_fd,
            recovery_fd,
            completed_fd,
            lock_fd,
            transactions_fd,
            root_fd,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


class CaptureStagingLease:
    """Exact live authority for one exposed per-session staging leaf."""

    __slots__ = (
        "_shared_root",
        "_leaf_path",
        "_session_name",
        "_identity_sha256",
        "_staging_transaction_intent_sha256",
        "_exposure_receipt",
        "_identities",
        "_device",
        "_root_fd",
        "_recovery_fd",
        "_quarantine_fd",
        "_transactions_fd",
        "_lock_fd",
        "_journal_fd",
        "_leaf_fd",
        "_next_sequence",
        "_state",
        "_spawn_intent",
        "_spawned",
        "_ready_bound",
        "_process_scope_dead",
        "_fault_hook",
    )

    def __init__(
        self,
        *,
        _token: object,
        shared_root: Path,
        leaf_path: Path,
        session_name: str,
        identity_sha256: str,
        staging_transaction_intent_sha256: str,
        exposure_receipt: Mapping[str, Any],
        identities: _StagingIdentities,
        device: int,
        root_fd: int,
        recovery_fd: int,
        quarantine_fd: int,
        transactions_fd: int,
        lock_fd: int,
        journal_fd: int,
        leaf_fd: int,
        next_sequence: int,
        fault_hook: Callable[[str], None] | None,
    ) -> None:
        if _token is not _LEASE_TOKEN:
            raise TypeError(
                "CaptureStagingLease cannot be constructed directly"
            )
        for descriptor in (
            root_fd,
            recovery_fd,
            quarantine_fd,
            transactions_fd,
            lock_fd,
            journal_fd,
            leaf_fd,
        ):
            os.set_inheritable(descriptor, False)
        self._shared_root = shared_root
        self._leaf_path = leaf_path
        self._session_name = session_name
        self._identity_sha256 = identity_sha256
        self._staging_transaction_intent_sha256 = (
            staging_transaction_intent_sha256
        )
        self._exposure_receipt = (
            staging_receipts.normalize_staging_exposure_receipt(
                exposure_receipt
            )
        )
        self._identities = identities
        self._device = device
        self._root_fd = root_fd
        self._recovery_fd = recovery_fd
        self._quarantine_fd = quarantine_fd
        self._transactions_fd = transactions_fd
        self._lock_fd = lock_fd
        self._journal_fd = journal_fd
        self._leaf_fd = leaf_fd
        self._next_sequence = next_sequence
        self._state = "exposed"
        self._spawn_intent = False
        self._spawned = False
        self._ready_bound = False
        self._process_scope_dead = False
        self._fault_hook = fault_hook

    @property
    def active(self) -> bool:
        return self._state == "exposed" and self._leaf_fd >= 0

    @property
    def session_id(self) -> str:
        if not self.active:
            raise _error("capture_staging_lease_closed")
        return self._session_name[len("session-") :]

    @property
    def session_name(self) -> str:
        if not self.active:
            raise _error("capture_staging_lease_closed")
        return self._session_name

    @property
    def leaf_path(self) -> Path:
        if not self.active:
            raise _error("capture_staging_lease_closed")
        return self._leaf_path

    @property
    def identity_sha256(self) -> str:
        if not self.active:
            raise _error("capture_staging_lease_closed")
        return self._identity_sha256

    @property
    def staging_transaction_intent_sha256(self) -> str:
        if not self.active:
            raise _error("capture_staging_lease_closed")
        return self._staging_transaction_intent_sha256

    @property
    def exposure_receipt(self) -> dict[str, Any]:
        if not self.active:
            raise _error("capture_staging_lease_closed")
        return dict(self._exposure_receipt)

    @property
    def exposure_receipt_sha256(self) -> str:
        return staging_receipts.staging_exposure_receipt_sha256(
            self.exposure_receipt
        )

    @property
    def spawned(self) -> bool:
        return self.active and self._spawned

    @property
    def process_scope_dead(self) -> bool:
        return self.active and self._process_scope_dead

    def _record(
        self,
        event: str,
        *,
        lifecycle_scope_empty_receipt_sha256: str | None = None,
        outer_lifecycle_clearance_record_sha256: str | None = None,
    ) -> None:
        _append_record(
            self._journal_fd,
            session_name=self._session_name,
            sequence=self._next_sequence,
            event=event,
            identity_sha256=self._identity_sha256,
            staging_transaction_intent_sha256=(
                self._staging_transaction_intent_sha256
            ),
            lifecycle_scope_empty_receipt_sha256=(
                lifecycle_scope_empty_receipt_sha256
            ),
            outer_lifecycle_clearance_record_sha256=(
                outer_lifecycle_clearance_record_sha256
            ),
        )
        self._next_sequence += 1

    def duplicate_leaf_descriptor(self) -> int:
        if not self.active:
            raise _error("capture_staging_lease_closed")
        if not _bound_name_matches(
            self._recovery_fd,
            self._session_name,
            self._leaf_fd,
        ):
            raise _error("capture_staging_recovery_name_rebound")
        try:
            descriptor = fcntl.fcntl(
                self._leaf_fd,
                fcntl.F_DUPFD_CLOEXEC,
                3,
            )
        except OSError as exc:
            raise _error("capture_staging_leaf_dup_failed") from exc
        os.set_inheritable(descriptor, False)
        return descriptor

    def record_spawn_intent(self) -> None:
        if not self.active or self._spawn_intent:
            raise _error("capture_staging_spawn_transition_invalid")
        self._record("spawn_intent")
        self._spawn_intent = True

    def record_spawn_failed(self) -> None:
        if (
            not self.active
            or not self._spawn_intent
            or self._spawned
        ):
            raise _error("capture_staging_spawn_transition_invalid")
        self._record("spawn_failed")
        self._spawn_intent = False

    def record_spawned(self) -> None:
        if (
            not self.active
            or not self._spawn_intent
            or self._spawned
        ):
            raise _error("capture_staging_spawn_transition_invalid")
        self._record("spawned")
        self._spawned = True

    def record_ready_bound(self) -> None:
        if (
            not self.active
            or not self._spawned
            or self._ready_bound
            or self._process_scope_dead
        ):
            raise _error("capture_staging_ready_transition_invalid")
        self._record("ready_bound")
        self._ready_bound = True

    def mark_process_scope_dead(
        self,
        *,
        lifecycle_scope_empty_receipt_sha256: str,
        outer_lifecycle_clearance_record_sha256: str,
    ) -> None:
        if (
            not self.active
            or not self._spawned
            or self._process_scope_dead
        ):
            raise _error("capture_staging_reap_transition_invalid")
        self._record(
            "process_scope_dead",
            lifecycle_scope_empty_receipt_sha256=(
                lifecycle_scope_empty_receipt_sha256
            ),
            outer_lifecycle_clearance_record_sha256=(
                outer_lifecycle_clearance_record_sha256
            ),
        )
        self._process_scope_dead = True

    def _close_descriptors(self) -> None:
        descriptors = (
            "_leaf_fd",
            "_journal_fd",
            "_quarantine_fd",
            "_recovery_fd",
            "_transactions_fd",
            "_root_fd",
            "_lock_fd",
        )
        first_error: OSError | None = None
        for attribute in descriptors:
            descriptor = getattr(self, attribute)
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError as exc:
                    first_error = first_error or exc
                setattr(self, attribute, -1)
        if first_error is not None:
            raise _error("capture_staging_descriptor_close_failed") from (
                first_error
            )

    def _finish(
        self,
        *,
        success: bool,
    ) -> CaptureStagingRecoveryOutcome:
        if not self.active:
            raise _error("capture_staging_lease_closed")
        if self._spawned and not self._process_scope_dead:
            raise _error("capture_staging_process_scope_not_dead")
        outcome = ""
        terminal_outcome: CaptureStagingRecoveryOutcome | None = None
        try:
            if not _bound_name_matches(
                self._recovery_fd,
                self._session_name,
                self._leaf_fd,
            ):
                raise _error("capture_staging_recovery_name_rebound")
            if success:
                self._record("cleanup_intent")
                _revoke_leaf(
                    self._leaf_fd,
                    identities=self._identities,
                    device=self._device,
                    expected_identity_sha256=self._identity_sha256,
                    field="capture_staging_success_leaf",
                )
                if not _leaf_empty(self._leaf_fd):
                    raise _error(
                        "capture_staging_success_leaf_not_empty"
                    )
                try:
                    os.rmdir(
                        self._session_name,
                        dir_fd=self._recovery_fd,
                    )
                except OSError as exc:
                    raise _error(
                        "capture_staging_success_remove_failed"
                    ) from exc
                if self._fault_hook is not None:
                    self._fault_hook(
                        "after_success_leaf_removed"
                    )
                try:
                    os.fsync(self._recovery_fd)
                except OSError as exc:
                    raise _error(
                        "capture_staging_success_parent_fsync_failed"
                    ) from exc
                if self._fault_hook is not None:
                    self._fault_hook(
                        "after_success_parent_fsync"
                    )
                self._record("removed")
                outcome = "removed"
            else:
                # _move_to_quarantine records the single durable intent
                # immediately before the namespace effect.
                self._next_sequence, outcome = _move_to_quarantine(
                    recovery_fd=self._recovery_fd,
                    quarantine_fd=self._quarantine_fd,
                    session_name=self._session_name,
                    leaf_fd=self._leaf_fd,
                    identities=self._identities,
                    device=self._device,
                    identity_sha256=self._identity_sha256,
                    staging_transaction_intent_sha256=(
                        self._staging_transaction_intent_sha256
                    ),
                    journal_fd=self._journal_fd,
                    next_sequence=self._next_sequence,
                    event_prefix="live",
                    reason_code="capture_failed",
                    remove_if_empty=True,
                    fault_hook=self._fault_hook,
                )
            if outcome == "removed":
                terminal_outcome = _build_absence_outcome(
                    root_fd=self._root_fd,
                    recovery_fd=self._recovery_fd,
                    quarantine_fd=self._quarantine_fd,
                    transactions_fd=self._transactions_fd,
                    lock_fd=self._lock_fd,
                    journal_fd=self._journal_fd,
                    session_name=self._session_name,
                )
            elif outcome == "quarantined":
                terminal_outcome = _build_quarantine_outcome(
                    root_fd=self._root_fd,
                    recovery_fd=self._recovery_fd,
                    quarantine_fd=self._quarantine_fd,
                    transactions_fd=self._transactions_fd,
                    lock_fd=self._lock_fd,
                    journal_fd=self._journal_fd,
                    leaf_fd=self._leaf_fd,
                    session_name=self._session_name,
                    reason_code="capture_failed",
                )
            else:
                raise _error(
                    "capture_staging_terminal_disposition_invalid"
                )
            self._state = outcome
        except BaseException as original:
            try:
                self._record("operator_attention")
            except BaseException:
                pass
            self._state = "operator_attention"
            try:
                self._close_descriptors()
            except BaseException:
                pass
            raise original
        self._close_descriptors()
        if terminal_outcome is None:
            raise _error("capture_staging_terminal_receipt_missing")
        return terminal_outcome

    def finish_success(self) -> CaptureStagingRecoveryOutcome:
        return self._finish(success=True)

    def finish_failure(self) -> CaptureStagingRecoveryOutcome:
        return self._finish(success=False)

    def abandon(self) -> None:
        """Drop in-memory authority without filesystem effects.

        Production uses this only when process containment itself failed.
        Startup recovery will quarantine the exact journal-bound leaf without
        trusting serialized process identifiers.
        """

        if self._state != "exposed":
            return
        self._state = "abandoned"
        self._close_descriptors()

    def _abandon_for_test(self) -> None:
        self.abandon()

    def __reduce__(self) -> Any:
        raise TypeError("CaptureStagingLease is not serializable")

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError("CaptureStagingLease is not serializable")

    def __del__(self) -> None:
        if getattr(self, "_state", "closed") == "exposed":
            try:
                self.abandon()
            except BaseException:
                pass


def _create_impl(
    shared_root: Path,
    *,
    session_id: str,
    staging_transaction_intent_sha256: str,
    identities: _StagingIdentities,
    required_device: int | None,
    strict_parent_chain: bool,
    fault_hook: Callable[[str], None] | None,
) -> CaptureStagingLease | CaptureStagingRecoveryOutcome:
    # Selected transaction identity and its outer-journal authorization are
    # validated before path normalization, descriptor opens, namespace
    # creation, recovery, or any other filesystem effect.
    token = _session_token(session_id)
    transaction_intent = _digest(
        staging_transaction_intent_sha256,
        field="capture_staging_transaction_intent_sha256",
    )
    if fault_hook is not None and not callable(fault_hook):
        raise _error("capture_staging_fault_hook_invalid")
    session_name = f"session-{token}"
    root_path = _absolute_path(
        shared_root,
        field="capture_staging_shared_root",
    )
    root_fd = -1
    transactions_fd = -1
    completed_fd = -1
    lock_fd = -1
    recovery_fd = -1
    quarantine_root_fd = -1
    quarantine_fd = -1
    journal_fd = -1
    leaf_fd = -1
    lease: CaptureStagingLease | None = None
    identity_sha256: str | None = None
    next_sequence = 0
    try:
        root_fd, device = _open_shared_root(
            root_path,
            root_uid=identities.root_uid,
            root_gid=identities.root_gid,
            strict_parent_chain=strict_parent_chain,
            required_device=required_device,
        )
        transactions_fd = _ensure_namespace(
            root_fd,
            TRANSACTIONS_NAMESPACE,
            owner_uid=identities.root_uid,
            group_gid=identities.root_gid,
            mode=CONTROL_NAMESPACE_MODE,
            device=device,
            field="capture_staging_transactions_namespace",
        )
        lock_fd = _open_lock(
            transactions_fd,
            root_uid=identities.root_uid,
            root_gid=identities.root_gid,
            device=device,
        )
        completed_fd = _ensure_namespace(
            transactions_fd,
            COMPLETED_NAMESPACE,
            owner_uid=identities.root_uid,
            group_gid=identities.root_gid,
            mode=CONTROL_NAMESPACE_MODE,
            device=device,
            field="capture_staging_completed_namespace",
        )
        recovery_fd = _ensure_namespace(
            root_fd,
            RECOVERY_NAMESPACE,
            owner_uid=identities.root_uid,
            group_gid=identities.root_gid,
            mode=RECOVERY_NAMESPACE_MODE,
            device=device,
            field="capture_staging_recovery_namespace",
        )
        quarantine_root_fd = _ensure_namespace(
            root_fd,
            QUARANTINE_NAMESPACE,
            owner_uid=identities.root_uid,
            group_gid=identities.root_gid,
            mode=CONTROL_NAMESPACE_MODE,
            device=device,
            field="capture_staging_quarantine_namespace",
        )
        quarantine_fd = _ensure_namespace(
            quarantine_root_fd,
            QUARANTINE_STAGING_NAMESPACE,
            owner_uid=identities.root_uid,
            group_gid=identities.root_gid,
            mode=CONTROL_NAMESPACE_MODE,
            device=device,
            field="capture_staging_quarantine_staging_namespace",
        )
        os.close(quarantine_root_fd)
        quarantine_root_fd = -1
        recovered = _reconcile_selected_session(
            root_fd=root_fd,
            recovery_fd=recovery_fd,
            quarantine_fd=quarantine_fd,
            transactions_fd=transactions_fd,
            completed_fd=completed_fd,
            lock_fd=lock_fd,
            session_name=session_name,
            expected_transaction_intent_sha256=transaction_intent,
            identities=identities,
            device=device,
            fault_hook=fault_hook,
        )
        if recovered is not None:
            return recovered
        try:
            journal_fd = os.open(
                _journal_name(session_name),
                _journal_flags(create=True),
                JOURNAL_FILE_MODE,
                dir_fd=transactions_fd,
            )
        except FileExistsError as exc:
            raise _error("capture_staging_session_existing") from exc
        except OSError as exc:
            raise _error(
                "capture_staging_journal_create_failed"
            ) from exc
        os.fchown(journal_fd, identities.root_uid, identities.root_gid)
        os.fchmod(journal_fd, JOURNAL_FILE_MODE)
        _validate_regular_control_file(
            journal_fd,
            root_uid=identities.root_uid,
            root_gid=identities.root_gid,
            mode=JOURNAL_FILE_MODE,
            device=device,
            field="capture_staging_journal",
        )
        _append_record(
            journal_fd,
            session_name=session_name,
            sequence=next_sequence,
            event="create_intent",
            identity_sha256=None,
            staging_transaction_intent_sha256=transaction_intent,
        )
        next_sequence += 1
        os.fsync(transactions_fd)
        if fault_hook is not None:
            fault_hook("after_create_intent")
        try:
            os.mkdir(
                session_name,
                EXPOSED_LEAF_MODE,
                dir_fd=recovery_fd,
            )
        except OSError as exc:
            raise _error("capture_staging_leaf_create_failed") from exc
        leaf_fd, _created = _open_bound_directory(
            recovery_fd,
            session_name,
            field="capture_staging_created_leaf",
        )
        os.fchmod(leaf_fd, 0)
        os.fchown(
            leaf_fd,
            identities.root_uid,
            identities.root_gid,
        )
        os.fchmod(leaf_fd, EXPOSED_LEAF_MODE)
        os.fsync(leaf_fd)
        os.fsync(recovery_fd)
        info = _validate_leaf(
            leaf_fd,
            identities=identities,
            device=device,
            expected_identity_sha256=None,
            allow_exposed=False,
            allow_revoked=False,
            allow_root_created=True,
            field="capture_staging_created_leaf",
        )
        identity_sha256 = _identity_sha256(info)
        if fault_hook is not None:
            fault_hook("after_leaf_created")
        _append_record(
            journal_fd,
            session_name=session_name,
            sequence=next_sequence,
            event="leaf_created",
            identity_sha256=identity_sha256,
            staging_transaction_intent_sha256=transaction_intent,
        )
        next_sequence += 1
        if fault_hook is not None:
            fault_hook("after_leaf_identity_journaled")
        _append_record(
            journal_fd,
            session_name=session_name,
            sequence=next_sequence,
            event="staging_exposure_intent",
            identity_sha256=identity_sha256,
            staging_transaction_intent_sha256=transaction_intent,
        )
        next_sequence += 1
        if fault_hook is not None:
            fault_hook("after_exposure_intent")
        os.fchmod(leaf_fd, 0)
        os.fchown(
            leaf_fd,
            identities.capture_uid,
            identities.export_gid,
        )
        os.fchmod(leaf_fd, EXPOSED_LEAF_MODE)
        os.fsync(leaf_fd)
        os.fsync(recovery_fd)
        _validate_leaf(
            leaf_fd,
            identities=identities,
            device=device,
            expected_identity_sha256=identity_sha256,
            allow_exposed=True,
            allow_revoked=False,
            allow_root_created=False,
            field="capture_staging_exposed_leaf",
        )
        _append_record(
            journal_fd,
            session_name=session_name,
            sequence=next_sequence,
            event="staging_exposed",
            identity_sha256=identity_sha256,
            staging_transaction_intent_sha256=transaction_intent,
        )
        next_sequence += 1
        exposure_state = _parse_journal(
            _read_descriptor(
                journal_fd,
                maximum_bytes=MAX_JOURNAL_BYTES,
            ),
            session_name=session_name,
        )
        if (
            exposure_state.next_sequence != 4
            or exposure_state.last_event != "staging_exposed"
            or exposure_state.last_record_sha256 is None
            or exposure_state.staging_transaction_intent_sha256
            != transaction_intent
        ):
            raise _error(
                "capture_staging_exposure_journal_binding_invalid"
            )
        exposure_namespace_binding = _terminal_namespace_binding(
            root_fd=root_fd,
            recovery_fd=recovery_fd,
            quarantine_fd=quarantine_fd,
            transactions_fd=transactions_fd,
        )
        exposure_receipt = (
            staging_receipts.normalize_staging_exposure_receipt(
                {
                    "schema_version": (
                        staging_receipts
                        .STAGING_EXPOSURE_RECEIPT_SCHEMA
                    ),
                    "status": (
                        staging_receipts.STAGING_EXPOSURE_STATUS
                    ),
                    "capture_session_id": token,
                    "staging_leaf_name": session_name,
                    "staging_transaction_intent_sha256": (
                        transaction_intent
                    ),
                    "staging_leaf_identity_sha256": (
                        identity_sha256
                    ),
                    "capture_uid": identities.capture_uid,
                    "export_gid": identities.export_gid,
                    "staging_leaf_mode": EXPOSED_LEAF_MODE,
                    **exposure_namespace_binding,
                    "staging_journal_schema": (
                        STAGING_JOURNAL_SCHEMA
                    ),
                    "staging_journal_sequence": 3,
                    "staging_journal_head_sha256": (
                        exposure_state.last_record_sha256
                    ),
                }
            )
        )
        if fault_hook is not None:
            fault_hook("after_staging_exposed")
        os.close(completed_fd)
        completed_fd = -1
        lease = CaptureStagingLease(
            _token=_LEASE_TOKEN,
            shared_root=root_path,
            leaf_path=(
                root_path / RECOVERY_NAMESPACE / session_name
            ),
            session_name=session_name,
            identity_sha256=identity_sha256,
            staging_transaction_intent_sha256=transaction_intent,
            exposure_receipt=exposure_receipt,
            identities=identities,
            device=device,
            root_fd=root_fd,
            recovery_fd=recovery_fd,
            quarantine_fd=quarantine_fd,
            transactions_fd=transactions_fd,
            lock_fd=lock_fd,
            journal_fd=journal_fd,
            leaf_fd=leaf_fd,
            next_sequence=next_sequence,
            fault_hook=fault_hook,
        )
        root_fd = -1
        recovery_fd = -1
        quarantine_fd = -1
        transactions_fd = -1
        lock_fd = -1
        journal_fd = -1
        leaf_fd = -1
        return lease
    except BaseException as original:
        cleanup_failure: BaseException | None = None
        if (
            leaf_fd >= 0
            and journal_fd >= 0
            and identity_sha256 is not None
            and session_name
        ):
            try:
                next_sequence, cleanup_outcome = _move_to_quarantine(
                    recovery_fd=recovery_fd,
                    quarantine_fd=quarantine_fd,
                    session_name=session_name,
                    leaf_fd=leaf_fd,
                    identities=identities,
                    device=device,
                    identity_sha256=identity_sha256,
                    staging_transaction_intent_sha256=(
                        transaction_intent
                    ),
                    journal_fd=journal_fd,
                    next_sequence=next_sequence,
                    event_prefix="live",
                    reason_code="capture_failed",
                    remove_if_empty=True,
                    fault_hook=fault_hook,
                )
            except BaseException as exc:
                cleanup_failure = exc
        elif leaf_fd >= 0 and session_name:
            try:
                info = os.fstat(leaf_fd)
                observed = _identity_sha256(info)
                _revoke_leaf(
                    leaf_fd,
                    identities=identities,
                    device=device,
                    expected_identity_sha256=observed,
                    field="capture_staging_failed_create_leaf",
                )
                if _leaf_empty(leaf_fd):
                    os.rmdir(session_name, dir_fd=recovery_fd)
                    os.fsync(recovery_fd)
            except BaseException as exc:
                cleanup_failure = exc
        if cleanup_failure is not None:
            raise _error("capture_staging_create_cleanup_failed") from (
                cleanup_failure
            )
        raise original
    finally:
        if lease is None:
            for descriptor in (
                leaf_fd,
                journal_fd,
                quarantine_fd,
                quarantine_root_fd,
                recovery_fd,
                completed_fd,
                lock_fd,
                transactions_fd,
                root_fd,
            ):
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass


def create_session_staging(
    shared_root: Path,
    *,
    session_id: str,
    staging_transaction_intent_sha256: str,
    capture_uid: int,
    export_gid: int,
    required_device: int | None = None,
) -> CaptureStagingLease | CaptureStagingRecoveryOutcome:
    """Create one production root-managed staging leaf."""

    if os.getuid() != 0 or os.geteuid() != 0:
        raise _error("capture_staging_requires_root")
    identities = _StagingIdentities(
        root_uid=0,
        root_gid=0,
        capture_uid=_integer(
            capture_uid,
            field="capture_staging_capture_uid",
            minimum=1,
            maximum=(1 << 31) - 1,
        ),
        export_gid=_integer(
            export_gid,
            field="capture_staging_export_gid",
            minimum=1,
            maximum=(1 << 31) - 1,
        ),
    )
    device = (
        None
        if required_device is None
        else _integer(
            required_device,
            field="capture_staging_required_device",
            maximum=(1 << 63) - 1,
        )
    )
    return _create_impl(
        shared_root,
        session_id=session_id,
        staging_transaction_intent_sha256=(
            staging_transaction_intent_sha256
        ),
        identities=identities,
        required_device=device,
        strict_parent_chain=True,
        fault_hook=None,
    )


def _create_session_staging_for_test(
    shared_root: Path,
    *,
    session_id: str | None = None,
    staging_transaction_intent_sha256: str | None = None,
    token_factory: Callable[[], str] = lambda: secrets.token_hex(32),
    fault_hook: Callable[[str], None] | None = None,
) -> CaptureStagingLease | CaptureStagingRecoveryOutcome:
    """Unprivileged mechanical seam using the caller's identities."""

    if session_id is not None and not isinstance(session_id, str):
        raise _error("capture_staging_session_token_invalid")
    if session_id is None:
        if not callable(token_factory):
            raise _error("capture_staging_token_factory_invalid")
        selected_session_id = token_factory()
    else:
        selected_session_id = session_id
    selected_intent = (
        _sha256(
            _canonical_json(
                {
                    "test_only": True,
                    "capture_session_id": selected_session_id,
                }
            )
        )
        if staging_transaction_intent_sha256 is None
        else staging_transaction_intent_sha256
    )
    identities = _StagingIdentities(
        root_uid=os.geteuid(),
        root_gid=os.getegid(),
        capture_uid=os.geteuid(),
        export_gid=os.getegid(),
    )
    return _create_impl(
        shared_root,
        session_id=selected_session_id,
        staging_transaction_intent_sha256=selected_intent,
        identities=identities,
        required_device=None,
        strict_parent_chain=False,
        fault_hook=fault_hook,
    )


def open_installed_capture_staging_control(
    shared_root: Path | str,
    *,
    capture_uid: int,
    export_gid: int,
    required_device: int | None = None,
) -> InstalledCaptureStagingControl:
    """Retain the installed root descriptor used by recovered ACK commit."""

    if os.getuid() != 0 or os.geteuid() != 0:
        raise _error("capture_staging_requires_root")
    identities = _StagingIdentities(
        root_uid=0,
        root_gid=0,
        capture_uid=_integer(
            capture_uid,
            field="capture_staging_capture_uid",
            minimum=1,
            maximum=(1 << 31) - 1,
        ),
        export_gid=_integer(
            export_gid,
            field="capture_staging_export_gid",
            minimum=1,
            maximum=(1 << 31) - 1,
        ),
    )
    device = (
        None
        if required_device is None
        else _integer(
            required_device,
            field="capture_staging_required_device",
            maximum=(1 << 63) - 1,
        )
    )
    return _open_installed_capture_staging_control_impl(
        shared_root,
        identities=identities,
        required_device=device,
        strict_parent_chain=True,
    )


def _open_installed_capture_staging_control_for_test(
    shared_root: Path | str,
) -> InstalledCaptureStagingControl:
    """Unprivileged factory retaining the exact test shared-root FD."""

    identities = _StagingIdentities(
        root_uid=os.geteuid(),
        root_gid=os.getegid(),
        capture_uid=os.geteuid(),
        export_gid=os.getegid(),
    )
    return _open_installed_capture_staging_control_impl(
        shared_root,
        identities=identities,
        required_device=None,
        strict_parent_chain=False,
    )


def acknowledge_terminal_tombstone(
    shared_root: Path,
    *,
    session_id: str,
    staging_transaction_intent_sha256: str,
    terminal_receipt: Mapping[str, Any],
    outer_ack_pending_record_sha256: str,
    outer_quarantine_intent_record_sha256: str | None = None,
    outer_lifecycle_clearance_record_sha256: str | None,
    capture_uid: int,
    export_gid: int,
    required_device: int | None = None,
) -> dict[str, Any]:
    """Archive or retain one terminal journal after outer authorization."""

    if os.getuid() != 0 or os.geteuid() != 0:
        raise _error("capture_staging_requires_root")
    identities = _StagingIdentities(
        root_uid=0,
        root_gid=0,
        capture_uid=_integer(
            capture_uid,
            field="capture_staging_capture_uid",
            minimum=1,
            maximum=(1 << 31) - 1,
        ),
        export_gid=_integer(
            export_gid,
            field="capture_staging_export_gid",
            minimum=1,
            maximum=(1 << 31) - 1,
        ),
    )
    device = (
        None
        if required_device is None
        else _integer(
            required_device,
            field="capture_staging_required_device",
            maximum=(1 << 63) - 1,
        )
    )
    return _acknowledge_terminal_impl(
        shared_root,
        session_id=session_id,
        staging_transaction_intent_sha256=(
            staging_transaction_intent_sha256
        ),
        terminal_receipt=terminal_receipt,
        outer_ack_pending_record_sha256=(
            outer_ack_pending_record_sha256
        ),
        outer_quarantine_intent_record_sha256=(
            outer_quarantine_intent_record_sha256
        ),
        outer_lifecycle_clearance_record_sha256=(
            outer_lifecycle_clearance_record_sha256
        ),
        identities=identities,
        required_device=device,
        strict_parent_chain=True,
        fault_hook=None,
    )


def _acknowledge_terminal_tombstone_for_test(
    shared_root: Path,
    *,
    session_id: str,
    staging_transaction_intent_sha256: str,
    terminal_receipt: Mapping[str, Any],
    outer_ack_pending_record_sha256: str,
    outer_quarantine_intent_record_sha256: str | None = None,
    outer_lifecycle_clearance_record_sha256: str | None = None,
    fault_hook: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Unprivileged mechanical seam for ACK durability tests."""

    identities = _StagingIdentities(
        root_uid=os.geteuid(),
        root_gid=os.getegid(),
        capture_uid=os.geteuid(),
        export_gid=os.getegid(),
    )
    return _acknowledge_terminal_impl(
        shared_root,
        session_id=session_id,
        staging_transaction_intent_sha256=(
            staging_transaction_intent_sha256
        ),
        terminal_receipt=terminal_receipt,
        outer_ack_pending_record_sha256=(
            outer_ack_pending_record_sha256
        ),
        outer_quarantine_intent_record_sha256=(
            outer_quarantine_intent_record_sha256
        ),
        outer_lifecycle_clearance_record_sha256=(
            outer_lifecycle_clearance_record_sha256
        ),
        identities=identities,
        required_device=None,
        strict_parent_chain=False,
        fault_hook=fault_hook,
    )


def resolve_quarantined_session(
    shared_root: Path,
    *,
    session_id: str,
    staging_transaction_intent_sha256: str,
    outer_staging_tombstone_acked_record_sha256: str,
    expected_identity_sha256: str,
    required_device: int | None = None,
) -> str:
    """Manually remove one exact ACKed quarantine after operator review.

    This root-only function is intentionally not an orchestration or cron
    surface.  A human operator must select the exact session, outer intent,
    and quarantined inode identity after inspecting the sealed artifact.
    """

    if os.getuid() != 0 or os.geteuid() != 0:
        raise _error("capture_staging_operator_resolution_requires_root")
    device = (
        None
        if required_device is None
        else _integer(
            required_device,
            field="capture_staging_required_device",
            maximum=(1 << 63) - 1,
        )
    )
    return _resolve_quarantined_impl(
        shared_root,
        session_id=session_id,
        staging_transaction_intent_sha256=(
            staging_transaction_intent_sha256
        ),
        outer_staging_tombstone_acked_record_sha256=(
            outer_staging_tombstone_acked_record_sha256
        ),
        expected_identity_sha256=expected_identity_sha256,
        identities=_StagingIdentities(
            root_uid=0,
            root_gid=0,
            capture_uid=0,
            export_gid=0,
        ),
        required_device=device,
        strict_parent_chain=True,
        fault_hook=None,
    )


def _resolve_quarantined_session_for_test(
    shared_root: Path,
    *,
    session_id: str,
    staging_transaction_intent_sha256: str,
    outer_staging_tombstone_acked_record_sha256: str,
    expected_identity_sha256: str,
    fault_hook: Callable[[str], None] | None = None,
) -> str:
    identities = _StagingIdentities(
        root_uid=os.geteuid(),
        root_gid=os.getegid(),
        capture_uid=os.geteuid(),
        export_gid=os.getegid(),
    )
    return _resolve_quarantined_impl(
        shared_root,
        session_id=session_id,
        staging_transaction_intent_sha256=(
            staging_transaction_intent_sha256
        ),
        outer_staging_tombstone_acked_record_sha256=(
            outer_staging_tombstone_acked_record_sha256
        ),
        expected_identity_sha256=expected_identity_sha256,
        identities=identities,
        required_device=None,
        strict_parent_chain=False,
        fault_hook=fault_hook,
    )


__all__ = [
    "CONTROL_NAMESPACE_MODE",
    "CaptureStagingError",
    "CaptureStagingLease",
    "CaptureStagingRecoveryOutcome",
    "InstalledCaptureStagingControl",
    "EXPOSED_LEAF_MODE",
    "JOURNAL_FILE_MODE",
    "LOCK_FILE_MODE",
    "PRODUCTION_ACTIVATION",
    "RECOVERY_NAMESPACE",
    "RECOVERY_NAMESPACE_MODE",
    "REVOKED_LEAF_MODE",
    "SESSION_NAME_RE",
    "SHARED_ROOT_MODE",
    "STAGING_JOURNAL_SCHEMA",
    "TERMINAL_JOURNAL_EVENTS",
    "TRANSACTIONS_NAMESPACE",
    "acknowledge_terminal_tombstone",
    "create_session_staging",
    "open_installed_capture_staging_control",
    "resolve_quarantined_session",
]
