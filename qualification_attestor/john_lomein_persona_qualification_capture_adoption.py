#!/usr/bin/env python3
"""Descriptor-relative adoption of one non-root qualification capture.

This module is deliberately dormant.  It contains no model, YAML, signing,
attestation-chain, or network code.  Its sole authority is to transform one
already-sealed staging tree, after the capture child and its process group have
been reaped, from the capture identity into a root-owned verifier-readable
tree without copying or changing the bound inode.

The production entry points remain disabled until the installer, handoff
protocol, account/group audit, and privileged canaries bind this primitive.
The private test seam exercises the same descriptor operations with the
calling user's filesystem identities; it is not an activation path.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import platform
import re
import signal
import stat
import sys
import time
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from qualification_attestor import (
    john_lomein_persona_qualification_capture_staging as capture_staging,
)


PRODUCTION_ACTIVATION = False

ADOPTION_POLICY_SCHEMA = (
    "john-lomein.persona-qualification-capture-adoption-policy.v2"
)
ADOPTION_RECEIPT_SCHEMA = (
    "john-lomein.persona-qualification-capture-adoption.v2"
)
ADOPTION_STATUS = "adopted"
RECOVERY_HANDOFF_RECEIPT_SCHEMA = (
    "john-lomein.persona-qualification-capture-recovery-handoff.v1"
)
RECOVERY_HANDOFF_STATUS = (
    "attestation_publication_ambiguous_recovery_deferred"
)
RECOVERY_HANDOFF_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "capture_session_id",
        "capture_adoption_receipt_sha256",
        "capture_object_identity_sha256",
        "capture_plan_sha256",
        "capture_manifest_sha256",
        "capture_request_sha256",
        "requested_evidence_sha256",
        "final_name",
        "deferred_object_stat_sha256",
        "recovery_parent_identity_sha256",
        "deferred_by_uid",
        "deferred_at_unix",
    }
)

SESSION_ID_RE = re.compile(r"^[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CAPTURE_NAME_RE = re.compile(r"^opaque-capture-[0-9a-f]{32}$")

MAX_CAPTURE_FILES = 4_096
MAX_CAPTURE_DIRECTORIES = 4_096
MAX_CAPTURE_BYTES = 128 * 1024 * 1024
MAX_CAPTURE_FILE_BYTES = 16 * 1024 * 1024
MAX_CAPTURE_DEPTH = 64
MAX_REAP_SECONDS = 30
POLL_INTERVAL_SECONDS = 0.01

PROVISIONAL_DIRECTORY_MODE = 0o500
PROVISIONAL_FILE_MODE = 0o400
BUILDING_DIRECTORY_MODE = 0o700
BUILDING_FILE_MODE = 0o600
STAGING_PARENT_MODE = 0o700
REVOKED_STAGING_PARENT_MODE = 0o500
FINAL_PARENT_MODE = 0o710
ADOPTED_DIRECTORY_MODE = 0o550
ADOPTED_FILE_MODE = 0o440

_RENAME_NOREPLACE = 1
_DARWIN_RENAME_EXCL = 0x00000004


class CaptureAdoptionError(RuntimeError):
    """Stable, public-safe adoption rejection."""

    def __init__(self, code: str, *, child_reaped: bool = False):
        self.code = code
        # This is an in-process supervisor signal, never serialized into a
        # public receipt.  A caller must not perform PID/PGID cleanup after an
        # error that follows the final waitpid: the numeric identifier may
        # already name an unrelated process group.
        self.child_reaped = child_reaped
        super().__init__(code)


def _error(
    code: str,
    *,
    child_reaped: bool = False,
) -> CaptureAdoptionError:
    return CaptureAdoptionError(code, child_reaped=child_reaped)


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
        raise _error("capture_adoption_json_invalid") from exc


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise _error(f"{field}_invalid")
    return value


def _integer(
    value: Any,
    *,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _error(f"{field}_invalid")
    return value


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


def _component(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or value in {".", ".."}
        or "/" in value
        or "\x00" in value
        or unicodedata.normalize("NFC", value) != value
        or not CAPTURE_NAME_RE.fullmatch(value)
    ):
        raise _error(f"{field}_invalid")
    return value


def _session_id(value: Any) -> str:
    if not isinstance(value, str) or not SESSION_ID_RE.fullmatch(value):
        raise _error("capture_adoption_session_id_invalid")
    return value


def _path_key(path: Path | str) -> str:
    return unicodedata.normalize(
        "NFC",
        str(path).rstrip(os.sep),
    ).casefold()


def _paths_overlap(left: Path, right: Path) -> bool:
    left_key = _path_key(left)
    right_key = _path_key(right)
    return (
        left_key == right_key
        or left_key.startswith(right_key + os.sep)
        or right_key.startswith(left_key + os.sep)
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


def _object_sha256(info: os.stat_result) -> str:
    return _sha256(_canonical_json(list(_stable_object_tuple(info))))


def _stat_sha256(info: os.stat_result) -> str:
    return _sha256(_canonical_json(list(_full_stat_tuple(info))))


def _recovery_parent_identity_sha256(
    info: os.stat_result,
) -> str:
    """Digest only stable, path-independent parent identity attributes."""

    return _sha256(
        _canonical_json(
            {
                "device": int(info.st_dev),
                "inode": int(info.st_ino),
                "type": int(stat.S_IFMT(info.st_mode)),
                "uid": int(info.st_uid),
                "gid": int(info.st_gid),
                "mode": int(stat.S_IMODE(info.st_mode)),
            }
        )
    )


def normalize_recovery_handoff_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the exact path-free durable recovery handoff contract."""

    if (
        not isinstance(value, Mapping)
        or set(value) != RECOVERY_HANDOFF_RECEIPT_FIELDS
    ):
        raise _error(
            "capture_adoption_recovery_handoff_receipt_fields_invalid"
        )
    if value.get("schema_version") != RECOVERY_HANDOFF_RECEIPT_SCHEMA:
        raise _error(
            "capture_adoption_recovery_handoff_receipt_schema_invalid"
        )
    if value.get("status") != RECOVERY_HANDOFF_STATUS:
        raise _error(
            "capture_adoption_recovery_handoff_receipt_status_invalid"
        )
    deferred_by_uid = _integer(
        value.get("deferred_by_uid"),
        field="capture_adoption_recovery_handoff_deferred_by_uid",
        minimum=0,
        maximum=(1 << 31) - 1,
    )
    if deferred_by_uid != 0:
        raise _error(
            "capture_adoption_recovery_handoff_deferred_by_uid_invalid"
        )
    return {
        "schema_version": RECOVERY_HANDOFF_RECEIPT_SCHEMA,
        "status": RECOVERY_HANDOFF_STATUS,
        "capture_session_id": _session_id(
            value.get("capture_session_id")
        ),
        "capture_adoption_receipt_sha256": _digest(
            value.get("capture_adoption_receipt_sha256"),
            field=(
                "capture_adoption_recovery_handoff_adoption_receipt_sha256"
            ),
        ),
        "capture_object_identity_sha256": _digest(
            value.get("capture_object_identity_sha256"),
            field=(
                "capture_adoption_recovery_handoff_object_identity_sha256"
            ),
        ),
        "capture_plan_sha256": _digest(
            value.get("capture_plan_sha256"),
            field="capture_adoption_recovery_handoff_plan_sha256",
        ),
        "capture_manifest_sha256": _digest(
            value.get("capture_manifest_sha256"),
            field="capture_adoption_recovery_handoff_manifest_sha256",
        ),
        "capture_request_sha256": _digest(
            value.get("capture_request_sha256"),
            field="capture_adoption_recovery_handoff_request_sha256",
        ),
        "requested_evidence_sha256": _digest(
            value.get("requested_evidence_sha256"),
            field=(
                "capture_adoption_recovery_handoff_requested_evidence_sha256"
            ),
        ),
        "final_name": _component(
            value.get("final_name"),
            field="capture_adoption_recovery_handoff_final_name",
        ),
        "deferred_object_stat_sha256": _digest(
            value.get("deferred_object_stat_sha256"),
            field=(
                "capture_adoption_recovery_handoff_deferred_stat_sha256"
            ),
        ),
        "recovery_parent_identity_sha256": _digest(
            value.get("recovery_parent_identity_sha256"),
            field=(
                "capture_adoption_recovery_handoff_parent_identity_sha256"
            ),
        ),
        "deferred_by_uid": deferred_by_uid,
        "deferred_at_unix": _integer(
            value.get("deferred_at_unix"),
            field="capture_adoption_recovery_handoff_deferred_at_unix",
            minimum=1,
            maximum=(1 << 53) - 1,
        ),
    }


def recovery_handoff_receipt_sha256(
    value: Mapping[str, Any],
) -> str:
    """Return the canonical digest bound into ambiguity journals."""

    return _sha256(
        _canonical_json(normalize_recovery_handoff_receipt(value))
    )


def capture_object_identity_sha256(descriptor: int) -> str:
    """Return the path-independent digest used by a helper handoff."""

    try:
        info = os.fstat(descriptor)
    except OSError as exc:
        raise _error("capture_adoption_object_unreadable") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise _error("capture_adoption_object_not_directory")
    return _object_sha256(info)


@dataclass(frozen=True)
class CaptureAdoptionPolicy:
    """Complete immutable policy for one staged capture adoption."""

    session_id: str
    staging_parent: Path
    final_parent: Path
    provisional_name: str
    final_name: str
    expected_object_sha256: str
    capture_uid: int
    capture_gid: int
    verifier_uid: int
    verifier_gid: int
    capture_selection_sha256: str
    capture_plan_sha256: str
    capture_manifest_sha256: str
    capture_boundary_policy_sha256: str
    helper_activation_policy_sha256: str
    request_sha256: str
    max_files: int
    max_directories: int
    max_bytes: int
    max_file_bytes: int
    max_depth: int

    def activation_record(self) -> dict[str, Any]:
        return {
            "schema_version": ADOPTION_POLICY_SCHEMA,
            "session_id": self.session_id,
            "staging_parent": str(self.staging_parent),
            "final_parent": str(self.final_parent),
            "provisional_name": self.provisional_name,
            "final_name": self.final_name,
            "expected_object_sha256": self.expected_object_sha256,
            "capture_uid": self.capture_uid,
            "capture_gid": self.capture_gid,
            "verifier_uid": self.verifier_uid,
            "verifier_gid": self.verifier_gid,
            "capture_selection_sha256": (
                self.capture_selection_sha256
            ),
            "capture_plan_sha256": self.capture_plan_sha256,
            "capture_manifest_sha256": (
                self.capture_manifest_sha256
            ),
            "capture_boundary_policy_sha256": (
                self.capture_boundary_policy_sha256
            ),
            "helper_activation_policy_sha256": (
                self.helper_activation_policy_sha256
            ),
            "request_sha256": self.request_sha256,
            "limits": {
                "max_files": self.max_files,
                "max_directories": self.max_directories,
                "max_bytes": self.max_bytes,
                "max_file_bytes": self.max_file_bytes,
                "max_depth": self.max_depth,
            },
            "ownership_contract": (
                "capture-export-to-root-verifier-same-inode"
            ),
            "rename_contract": (
                "same-filesystem-exclusive-no-replace-no-copy"
            ),
            "provisional_authority_contract": (
                "ready-retained-fd-one-shot-no-name-reopen"
            ),
            "staging_lifecycle_contract": (
                "root-session-leaf-reap-revoke-clean-or-quarantine"
            ),
            "provisional_modes": {
                "parent": STAGING_PARENT_MODE,
                "directory": PROVISIONAL_DIRECTORY_MODE,
                "file": PROVISIONAL_FILE_MODE,
            },
            "adopted_modes": {
                "parent": FINAL_PARENT_MODE,
                "directory": ADOPTED_DIRECTORY_MODE,
                "file": ADOPTED_FILE_MODE,
            },
        }

    def policy_sha256(self) -> str:
        return _sha256(_canonical_json(self.activation_record()))


def normalize_adoption_policy(
    policy: CaptureAdoptionPolicy,
) -> CaptureAdoptionPolicy:
    if type(policy) is not CaptureAdoptionPolicy:
        raise _error("capture_adoption_policy_invalid")
    session = _session_id(policy.session_id)
    staging = _absolute_path(
        policy.staging_parent,
        field="capture_adoption_staging_parent",
    )
    final = _absolute_path(
        policy.final_parent,
        field="capture_adoption_final_parent",
    )
    if _paths_overlap(staging, final):
        raise _error("capture_adoption_parents_overlap")
    provisional_name = _component(
        policy.provisional_name,
        field="capture_adoption_provisional_name",
    )
    final_name = _component(
        policy.final_name,
        field="capture_adoption_final_name",
    )
    capture_uid = _integer(
        policy.capture_uid,
        field="capture_adoption_capture_uid",
        minimum=1,
        maximum=(1 << 31) - 1,
    )
    capture_gid = _integer(
        policy.capture_gid,
        field="capture_adoption_capture_gid",
        minimum=1,
        maximum=(1 << 31) - 1,
    )
    verifier_uid = _integer(
        policy.verifier_uid,
        field="capture_adoption_verifier_uid",
        minimum=1,
        maximum=(1 << 31) - 1,
    )
    verifier_gid = _integer(
        policy.verifier_gid,
        field="capture_adoption_verifier_gid",
        minimum=1,
        maximum=(1 << 31) - 1,
    )
    if capture_uid == verifier_uid:
        raise _error("capture_adoption_uid_separation_missing")
    if capture_gid == verifier_gid:
        raise _error("capture_adoption_group_separation_missing")
    max_files = _integer(
        policy.max_files,
        field="capture_adoption_max_files",
        minimum=1,
        maximum=MAX_CAPTURE_FILES,
    )
    max_directories = _integer(
        policy.max_directories,
        field="capture_adoption_max_directories",
        minimum=1,
        maximum=MAX_CAPTURE_DIRECTORIES,
    )
    max_bytes = _integer(
        policy.max_bytes,
        field="capture_adoption_max_bytes",
        minimum=1,
        maximum=MAX_CAPTURE_BYTES,
    )
    max_file_bytes = _integer(
        policy.max_file_bytes,
        field="capture_adoption_max_file_bytes",
        minimum=1,
        maximum=MAX_CAPTURE_FILE_BYTES,
    )
    max_depth = _integer(
        policy.max_depth,
        field="capture_adoption_max_depth",
        minimum=1,
        maximum=MAX_CAPTURE_DEPTH,
    )
    if max_file_bytes > max_bytes:
        raise _error("capture_adoption_file_limit_exceeds_total")
    return CaptureAdoptionPolicy(
        session_id=session,
        staging_parent=staging,
        final_parent=final,
        provisional_name=provisional_name,
        final_name=final_name,
        expected_object_sha256=_digest(
            policy.expected_object_sha256,
            field="capture_adoption_expected_object_sha256",
        ),
        capture_uid=capture_uid,
        capture_gid=capture_gid,
        verifier_uid=verifier_uid,
        verifier_gid=verifier_gid,
        capture_selection_sha256=_digest(
            policy.capture_selection_sha256,
            field="capture_adoption_selection_sha256",
        ),
        capture_plan_sha256=_digest(
            policy.capture_plan_sha256,
            field="capture_adoption_plan_sha256",
        ),
        capture_manifest_sha256=_digest(
            policy.capture_manifest_sha256,
            field="capture_adoption_manifest_sha256",
        ),
        capture_boundary_policy_sha256=_digest(
            policy.capture_boundary_policy_sha256,
            field="capture_adoption_boundary_policy_sha256",
        ),
        helper_activation_policy_sha256=_digest(
            policy.helper_activation_policy_sha256,
            field="capture_adoption_helper_policy_sha256",
        ),
        request_sha256=_digest(
            policy.request_sha256,
            field="capture_adoption_request_sha256",
        ),
        max_files=max_files,
        max_directories=max_directories,
        max_bytes=max_bytes,
        max_file_bytes=max_file_bytes,
        max_depth=max_depth,
    )


_CHILD_DEATH_PROOF_TOKEN = object()


class ChildDeathProof:
    """One-shot, nonserializable proof minted only by the reaper."""

    __slots__ = (
        "_session_id",
        "_capture_uid",
        "_pid",
        "_status",
        "_process_group_reaped",
        "_consumed",
    )

    def __init__(
        self,
        *,
        _token: object,
        session_id: str,
        capture_uid: int,
        pid: int,
        status: int,
        process_group_reaped: bool,
    ) -> None:
        if _token is not _CHILD_DEATH_PROOF_TOKEN:
            raise TypeError("ChildDeathProof cannot be constructed directly")
        self._session_id = _session_id(session_id)
        self._capture_uid = capture_uid
        self._pid = pid
        self._status = status
        self._process_group_reaped = process_group_reaped
        self._consumed = False

    def _consume(
        self,
        *,
        session_id: str,
        capture_uid: int,
    ) -> tuple[int, int]:
        if self._consumed:
            raise _error("capture_adoption_child_proof_consumed")
        if (
            self._session_id != session_id
            or self._capture_uid != capture_uid
            or self._status != 0
            or self._process_group_reaped is not True
        ):
            raise _error("capture_adoption_child_proof_mismatch")
        self._consumed = True
        return self._pid, self._status

    def __reduce__(self) -> Any:
        raise TypeError("ChildDeathProof is not serializable")

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError("ChildDeathProof is not serializable")


def _kill_process_group(
    process_group_id: int,
    *,
    killpg: Callable[[int, int], None] = os.killpg,
    allow_darwin_zombie_eperm: bool = False,
) -> None:
    try:
        killpg(process_group_id, signal.SIGKILL)
    except ProcessLookupError:
        return
    except PermissionError as exc:
        # On Darwin, killpg against a group containing only the pinned zombie
        # leader reports EPERM to an unprivileged same-UID test coordinator.
        # The production coordinator is root and the enforced capture sandbox
        # forbids descendants, so this result means there is no signalable
        # member left.  Other platforms and other errors fail closed.
        if allow_darwin_zombie_eperm and platform.system() == "Darwin":
            return
        raise _error("capture_adoption_process_group_kill_failed") from exc
    except OSError as exc:
        raise _error("capture_adoption_process_group_kill_failed") from exc


@dataclass(frozen=True)
class _ReapSyscalls:
    """Explicit syscall seam for ordering and PID-reuse regression tests."""

    getpgid: Callable[[int], int]
    waitid: Callable[[int, int, int], Any]
    killpg: Callable[[int, int], None]
    waitpid: Callable[[int, int], tuple[int, int]]
    waitstatus_to_exitcode: Callable[[int], int]
    sleep: Callable[[float], None]


class _DarwinSigval(ctypes.Union):
    _fields_ = (
        ("sival_int", ctypes.c_int),
        ("sival_ptr", ctypes.c_void_p),
    )


class _DarwinSiginfo(ctypes.Structure):
    # Darwin's public siginfo_t layout from <sys/signal.h>.  The complete
    # structure is required because libc writes beyond the SIGCHLD fields.
    _fields_ = (
        ("si_signo", ctypes.c_int),
        ("si_errno", ctypes.c_int),
        ("si_code", ctypes.c_int),
        ("si_pid", ctypes.c_int),
        ("si_uid", ctypes.c_uint),
        ("si_status", ctypes.c_int),
        ("si_addr", ctypes.c_void_p),
        ("si_value", _DarwinSigval),
        ("si_band", ctypes.c_long),
        ("reserved", ctypes.c_ulong * 7),
    )


@dataclass(frozen=True)
class _WaitidObservation:
    si_pid: int
    si_code: int
    si_status: int


def _darwin_waitid_callable() -> Callable[[int, int, int], Any]:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        waitid = libc.waitid
        waitid.argtypes = (
            ctypes.c_int,
            ctypes.c_uint,
            ctypes.POINTER(_DarwinSiginfo),
            ctypes.c_int,
        )
        waitid.restype = ctypes.c_int
    except (AttributeError, OSError) as exc:
        raise _error(
            "capture_adoption_child_death_observation_unsupported"
        ) from exc

    def observe(idtype: int, child_pid: int, flags: int) -> Any:
        info = _DarwinSiginfo()
        ctypes.set_errno(0)
        if waitid(idtype, child_pid, ctypes.byref(info), flags) != 0:
            error_number = ctypes.get_errno()
            if error_number == errno.ECHILD:
                raise ChildProcessError(
                    error_number,
                    os.strerror(error_number),
                )
            raise OSError(
                error_number,
                os.strerror(error_number),
            )
        if info.si_pid == 0:
            return None
        return _WaitidObservation(
            si_pid=int(info.si_pid),
            si_code=int(info.si_code),
            si_status=int(info.si_status),
        )

    return observe


def _runtime_reap_syscalls() -> _ReapSyscalls:
    required = (
        "P_PID",
        "WEXITED",
        "WNOHANG",
        "WNOWAIT",
        "CLD_EXITED",
    )
    if not all(hasattr(os, name) for name in required):
        raise _error(
            "capture_adoption_child_death_observation_unsupported"
        )
    if hasattr(os, "waitid"):
        waitid = os.waitid
    elif platform.system() == "Darwin":
        waitid = _darwin_waitid_callable()
    else:
        raise _error(
            "capture_adoption_child_death_observation_unsupported"
        )
    return _ReapSyscalls(
        getpgid=os.getpgid,
        waitid=waitid,
        killpg=os.killpg,
        waitpid=os.waitpid,
        waitstatus_to_exitcode=os.waitstatus_to_exitcode,
        sleep=time.sleep,
    )


def _observe_child_exit_without_reaping(
    child_pid: int,
    *,
    deadline: float,
    monotonic: Callable[[], float],
    syscalls: _ReapSyscalls,
) -> tuple[int, int]:
    """Observe death with WNOWAIT so PID/PGID reuse remains impossible."""

    flags = os.WEXITED | os.WNOHANG | os.WNOWAIT
    while True:
        try:
            observed = syscalls.waitid(os.P_PID, child_pid, flags)
        except InterruptedError:
            continue
        except ChildProcessError as exc:
            raise _error(
                "capture_adoption_child_wait_lost",
                child_reaped=True,
            ) from exc
        except OSError as exc:
            if exc.errno == errno.ECHILD:
                raise _error(
                    "capture_adoption_child_wait_lost",
                    child_reaped=True,
                ) from exc
            raise _error("capture_adoption_child_wait_failed") from exc
        if observed is not None:
            observed_pid = getattr(observed, "si_pid", None)
            if observed_pid not in (0, child_pid):
                raise _error(
                    "capture_adoption_child_death_observation_invalid"
                )
            if observed_pid == child_pid:
                code = getattr(observed, "si_code", None)
                status = getattr(observed, "si_status", None)
                if type(code) is not int or type(status) is not int:
                    raise _error(
                        "capture_adoption_child_death_observation_invalid"
                    )
                return code, status
        if monotonic() >= deadline:
            raise _error("capture_adoption_child_exit_timeout")
        syscalls.sleep(POLL_INTERVAL_SECONDS)


def _final_reap(
    child_pid: int,
    *,
    syscalls: _ReapSyscalls,
) -> int:
    """Perform the one final wait; callers must not signal the PGID later."""

    while True:
        try:
            observed, raw_status = syscalls.waitpid(child_pid, 0)
        except InterruptedError:
            continue
        except ChildProcessError as exc:
            raise _error(
                "capture_adoption_child_wait_lost",
                child_reaped=True,
            ) from exc
        except OSError as exc:
            if exc.errno == errno.ECHILD:
                raise _error(
                    "capture_adoption_child_wait_lost",
                    child_reaped=True,
                ) from exc
            raise _error("capture_adoption_child_wait_failed") from exc
        if observed != child_pid:
            raise _error("capture_adoption_child_wait_lost")
        try:
            return syscalls.waitstatus_to_exitcode(raw_status)
        except ValueError as exc:
            raise _error(
                "capture_adoption_child_status_invalid",
                child_reaped=True,
            ) from exc


def _reap_capture_child_with_syscalls(
    *,
    session_id: str,
    capture_uid: int,
    child_pid: int,
    timeout: int,
    monotonic: Callable[[], float],
    syscalls: _ReapSyscalls,
) -> ChildDeathProof:
    try:
        observed_group: int | None = syscalls.getpgid(child_pid)
    except ProcessLookupError:
        # A very short-lived session leader may already be a zombie.  WNOWAIT
        # below pins its PID until group cleanup has been issued.
        observed_group = None
    except OSError as exc:
        raise _error("capture_adoption_child_group_unreadable") from exc
    if observed_group is not None and observed_group != child_pid:
        raise _error("capture_adoption_child_not_session_leader")

    deadline = monotonic() + timeout
    observed_code, observed_status = _observe_child_exit_without_reaping(
        child_pid,
        deadline=deadline,
        monotonic=monotonic,
        syscalls=syscalls,
    )

    # The unreaped leader is still a zombie here.  It pins the numeric PID and
    # process-group identifier, so this signal cannot be redirected to a group
    # created by PID reuse.  The sandbox's deny-fork rule is the independent
    # proof that the group cannot contain an escaping descendant.
    cleanup_error: CaptureAdoptionError | None = None
    try:
        _kill_process_group(
            child_pid,
            killpg=syscalls.killpg,
            allow_darwin_zombie_eperm=(
                os.geteuid() != 0
            ),
        )
    except CaptureAdoptionError as exc:
        cleanup_error = exc

    status = _final_reap(child_pid, syscalls=syscalls)
    if cleanup_error is not None:
        raise _error(
            cleanup_error.code,
            child_reaped=True,
        ) from cleanup_error
    if (
        observed_code != os.CLD_EXITED
        or observed_status != 0
        or status != observed_status
    ):
        raise _error(
            "capture_adoption_child_exit_failed",
            child_reaped=True,
        )
    return ChildDeathProof(
        _token=_CHILD_DEATH_PROOF_TOKEN,
        session_id=session_id,
        capture_uid=capture_uid,
        pid=child_pid,
        status=status,
        process_group_reaped=True,
    )


def reap_capture_child(
    *,
    session_id: str,
    capture_uid: int,
    pid: int,
    timeout_seconds: int,
    monotonic: Callable[[], float] = time.monotonic,
) -> ChildDeathProof:
    """Observe one session leader, clean its pinned group, then reap it."""

    session = _session_id(session_id)
    uid = _integer(
        capture_uid,
        field="capture_adoption_reap_capture_uid",
        minimum=1,
        maximum=(1 << 31) - 1,
    )
    child_pid = _integer(
        pid,
        field="capture_adoption_reap_pid",
        minimum=2,
        maximum=(1 << 31) - 1,
    )
    timeout = _integer(
        timeout_seconds,
        field="capture_adoption_reap_timeout",
        minimum=1,
        maximum=MAX_REAP_SECONDS,
    )
    if not callable(monotonic):
        raise _error("capture_adoption_reap_clock_invalid")
    return _reap_capture_child_with_syscalls(
        session_id=session,
        capture_uid=uid,
        child_pid=child_pid,
        timeout=timeout,
        monotonic=monotonic,
        syscalls=_runtime_reap_syscalls(),
    )


def _directory_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("capture_adoption_nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _file_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("capture_adoption_nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    return flags


def _dup_cloexec(descriptor: int) -> int:
    try:
        duplicate = fcntl.fcntl(
            descriptor,
            fcntl.F_DUPFD_CLOEXEC,
            64,
        )
    except OSError as exc:
        raise _error("capture_adoption_descriptor_duplicate_failed") from exc
    if os.get_inheritable(duplicate):
        os.close(duplicate)
        raise _error("capture_adoption_descriptor_inheritable")
    return duplicate


def _lock_exclusive(descriptor: int, *, field: str) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise _error(f"{field}_busy") from exc
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EAGAIN}:
            raise _error(f"{field}_busy") from exc
        raise _error(f"{field}_lock_failed") from exc


def _reject_fd_metadata(descriptor: int, *, field: str) -> None:
    """Reject ACLs and every non-platform filesystem authority attribute."""

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


def _validate_trusted_parent_chain(path: Path, *, root_uid: int) -> None:
    for parent in _path_parent_chain(path):
        try:
            info = parent.lstat()
        except OSError as exc:
            raise _error("capture_adoption_parent_unreadable") from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != root_uid
            or info.st_mode & 0o022
        ):
            raise _error("capture_adoption_parent_unsafe")


def _validate_path_fd_binding(
    path: Path,
    descriptor: int,
    *,
    field: str,
) -> os.stat_result:
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
    _reject_fd_metadata(descriptor, field=field)
    return opened


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
    normalized: list[str] = []
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
        normalized.append(value)
    return sorted(normalized)


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
            or _stable_object_tuple(named)
            != _stable_object_tuple(opened)
        ):
            raise _error(f"{field}_inode_mismatch")
        _reject_fd_metadata(descriptor, field=field)
        return descriptor, opened
    except Exception:
        os.close(descriptor)
        raise


def _open_bound_file(
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
            _file_flags(),
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(named.st_mode)
            or _stable_object_tuple(named)
            != _stable_object_tuple(opened)
        ):
            raise _error(f"{field}_inode_mismatch")
        _reject_fd_metadata(descriptor, field=field)
        return descriptor, opened
    except Exception:
        os.close(descriptor)
        raise


_RETAINED_PROVISIONAL_TOKEN = object()


class RetainedProvisionalCapture:
    """One-shot descriptor authority pinned at the READY boundary."""

    __slots__ = (
        "_descriptor",
        "_session_id",
        "_capture_uid",
        "_provisional_name",
        "_object_identity_sha256",
        "_state",
    )

    def __init__(
        self,
        *,
        _token: object,
        descriptor: int,
        session_id: str,
        capture_uid: int,
        provisional_name: str,
        object_identity_sha256: str,
    ) -> None:
        if _token is not _RETAINED_PROVISIONAL_TOKEN:
            raise TypeError(
                "RetainedProvisionalCapture cannot be constructed directly"
            )
        self._descriptor = descriptor
        self._session_id = session_id
        self._capture_uid = capture_uid
        self._provisional_name = provisional_name
        self._object_identity_sha256 = object_identity_sha256
        self._state = "retained"

    @property
    def active(self) -> bool:
        return self._state == "retained" and self._descriptor >= 0

    @property
    def consumed(self) -> bool:
        return self._state == "consumed"

    def _consume(self, policy: CaptureAdoptionPolicy) -> int:
        if self._state == "consumed":
            raise _error(
                "capture_adoption_provisional_authority_consumed"
            )
        if not self.active:
            raise _error("capture_adoption_provisional_authority_closed")
        normalized = normalize_adoption_policy(policy)
        if (
            self._session_id != normalized.session_id
            or self._capture_uid != normalized.capture_uid
            or self._provisional_name != normalized.provisional_name
            or self._object_identity_sha256
            != normalized.expected_object_sha256
        ):
            self.close()
            raise _error(
                "capture_adoption_provisional_authority_mismatch"
            )
        try:
            info = os.fstat(self._descriptor)
        except OSError as exc:
            self.close()
            raise _error(
                "capture_adoption_provisional_authority_unreadable"
            ) from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or _object_sha256(info)
            != self._object_identity_sha256
        ):
            self.close()
            raise _error(
                "capture_adoption_provisional_authority_changed"
            )
        descriptor = self._descriptor
        self._descriptor = -1
        self._state = "consumed"
        return descriptor

    def close(self) -> None:
        if not self.active:
            return
        descriptor = self._descriptor
        os.close(descriptor)
        self._descriptor = -1
        self._state = "closed"

    def _fileno_for_test(self) -> int:
        if not self.active:
            raise _error("capture_adoption_provisional_authority_closed")
        return self._descriptor

    def __reduce__(self) -> Any:
        raise TypeError(
            "RetainedProvisionalCapture is not serializable"
        )

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError(
            "RetainedProvisionalCapture is not serializable"
        )

    def __del__(self) -> None:
        if getattr(self, "_state", "closed") == "retained":
            try:
                self.close()
            except BaseException:
                pass


def _retained_directory_flags() -> int:
    required = ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC")
    if not all(hasattr(os, name) for name in required):
        raise _error(
            "capture_adoption_provisional_authority_unsupported"
        )
    return (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | os.O_DIRECTORY
        | os.O_CLOEXEC
    )


def retain_provisional_capture(
    *,
    staging_parent_fd: int,
    session_id: str,
    capture_uid: int,
    provisional_name: str,
    expected_object_sha256: str,
) -> RetainedProvisionalCapture:
    """Open and bind the READY object before the child can be reaped."""

    session = _session_id(session_id)
    uid = _integer(
        capture_uid,
        field="capture_adoption_provisional_authority_capture_uid",
        minimum=1,
        maximum=(1 << 31) - 1,
    )
    name = _component(
        provisional_name,
        field="capture_adoption_provisional_authority_name",
    )
    expected = _digest(
        expected_object_sha256,
        field="capture_adoption_provisional_authority_object_sha256",
    )
    try:
        descriptor = os.open(
            name,
            _retained_directory_flags(),
            dir_fd=staging_parent_fd,
        )
    except OSError as exc:
        raise _error(
            "capture_adoption_provisional_authority_unreadable"
        ) from exc
    try:
        os.set_inheritable(descriptor, False)
        if os.get_inheritable(descriptor):
            raise _error(
                "capture_adoption_provisional_authority_inheritable"
            )
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise _error(
                "capture_adoption_provisional_authority_not_directory"
            )
        if _object_sha256(info) != expected:
            raise _error(
                "capture_adoption_object_identity_mismatch"
            )
        _reject_fd_metadata(
            descriptor,
            field="capture_adoption_provisional_authority",
        )
        if not _bound_name_matches(
            staging_parent_fd,
            name,
            descriptor,
        ):
            raise _error(
                "capture_adoption_provisional_name_rebound"
            )
        return RetainedProvisionalCapture(
            _token=_RETAINED_PROVISIONAL_TOKEN,
            descriptor=descriptor,
            session_id=session,
            capture_uid=uid,
            provisional_name=name,
            object_identity_sha256=expected,
        )
    except BaseException:
        os.close(descriptor)
        raise


@dataclass
class _Inventory:
    records: list[dict[str, Any]]
    files: int = 0
    directories: int = 0
    total_bytes: int = 0

    def content_sha256(self) -> str:
        return _sha256(
            _canonical_json(
                sorted(
                    self.records,
                    key=lambda item: item["path"],
                )
            )
        )


@dataclass(frozen=True)
class _FilesystemIdentities:
    capture_uid: int
    capture_gid: int
    root_uid: int
    root_gid: int
    verifier_gid: int
    revoked_parent_mode: int = REVOKED_STAGING_PARENT_MODE


def _validate_directory_info(
    info: os.stat_result,
    *,
    owner_uid: int,
    group_gid: int,
    mode: int,
    root_device: int,
    field: str,
) -> None:
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_dev != root_device
        or info.st_uid != owner_uid
        or info.st_gid != group_gid
        or stat.S_IMODE(info.st_mode) != mode
    ):
        raise _error(f"{field}_unsafe")


def _validate_file_info(
    info: os.stat_result,
    *,
    owner_uid: int,
    group_gid: int,
    mode: int,
    root_device: int,
    maximum_bytes: int,
    field: str,
) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_dev != root_device
        or info.st_uid != owner_uid
        or info.st_gid != group_gid
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != mode
        or not 0 <= info.st_size <= maximum_bytes
    ):
        raise _error(f"{field}_unsafe")


def _read_digest(
    descriptor: int,
    *,
    maximum_bytes: int,
    field: str,
) -> tuple[int, str]:
    digest = hashlib.sha256()
    observed = 0
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while observed <= maximum_bytes:
            chunk = os.read(
                descriptor,
                min(64 * 1024, maximum_bytes + 1 - observed),
            )
            if not chunk:
                break
            observed += len(chunk)
            digest.update(chunk)
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    if observed > maximum_bytes:
        raise _error(f"{field}_too_large")
    return observed, digest.hexdigest()


def _inventory_tree(
    descriptor: int,
    *,
    prefix: str,
    owner_uid: int,
    group_gid: int,
    directory_mode: int,
    file_mode: int,
    root_device: int,
    policy: CaptureAdoptionPolicy,
    inventory: _Inventory,
    depth: int,
) -> None:
    if depth > policy.max_depth:
        raise _error("capture_adoption_tree_too_deep")
    before = os.fstat(descriptor)
    _validate_directory_info(
        before,
        owner_uid=owner_uid,
        group_gid=group_gid,
        mode=directory_mode,
        root_device=root_device,
        field="capture_adoption_directory",
    )
    _reject_fd_metadata(
        descriptor,
        field="capture_adoption_directory",
    )
    inventory.directories += 1
    if inventory.directories > policy.max_directories:
        raise _error("capture_adoption_directory_count_exceeded")
    inventory.records.append(
        {"path": prefix, "type": "directory"}
    )
    entries = _bounded_entries(
        descriptor,
        maximum=(
            policy.max_files
            + policy.max_directories
            - inventory.files
            - inventory.directories
            + 1
        ),
        field="capture_adoption_directory_inventory",
    )
    for name in entries:
        relative = f"{prefix}/{name}" if prefix else name
        try:
            named = os.stat(
                name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise _error("capture_adoption_entry_unreadable") from exc
        if stat.S_ISDIR(named.st_mode):
            child, opened = _open_bound_directory(
                descriptor,
                name,
                field="capture_adoption_directory",
            )
            try:
                if _stable_object_tuple(named) != _stable_object_tuple(
                    opened
                ):
                    raise _error(
                        "capture_adoption_directory_inode_mismatch"
                    )
                _inventory_tree(
                    child,
                    prefix=relative,
                    owner_uid=owner_uid,
                    group_gid=group_gid,
                    directory_mode=directory_mode,
                    file_mode=file_mode,
                    root_device=root_device,
                    policy=policy,
                    inventory=inventory,
                    depth=depth + 1,
                )
            finally:
                os.close(child)
        elif stat.S_ISREG(named.st_mode):
            child, opened = _open_bound_file(
                descriptor,
                name,
                field="capture_adoption_file",
            )
            try:
                _validate_file_info(
                    opened,
                    owner_uid=owner_uid,
                    group_gid=group_gid,
                    mode=file_mode,
                    root_device=root_device,
                    maximum_bytes=policy.max_file_bytes,
                    field="capture_adoption_file",
                )
                file_before = _full_stat_tuple(opened)
                size, digest = _read_digest(
                    child,
                    maximum_bytes=policy.max_file_bytes,
                    field="capture_adoption_file",
                )
                after = os.fstat(child)
                rebound = os.stat(
                    name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if (
                    size != opened.st_size
                    or file_before != _full_stat_tuple(after)
                    or _stable_object_tuple(after)
                    != _stable_object_tuple(rebound)
                ):
                    raise _error("capture_adoption_file_changed")
                inventory.files += 1
                inventory.total_bytes += size
                if inventory.files > policy.max_files:
                    raise _error(
                        "capture_adoption_file_count_exceeded"
                    )
                if inventory.total_bytes > policy.max_bytes:
                    raise _error("capture_adoption_size_exceeded")
                inventory.records.append(
                    {
                        "path": relative,
                        "type": "file",
                        "size": size,
                        "sha256": digest,
                    }
                )
            finally:
                os.close(child)
        else:
            raise _error("capture_adoption_entry_type_unsafe")
    after = os.fstat(descriptor)
    if _full_stat_tuple(before) != _full_stat_tuple(after):
        raise _error("capture_adoption_directory_changed")


def _inventory(
    descriptor: int,
    *,
    owner_uid: int,
    group_gid: int,
    directory_mode: int,
    file_mode: int,
    policy: CaptureAdoptionPolicy,
) -> _Inventory:
    root = os.fstat(descriptor)
    inventory = _Inventory(records=[])
    _inventory_tree(
        descriptor,
        prefix="",
        owner_uid=owner_uid,
        group_gid=group_gid,
        directory_mode=directory_mode,
        file_mode=file_mode,
        root_device=root.st_dev,
        policy=policy,
        inventory=inventory,
        depth=0,
    )
    return inventory


def _adopt_tree(
    descriptor: int,
    *,
    prefix: str,
    identities: _FilesystemIdentities,
    root_device: int,
    policy: CaptureAdoptionPolicy,
    fault_hook: Callable[[str], None] | None,
    depth: int,
) -> None:
    if depth > policy.max_depth:
        raise _error("capture_adoption_tree_too_deep")
    info = os.fstat(descriptor)
    _validate_directory_info(
        info,
        owner_uid=identities.capture_uid,
        group_gid=identities.capture_gid,
        mode=PROVISIONAL_DIRECTORY_MODE,
        root_device=root_device,
        field="capture_adoption_provisional_directory",
    )
    entries = _bounded_entries(
        descriptor,
        maximum=policy.max_files + policy.max_directories,
        field="capture_adoption_transform_inventory",
    )
    for name in entries:
        relative = f"{prefix}/{name}" if prefix else name
        named = os.stat(
            name,
            dir_fd=descriptor,
            follow_symlinks=False,
        )
        if stat.S_ISDIR(named.st_mode):
            child, opened = _open_bound_directory(
                descriptor,
                name,
                field="capture_adoption_transform_directory",
            )
            try:
                _validate_directory_info(
                    opened,
                    owner_uid=identities.capture_uid,
                    group_gid=identities.capture_gid,
                    mode=PROVISIONAL_DIRECTORY_MODE,
                    root_device=root_device,
                    field="capture_adoption_provisional_directory",
                )
                _adopt_tree(
                    child,
                    prefix=relative,
                    identities=identities,
                    root_device=root_device,
                    policy=policy,
                    fault_hook=fault_hook,
                    depth=depth + 1,
                )
            finally:
                os.close(child)
        elif stat.S_ISREG(named.st_mode):
            child, opened = _open_bound_file(
                descriptor,
                name,
                field="capture_adoption_transform_file",
            )
            try:
                _validate_file_info(
                    opened,
                    owner_uid=identities.capture_uid,
                    group_gid=identities.capture_gid,
                    mode=PROVISIONAL_FILE_MODE,
                    root_device=root_device,
                    maximum_bytes=policy.max_file_bytes,
                    field="capture_adoption_provisional_file",
                )
                os.fchmod(child, 0)
                os.fchown(
                    child,
                    identities.root_uid,
                    identities.verifier_gid,
                )
                os.fchmod(child, ADOPTED_FILE_MODE)
                os.fsync(child)
                adopted = os.fstat(child)
                _validate_file_info(
                    adopted,
                    owner_uid=identities.root_uid,
                    group_gid=identities.verifier_gid,
                    mode=ADOPTED_FILE_MODE,
                    root_device=root_device,
                    maximum_bytes=policy.max_file_bytes,
                    field="capture_adoption_adopted_file",
                )
                _reject_fd_metadata(
                    child,
                    field="capture_adoption_adopted_file",
                )
                if fault_hook is not None:
                    fault_hook(f"after_entry_adopted:{relative}")
            finally:
                os.close(child)
        else:
            raise _error("capture_adoption_entry_type_unsafe")
    os.fchmod(descriptor, 0)
    os.fchown(
        descriptor,
        identities.root_uid,
        identities.verifier_gid,
    )
    os.fchmod(descriptor, ADOPTED_DIRECTORY_MODE)
    os.fsync(descriptor)
    adopted_root = os.fstat(descriptor)
    _validate_directory_info(
        adopted_root,
        owner_uid=identities.root_uid,
        group_gid=identities.verifier_gid,
        mode=ADOPTED_DIRECTORY_MODE,
        root_device=root_device,
        field="capture_adoption_adopted_directory",
    )
    _reject_fd_metadata(
        descriptor,
        field="capture_adoption_adopted_directory",
    )
    if fault_hook is not None:
        fault_hook(f"after_directory_adopted:{prefix}")


def _exclusive_rename(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
) -> str:
    """Rename a directory without replacement; there is no copy fallback."""

    source = source_name.encode("utf-8")
    destination = destination_name.encode("utf-8")
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
        raise _error("capture_adoption_exclusive_rename_unsupported")
    if result != 0:
        observed = ctypes.get_errno()
        if observed in {errno.EEXIST, errno.ENOTEMPTY}:
            raise _error("capture_adoption_destination_exists")
        if observed == errno.EXDEV:
            raise _error("capture_adoption_cross_device_forbidden")
        raise _error("capture_adoption_rename_failed")
    return primitive


def _allowed_recovery_identity(
    info: os.stat_result,
    *,
    identities: _FilesystemIdentities,
    directory: bool,
) -> bool:
    pair = (info.st_uid, info.st_gid)
    allowed_pairs = {
        (identities.capture_uid, identities.capture_gid),
        (identities.root_uid, identities.verifier_gid),
    }
    modes = (
        {
            0,
            PROVISIONAL_DIRECTORY_MODE,
            BUILDING_DIRECTORY_MODE,
            ADOPTED_DIRECTORY_MODE,
        }
        if directory
        else {
            0,
            PROVISIONAL_FILE_MODE,
            BUILDING_FILE_MODE,
            ADOPTED_FILE_MODE,
        }
    )
    return pair in allowed_pairs and stat.S_IMODE(info.st_mode) in modes


def _cleanup_tree_mixed(
    descriptor: int,
    *,
    identities: _FilesystemIdentities,
    root_device: int,
    policy: CaptureAdoptionPolicy,
    counters: dict[str, int],
    depth: int,
) -> None:
    if depth > policy.max_depth:
        raise _error("capture_adoption_cleanup_depth_exceeded")
    root = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(root.st_mode)
        or root.st_dev != root_device
        or not _allowed_recovery_identity(
            root,
            identities=identities,
            directory=True,
        )
    ):
        raise _error("capture_adoption_cleanup_directory_unsafe")
    _reject_fd_metadata(
        descriptor,
        field="capture_adoption_cleanup_directory",
    )
    os.fchmod(descriptor, 0o700)
    entries = _bounded_entries(
        descriptor,
        maximum=policy.max_files + policy.max_directories + 1,
        field="capture_adoption_cleanup_inventory",
    )
    for name in entries:
        named = os.stat(
            name,
            dir_fd=descriptor,
            follow_symlinks=False,
        )
        counters["entries"] += 1
        if counters["entries"] > (
            policy.max_files + policy.max_directories
        ):
            raise _error("capture_adoption_cleanup_count_exceeded")
        if stat.S_ISDIR(named.st_mode):
            if not _allowed_recovery_identity(
                named,
                identities=identities,
                directory=True,
            ):
                raise _error(
                    "capture_adoption_cleanup_directory_unsafe"
                )
            child, opened = _open_bound_directory(
                descriptor,
                name,
                field="capture_adoption_cleanup_directory",
            )
            try:
                if opened.st_dev != root_device:
                    raise _error(
                        "capture_adoption_cleanup_mount_unsafe"
                    )
                _cleanup_tree_mixed(
                    child,
                    identities=identities,
                    root_device=root_device,
                    policy=policy,
                    counters=counters,
                    depth=depth + 1,
                )
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=descriptor)
        elif stat.S_ISREG(named.st_mode):
            if (
                named.st_dev != root_device
                or named.st_nlink != 1
                or not _allowed_recovery_identity(
                    named,
                    identities=identities,
                    directory=False,
                )
            ):
                raise _error("capture_adoption_cleanup_file_unsafe")
            child, _opened = _open_bound_file(
                descriptor,
                name,
                field="capture_adoption_cleanup_file",
            )
            try:
                _reject_fd_metadata(
                    child,
                    field="capture_adoption_cleanup_file",
                )
            finally:
                os.close(child)
            os.unlink(name, dir_fd=descriptor)
        else:
            raise _error("capture_adoption_cleanup_entry_type_unsafe")
    os.fsync(descriptor)


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
        and _stable_object_tuple(named) == _stable_object_tuple(opened)
    )


def _unlink_bound_tree(
    parent_fd: int,
    name: str,
    descriptor: int,
    *,
    identities: _FilesystemIdentities,
    policy: CaptureAdoptionPolicy,
) -> None:
    if not _bound_name_matches(parent_fd, name, descriptor):
        raise _error("capture_adoption_cleanup_inode_mismatch")
    root_device = os.fstat(descriptor).st_dev
    _cleanup_tree_mixed(
        descriptor,
        identities=identities,
        root_device=root_device,
        policy=policy,
        counters={"entries": 0},
        depth=0,
    )
    try:
        os.rmdir(name, dir_fd=parent_fd)
    except OSError as exc:
        raise _error("capture_adoption_cleanup_remove_failed") from exc


def _fsync_cleanup_parent(parent_fd: int) -> None:
    try:
        os.fsync(parent_fd)
    except OSError as exc:
        raise _error(
            "capture_adoption_cleanup_parent_fsync_failed"
        ) from exc


def _remove_bound_tree(
    parent_fd: int,
    name: str,
    descriptor: int,
    *,
    identities: _FilesystemIdentities,
    policy: CaptureAdoptionPolicy,
) -> None:
    _unlink_bound_tree(
        parent_fd,
        name,
        descriptor,
        identities=identities,
        policy=policy,
    )
    _fsync_cleanup_parent(parent_fd)


_ADOPTED_LEASE_TOKEN = object()
_LEASE_CLEANUP_BOUND = "bound"
_LEASE_CLEANUP_BOUND_RETRY = "bound_retry"
_LEASE_CLEANUP_PARENT_FSYNC_RETRY = "parent_fsync_retry"
_LEASE_CLEANUP_DETACHED = "recovery_detached"
_LEASE_CLEANUP_CLOSED = "closed"


class AdoptedCaptureLease:
    """Exclusive lifetime handle for one root-owned adopted capture."""

    __slots__ = (
        "_root_fd",
        "_parent_fd",
        "_capture_root",
        "_final_name",
        "_identities",
        "_policy",
        "_receipt",
        "_recovery_handoff_receipt",
        "_cleanup_state",
    )

    def __init__(
        self,
        *,
        _token: object,
        root_fd: int,
        parent_fd: int,
        capture_root: Path,
        final_name: str,
        identities: _FilesystemIdentities,
        policy: CaptureAdoptionPolicy,
        receipt: Mapping[str, Any],
    ) -> None:
        if _token is not _ADOPTED_LEASE_TOKEN:
            raise TypeError(
                "AdoptedCaptureLease cannot be constructed directly"
            )
        os.set_inheritable(root_fd, False)
        os.set_inheritable(parent_fd, False)
        self._root_fd = root_fd
        self._parent_fd = parent_fd
        self._capture_root = capture_root
        self._final_name = final_name
        self._identities = identities
        self._policy = policy
        self._receipt = dict(receipt)
        self._recovery_handoff_receipt: dict[str, Any] | None = None
        self._cleanup_state = _LEASE_CLEANUP_BOUND

    @property
    def active(self) -> bool:
        return (
            self._cleanup_state
            in {
                _LEASE_CLEANUP_BOUND,
                _LEASE_CLEANUP_BOUND_RETRY,
                _LEASE_CLEANUP_PARENT_FSYNC_RETRY,
            }
            and self._root_fd >= 0
            and self._parent_fd >= 0
        )

    @property
    def detached(self) -> bool:
        """Whether recovery now owns the durable namespace object."""

        return self._cleanup_state == _LEASE_CLEANUP_DETACHED

    @property
    def cleanup_pending(self) -> bool:
        """Whether a failed cleanup still retains retry authority."""

        return self.active and self._cleanup_state in {
            _LEASE_CLEANUP_BOUND_RETRY,
            _LEASE_CLEANUP_PARENT_FSYNC_RETRY,
        }

    @property
    def capture_root(self) -> Path:
        if not self.active:
            raise _error("capture_adoption_lease_closed")
        return self._capture_root

    @property
    def receipt(self) -> dict[str, Any]:
        if not self.active and not self.detached:
            raise _error("capture_adoption_lease_closed")
        return json.loads(_canonical_json(self._receipt).decode("ascii"))

    @property
    def receipt_sha256(self) -> str:
        return _sha256(_canonical_json(self.receipt))

    @property
    def recovery_handoff_receipt(self) -> dict[str, Any]:
        if (
            not self.detached
            or self._recovery_handoff_receipt is None
        ):
            raise _error(
                "capture_adoption_recovery_handoff_not_deferred"
            )
        return normalize_recovery_handoff_receipt(
            self._recovery_handoff_receipt
        )

    @property
    def recovery_handoff_receipt_sha256(self) -> str:
        return recovery_handoff_receipt_sha256(
            self.recovery_handoff_receipt
        )

    def _assert_post_verifier_revalidation_binding(
        self,
    ) -> dict[str, Any]:
        """Prove the retained lease still names the adopted receipt object."""

        if not self.active:
            raise _error("capture_adoption_lease_closed")
        if (
            os.get_inheritable(self._root_fd)
            or os.get_inheritable(self._parent_fd)
        ):
            raise _error(
                "capture_adoption_revalidation_descriptor_inheritable"
            )
        if not _bound_name_matches(
            self._parent_fd,
            self._final_name,
            self._root_fd,
        ):
            raise _error(
                "capture_adoption_revalidation_name_rebound"
            )
        try:
            info = os.fstat(self._root_fd)
        except OSError as exc:
            raise _error(
                "capture_adoption_revalidation_object_unreadable"
            ) from exc
        object_identity = _object_sha256(info)
        receipt = self._receipt
        if (
            object_identity != self._policy.expected_object_sha256
            or receipt.get("schema_version")
            != ADOPTION_RECEIPT_SCHEMA
            or receipt.get("status") != ADOPTION_STATUS
            or receipt.get("session_id") != self._policy.session_id
            or receipt.get("object_identity_sha256")
            != object_identity
            or receipt.get("adopted_stat_sha256")
            != _stat_sha256(info)
            or receipt.get("capture_plan_sha256")
            != self._policy.capture_plan_sha256
            or receipt.get("capture_manifest_sha256")
            != self._policy.capture_manifest_sha256
            or receipt.get("request_sha256")
            != self._policy.request_sha256
            or receipt.get("capture_uid")
            != self._policy.capture_uid
            or receipt.get("capture_gid")
            != self._policy.capture_gid
            or receipt.get("adopted_uid")
            != self._identities.root_uid
            or receipt.get("verifier_gid")
            != self._policy.verifier_gid
            or receipt.get("final_name") != self._final_name
        ):
            raise _error(
                "capture_adoption_revalidation_receipt_mismatch"
            )
        return {
            "snapshot_root": self._capture_root,
            "capture_adoption_receipt_sha256": (
                self.receipt_sha256
            ),
            "capture_object_identity_sha256": object_identity,
            "capture_plan_sha256": (
                self._policy.capture_plan_sha256
            ),
            "capture_manifest_sha256": (
                self._policy.capture_manifest_sha256
            ),
        }

    def defer_to_recovery(
        self,
        *,
        expected_object_sha256: str,
        expected_adoption_receipt_sha256: str,
        requested_evidence_sha256: str,
    ) -> dict[str, Any]:
        """Transfer cleanup authority without unlinking the capture.

        The returned receipt deliberately contains no path.  The final
        component and stable parent identity are sufficient for the durable
        recovery journal to bind the exact object without turning this method
        into a general pathname authority.
        """

        expected_object = _digest(
            expected_object_sha256,
            field=(
                "capture_adoption_recovery_handoff_expected_object_sha256"
            ),
        )
        expected_adoption = _digest(
            expected_adoption_receipt_sha256,
            field=(
                "capture_adoption_recovery_handoff_expected_adoption_sha256"
            ),
        )
        requested_evidence = _digest(
            requested_evidence_sha256,
            field=(
                "capture_adoption_recovery_handoff_requested_evidence_sha256"
            ),
        )
        if self._recovery_handoff_receipt is not None:
            cached = normalize_recovery_handoff_receipt(
                self._recovery_handoff_receipt
            )
            if requested_evidence != cached["requested_evidence_sha256"]:
                raise _error(
                    "capture_adoption_recovery_handoff_evidence_mismatch"
                )
            if (
                expected_object
                != cached["capture_object_identity_sha256"]
                or expected_adoption
                != cached["capture_adoption_receipt_sha256"]
            ):
                raise _error(
                    "capture_adoption_recovery_handoff_binding_mismatch"
                )
            if not self.detached:
                raise _error(
                    "capture_adoption_recovery_handoff_state_invalid"
                )
            return cached

        if not self.active:
            raise _error("capture_adoption_lease_closed")
        if os.getuid() != 0 or os.geteuid() != 0:
            raise _error(
                "capture_adoption_recovery_handoff_requires_root"
            )
        pre_binding = self._assert_post_verifier_revalidation_binding()
        if (
            pre_binding["capture_object_identity_sha256"]
            != expected_object
            or pre_binding["capture_adoption_receipt_sha256"]
            != expected_adoption
        ):
            raise _error(
                "capture_adoption_recovery_handoff_binding_mismatch"
            )
        try:
            object_info = os.fstat(self._root_fd)
            parent_info = os.fstat(self._parent_fd)
        except OSError as exc:
            raise _error(
                "capture_adoption_recovery_handoff_object_unreadable"
            ) from exc
        if (
            not stat.S_ISDIR(object_info.st_mode)
            or not stat.S_ISDIR(parent_info.st_mode)
        ):
            raise _error(
                "capture_adoption_recovery_handoff_object_invalid"
            )
        try:
            os.fsync(self._root_fd)
            os.fsync(self._parent_fd)
        except OSError as exc:
            raise _error(
                "capture_adoption_recovery_handoff_fsync_failed"
            ) from exc
        post_binding = self._assert_post_verifier_revalidation_binding()
        try:
            deferred_info = os.fstat(self._root_fd)
            deferred_parent_info = os.fstat(self._parent_fd)
        except OSError as exc:
            raise _error(
                "capture_adoption_recovery_handoff_object_unreadable"
            ) from exc
        if (
            post_binding != pre_binding
            or _full_stat_tuple(deferred_info)
            != _full_stat_tuple(object_info)
            or _stable_object_tuple(deferred_parent_info)
            != _stable_object_tuple(parent_info)
            or int(deferred_parent_info.st_uid)
            != int(parent_info.st_uid)
            or int(deferred_parent_info.st_gid)
            != int(parent_info.st_gid)
            or stat.S_IMODE(deferred_parent_info.st_mode)
            != stat.S_IMODE(parent_info.st_mode)
        ):
            raise _error(
                "capture_adoption_recovery_handoff_binding_changed"
            )
        deferred_at = _integer(
            int(time.time()),
            field="capture_adoption_recovery_handoff_deferred_at_unix",
            minimum=1,
            maximum=(1 << 53) - 1,
        )
        handoff = normalize_recovery_handoff_receipt(
            {
                "schema_version": RECOVERY_HANDOFF_RECEIPT_SCHEMA,
                "status": RECOVERY_HANDOFF_STATUS,
                "capture_session_id": self._policy.session_id,
                "capture_adoption_receipt_sha256": expected_adoption,
                "capture_object_identity_sha256": expected_object,
                "capture_plan_sha256": (
                    self._policy.capture_plan_sha256
                ),
                "capture_manifest_sha256": (
                    self._policy.capture_manifest_sha256
                ),
                "capture_request_sha256": (
                    self._policy.request_sha256
                ),
                "requested_evidence_sha256": requested_evidence,
                "final_name": self._final_name,
                "deferred_object_stat_sha256": (
                    _stat_sha256(deferred_info)
                ),
                "recovery_parent_identity_sha256": (
                    _recovery_parent_identity_sha256(
                        deferred_parent_info
                    )
                ),
                "deferred_by_uid": 0,
                "deferred_at_unix": deferred_at,
            }
        )
        # Cache the complete path-free authority record before descriptor
        # closure.  Once detached, cleanup and finalizers must never unlink.
        self._recovery_handoff_receipt = handoff
        self._cleanup_state = _LEASE_CLEANUP_DETACHED
        close_failure: OSError | None = None
        try:
            os.close(self._root_fd)
        except OSError as exc:
            close_failure = exc
        finally:
            self._root_fd = -1
        try:
            os.close(self._parent_fd)
        except OSError as exc:
            if close_failure is None:
                close_failure = exc
        finally:
            self._parent_fd = -1
        if close_failure is not None:
            raise _error(
                "capture_adoption_recovery_handoff_descriptor_close_failed"
            ) from close_failure
        return normalize_recovery_handoff_receipt(handoff)

    def cleanup(self) -> None:
        if not self.active:
            return
        root_fd = self._root_fd
        parent_fd = self._parent_fd
        if self._cleanup_state in {
            _LEASE_CLEANUP_BOUND,
            _LEASE_CLEANUP_BOUND_RETRY,
        }:
            try:
                _unlink_bound_tree(
                    parent_fd,
                    self._final_name,
                    root_fd,
                    identities=self._identities,
                    policy=self._policy,
                )
            except BaseException:
                self._cleanup_state = _LEASE_CLEANUP_BOUND_RETRY
                raise
            self._cleanup_state = (
                _LEASE_CLEANUP_PARENT_FSYNC_RETRY
            )
        try:
            _fsync_cleanup_parent(parent_fd)
        except BaseException:
            self._cleanup_state = _LEASE_CLEANUP_PARENT_FSYNC_RETRY
            raise
        close_failure: OSError | None = None
        try:
            os.close(root_fd)
        except OSError as exc:
            close_failure = exc
        finally:
            self._root_fd = -1
        try:
            os.close(parent_fd)
        except OSError as exc:
            if close_failure is None:
                close_failure = exc
        finally:
            self._parent_fd = -1
        self._cleanup_state = _LEASE_CLEANUP_CLOSED
        if close_failure is not None:
            raise _error(
                "capture_adoption_cleanup_descriptor_close_failed"
            ) from close_failure

    def close(self) -> None:
        self.cleanup()

    def __enter__(self) -> "AdoptedCaptureLease":
        if not self.active:
            raise _error("capture_adoption_lease_closed")
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        del exc_type, exc, traceback
        self.cleanup()
        return False

    def __reduce__(self) -> Any:
        raise TypeError("AdoptedCaptureLease is not serializable")

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError("AdoptedCaptureLease is not serializable")

    def __del__(self) -> None:
        if (
            getattr(self, "_cleanup_state", _LEASE_CLEANUP_CLOSED)
            == _LEASE_CLEANUP_DETACHED
        ):
            return
        if getattr(self, "_root_fd", -1) >= 0:
            try:
                self.cleanup()
            except BaseException:
                pass


def _validate_parent_descriptors(
    policy: CaptureAdoptionPolicy,
    *,
    staging_fd: int,
    final_fd: int,
    identities: _FilesystemIdentities,
    strict_parent_chain: bool,
) -> None:
    if strict_parent_chain:
        _validate_trusted_parent_chain(
            policy.staging_parent.parent,
            root_uid=identities.root_uid,
        )
        _validate_trusted_parent_chain(
            policy.final_parent.parent,
            root_uid=identities.root_uid,
        )
        if (
            not capture_staging.SESSION_NAME_RE.fullmatch(
                policy.staging_parent.name
            )
            or policy.staging_parent.parent.name
            != capture_staging.RECOVERY_NAMESPACE
        ):
            raise _error(
                "capture_adoption_session_staging_leaf_invalid"
            )
        shared_root = policy.staging_parent.parent.parent
        try:
            recovery = policy.staging_parent.parent.lstat()
            shared = shared_root.lstat()
        except OSError as exc:
            raise _error(
                "capture_adoption_staging_namespace_unreadable"
            ) from exc
        if (
            not stat.S_ISDIR(recovery.st_mode)
            or recovery.st_uid != identities.root_uid
            or recovery.st_gid != identities.root_gid
            or stat.S_IMODE(recovery.st_mode)
            != capture_staging.RECOVERY_NAMESPACE_MODE
            or not stat.S_ISDIR(shared.st_mode)
            or shared.st_uid != identities.root_uid
            or shared.st_gid != identities.root_gid
            or stat.S_IMODE(shared.st_mode)
            != capture_staging.SHARED_ROOT_MODE
        ):
            raise _error(
                "capture_adoption_staging_namespace_unsafe"
            )
    staging = _validate_path_fd_binding(
        policy.staging_parent,
        staging_fd,
        field="capture_adoption_staging_parent",
    )
    final = _validate_path_fd_binding(
        policy.final_parent,
        final_fd,
        field="capture_adoption_final_parent",
    )
    if (
        staging.st_uid != identities.capture_uid
        or staging.st_gid != identities.capture_gid
        or stat.S_IMODE(staging.st_mode) != STAGING_PARENT_MODE
    ):
        raise _error("capture_adoption_staging_parent_unsafe")
    if (
        final.st_uid != identities.root_uid
        or final.st_gid != identities.verifier_gid
        or stat.S_IMODE(final.st_mode) != FINAL_PARENT_MODE
    ):
        raise _error("capture_adoption_final_parent_unsafe")
    if staging.st_dev != final.st_dev:
        raise _error("capture_adoption_cross_device_forbidden")


def _revoke_staging_parent(
    descriptor: int,
    *,
    identities: _FilesystemIdentities,
) -> None:
    try:
        os.fchmod(descriptor, 0)
        os.fchown(
            descriptor,
            identities.root_uid,
            identities.root_gid,
        )
        os.fchmod(descriptor, identities.revoked_parent_mode)
        os.fsync(descriptor)
    except OSError as exc:
        raise _error("capture_adoption_staging_revoke_failed") from exc
    info = os.fstat(descriptor)
    if (
        info.st_uid != identities.root_uid
        or info.st_gid != identities.root_gid
        or stat.S_IMODE(info.st_mode)
        != identities.revoked_parent_mode
    ):
        raise _error("capture_adoption_staging_revoke_incomplete")


def _build_receipt(
    *,
    policy: CaptureAdoptionPolicy,
    child_pid: int,
    child_status: int,
    primitive: str,
    provisional_stat: os.stat_result,
    adopted_stat: os.stat_result,
    inventory: _Inventory,
    adopted_at_unix: int,
    adopted_uid: int,
) -> dict[str, Any]:
    return {
        "schema_version": ADOPTION_RECEIPT_SCHEMA,
        "status": ADOPTION_STATUS,
        "session_id": policy.session_id,
        "capture_adoption_policy_sha256": policy.policy_sha256(),
        "capture_selection_sha256": policy.capture_selection_sha256,
        "capture_plan_sha256": policy.capture_plan_sha256,
        "capture_manifest_sha256": policy.capture_manifest_sha256,
        "capture_boundary_policy_sha256": (
            policy.capture_boundary_policy_sha256
        ),
        "helper_activation_policy_sha256": (
            policy.helper_activation_policy_sha256
        ),
        "request_sha256": policy.request_sha256,
        "capture_uid": policy.capture_uid,
        "capture_gid": policy.capture_gid,
        "adopted_uid": adopted_uid,
        "verifier_uid": policy.verifier_uid,
        "verifier_gid": policy.verifier_gid,
        "final_name": policy.final_name,
        "object_identity_sha256": policy.expected_object_sha256,
        "provisional_stat_sha256": _stat_sha256(provisional_stat),
        "adopted_stat_sha256": _stat_sha256(adopted_stat),
        "content_inventory_sha256": inventory.content_sha256(),
        "file_count": inventory.files,
        "directory_count": inventory.directories,
        "total_bytes": inventory.total_bytes,
        "child_pid": child_pid,
        "child_exit_status": child_status,
        "child_stderr_sha256": _sha256(b""),
        "process_group_reaped": True,
        "staging_namespace_revoked": True,
        "same_filesystem": True,
        "rename_noreplace": True,
        "rename_primitive": primitive,
        "adopted_at_unix": adopted_at_unix,
    }


def _adopt_impl(
    policy: CaptureAdoptionPolicy,
    proof: ChildDeathProof,
    *,
    provisional_authority: RetainedProvisionalCapture,
    staging_parent_fd: int,
    final_parent_fd: int,
    identities: _FilesystemIdentities,
    strict_parent_chain: bool,
    fault_hook: Callable[[str], None] | None = None,
    clock: Callable[[], int] = lambda: int(time.time()),
) -> AdoptedCaptureLease:
    normalized = normalize_adoption_policy(policy)
    if type(proof) is not ChildDeathProof:
        raise _error("capture_adoption_child_proof_required")
    if type(provisional_authority) is not RetainedProvisionalCapture:
        raise _error(
            "capture_adoption_provisional_authority_required"
        )
    if os.geteuid() != identities.root_uid:
        raise _error("capture_adoption_requires_root")
    if fault_hook is not None and not callable(fault_hook):
        raise _error("capture_adoption_fault_hook_invalid")
    if not callable(clock):
        raise _error("capture_adoption_clock_invalid")
    staging_fd = -1
    final_fd = -1
    root_fd: int | None = None
    namespace_bound = False
    renamed = False
    lease_created = False
    try:
        staging_fd = _dup_cloexec(staging_parent_fd)
        final_fd = _dup_cloexec(final_parent_fd)
        _validate_parent_descriptors(
            normalized,
            staging_fd=staging_fd,
            final_fd=final_fd,
            identities=identities,
            strict_parent_chain=strict_parent_chain,
        )
        _lock_exclusive(
            staging_fd,
            field="capture_adoption_staging_parent",
        )
        _lock_exclusive(
            final_fd,
            field="capture_adoption_final_parent",
        )
        root_fd = provisional_authority._consume(normalized)
        child_pid, child_status = proof._consume(
            session_id=normalized.session_id,
            capture_uid=normalized.capture_uid,
        )
        _revoke_staging_parent(
            staging_fd,
            identities=identities,
        )
        _validate_path_fd_binding(
            normalized.staging_parent,
            staging_fd,
            field="capture_adoption_revoked_staging_parent",
        )
        if fault_hook is not None:
            fault_hook("after_staging_revoked")

        if not _bound_name_matches(
            staging_fd,
            normalized.provisional_name,
            root_fd,
        ):
            raise _error(
                "capture_adoption_provisional_name_rebound"
            )
        namespace_bound = True
        entries = _bounded_entries(
            staging_fd,
            maximum=2,
            field="capture_adoption_staging_inventory",
        )
        if entries != [normalized.provisional_name]:
            raise _error("capture_adoption_staging_inventory_invalid")
        provisional_stat = os.fstat(root_fd)
        if (
            _object_sha256(provisional_stat)
            != normalized.expected_object_sha256
        ):
            raise _error("capture_adoption_object_identity_mismatch")
        _reject_fd_metadata(
            root_fd,
            field="capture_adoption_provisional_root",
        )
        provisional_inventory = _inventory(
            root_fd,
            owner_uid=identities.capture_uid,
            group_gid=identities.capture_gid,
            directory_mode=PROVISIONAL_DIRECTORY_MODE,
            file_mode=PROVISIONAL_FILE_MODE,
            policy=normalized,
        )
        if fault_hook is not None:
            fault_hook("after_provisional_validated")

        _adopt_tree(
            root_fd,
            prefix="",
            identities=identities,
            root_device=provisional_stat.st_dev,
            policy=normalized,
            fault_hook=fault_hook,
            depth=0,
        )
        adopted_before_rename = os.fstat(root_fd)
        adopted_inventory = _inventory(
            root_fd,
            owner_uid=identities.root_uid,
            group_gid=identities.verifier_gid,
            directory_mode=ADOPTED_DIRECTORY_MODE,
            file_mode=ADOPTED_FILE_MODE,
            policy=normalized,
        )
        if (
            provisional_inventory.content_sha256()
            != adopted_inventory.content_sha256()
            or provisional_inventory.files != adopted_inventory.files
            or provisional_inventory.directories
            != adopted_inventory.directories
            or provisional_inventory.total_bytes
            != adopted_inventory.total_bytes
        ):
            raise _error("capture_adoption_content_changed")
        if _object_sha256(adopted_before_rename) != (
            normalized.expected_object_sha256
        ):
            raise _error("capture_adoption_object_changed")
        if fault_hook is not None:
            fault_hook("after_tree_adopted")

        # Darwin requires owner-write permission on a directory being renamed.
        # The capture child is already dead and the staging namespace is
        # revoked, so make only the root-owned capture root writable for the
        # syscall.  BUILDING_DIRECTORY_MODE is also an accepted crash-recovery
        # state.  Verifier traversal is restored immediately after rename.
        os.fchmod(root_fd, BUILDING_DIRECTORY_MODE)
        os.fsync(root_fd)
        primitive = _exclusive_rename(
            staging_fd,
            normalized.provisional_name,
            final_fd,
            normalized.final_name,
        )
        renamed = True
        os.fchmod(root_fd, ADOPTED_DIRECTORY_MODE)
        os.fsync(root_fd)
        if fault_hook is not None:
            fault_hook("after_rename")
        os.fsync(staging_fd)
        os.fsync(final_fd)
        if fault_hook is not None:
            fault_hook("after_parent_fsync")
        if not _bound_name_matches(
            final_fd,
            normalized.final_name,
            root_fd,
        ):
            raise _error("capture_adoption_final_inode_mismatch")
        final_stat = os.fstat(root_fd)
        if (
            _object_sha256(final_stat)
            != normalized.expected_object_sha256
        ):
            raise _error("capture_adoption_final_object_changed")
        final_inventory = _inventory(
            root_fd,
            owner_uid=identities.root_uid,
            group_gid=identities.verifier_gid,
            directory_mode=ADOPTED_DIRECTORY_MODE,
            file_mode=ADOPTED_FILE_MODE,
            policy=normalized,
        )
        if (
            final_inventory.content_sha256()
            != provisional_inventory.content_sha256()
        ):
            raise _error("capture_adoption_final_content_changed")
        adopted_at = _integer(
            clock(),
            field="capture_adoption_clock",
            minimum=1,
            maximum=(1 << 53) - 1,
        )
        receipt = _build_receipt(
            policy=normalized,
            child_pid=child_pid,
            child_status=child_status,
            primitive=primitive,
            provisional_stat=provisional_stat,
            adopted_stat=final_stat,
            inventory=final_inventory,
            adopted_at_unix=adopted_at,
            adopted_uid=identities.root_uid,
        )
        lease = AdoptedCaptureLease(
            _token=_ADOPTED_LEASE_TOKEN,
            root_fd=root_fd,
            parent_fd=final_fd,
            capture_root=normalized.final_parent / normalized.final_name,
            final_name=normalized.final_name,
            identities=identities,
            policy=normalized,
            receipt=receipt,
        )
        root_fd = None
        final_fd = -1
        lease_created = True
        return lease
    except BaseException as original:
        cleanup_failure: BaseException | None = None
        try:
            if root_fd is not None and namespace_bound:
                parent = final_fd if renamed else staging_fd
                name = (
                    normalized.final_name
                    if renamed
                    else normalized.provisional_name
                )
                _remove_bound_tree(
                    parent,
                    name,
                    root_fd,
                    identities=identities,
                    policy=normalized,
                )
        except BaseException as exc:
            cleanup_failure = exc
        if cleanup_failure is not None:
            raise _error("capture_adoption_failure_cleanup_failed") from (
                cleanup_failure
            )
        raise original
    finally:
        if root_fd is not None:
            os.close(root_fd)
        if staging_fd >= 0:
            os.close(staging_fd)
        if final_fd >= 0:
            os.close(final_fd)
        if lease_created:
            # Ownership of root/final fds transferred into the lease.
            pass


def adopt_staged_capture(
    policy: CaptureAdoptionPolicy,
    proof: ChildDeathProof,
    *,
    provisional_authority: RetainedProvisionalCapture | None = None,
    staging_parent_fd: int,
    final_parent_fd: int,
) -> AdoptedCaptureLease:
    """Production adoption entry point; intentionally disabled."""

    if not PRODUCTION_ACTIVATION:
        raise _error("capture_adoption_production_disabled")
    identities = _FilesystemIdentities(
        capture_uid=policy.capture_uid,
        capture_gid=policy.capture_gid,
        root_uid=0,
        root_gid=0,
        verifier_gid=policy.verifier_gid,
    )
    try:
        return _adopt_impl(
            policy,
            proof,
            provisional_authority=provisional_authority,
            staging_parent_fd=staging_parent_fd,
            final_parent_fd=final_parent_fd,
            identities=identities,
            strict_parent_chain=True,
        )
    finally:
        if type(provisional_authority) is RetainedProvisionalCapture:
            provisional_authority.close()


def adopt_staged_capture_canary(
    policy: CaptureAdoptionPolicy,
    proof: ChildDeathProof,
    *,
    provisional_authority: RetainedProvisionalCapture | None = None,
    staging_parent_fd: int,
    final_parent_fd: int,
) -> AdoptedCaptureLease:
    """Exercise the real root boundary without enabling production."""

    identities = _FilesystemIdentities(
        capture_uid=policy.capture_uid,
        capture_gid=policy.capture_gid,
        root_uid=0,
        root_gid=0,
        verifier_gid=policy.verifier_gid,
    )
    try:
        return _adopt_impl(
            policy,
            proof,
            provisional_authority=provisional_authority,
            staging_parent_fd=staging_parent_fd,
            final_parent_fd=final_parent_fd,
            identities=identities,
            strict_parent_chain=True,
        )
    finally:
        if type(provisional_authority) is RetainedProvisionalCapture:
            provisional_authority.close()


def _adopt_staged_capture_for_test(
    policy: CaptureAdoptionPolicy,
    proof: ChildDeathProof,
    *,
    provisional_authority: RetainedProvisionalCapture | None = None,
    staging_parent_fd: int,
    final_parent_fd: int,
    fault_hook: Callable[[str], None] | None = None,
) -> AdoptedCaptureLease:
    """Unprivileged mechanical test seam; never called by production code."""

    if type(proof) is not ChildDeathProof:
        raise _error("capture_adoption_child_proof_required")
    identities = _FilesystemIdentities(
        capture_uid=os.geteuid(),
        capture_gid=os.getegid(),
        root_uid=os.geteuid(),
        root_gid=os.getegid(),
        verifier_gid=os.getegid(),
        # A non-root test process needs owner-write permission for rename.
        revoked_parent_mode=0o700,
    )
    authority = provisional_authority
    if authority is None:
        authority = retain_provisional_capture(
            staging_parent_fd=staging_parent_fd,
            session_id=policy.session_id,
            capture_uid=policy.capture_uid,
            provisional_name=policy.provisional_name,
            expected_object_sha256=policy.expected_object_sha256,
        )
    try:
        return _adopt_impl(
            policy,
            proof,
            provisional_authority=authority,
            staging_parent_fd=staging_parent_fd,
            final_parent_fd=final_parent_fd,
            identities=identities,
            strict_parent_chain=False,
            fault_hook=fault_hook,
        )
    finally:
        if type(authority) is RetainedProvisionalCapture:
            authority.close()


def _recover_staged_capture_for_test(
    policy: CaptureAdoptionPolicy,
    proof: ChildDeathProof,
    *,
    staging_parent_fd: int,
) -> None:
    """Exercise descriptor-relative mixed-owner recovery in unit tests."""

    normalized = normalize_adoption_policy(policy)
    proof._consume(
        session_id=normalized.session_id,
        capture_uid=normalized.capture_uid,
    )
    identities = _FilesystemIdentities(
        capture_uid=os.geteuid(),
        capture_gid=os.getegid(),
        root_uid=os.geteuid(),
        root_gid=os.getegid(),
        verifier_gid=os.getegid(),
        revoked_parent_mode=0o700,
    )
    descriptor = _dup_cloexec(staging_parent_fd)
    root_fd: int | None = None
    try:
        _revoke_staging_parent(descriptor, identities=identities)
        entries = _bounded_entries(
            descriptor,
            maximum=2,
            field="capture_adoption_recovery_inventory",
        )
        if entries != [normalized.provisional_name]:
            raise _error("capture_adoption_recovery_inventory_invalid")
        root_fd, info = _open_bound_directory(
            descriptor,
            normalized.provisional_name,
            field="capture_adoption_recovery_root",
        )
        if _object_sha256(info) != normalized.expected_object_sha256:
            raise _error("capture_adoption_recovery_object_mismatch")
        _remove_bound_tree(
            descriptor,
            normalized.provisional_name,
            root_fd,
            identities=identities,
            policy=normalized,
        )
    finally:
        if root_fd is not None:
            os.close(root_fd)
        os.close(descriptor)


__all__ = [
    "ADOPTED_DIRECTORY_MODE",
    "ADOPTED_FILE_MODE",
    "ADOPTION_POLICY_SCHEMA",
    "ADOPTION_RECEIPT_SCHEMA",
    "AdoptedCaptureLease",
    "CaptureAdoptionError",
    "CaptureAdoptionPolicy",
    "ChildDeathProof",
    "FINAL_PARENT_MODE",
    "PRODUCTION_ACTIVATION",
    "PROVISIONAL_DIRECTORY_MODE",
    "PROVISIONAL_FILE_MODE",
    "RECOVERY_HANDOFF_RECEIPT_FIELDS",
    "RECOVERY_HANDOFF_RECEIPT_SCHEMA",
    "RECOVERY_HANDOFF_STATUS",
    "RetainedProvisionalCapture",
    "REVOKED_STAGING_PARENT_MODE",
    "STAGING_PARENT_MODE",
    "adopt_staged_capture",
    "adopt_staged_capture_canary",
    "capture_object_identity_sha256",
    "normalize_adoption_policy",
    "normalize_recovery_handoff_receipt",
    "reap_capture_child",
    "recovery_handoff_receipt_sha256",
    "retain_provisional_capture",
]
