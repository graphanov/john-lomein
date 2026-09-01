#!/usr/bin/env python3
"""Fail-closed sandbox and supervision primitives for qualification verification.

This module deliberately does not create an activation receipt.  The production
entrypoint accepts only a canonical, root-owned receipt emitted after an
installer-owned privileged canary has exercised the same immutable installation
policy.  Until that receipt exists, production launch is disabled.

The command/profile builders are deterministic and unit-testable.  They are not
evidence that Seatbelt, bubblewrap, seccomp, namespaces, or privilege dropping
work on a particular host; the privileged installer canary is the authority for
that claim.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import math
import os
import platform
import resource
import secrets
import signal
import stat
import struct
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Literal, Mapping, Sequence

from qualification_attestor import (
    john_lomein_persona_qualification_attestor as authority_core,
)


ACTIVATION_RECEIPT_SCHEMA = (
    "john-lomein.persona.qualification-sandbox-activation.v1"
)
ACTIVATION_STATUS = "privileged_canary_passed"
CANARY_ASSERTIONS = (
    "backend_fail_closed",
    "bundle_read_only",
    "capture_read_only",
    "close_fds",
    "filesystem_allowlist",
    "fork_denied",
    "groups_empty",
    "key_unreadable",
    "linux_capabilities_empty_or_not_applicable",
    "linux_no_new_privs_or_not_applicable",
    "network_denied",
    "private_scratch_only",
    "process_group_reaped",
    "saved_gid_regain_denied",
    "saved_uid_regain_denied",
)
FIXED_PYTHON_FLAGS = ("-I", "-S", "-B")
FIXED_ENVIRONMENT_KEYS = (
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "TMPDIR",
    "TZ",
)
MAX_REQUEST_BYTES = 64 * 1024
MAX_STDOUT_BYTES = 1_000_000
MAX_STDERR_BYTES = 256_000
MAX_TIMEOUT_SECONDS = 600
MAX_LOADER_MOUNTS = 32
MAX_RECEIPT_BYTES = 64 * 1024
MAX_SCRATCH_ENTRIES = 16
MAX_ADDRESS_SPACE_BYTES = 2_147_483_648
MAX_OPEN_FILES = 32
MAX_WRAPPER_PROCESSES = 8
LINUX_SCRATCH_TMPFS_BYTES = 8 * 1024 * 1024
POLL_INTERVAL_SECONDS = 0.01
SECCOMP_FD = 3
CONTROLLED_PATH = "/nonexistent"

LINUX_BWRAP_PATHS = (Path("/usr/bin/bwrap"), Path("/bin/bwrap"))
DARWIN_SANDBOX_PATH = Path("/usr/bin/sandbox-exec")

# Classic-BPF/seccomp constants from linux/filter.h, linux/seccomp.h, and
# linux/audit.h.  Keeping the filter construction here avoids a runtime package
# dependency inside the sealed verifier bundle.
_BPF_LD = 0x00
_BPF_W = 0x00
_BPF_ABS = 0x20
_BPF_JMP = 0x05
_BPF_JEQ = 0x10
_BPF_JSET = 0x40
_BPF_K = 0x00
_BPF_RET = 0x06
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_RET_ALLOW = 0x7FFF0000
_AUDIT_ARCH_X86_64 = 0xC000003E
_AUDIT_ARCH_AARCH64 = 0xC00000B7
_X32_SYSCALL_BIT = 0x40000000

_PR_CAPBSET_READ = 23
_PR_CAPBSET_DROP = 24
_PR_SET_NO_NEW_PRIVS = 38
_PR_GET_NO_NEW_PRIVS = 39
_PR_CAP_AMBIENT = 47
_PR_CAP_AMBIENT_IS_SET = 1
_PR_CAP_AMBIENT_CLEAR_ALL = 4
_LINUX_CAPABILITY_VERSION_3 = 0x20080522


class QualificationSandboxError(RuntimeError):
    """A stable fail-closed error from the qualification sandbox."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _error(code: str) -> QualificationSandboxError:
    return QualificationSandboxError(code)


@dataclass(frozen=True)
class ImmutableReadMount:
    """One immutable host loader path and its exact sandbox spelling."""

    source: Path
    destination: Path
    kind: Literal["file", "directory"]

    def as_record(self) -> dict[str, str]:
        return {
            "source": str(self.source),
            "destination": str(self.destination),
            "kind": self.kind,
        }


@dataclass(frozen=True)
class QualificationSandboxPolicy:
    """Complete policy input for one sealed-capture verifier run."""

    system: Literal["Linux", "Darwin"]
    kernel_release: str
    backend_path: Path
    backend_sha256: str
    bundle_root: Path
    bundle_sha256: str
    capture_parent: Path
    capture_root: Path
    python_path: Path
    entrypoint_path: Path
    scratch_root: Path
    activation_receipt_path: Path
    verifier_uid: int
    verifier_gid: int
    timeout_seconds: int
    loader_mounts: tuple[ImmutableReadMount, ...] = ()
    maximum_request_bytes: int = MAX_REQUEST_BYTES
    maximum_stdout_bytes: int = MAX_STDOUT_BYTES
    maximum_stderr_bytes: int = MAX_STDERR_BYTES

    def verifier_argv(self) -> tuple[str, ...]:
        return (
            str(self.python_path),
            *FIXED_PYTHON_FLAGS,
            str(self.entrypoint_path),
        )

    def fixed_environment(self) -> dict[str, str]:
        scratch = str(self.scratch_root)
        return {
            "HOME": scratch,
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": CONTROLLED_PATH,
            "TMPDIR": scratch,
            "TZ": "UTC",
        }

    def activation_record(self) -> dict[str, Any]:
        """Return the static installation policy a canary receipt must bind.

        The exact per-run capture is deliberately excluded.  Its immutable
        parent is included, and runtime validation permits only one immediate,
        sealed child of that parent.
        """

        return {
            "schema_version": (
                "john-lomein.persona.qualification-sandbox-policy.v1"
            ),
            "system": self.system,
            "kernel_release": self.kernel_release,
            "backend_path": str(self.backend_path),
            "backend_sha256": self.backend_sha256,
            "bundle_root": str(self.bundle_root),
            "bundle_sha256": self.bundle_sha256,
            "capture_parent": str(self.capture_parent),
            "python_path": str(self.python_path),
            "entrypoint_path": str(self.entrypoint_path),
            "scratch_root": str(self.scratch_root),
            "verifier_uid": self.verifier_uid,
            "verifier_gid": self.verifier_gid,
            "timeout_seconds": self.timeout_seconds,
            "loader_mounts": [
                mount.as_record() for mount in self.loader_mounts
            ],
            "maximum_request_bytes": self.maximum_request_bytes,
            "maximum_stdout_bytes": self.maximum_stdout_bytes,
            "maximum_stderr_bytes": self.maximum_stderr_bytes,
            "fixed_argv": list(self.verifier_argv()),
            "fixed_environment": self.fixed_environment(),
            "linux_seccomp_version": 1,
            "linux_scratch_tmpfs_bytes": LINUX_SCRATCH_TMPFS_BYTES,
            "filesystem_policy": (
                "deny-default:bundle+one-capture+loader-read:"
                "private-scratch-write"
            ),
        }

    def activation_policy_sha256(self) -> str:
        return hashlib.sha256(
            _canonical_json(self.activation_record())
        ).hexdigest()


@dataclass(frozen=True)
class SandboxRunResult:
    stdout: bytes
    stderr: bytes
    returncode: int
    elapsed_seconds: float


@dataclass(frozen=True)
class _Spool:
    path: Path
    descriptor: int


@dataclass(frozen=True)
class _ExitObservation:
    reaped: bool
    status: int | None = None


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _sha256_file(path: Path, *, maximum_bytes: int = 128 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    observed = 0
    try:
        with path.open("rb", buffering=0) as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                observed += len(chunk)
                if observed > maximum_bytes:
                    raise _error("sandbox_backend_too_large")
                digest.update(chunk)
    except QualificationSandboxError:
        raise
    except OSError as exc:
        raise _error("sandbox_backend_unreadable") from exc
    return digest.hexdigest()


def _hex_digest(value: str, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise _error(f"{field}_invalid")
    return value


def _integer(
    value: Any,
    *,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise _error(f"{field}_invalid")
    return value


def _absolute_path(value: Path | str, *, field: str) -> Path:
    text = str(value)
    if (
        not text
        or "\x00" in text
        or "\n" in text
        or "\r" in text
        or unicodedata.normalize("NFC", text) != text
        or not Path(text).is_absolute()
        or "." in Path(text).parts
        or ".." in Path(text).parts
        or os.path.normpath(text) != text
    ):
        raise _error(f"{field}_invalid")
    return Path(text)


def _inside(path: Path, root: Path) -> bool:
    path_parts = tuple(
        unicodedata.normalize("NFC", part).casefold()
        for part in path.parts
    )
    root_parts = tuple(
        unicodedata.normalize("NFC", part).casefold()
        for part in root.parts
    )
    return path_parts[: len(root_parts)] == root_parts


def _overlap(left: Path, right: Path) -> bool:
    return _inside(left, right) or _inside(right, left)


def _path_parent_chain(path: Path) -> list[Path]:
    parents: list[Path] = []
    current = path
    while current != current.parent:
        parents.append(current)
        current = current.parent
    parents.append(current)
    return list(reversed(parents))


def _reject_authority_metadata(path: Path, *, field: str) -> None:
    """Reject metadata that can make checked mode bits an incomplete proof."""

    try:
        authority_core._reject_acl_or_xattrs(path, field=field)
    except authority_core.QualificationAttestorError as exc:
        raise _error(exc.code) from exc


def _validate_trusted_parent_chain(path: Path) -> None:
    for parent in _path_parent_chain(path):
        try:
            info = parent.lstat()
        except OSError as exc:
            raise _error("sandbox_path_parent_unreadable") from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
        ):
            raise _error("sandbox_path_parent_unsafe")
        _reject_authority_metadata(
            parent,
            field="sandbox_path_parent",
        )


def _validate_root_owned_leaf(
    path: Path,
    *,
    field: str,
    executable: bool = False,
) -> os.stat_result:
    _validate_trusted_parent_chain(path.parent)
    try:
        info = path.lstat()
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_nlink != 1
        or info.st_mode & 0o022
        or (executable and not info.st_mode & 0o500)
    ):
        raise _error(f"{field}_unsafe")
    _reject_authority_metadata(path, field=field)
    return info


def _validate_root_owned_directory(
    path: Path,
    *,
    field: str,
    expected_gid: int | None = None,
    exact_mode: int | None = None,
) -> os.stat_result:
    _validate_trusted_parent_chain(path.parent)
    try:
        info = path.lstat()
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
        or (expected_gid is not None and info.st_gid != expected_gid)
        or (
            exact_mode is not None
            and stat.S_IMODE(info.st_mode) != exact_mode
        )
    ):
        raise _error(f"{field}_unsafe")
    _reject_authority_metadata(path, field=field)
    return info


def _loader_scope_roots(system: str) -> tuple[Path, ...]:
    if system == "Linux":
        return (
            Path("/lib"),
            Path("/lib64"),
            Path("/usr/lib"),
            Path("/usr/lib64"),
            Path("/etc/ld.so.cache"),
        )
    if system == "Darwin":
        return (
            Path("/usr/lib"),
            Path("/System/Library"),
            Path("/private/var/db/dyld"),
        )
    raise _error("sandbox_platform_unsupported")


def _validate_loader_scope(
    mount: ImmutableReadMount,
    *,
    system: str,
) -> None:
    roots = _loader_scope_roots(system)
    if not any(_inside(mount.source, root) for root in roots):
        raise _error("loader_mount_source_outside_system_closure")
    if not any(_inside(mount.destination, root) for root in roots):
        raise _error("loader_mount_destination_outside_system_closure")


def _validate_loader_mount(
    mount: ImmutableReadMount,
    *,
    system: str,
) -> None:
    source = _absolute_path(mount.source, field="loader_mount_source")
    destination = _absolute_path(
        mount.destination,
        field="loader_mount_destination",
    )
    if source != mount.source or destination != mount.destination:
        raise _error("loader_mount_path_noncanonical")
    if mount.kind not in {"file", "directory"}:
        raise _error("loader_mount_kind_invalid")
    _validate_loader_scope(mount, system=system)
    _validate_trusted_parent_chain(source.parent)
    try:
        info = source.lstat()
    except OSError as exc:
        raise _error("loader_mount_unreadable") from exc
    expected_type = (
        stat.S_ISREG(info.st_mode)
        if mount.kind == "file"
        else stat.S_ISDIR(info.st_mode)
    )
    if not expected_type or info.st_uid != 0 or info.st_mode & 0o022:
        raise _error("loader_mount_unsafe")
    _reject_authority_metadata(source, field="loader_mount")
    # A root, /usr, /etc, /System, or /private mount is an accidental host
    # filesystem grant rather than a loader closure.
    if destination in {
        Path("/"),
        Path("/usr"),
        Path("/etc"),
        Path("/System"),
        Path("/private"),
    }:
        raise _error("loader_mount_too_broad")


def _discover_backend(system: str) -> Path:
    candidates: Sequence[Path]
    if system == "Darwin":
        candidates = (DARWIN_SANDBOX_PATH,)
    elif system == "Linux":
        candidates = LINUX_BWRAP_PATHS
    else:
        raise _error("sandbox_platform_unsupported")
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise _error(
        "sandbox_seatbelt_unavailable"
        if system == "Darwin"
        else "sandbox_bubblewrap_unavailable"
    )


def build_policy(
    *,
    bundle_root: Path,
    bundle_sha256: str,
    capture_parent: Path,
    capture_root: Path,
    python_path: Path,
    entrypoint_path: Path,
    scratch_root: Path,
    activation_receipt_path: Path,
    verifier_uid: int,
    verifier_gid: int,
    timeout_seconds: int,
    loader_mounts: Sequence[ImmutableReadMount] = (),
    system: str | None = None,
    backend_path: Path | None = None,
    backend_sha256: str | None = None,
    kernel_release: str | None = None,
    maximum_request_bytes: int = MAX_REQUEST_BYTES,
    maximum_stdout_bytes: int = MAX_STDOUT_BYTES,
    maximum_stderr_bytes: int = MAX_STDERR_BYTES,
) -> QualificationSandboxPolicy:
    """Normalize a policy; launch-time validation proves its immutable paths."""

    selected_system = system or platform.system()
    if selected_system not in {"Linux", "Darwin"}:
        raise _error("sandbox_platform_unsupported")
    selected_backend = (
        _discover_backend(selected_system)
        if backend_path is None
        else _absolute_path(backend_path, field="backend_path")
    )
    selected_backend_digest = (
        _sha256_file(selected_backend)
        if backend_sha256 is None
        else _hex_digest(backend_sha256, field="backend_sha256")
    )
    normalized_mounts = tuple(loader_mounts)
    if len(normalized_mounts) > MAX_LOADER_MOUNTS:
        raise _error("loader_mounts_too_many")
    policy = QualificationSandboxPolicy(
        system=selected_system,
        kernel_release=kernel_release or platform.release(),
        backend_path=selected_backend,
        backend_sha256=selected_backend_digest,
        bundle_root=_absolute_path(bundle_root, field="bundle_root"),
        bundle_sha256=_hex_digest(bundle_sha256, field="bundle_sha256"),
        capture_parent=_absolute_path(
            capture_parent,
            field="capture_parent",
        ),
        capture_root=_absolute_path(capture_root, field="capture_root"),
        python_path=_absolute_path(python_path, field="python_path"),
        entrypoint_path=_absolute_path(
            entrypoint_path,
            field="entrypoint_path",
        ),
        scratch_root=_absolute_path(scratch_root, field="scratch_root"),
        activation_receipt_path=_absolute_path(
            activation_receipt_path,
            field="activation_receipt_path",
        ),
        verifier_uid=_integer(
            verifier_uid,
            field="verifier_uid",
            minimum=1,
            maximum=2**31 - 1,
        ),
        verifier_gid=_integer(
            verifier_gid,
            field="verifier_gid",
            minimum=1,
            maximum=2**31 - 1,
        ),
        timeout_seconds=_integer(
            timeout_seconds,
            field="timeout_seconds",
            minimum=1,
            maximum=MAX_TIMEOUT_SECONDS,
        ),
        loader_mounts=normalized_mounts,
        maximum_request_bytes=_integer(
            maximum_request_bytes,
            field="maximum_request_bytes",
            minimum=1,
            maximum=MAX_REQUEST_BYTES,
        ),
        maximum_stdout_bytes=_integer(
            maximum_stdout_bytes,
            field="maximum_stdout_bytes",
            minimum=1,
            maximum=MAX_STDOUT_BYTES,
        ),
        maximum_stderr_bytes=_integer(
            maximum_stderr_bytes,
            field="maximum_stderr_bytes",
            minimum=1,
            maximum=MAX_STDERR_BYTES,
        ),
    )
    _validate_policy_shape(policy)
    return policy


def _validate_policy_shape(policy: QualificationSandboxPolicy) -> None:
    if policy.capture_root.parent != policy.capture_parent:
        raise _error("capture_not_immediate_child")
    if not _inside(policy.python_path, policy.bundle_root):
        raise _error("python_outside_bundle")
    if not _inside(policy.entrypoint_path, policy.bundle_root):
        raise _error("entrypoint_outside_bundle")
    protected = (
        policy.bundle_root,
        policy.capture_parent,
        policy.scratch_root,
        policy.activation_receipt_path,
    )
    for index, left in enumerate(protected):
        for right in protected[index + 1 :]:
            if _overlap(left, right):
                raise _error("sandbox_control_paths_overlap")
    destinations = [
        policy.bundle_root,
        policy.capture_root,
        policy.scratch_root,
    ]
    for mount in policy.loader_mounts:
        source = _absolute_path(mount.source, field="loader_mount_source")
        destination = _absolute_path(
            mount.destination,
            field="loader_mount_destination",
        )
        if policy.system == "Darwin" and source != destination:
            raise _error("seatbelt_loader_alias_unsupported")
        for existing in destinations:
            if _overlap(destination, existing):
                raise _error("sandbox_mount_destinations_overlap")
        destinations.append(destination)
        _validate_loader_scope(mount, system=policy.system)
    if set(policy.fixed_environment()) != set(FIXED_ENVIRONMENT_KEYS):
        raise _error("sandbox_environment_contract_invalid")


def _validate_policy_runtime(policy: QualificationSandboxPolicy) -> None:
    if platform.system() != policy.system:
        raise _error("sandbox_runtime_platform_mismatch")
    if platform.release() != policy.kernel_release:
        raise _error("sandbox_kernel_release_changed")
    expected_backend_paths = (
        (DARWIN_SANDBOX_PATH,)
        if policy.system == "Darwin"
        else LINUX_BWRAP_PATHS
    )
    if policy.backend_path not in expected_backend_paths:
        raise _error("sandbox_backend_path_untrusted")
    _validate_root_owned_leaf(
        policy.backend_path,
        field="sandbox_backend",
        executable=True,
    )
    if _sha256_file(policy.backend_path) != policy.backend_sha256:
        raise _error("sandbox_backend_digest_changed")
    _validate_root_owned_directory(
        policy.bundle_root,
        field="sandbox_bundle",
    )
    _validate_root_owned_leaf(
        policy.python_path,
        field="sandbox_python",
        executable=True,
    )
    _validate_root_owned_leaf(
        policy.entrypoint_path,
        field="sandbox_entrypoint",
    )
    _validate_root_owned_directory(
        policy.capture_parent,
        field="sandbox_capture_parent",
        expected_gid=policy.verifier_gid,
        exact_mode=0o710,
    )
    _validate_root_owned_directory(
        policy.capture_root,
        field="sandbox_capture",
        expected_gid=policy.verifier_gid,
        exact_mode=0o550,
    )
    _validate_trusted_parent_chain(policy.scratch_root.parent)
    try:
        scratch_info = policy.scratch_root.lstat()
    except OSError as exc:
        raise _error("sandbox_scratch_unreadable") from exc
    if (
        not stat.S_ISDIR(scratch_info.st_mode)
        or scratch_info.st_uid != policy.verifier_uid
        or scratch_info.st_gid != policy.verifier_gid
        or stat.S_IMODE(scratch_info.st_mode) != 0o700
    ):
        raise _error("sandbox_scratch_unsafe")
    _reject_authority_metadata(
        policy.scratch_root,
        field="sandbox_scratch",
    )
    _assert_scratch_empty(policy.scratch_root)
    for mount in policy.loader_mounts:
        _validate_loader_mount(mount, system=policy.system)


def _assert_scratch_empty(path: Path) -> None:
    try:
        with os.scandir(path) as entries:
            for index, _entry in enumerate(entries, start=1):
                if index > MAX_SCRATCH_ENTRIES:
                    raise _error("sandbox_scratch_entries_exceeded")
                raise _error("sandbox_scratch_not_empty")
    except QualificationSandboxError:
        raise
    except OSError as exc:
        raise _error("sandbox_scratch_unreadable") from exc


def _scheme_string(value: Path | str) -> str:
    text = str(value)
    if "\x00" in text or "\n" in text or "\r" in text:
        raise _error("sandbox_policy_path_unsafe")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _darwin_literal_ancestors(paths: Sequence[Path]) -> tuple[Path, ...]:
    """Return exact traversal points without granting ancestor subtrees."""

    ancestors: set[Path] = set()
    for path in paths:
        current = path.parent
        while True:
            ancestors.add(current)
            if current.parent == current:
                break
            current = current.parent
    return tuple(
        sorted(
            ancestors,
            key=lambda item: (len(item.parts), str(item)),
        )
    )


def build_darwin_profile(policy: QualificationSandboxPolicy) -> str:
    """Build the deny-default Seatbelt profile for an already-validated policy."""

    if policy.system != "Darwin":
        raise _error("seatbelt_policy_platform_mismatch")
    read_filters = [
        f"(subpath {_scheme_string(policy.bundle_root)})",
        f"(subpath {_scheme_string(policy.capture_root)})",
        f"(subpath {_scheme_string(policy.scratch_root)})",
    ]
    traversal_paths = [
        policy.bundle_root,
        policy.capture_root,
        policy.scratch_root,
        policy.python_path,
        policy.entrypoint_path,
    ]
    for mount in policy.loader_mounts:
        operation = "literal" if mount.kind == "file" else "subpath"
        read_filters.append(
            f"({operation} {_scheme_string(mount.destination)})"
        )
        traversal_paths.append(mount.destination)
    read_filters.extend(
        f"(literal {_scheme_string(ancestor)})"
        for ancestor in _darwin_literal_ancestors(traversal_paths)
    )
    return "\n".join(
        [
            "(version 1)",
            "(deny default)",
            "(deny network*)",
            "(deny process-fork)",
            "(deny file-link)",
            "(allow process-exec "
            f"(literal {_scheme_string(policy.python_path)}))",
            "(allow process-info*)",
            "(allow sysctl-read)",
            "(allow file-read*",
            *(f"  {item}" for item in read_filters),
            ")",
            "(allow file-write*",
            f"  (subpath {_scheme_string(policy.scratch_root)})",
            ")",
            "",
        ]
    )


def build_darwin_command(policy: QualificationSandboxPolicy) -> list[str]:
    if policy.system != "Darwin":
        raise _error("seatbelt_command_platform_mismatch")
    return [
        str(policy.backend_path),
        "-p",
        build_darwin_profile(policy),
        *policy.verifier_argv(),
    ]


def _linux_syscalls(machine: str) -> tuple[int, tuple[tuple[str, int], ...]]:
    normalized = machine.lower()
    common_x86_64 = (
        ("fork", 57),
        ("vfork", 58),
        ("clone", 56),
        ("clone3", 435),
        ("socket", 41),
        ("socketpair", 53),
        ("connect", 42),
        ("accept", 43),
        ("sendto", 44),
        ("recvfrom", 45),
        ("sendmsg", 46),
        ("recvmsg", 47),
        ("shutdown", 48),
        ("bind", 49),
        ("listen", 50),
        ("getsockname", 51),
        ("getpeername", 52),
        ("setsockopt", 54),
        ("getsockopt", 55),
        ("accept4", 288),
        ("unshare", 272),
        ("setns", 308),
        ("mount", 165),
        ("umount2", 166),
        ("pivot_root", 155),
        ("ptrace", 101),
        ("bpf", 321),
        ("perf_event_open", 298),
        ("keyctl", 250),
        ("add_key", 248),
        ("request_key", 249),
        ("userfaultfd", 323),
        ("open_by_handle_at", 304),
        ("pidfd_getfd", 438),
        ("process_vm_readv", 310),
        ("process_vm_writev", 311),
        ("io_uring_setup", 425),
        ("io_uring_enter", 426),
        ("io_uring_register", 427),
        ("setuid", 105),
        ("setgid", 106),
        ("setreuid", 113),
        ("setregid", 114),
        ("setresuid", 117),
        ("setresgid", 119),
        ("setgroups", 116),
        ("setfsuid", 122),
        ("setfsgid", 123),
        ("capset", 126),
        ("execveat", 322),
    )
    common_aarch64 = (
        ("clone", 220),
        ("clone3", 435),
        ("socket", 198),
        ("socketpair", 199),
        ("bind", 200),
        ("listen", 201),
        ("accept", 202),
        ("connect", 203),
        ("getsockname", 204),
        ("getpeername", 205),
        ("sendto", 206),
        ("recvfrom", 207),
        ("setsockopt", 208),
        ("getsockopt", 209),
        ("shutdown", 210),
        ("sendmsg", 211),
        ("recvmsg", 212),
        ("accept4", 242),
        ("unshare", 97),
        ("setns", 268),
        ("mount", 40),
        ("umount2", 39),
        ("pivot_root", 41),
        ("ptrace", 117),
        ("bpf", 280),
        ("perf_event_open", 241),
        ("keyctl", 219),
        ("add_key", 217),
        ("request_key", 218),
        ("userfaultfd", 282),
        ("open_by_handle_at", 265),
        ("pidfd_getfd", 438),
        ("process_vm_readv", 270),
        ("process_vm_writev", 271),
        ("io_uring_setup", 425),
        ("io_uring_enter", 426),
        ("io_uring_register", 427),
        ("setuid", 146),
        ("setgid", 144),
        ("setreuid", 145),
        ("setregid", 143),
        ("setresuid", 147),
        ("setresgid", 149),
        ("setgroups", 159),
        ("setfsuid", 151),
        ("setfsgid", 152),
        ("capset", 91),
        ("execveat", 281),
    )
    if normalized in {"x86_64", "amd64"}:
        return _AUDIT_ARCH_X86_64, common_x86_64
    if normalized in {"aarch64", "arm64"}:
        return _AUDIT_ARCH_AARCH64, common_aarch64
    raise _error("sandbox_linux_architecture_unsupported")


def linux_seccomp_denied_syscalls(
    machine: str | None = None,
) -> tuple[str, ...]:
    """Return the explicit syscall-denial names for audit and canary code."""

    _architecture, entries = _linux_syscalls(machine or platform.machine())
    return tuple(name for name, _number in entries)


def build_linux_seccomp_filter(machine: str | None = None) -> bytes:
    """Build a classic-BPF filter denying descendants, network, and escapes."""

    audit_architecture, entries = _linux_syscalls(
        machine or platform.machine()
    )
    instructions: list[tuple[int, int, int, int]] = [
        (_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, 4),
        (
            _BPF_JMP | _BPF_JEQ | _BPF_K,
            1,
            0,
            audit_architecture,
        ),
        (_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_KILL_PROCESS),
        (_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, 0),
    ]
    if audit_architecture == _AUDIT_ARCH_X86_64:
        # Linux x32 syscalls share AUDIT_ARCH_X86_64 but set bit 30 on the
        # syscall number. Without this guard, every explicit deny below can
        # be bypassed on a kernel with the x32 ABI enabled.
        instructions.extend(
            (
                (
                    _BPF_JMP | _BPF_JSET | _BPF_K,
                    0,
                    1,
                    _X32_SYSCALL_BIT,
                ),
                (
                    _BPF_RET | _BPF_K,
                    0,
                    0,
                    _SECCOMP_RET_KILL_PROCESS,
                ),
            )
        )
    for _name, syscall_number in entries:
        instructions.extend(
            (
                (
                    _BPF_JMP | _BPF_JEQ | _BPF_K,
                    0,
                    1,
                    syscall_number,
                ),
                (
                    _BPF_RET | _BPF_K,
                    0,
                    0,
                    _SECCOMP_RET_ERRNO | errno.EPERM,
                ),
            )
        )
    instructions.append(
        (_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_ALLOW)
    )
    return b"".join(
        struct.pack("=HBBI", code, jump_true, jump_false, value)
        for code, jump_true, jump_false, value in instructions
    )


def build_linux_command(
    policy: QualificationSandboxPolicy,
    *,
    seccomp_fd: int = SECCOMP_FD,
) -> list[str]:
    if policy.system != "Linux":
        raise _error("bubblewrap_command_platform_mismatch")
    command = [
        str(policy.backend_path),
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--cap-drop",
        "ALL",
        "--uid",
        str(policy.verifier_uid),
        "--gid",
        str(policy.verifier_gid),
        "--clearenv",
        "--tmpfs",
        "/",
        "--ro-bind",
        str(policy.bundle_root),
        str(policy.bundle_root),
        "--ro-bind",
        str(policy.capture_root),
        str(policy.capture_root),
    ]
    for mount in policy.loader_mounts:
        command.extend(
            (
                "--ro-bind",
                str(mount.source),
                str(mount.destination),
            )
        )
    command.extend(
        (
            "--size",
            str(LINUX_SCRATCH_TMPFS_BYTES),
            "--tmpfs",
            str(policy.scratch_root),
            "--remount-ro",
            "/",
            "--chdir",
            str(policy.bundle_root),
        )
    )
    for key, value in policy.fixed_environment().items():
        command.extend(("--setenv", key, value))
    command.extend(
        (
            "--seccomp",
            str(seccomp_fd),
            "--",
            *policy.verifier_argv(),
        )
    )
    return command


def normalize_activation_receipt(
    value: Any,
    *,
    policy: QualificationSandboxPolicy,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _error("sandbox_activation_receipt_invalid")
    expected_fields = {
        "schema_version",
        "status",
        "activation_policy_sha256",
        "system",
        "kernel_release",
        "backend_path",
        "backend_sha256",
        "bundle_sha256",
        "verifier_uid",
        "verifier_gid",
        "assertions",
    }
    if set(value) != expected_fields:
        raise _error("sandbox_activation_receipt_fields_invalid")
    assertions = value.get("assertions")
    if (
        not isinstance(assertions, Mapping)
        or set(assertions) != set(CANARY_ASSERTIONS)
        or any(assertions[name] is not True for name in CANARY_ASSERTIONS)
    ):
        raise _error("sandbox_activation_assertions_incomplete")
    expected = {
        "schema_version": ACTIVATION_RECEIPT_SCHEMA,
        "status": ACTIVATION_STATUS,
        "activation_policy_sha256": policy.activation_policy_sha256(),
        "system": policy.system,
        "kernel_release": policy.kernel_release,
        "backend_path": str(policy.backend_path),
        "backend_sha256": policy.backend_sha256,
        "bundle_sha256": policy.bundle_sha256,
        "verifier_uid": policy.verifier_uid,
        "verifier_gid": policy.verifier_gid,
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            raise _error(f"sandbox_activation_{field}_mismatch")
    return {
        **expected,
        "assertions": {name: True for name in CANARY_ASSERTIONS},
    }


def _read_activation_receipt(
    policy: QualificationSandboxPolicy,
) -> dict[str, Any]:
    path = policy.activation_receipt_path
    _validate_root_owned_leaf(
        path,
        field="sandbox_activation_receipt",
    )
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise _error("sandbox_activation_receipt_unreadable") from exc
    try:
        info = os.fstat(descriptor)
        if (
            info.st_uid != 0
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > MAX_RECEIPT_BYTES
        ):
            raise _error("sandbox_activation_receipt_unsafe")
        raw = os.read(descriptor, MAX_RECEIPT_BYTES + 1)
        if len(raw) > MAX_RECEIPT_BYTES:
            raise _error("sandbox_activation_receipt_too_large")
    finally:
        os.close(descriptor)
    try:
        parsed = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _error("sandbox_activation_receipt_invalid") from exc
    normalized = normalize_activation_receipt(parsed, policy=policy)
    if raw != _canonical_json(normalized) + b"\n":
        raise _error("sandbox_activation_receipt_noncanonical")
    return normalized


class _CapabilityHeader(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("pid", ctypes.c_int),
    ]


class _CapabilityData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


def _linux_libc() -> Any:
    return ctypes.CDLL(None, use_errno=True)


def _prctl(
    option: int,
    argument2: int = 0,
    argument3: int = 0,
    argument4: int = 0,
    argument5: int = 0,
) -> int:
    libc = _linux_libc()
    result = libc.prctl(
        option,
        argument2,
        argument3,
        argument4,
        argument5,
    )
    if result < 0:
        observed_errno = ctypes.get_errno()
        raise OSError(observed_errno, os.strerror(observed_errno))
    return int(result)


def _linux_capability_words() -> tuple[int, ...]:
    libc = _linux_libc()
    header = _CapabilityHeader(_LINUX_CAPABILITY_VERSION_3, 0)
    data = (_CapabilityData * 2)()
    if libc.capget(ctypes.byref(header), ctypes.byref(data)) != 0:
        observed_errno = ctypes.get_errno()
        raise OSError(observed_errno, os.strerror(observed_errno))
    return tuple(
        value
        for row in data
        for value in (row.effective, row.permitted, row.inheritable)
    )


def assert_linux_privilege_confinement() -> None:
    """Native replacement for parsing ``/proc/self/status``.

    The verifier may call this after checking its real/effective/saved IDs.
    It proves effective, permitted, inheritable, bounding, and ambient
    capability sets are empty and ``no_new_privs`` is active without mounting
    procfs in the sandbox.
    """

    if platform.system() != "Linux":
        raise _error("linux_privilege_check_platform_mismatch")
    try:
        if any(_linux_capability_words()):
            raise _error("linux_capability_residue")
        for capability in range(64):
            try:
                if _prctl(_PR_CAPBSET_READ, capability) != 0:
                    raise _error("linux_capability_bounding_residue")
            except OSError as exc:
                if exc.errno == errno.EINVAL:
                    continue
                raise
            try:
                if (
                    _prctl(
                        _PR_CAP_AMBIENT,
                        _PR_CAP_AMBIENT_IS_SET,
                        capability,
                    )
                    != 0
                ):
                    raise _error("linux_capability_ambient_residue")
            except OSError as exc:
                if exc.errno == errno.EINVAL:
                    continue
                raise
        if _prctl(_PR_GET_NO_NEW_PRIVS) != 1:
            raise _error("linux_no_new_privs_missing")
    except QualificationSandboxError:
        raise
    except OSError as exc:
        raise _error("linux_privilege_check_failed") from exc


def _drop_linux_privileges() -> None:
    try:
        try:
            _prctl(
                _PR_CAP_AMBIENT,
                _PR_CAP_AMBIENT_CLEAR_ALL,
                0,
            )
        except OSError as exc:
            if exc.errno != errno.EINVAL:
                raise
        for capability in range(64):
            try:
                _prctl(_PR_CAPBSET_DROP, capability)
            except OSError as exc:
                if exc.errno == errno.EINVAL:
                    continue
                raise
        _prctl(_PR_SET_NO_NEW_PRIVS, 1)
    except OSError as exc:
        raise _error("linux_privilege_drop_failed") from exc


def _set_limit(kind: int, maximum: int) -> None:
    _soft, hard = resource.getrlimit(kind)
    selected = maximum if hard == resource.RLIM_INFINITY else min(
        maximum,
        hard,
    )
    resource.setrlimit(kind, (selected, selected))


def _resource_limits(policy: QualificationSandboxPolicy) -> None:
    _set_limit(resource.RLIMIT_CORE, 0)
    _set_limit(
        resource.RLIMIT_CPU,
        min(
            math.ceil(policy.timeout_seconds) + 2,
            MAX_TIMEOUT_SECONDS,
        ),
    )
    if hasattr(resource, "RLIMIT_AS"):
        _set_limit(resource.RLIMIT_AS, MAX_ADDRESS_SPACE_BYTES)
    _set_limit(
        resource.RLIMIT_FSIZE,
        max(
            policy.maximum_stdout_bytes,
            policy.maximum_stderr_bytes,
        )
        + 1,
    )
    _set_limit(resource.RLIMIT_NOFILE, MAX_OPEN_FILES)
    if hasattr(resource, "RLIMIT_NPROC"):
        # The wrapper may need a small, bounded process set while constructing
        # namespaces.  Seatbelt/seccomp, not this coarse per-UID limit, is the
        # no-descendant authority.
        _set_limit(resource.RLIMIT_NPROC, MAX_WRAPPER_PROCESSES)


def _identity_tuple(kind: Literal["uid", "gid"]) -> tuple[int, ...]:
    getter = getattr(os, f"getres{kind}", None)
    if getter is not None:
        return tuple(int(item) for item in getter())
    if kind == "uid":
        return (os.getuid(), os.geteuid())
    return (os.getgid(), os.getegid())


def _regain_canary(kind: Literal["uid", "gid"]) -> None:
    setters: list[tuple[Callable[..., None], tuple[int, ...]]] = []
    effective = getattr(os, f"sete{kind}", None)
    basic = getattr(os, f"set{kind}", None)
    residual = getattr(os, f"setres{kind}", None)
    if effective is not None:
        setters.append((effective, (0,)))
    if basic is not None:
        setters.append((basic, (0,)))
    if residual is not None:
        setters.append((residual, (0, 0, 0)))
    for setter, arguments in setters:
        try:
            setter(*arguments)
        except OSError:
            continue
        # A successful regain is terminal.  Do not execute Python cleanup with
        # unexpectedly restored privilege.
        os._exit(126)


def _prepare_child_identity(policy: QualificationSandboxPolicy) -> None:
    os.umask(0o077)
    _resource_limits(policy)
    if policy.system == "Linux":
        _drop_linux_privileges()
    try:
        os.setgroups([])
        setresgid = getattr(os, "setresgid", None)
        if setresgid is not None:
            setresgid(
                policy.verifier_gid,
                policy.verifier_gid,
                policy.verifier_gid,
            )
        else:
            os.setgid(policy.verifier_gid)
        setresuid = getattr(os, "setresuid", None)
        if setresuid is not None:
            setresuid(
                policy.verifier_uid,
                policy.verifier_uid,
                policy.verifier_uid,
            )
        else:
            # A privileged setuid/setgid on Darwin changes saved IDs too.  The
            # regain canaries below are the executable proof.
            os.setuid(policy.verifier_uid)
    except OSError as exc:
        raise _error("sandbox_identity_drop_failed") from exc
    if (
        _identity_tuple("uid")
        != (policy.verifier_uid,) * len(_identity_tuple("uid"))
        or _identity_tuple("gid")
        != (policy.verifier_gid,) * len(_identity_tuple("gid"))
        or os.getgroups()
    ):
        raise _error("sandbox_identity_drop_incomplete")
    _regain_canary("gid")
    _regain_canary("uid")
    if policy.system == "Linux":
        assert_linux_privilege_confinement()


def _write_all(descriptor: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        written = os.write(descriptor, value[offset:])
        if written <= 0:
            raise _error("sandbox_spool_write_failed")
        offset += written


def _create_spool(
    scratch_root: Path,
    *,
    name: str,
    verifier_uid: int,
    verifier_gid: int,
) -> _Spool:
    for _attempt in range(8):
        path = scratch_root / f".{name}-{secrets.token_hex(16)}"
        try:
            descriptor = os.open(
                path,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except FileExistsError:
            continue
        except OSError as exc:
            raise _error("sandbox_spool_create_failed") from exc
        try:
            os.fchmod(descriptor, 0o600)
            if os.geteuid() == 0:
                os.fchown(descriptor, verifier_uid, verifier_gid)
        except OSError as exc:
            os.close(descriptor)
            try:
                path.unlink()
            except OSError:
                pass
            raise _error("sandbox_spool_metadata_failed") from exc
        return _Spool(path=path, descriptor=descriptor)
    raise _error("sandbox_spool_name_exhausted")


def _duplicate_child_fds(
    *,
    stdin_fd: int,
    stdout_fd: int,
    stderr_fd: int,
    seccomp_fd: int | None,
) -> None:
    # Duplicate sources above ordinary descriptor space before assigning fixed
    # destinations.  This prevents a destination from clobbering a later
    # source, even in a parent with an unusual descriptor layout.
    sources = [stdin_fd, stdout_fd, stderr_fd]
    if seccomp_fd is not None:
        sources.append(seccomp_fd)
    safe_sources: list[int] = []
    minimum = 64
    for source in sources:
        duplicated = fcntl.fcntl(
            source,
            fcntl.F_DUPFD_CLOEXEC,
            minimum,
        )
        safe_sources.append(duplicated)
        minimum = duplicated + 1
    os.dup2(safe_sources[0], 0, inheritable=True)
    os.dup2(safe_sources[1], 1, inheritable=True)
    os.dup2(safe_sources[2], 2, inheritable=True)
    if seccomp_fd is not None:
        os.dup2(safe_sources[3], SECCOMP_FD, inheritable=True)
    for descriptor in safe_sources:
        try:
            os.close(descriptor)
        except OSError:
            pass
    _close_unrelated_fds(preserve_seccomp=seccomp_fd is not None)


def _close_unrelated_fds(*, preserve_seccomp: bool) -> None:
    first = 4 if preserve_seccomp else 3
    _soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    maximum = (
        1_048_576
        if hard == resource.RLIM_INFINITY
        else max(first, int(hard))
    )
    os.closerange(first, maximum)


def _child_exec(
    *,
    command: Sequence[str],
    environment: Mapping[str, str],
    cwd: Path,
    stdin_fd: int,
    stdout_fd: int,
    stderr_fd: int,
    seccomp_fd: int | None,
    prepare: Callable[[], None],
) -> None:
    try:
        os.setsid()
        _duplicate_child_fds(
            stdin_fd=stdin_fd,
            stdout_fd=stdout_fd,
            stderr_fd=stderr_fd,
            seccomp_fd=seccomp_fd,
        )
        os.chdir(cwd)
        prepare()
        os.execve(command[0], list(command), dict(environment))
    except BaseException:
        try:
            os.write(2, b"qualification sandbox child setup failed\n")
        except OSError:
            pass
        os._exit(126)


def _spawn_child(
    *,
    command: Sequence[str],
    environment: Mapping[str, str],
    cwd: Path,
    stdin_fd: int,
    stdout_fd: int,
    stderr_fd: int,
    seccomp_fd: int | None,
    prepare: Callable[[], None],
) -> int:
    try:
        pid = os.fork()
    except OSError as exc:
        raise _error("sandbox_fork_failed") from exc
    if pid == 0:
        _child_exec(
            command=command,
            environment=environment,
            cwd=cwd,
            stdin_fd=stdin_fd,
            stdout_fd=stdout_fd,
            stderr_fd=stderr_fd,
            seccomp_fd=seccomp_fd,
            prepare=prepare,
        )
        os._exit(126)
    return pid


def _wait_until_exit(
    pid: int,
    *,
    deadline: float,
    monotonic: Callable[[], float],
    sleeper: Callable[[float], None],
) -> _ExitObservation:
    while True:
        if all(
            hasattr(os, name)
            for name in ("waitid", "P_PID", "WEXITED", "WNOWAIT")
        ):
            try:
                observed = os.waitid(
                    os.P_PID,
                    pid,
                    os.WEXITED | os.WNOHANG | os.WNOWAIT,
                )
            except ChildProcessError as exc:
                raise _error("sandbox_child_wait_lost") from exc
            if observed is not None and observed.si_pid == pid:
                return _ExitObservation(reaped=False)
        else:
            try:
                observed_pid, status = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError as exc:
                raise _error("sandbox_child_wait_lost") from exc
            if observed_pid == pid:
                return _ExitObservation(reaped=True, status=status)
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise _error("sandbox_deadline_exceeded")
        sleeper(min(POLL_INTERVAL_SECONDS, remaining))


def _kill_and_reap_process_group(
    pid: int,
    observation: _ExitObservation | None = None,
) -> int:
    """Always kill the new process group and leader, then reap the leader."""

    cleanup_error: OSError | None = None
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as exc:
        cleanup_error = exc
    if observation is not None and observation.reaped:
        if observation.status is None:
            raise _error("sandbox_child_status_missing")
        if cleanup_error is not None:
            raise _error(
                "sandbox_process_group_cleanup_failed"
            ) from cleanup_error
        return os.waitstatus_to_exitcode(observation.status)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as exc:
        cleanup_error = cleanup_error or exc
    while True:
        try:
            reaped_pid, status = os.waitpid(pid, 0)
            if reaped_pid == pid:
                break
        except InterruptedError:
            continue
        except ChildProcessError as exc:
            raise _error("sandbox_child_reap_lost") from exc
    if cleanup_error is not None:
        raise _error("sandbox_process_group_cleanup_failed") from cleanup_error
    return os.waitstatus_to_exitcode(status)


def _read_bounded_spool(
    descriptor: int,
    *,
    maximum_bytes: int,
    field: str,
) -> bytes:
    try:
        size = os.fstat(descriptor).st_size
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    if size > maximum_bytes:
        raise _error(f"{field}_too_large")
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise _error(f"{field}_truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
    except QualificationSandboxError:
        raise
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    return b"".join(chunks)


def _supervise_command(
    *,
    command: Sequence[str],
    environment: Mapping[str, str],
    cwd: Path,
    request_bytes: bytes,
    scratch_root: Path,
    verifier_uid: int,
    verifier_gid: int,
    timeout_seconds: float,
    maximum_request_bytes: int,
    maximum_stdout_bytes: int,
    maximum_stderr_bytes: int,
    prepare: Callable[[], None],
    seccomp_filter: bytes | None,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> SandboxRunResult:
    if len(request_bytes) > maximum_request_bytes:
        raise _error("sandbox_request_too_large")
    if not command or not Path(command[0]).is_absolute():
        raise _error("sandbox_command_invalid")
    if not cwd.is_absolute():
        raise _error("sandbox_cwd_invalid")
    if set(environment) != set(FIXED_ENVIRONMENT_KEYS):
        raise _error("sandbox_environment_invalid")
    started = monotonic()
    deadline = started + timeout_seconds
    spools: list[_Spool] = []
    pid: int | None = None
    returncode: int | None = None
    observation: _ExitObservation | None = None
    try:
        for name in ("stdin", "stdout", "stderr"):
            spools.append(
                _create_spool(
                    scratch_root,
                    name=name,
                    verifier_uid=verifier_uid,
                    verifier_gid=verifier_gid,
                )
            )
        seccomp_spool: _Spool | None = None
        if seccomp_filter is not None:
            seccomp_spool = _create_spool(
                scratch_root,
                name="seccomp",
                verifier_uid=verifier_uid,
                verifier_gid=verifier_gid,
            )
            spools.append(seccomp_spool)
            _write_all(seccomp_spool.descriptor, seccomp_filter)
            os.lseek(seccomp_spool.descriptor, 0, os.SEEK_SET)
        _write_all(spools[0].descriptor, request_bytes)
        os.lseek(spools[0].descriptor, 0, os.SEEK_SET)
        if monotonic() >= deadline:
            raise _error("sandbox_deadline_exceeded")
        pid = _spawn_child(
            command=command,
            environment=environment,
            cwd=cwd,
            stdin_fd=spools[0].descriptor,
            stdout_fd=spools[1].descriptor,
            stderr_fd=spools[2].descriptor,
            seccomp_fd=(
                seccomp_spool.descriptor
                if seccomp_spool is not None
                else None
            ),
            prepare=prepare,
        )
        try:
            observation = _wait_until_exit(
                pid,
                deadline=deadline,
                monotonic=monotonic,
                sleeper=sleeper,
            )
        finally:
            try:
                returncode = _kill_and_reap_process_group(
                    pid,
                    observation,
                )
            finally:
                pid = None
        stdout = _read_bounded_spool(
            spools[1].descriptor,
            maximum_bytes=maximum_stdout_bytes,
            field="sandbox_stdout",
        )
        stderr = _read_bounded_spool(
            spools[2].descriptor,
            maximum_bytes=maximum_stderr_bytes,
            field="sandbox_stderr",
        )
        return SandboxRunResult(
            stdout=stdout,
            stderr=stderr,
            returncode=returncode,
            elapsed_seconds=max(0.0, monotonic() - started),
        )
    finally:
        if pid is not None:
            _kill_and_reap_process_group(pid)
        for spool in spools:
            try:
                os.close(spool.descriptor)
            except OSError:
                pass
            try:
                spool.path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise _error("sandbox_spool_cleanup_failed") from exc


def _encode_request(request: Mapping[str, Any], *, maximum: int) -> bytes:
    if not isinstance(request, Mapping):
        raise _error("sandbox_request_invalid")
    try:
        encoded = _canonical_json(dict(request)) + b"\n"
    except (TypeError, ValueError) as exc:
        raise _error("sandbox_request_invalid") from exc
    if len(encoded) > maximum:
        raise _error("sandbox_request_too_large")
    return encoded


def _run_validated_policy(
    policy: QualificationSandboxPolicy,
    request: Mapping[str, Any],
) -> SandboxRunResult:
    encoded_request = _encode_request(
        request,
        maximum=policy.maximum_request_bytes,
    )
    if policy.system == "Linux":
        command = build_linux_command(policy)
        seccomp_filter = build_linux_seccomp_filter()
    else:
        command = build_darwin_command(policy)
        seccomp_filter = None
    result = _supervise_command(
        command=command,
        environment=policy.fixed_environment(),
        cwd=policy.bundle_root,
        request_bytes=encoded_request,
        scratch_root=policy.scratch_root,
        verifier_uid=policy.verifier_uid,
        verifier_gid=policy.verifier_gid,
        timeout_seconds=policy.timeout_seconds,
        maximum_request_bytes=policy.maximum_request_bytes,
        maximum_stdout_bytes=policy.maximum_stdout_bytes,
        maximum_stderr_bytes=policy.maximum_stderr_bytes,
        prepare=lambda: _prepare_child_identity(policy),
        seccomp_filter=seccomp_filter,
    )
    _assert_scratch_empty(policy.scratch_root)
    _reject_authority_metadata(
        policy.scratch_root,
        field="sandbox_scratch",
    )
    return result


def launch_protected_verifier(
    policy: QualificationSandboxPolicy,
    request: Mapping[str, Any],
) -> SandboxRunResult:
    """Run only after a root-owned privileged-canary activation receipt exists."""

    if os.getuid() != 0 or os.geteuid() != 0:
        raise _error("sandbox_launcher_requires_root")
    _validate_policy_shape(policy)
    _validate_policy_runtime(policy)
    _read_activation_receipt(policy)
    return _run_validated_policy(policy, request)


def launch_privileged_canary_probe(
    policy: QualificationSandboxPolicy,
    request: Mapping[str, Any],
) -> SandboxRunResult:
    """Run the boundary before activation; never creates or blesses a receipt.

    The installer must independently test every assertion named in
    ``CANARY_ASSERTIONS`` and publish a canonical root-owned receipt only after
    all pass.  This function is intentionally root-only and has no signing or
    publication authority.
    """

    if os.getuid() != 0 or os.geteuid() != 0:
        raise _error("sandbox_canary_requires_root")
    _validate_policy_shape(policy)
    _validate_policy_runtime(policy)
    return _run_validated_policy(policy, request)
