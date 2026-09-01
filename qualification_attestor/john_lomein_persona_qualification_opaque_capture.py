"""Opaque, descriptor-relative persona-qualification evidence capture.

This module is intentionally ignorant of the evidence formats it copies.  It
imports only the standard library and the root-owned capture-plan contract; it
does not import YAML, the qualification runner, model adapters, or signing
code.  A source is either one fixed file or one complete directory tree, and
every selected byte is copied without semantic inspection.

The production coordinator does not activate this engine yet.  The public
entry point is nevertheless root-only so the security boundary can be tested
and installed before activation.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time
import unicodedata
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from qualification_attestor import (
    john_lomein_persona_qualification_capture_plan as capture_plan,
)


OPAQUE_CAPTURE_SCHEMA = "john-lomein.persona-opaque-capture.v1"
OPAQUE_CAPTURE_MANIFEST = "opaque-capture-manifest.json"
PRODUCTION_ACTIVATION = False

PRIVATE_SOURCE_DIRECTORY_MODE = 0o700
PRIVATE_SOURCE_FILE_MODE = 0o600
EXPORT_SOURCE_DIRECTORY_MODE = 0o750
EXPORT_SOURCE_FILE_MODE = 0o640
SEALED_DIRECTORY_MODE = 0o550
SEALED_FILE_MODE = 0o440
PROVISIONAL_DIRECTORY_MODE = 0o500
PROVISIONAL_FILE_MODE = 0o400

MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_DIRECTORY_INVENTORY_ENTRIES = (
    capture_plan.MAX_CAPTURE_FILES
    + capture_plan.MAX_CAPTURE_DIRECTORIES
    + capture_plan.MAX_PLAN_SOURCES
)
CAPTURE_NAME_RE = re.compile(
    r"^opaque-capture-[0-9a-f]{32}(?:\.building)?$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

MANIFEST_FIELDS = {
    "schema_version",
    "capture_policy_version",
    "capture_plan_sha256",
    "instance_slug",
    "captured_at_unix",
    "evidence_uid",
    "capture_uid",
    "verifier_gid",
    "limits",
    "lifecycle",
    "sources",
    "directories",
    "source_directories",
    "files",
    "file_count",
    "directory_count",
    "source_directory_count",
    "total_bytes",
}
FILE_FIELDS = {
    "path",
    "source_id",
    "source_class",
    "source_path",
    "source_relative_path",
    "source_uid",
    "source_mode",
    "source_identity_sha256",
    "size",
    "sha256",
}
SOURCE_DIRECTORY_FIELDS = {
    "path",
    "source_uid",
    "source_mode",
    "source_identity_sha256",
    "entry_count",
    "entries_sha256",
}


class OpaqueCaptureError(ValueError):
    """A stable, public-safe opaque-capture rejection."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _error(code: str) -> OpaqueCaptureError:
    return OpaqueCaptureError(code)


_LEASE_CONSTRUCTION_TOKEN = object()


class OpaqueCaptureLease:
    """Exclusive lifetime capability for one published opaque capture.

    The lease owns both the *same snapshot open-file description* locked
    before ``.building`` was renamed and the root-opened 0710 parent
    description whose flock is the actual liveness authority.  A verifier
    can open the 0550 snapshot, so its advisory lock is never trusted for
    orphan decisions.  The object is deliberately neither a mapping nor
    serializable.  The coordinator must keep it alive through verification,
    signing/publication, and cleanup, normally as a context manager.
    """

    __slots__ = (
        "_root_fd",
        "_parent_fd",
        "_snapshot_root",
        "_destination_parent",
        "_destination_parent_mode",
        "_capture_uid",
        "_verifier_gid",
        "_evidence_uid",
        "_capture_manifest_sha256",
        "_capture_plan_sha256",
        "_manifest_bytes_value",
    )

    def __init__(
        self,
        *,
        _token: object,
        root_fd: int,
        parent_fd: int,
        snapshot_root: Path,
        destination_parent: Path,
        destination_parent_mode: int,
        capture_uid: int,
        verifier_gid: int,
        evidence_uid: int,
        capture_manifest_sha256: str,
        capture_plan_sha256: str,
        manifest: Mapping[str, Any],
    ) -> None:
        if _token is not _LEASE_CONSTRUCTION_TOKEN:
            raise TypeError("OpaqueCaptureLease cannot be constructed directly")
        encoded_manifest = _manifest_bytes(manifest)
        os.set_inheritable(root_fd, False)
        os.set_inheritable(parent_fd, False)
        if os.get_inheritable(root_fd) or os.get_inheritable(parent_fd):
            raise _error("opaque_capture_lease_cloexec_failed")
        self._root_fd = root_fd
        self._parent_fd = parent_fd
        self._snapshot_root = snapshot_root
        self._destination_parent = destination_parent
        self._destination_parent_mode = destination_parent_mode
        self._capture_uid = capture_uid
        self._verifier_gid = verifier_gid
        self._evidence_uid = evidence_uid
        self._capture_manifest_sha256 = capture_manifest_sha256
        self._capture_plan_sha256 = capture_plan_sha256
        self._manifest_bytes_value = encoded_manifest

    @property
    def snapshot_root(self) -> Path:
        self._require_active()
        return self._snapshot_root

    @property
    def capture_manifest_sha256(self) -> str:
        self._require_active()
        return self._capture_manifest_sha256

    @property
    def capture_plan_sha256(self) -> str:
        self._require_active()
        return self._capture_plan_sha256

    @property
    def manifest(self) -> dict[str, Any]:
        self._require_active()
        value = _parse_manifest(self._manifest_bytes_value)
        if not isinstance(value, dict):
            raise _error("opaque_capture_lease_manifest_invalid")
        return value

    @property
    def active(self) -> bool:
        return self._root_fd >= 0 and self._parent_fd >= 0

    def _require_active(self) -> int:
        if self._root_fd < 0:
            raise _error("opaque_capture_lease_closed")
        return self._root_fd

    def _fileno_for_test(self) -> int:
        """Return the held descriptor for lifecycle tests only."""

        return self._require_active()

    def _parent_fileno_for_test(self) -> int:
        """Return the root-only admission descriptor for tests only."""

        self._require_active()
        return self._parent_fd

    def _object_identity_sha256_for_adoption(self) -> str:
        """Return the adoption identity of the exact retained directory."""

        descriptor = self._require_active()
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise _error("opaque_capture_adoption_object_unsafe")
        return _sha256(
            _canonical_json(
                [
                    int(info.st_dev),
                    int(info.st_ino),
                    int(stat.S_IFMT(info.st_mode)),
                ]
            )
        )

    def _relinquish_for_adoption(self) -> None:
        """Close authority descriptors without deleting the staged object.

        This is intentionally private and is used only by the short-lived v2
        capture child after it has emitted a digest-bound handoff record.  The
        root coordinator must already hold independent staging/final parent
        descriptors and must reap the entire child process group before
        adopting the object.
        """

        self._require_active()
        root_fd = self._root_fd
        parent_fd = self._parent_fd
        try:
            os.fsync(root_fd)
            os.fsync(parent_fd)
        except OSError as exc:
            raise _error("opaque_capture_adoption_fsync_failed") from exc
        os.close(root_fd)
        os.close(parent_fd)
        self._root_fd = -1
        self._parent_fd = -1

    def cleanup(self) -> None:
        cleanup_opaque_capture(self)

    def __enter__(self) -> OpaqueCaptureLease:
        self._require_active()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        del exc_type, exc, traceback
        self.cleanup()
        return False

    def __reduce__(self) -> Any:
        raise TypeError("OpaqueCaptureLease is not serializable")

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError("OpaqueCaptureLease is not serializable")

    def __getstate__(self) -> Any:
        raise TypeError("OpaqueCaptureLease is not serializable")

    def __copy__(self) -> Any:
        raise TypeError("OpaqueCaptureLease cannot be copied")

    def __deepcopy__(self, memo: Any) -> Any:
        del memo
        raise TypeError("OpaqueCaptureLease cannot be copied")

    def __del__(self) -> None:
        root_descriptor = getattr(self, "_root_fd", -1)
        parent_descriptor = getattr(self, "_parent_fd", -1)
        if root_descriptor >= 0:
            try:
                os.close(root_descriptor)
            except OSError:
                pass
            self._root_fd = -1
        if parent_descriptor >= 0:
            try:
                os.close(parent_descriptor)
            except OSError:
                pass
            self._parent_fd = -1


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _error("opaque_capture_manifest_not_canonical") from exc


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    raw = _canonical_json(manifest) + b"\n"
    if len(raw) > MAX_MANIFEST_BYTES:
        raise _error("opaque_capture_manifest_too_large")
    return raw


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _error("opaque_capture_manifest_duplicate_field")
        result[key] = value
    return result


def _parse_manifest(raw: bytes) -> Any:
    if not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise _error("opaque_capture_manifest_size_invalid")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _: (_ for _ in ()).throw(
                _error("opaque_capture_manifest_nonfinite")
            ),
        )
    except OpaqueCaptureError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _error("opaque_capture_manifest_invalid") from exc


def _absolute_path(value: Path | str, *, field: str) -> Path:
    text = os.fspath(value)
    if (
        not isinstance(text, str)
        or not text
        or len(text) > 4_096
        or "\x00" in text
        or any(ord(character) < 32 for character in text)
    ):
        raise _error(f"{field}_invalid")
    path = Path(text)
    if (
        not path.is_absolute()
        or "." in path.parts
        or ".." in path.parts
        or text != str(path)
    ):
        raise _error(f"{field}_invalid")
    return path


def _relative_path(
    value: Any,
    *,
    field: str,
    allow_empty: bool = False,
    maximum_depth: int = capture_plan.MAX_CAPTURE_DEPTH,
) -> str:
    if (
        not isinstance(value, str)
        or (not value and not allow_empty)
        or len(value) > 4_096
        or "\x00" in value
    ):
        raise _error(f"{field}_invalid")
    if not value and allow_empty:
        return ""
    path = Path(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or "." in path.parts
        or ".." in path.parts
        or any(not part for part in path.parts)
        or len(path.parts) > maximum_depth
    ):
        raise _error(f"{field}_invalid")
    for component in path.parts:
        _component(component, field=field)
    return value


def _component(value: str, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "/" in value
        or "\x00" in value
        or len(os.fsencode(value)) > 255
        or unicodedata.normalize("NFC", value) != value
        or any(ord(character) < 32 for character in value)
    ):
        raise _error(f"{field}_invalid")
    return value


def _path_identity(value: str) -> str:
    return unicodedata.normalize("NFC", value.rstrip(os.sep)).casefold()


def _paths_overlap(left: Path, right: Path) -> bool:
    left_text = _path_identity(str(left))
    right_text = _path_identity(str(right))
    return (
        left_text == right_text
        or left_text.startswith(right_text + os.sep)
        or right_text.startswith(left_text + os.sep)
    )


def _stat_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        getattr(
            info,
            "st_mtime_ns",
            int(info.st_mtime * 1_000_000_000),
        ),
        getattr(
            info,
            "st_ctime_ns",
            int(info.st_ctime * 1_000_000_000),
        ),
    )


def _identity_sha256(info: os.stat_result) -> str:
    return _sha256(_canonical_json(list(_stat_identity(info))))


def _entries_sha256(entries: list[str] | tuple[str, ...]) -> str:
    return _sha256(_canonical_json(list(entries)))


def _directory_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("opaque_capture_nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _read_file_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("opaque_capture_nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    return flags


def _lock_exclusive(
    descriptor: int,
    *,
    nonblocking: bool = False,
    field: str,
) -> bool:
    operation = fcntl.LOCK_EX
    if nonblocking:
        operation |= fcntl.LOCK_NB
    try:
        fcntl.flock(descriptor, operation)
    except BlockingIOError:
        if nonblocking:
            return False
        raise _error(f"{field}_lock_failed")
    except OSError as exc:
        if nonblocking and exc.errno in {errno.EACCES, errno.EAGAIN}:
            return False
        raise _error(f"{field}_lock_failed") from exc
    return True


def _reject_fd_metadata(descriptor: int, *, field: str) -> None:
    """Reject xattrs and authority-granting ACLs using the opened object."""

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
        attribute_bytes = libc.flistxattr(descriptor, None, 0, 0)
    else:
        libc.flistxattr.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        attribute_bytes = libc.flistxattr(descriptor, None, 0)
    if attribute_bytes < 0:
        raise _error(f"{field}_metadata_unreadable")
    attributes: set[bytes] = set()
    if attribute_bytes:
        buffer = ctypes.create_string_buffer(attribute_bytes)
        if sys.platform == "darwin":
            observed = libc.flistxattr(
                descriptor,
                buffer,
                attribute_bytes,
                0,
            )
        else:
            observed = libc.flistxattr(
                descriptor,
                buffer,
                attribute_bytes,
            )
        if observed != attribute_bytes:
            raise _error(f"{field}_metadata_changed")
        attributes = {
            name
            for name in bytes(buffer.raw[:observed]).split(b"\x00")
            if name
        }
    # These platform-managed labels add provenance or mandatory restrictions;
    # they cannot grant DAC access or supply parsed evidence. POSIX ACL,
    # capability, and arbitrary user attributes remain rejected.
    if sys.platform == "darwin":
        permitted = {b"com.apple.provenance"}
    elif sys.platform.startswith("linux"):
        permitted = {b"security.selinux"}
    else:
        permitted = set()
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
        acl_text = ctypes.string_at(text_pointer, length.value)
        if b":allow:" in acl_text:
            raise _error(f"{field}_acl_grants_unsupported")
    finally:
        if text_pointer:
            libc.acl_free(text_pointer)
        libc.acl_free(acl)


def _bounded_entries(
    descriptor: int,
    *,
    maximum: int,
    error_code: str,
) -> list[str]:
    if maximum < 0:
        raise _error(error_code)
    names: list[str] = []
    identities: set[str] = set()
    try:
        with os.scandir(descriptor) as iterator:
            for entry in iterator:
                if len(names) >= maximum:
                    raise _error(error_code)
                name = _component(
                    entry.name,
                    field="opaque_capture_source_entry",
                )
                identity = unicodedata.normalize("NFC", name).casefold()
                if identity in identities:
                    raise _error("opaque_capture_source_entry_alias")
                identities.add(identity)
                names.append(name)
    except OpaqueCaptureError:
        raise
    except OSError as exc:
        raise _error(error_code) from exc
    return sorted(names)


def _stable_directory_inventory(
    descriptor: int,
    *,
    maximum: int,
    field: str,
    error_code: str,
) -> tuple[os.stat_result, list[str]]:
    before = os.fstat(descriptor)
    _reject_fd_metadata(descriptor, field=field)
    entries = _bounded_entries(
        descriptor,
        maximum=maximum,
        error_code=error_code,
    )
    after = os.fstat(descriptor)
    _reject_fd_metadata(descriptor, field=field)
    if _stat_identity(before) != _stat_identity(after):
        raise _error(error_code)
    return after, entries


def _safe_ancestor(info: os.stat_result, *, evidence_uid: int) -> bool:
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, evidence_uid}:
        return False
    if not info.st_mode & 0o022:
        return True
    return bool(
        info.st_uid == 0
        and info.st_mode & stat.S_ISVTX
        and stat.S_ISDIR(info.st_mode)
    )


def _open_absolute_directory(
    path: Path,
    *,
    evidence_uid: int,
    final_uid: int,
    final_gid: int | None,
    final_mode: int,
    field: str,
) -> int:
    """Open every absolute component relative to its already-opened parent."""

    path = _absolute_path(path, field=field)
    descriptor = os.open("/", _directory_flags())
    try:
        components = path.parts[1:]
        if not components:
            info = os.fstat(descriptor)
            if (
                info.st_uid != final_uid
                or (
                    final_gid is not None
                    and info.st_gid != final_gid
                )
                or stat.S_IMODE(info.st_mode) != final_mode
            ):
                raise _error(f"{field}_unsafe")
            _reject_fd_metadata(descriptor, field=field)
            return descriptor
        for index, component in enumerate(components):
            _component(component, field=f"{field}_component")
            try:
                child = os.open(
                    component,
                    _directory_flags(),
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise _error(f"{field}_unreadable") from exc
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode):
                raise _error(f"{field}_unsafe")
            if index + 1 == len(components):
                if (
                    info.st_uid != final_uid
                    or (
                        final_gid is not None
                        and info.st_gid != final_gid
                    )
                    or stat.S_IMODE(info.st_mode) != final_mode
                ):
                    raise _error(f"{field}_unsafe")
                _reject_fd_metadata(descriptor, field=field)
            elif not _safe_ancestor(info, evidence_uid=evidence_uid):
                raise _error(f"{field}_ancestor_unsafe")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_source_parent(
    path: Path,
    *,
    evidence_uid: int,
    source_gid: int | None = None,
    source_directory_mode: int = PRIVATE_SOURCE_DIRECTORY_MODE,
    field: str,
) -> int:
    return _open_absolute_directory(
        path,
        evidence_uid=evidence_uid,
        final_uid=evidence_uid,
        final_gid=source_gid,
        final_mode=source_directory_mode,
        field=field,
    )


def _validate_source_file_info(
    info: os.stat_result,
    *,
    evidence_uid: int,
    source_gid: int | None = None,
    source_file_mode: int = PRIVATE_SOURCE_FILE_MODE,
    maximum_file_bytes: int,
    field: str,
) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != evidence_uid
        or (source_gid is not None and info.st_gid != source_gid)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != source_file_mode
        or not 0 <= info.st_size <= maximum_file_bytes
    ):
        raise _error(f"{field}_unsafe")


def _read_open_file(
    descriptor: int,
    *,
    maximum_bytes: int,
    field: str,
) -> tuple[bytes, str]:
    raw = bytearray()
    digest = hashlib.sha256()
    while len(raw) <= maximum_bytes:
        try:
            chunk = os.read(
                descriptor,
                min(64 * 1024, maximum_bytes + 1 - len(raw)),
            )
        except OSError as exc:
            raise _error(f"{field}_unreadable") from exc
        if not chunk:
            break
        raw.extend(chunk)
        digest.update(chunk)
    if len(raw) > maximum_bytes:
        raise _error(f"{field}_too_large")
    return bytes(raw), digest.hexdigest()


def _stable_open_sealed_file(
    parent_fd: int,
    name: str,
    *,
    owner_uid: int,
    verifier_gid: int,
    file_mode: int,
    maximum_file_bytes: int,
    field: str,
) -> tuple[bytes, str, os.stat_result]:
    """Read one exact descriptor-relative sealed regular file."""

    _component(name, field=field)
    try:
        named_before = os.stat(
            name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    if (
        not stat.S_ISREG(named_before.st_mode)
        or named_before.st_uid != owner_uid
        or named_before.st_gid != verifier_gid
        or named_before.st_nlink != 1
        or stat.S_IMODE(named_before.st_mode) != file_mode
        or not 0 <= named_before.st_size <= maximum_file_bytes
    ):
        raise _error(f"{field}_unsafe")
    try:
        descriptor = os.open(
            name,
            _read_file_flags(),
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _stat_identity(opened)
            != _stat_identity(named_before)
            or opened.st_uid != owner_uid
            or opened.st_gid != verifier_gid
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != file_mode
            or not 0 <= opened.st_size <= maximum_file_bytes
        ):
            raise _error(f"{field}_changed_during_read")
        _reject_fd_metadata(descriptor, field=field)
        raw, digest = _read_open_file(
            descriptor,
            maximum_bytes=maximum_file_bytes,
            field=field,
        )
        after = os.fstat(descriptor)
        try:
            named_after = os.stat(
                name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise _error(f"{field}_changed_during_read") from exc
        if (
            len(raw) != opened.st_size
            or not stat.S_ISREG(after.st_mode)
            or _stat_identity(opened) != _stat_identity(after)
            or _stat_identity(after) != _stat_identity(named_after)
        ):
            raise _error(f"{field}_changed_during_read")
        _reject_fd_metadata(descriptor, field=field)
        return raw, digest, after
    finally:
        os.close(descriptor)


def _stable_open_source_file(
    parent_fd: int,
    name: str,
    *,
    evidence_uid: int,
    source_gid: int | None = None,
    source_file_mode: int = PRIVATE_SOURCE_FILE_MODE,
    maximum_file_bytes: int,
    field: str,
) -> tuple[bytes, str, os.stat_result]:
    _component(name, field=field)
    try:
        descriptor = os.open(
            name,
            _read_file_flags(),
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    try:
        before = os.fstat(descriptor)
        _validate_source_file_info(
            before,
            evidence_uid=evidence_uid,
            source_gid=source_gid,
            source_file_mode=source_file_mode,
            maximum_file_bytes=maximum_file_bytes,
            field=field,
        )
        _reject_fd_metadata(descriptor, field=field)
        raw, digest = _read_open_file(
            descriptor,
            maximum_bytes=maximum_file_bytes,
            field=field,
        )
        after = os.fstat(descriptor)
        try:
            named = os.stat(
                name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise _error(f"{field}_changed_during_read") from exc
        if (
            len(raw) != before.st_size
            or _stat_identity(before) != _stat_identity(after)
            or _stat_identity(after) != _stat_identity(named)
        ):
            raise _error(f"{field}_changed_during_read")
        _reject_fd_metadata(descriptor, field=field)
        return raw, digest, after
    finally:
        os.close(descriptor)


def _write_new_file(
    parent_fd: int,
    name: str,
    raw: bytes,
    *,
    owner_uid: int,
) -> None:
    _component(name, field="opaque_capture_destination_file")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
    except OSError as exc:
        raise _error("opaque_capture_destination_write_failed") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != owner_uid
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise _error("opaque_capture_destination_unsafe")
        view = memoryview(raw)
        while view:
            try:
                written = os.write(descriptor, view)
            except OSError as exc:
                raise _error(
                    "opaque_capture_destination_write_failed"
                ) from exc
            if written <= 0:
                raise _error("opaque_capture_destination_write_failed")
            view = view[written:]
        os.fsync(descriptor)
        _reject_fd_metadata(
            descriptor,
            field="opaque_capture_destination_file",
        )
    finally:
        os.close(descriptor)


class _OpaqueCaptureBuilder:
    def __init__(
        self,
        *,
        root_fd: int,
        destination_parent_fd: int,
        plan: Mapping[str, Any],
        capture_uid: int,
        source_gid: int | None = None,
        source_directory_mode: int = PRIVATE_SOURCE_DIRECTORY_MODE,
        source_file_mode: int = PRIVATE_SOURCE_FILE_MODE,
    ):
        self.root_fd = root_fd
        self.plan = plan
        self.capture_uid = capture_uid
        self.evidence_uid = plan["evidence_uid"]
        self.source_gid = source_gid
        self.source_directory_mode = source_directory_mode
        self.source_file_mode = source_file_mode
        self.limits = plan["limits"]
        self.files: list[dict[str, Any]] = []
        self.directories: set[str] = set()
        self.source_directories: dict[
            str,
            tuple[tuple[int, ...], tuple[str, ...]],
        ] = {}
        self.total_bytes = 0
        self.source_inventory_entries = 0
        self._destination_spellings: dict[str, str] = {}
        root_info = os.fstat(root_fd)
        parent_info = os.fstat(destination_parent_fd)
        self._forbidden_source_directories = {
            (root_info.st_dev, root_info.st_ino),
            (parent_info.st_dev, parent_info.st_ino),
        }
        self._source_directory_aliases: dict[
            tuple[int, int],
            str,
        ] = {}

    def _register_destination(self, relative: str) -> None:
        identity = "/".join(
            unicodedata.normalize("NFC", part).casefold()
            for part in Path(relative).parts
        )
        previous = self._destination_spellings.get(identity)
        if previous is not None and previous != relative:
            raise _error("opaque_capture_destination_alias")
        self._destination_spellings[identity] = relative

    def ensure_directory(self, relative: str) -> int:
        relative = _relative_path(
            relative,
            field="opaque_capture_destination_directory",
            allow_empty=True,
            maximum_depth=self.limits["max_depth"],
        )
        descriptor = os.dup(self.root_fd)
        if not relative:
            return descriptor
        accumulated: list[str] = []
        try:
            for component in Path(relative).parts:
                accumulated.append(component)
                current = "/".join(accumulated)
                self._register_destination(current)
                if current not in self.directories:
                    if len(self.directories) >= self.limits["max_directories"]:
                        raise _error(
                            "opaque_capture_directory_count_exceeded"
                        )
                    try:
                        os.mkdir(
                            component,
                            0o700,
                            dir_fd=descriptor,
                        )
                    except FileExistsError:
                        pass
                    except OSError as exc:
                        raise _error(
                            "opaque_capture_destination_write_failed"
                        ) from exc
                    self.directories.add(current)
                try:
                    child = os.open(
                        component,
                        _directory_flags(),
                        dir_fd=descriptor,
                    )
                except OSError as exc:
                    raise _error(
                        "opaque_capture_destination_unreadable"
                    ) from exc
                info = os.fstat(child)
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != self.capture_uid
                    or stat.S_IMODE(info.st_mode) != 0o700
                ):
                    os.close(child)
                    raise _error("opaque_capture_destination_unsafe")
                _reject_fd_metadata(
                    child,
                    field="opaque_capture_destination_directory",
                )
                os.close(descriptor)
                descriptor = child
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def _write_evidence_file(
        self,
        *,
        raw: bytes,
        digest: str,
        info: os.stat_result,
        source: Mapping[str, Any],
        source_path: Path,
        source_relative_path: str,
        destination: str,
    ) -> None:
        destination = _relative_path(
            destination,
            field="opaque_capture_destination_file",
            maximum_depth=self.limits["max_depth"],
        )
        self._register_destination(destination)
        if len(self.files) >= self.limits["max_files"]:
            raise _error("opaque_capture_file_count_exceeded")
        if len(raw) > self.limits["max_file_bytes"]:
            raise _error("opaque_capture_file_too_large")
        if self.total_bytes + len(raw) > self.limits["max_bytes"]:
            raise _error("opaque_capture_size_exceeded")
        relative = Path(destination)
        parent = relative.parent.as_posix()
        if parent == ".":
            parent = ""
        parent_fd = self.ensure_directory(parent)
        try:
            _write_new_file(
                parent_fd,
                relative.name,
                raw,
                owner_uid=self.capture_uid,
            )
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        self.total_bytes += len(raw)
        self.files.append(
            {
                "path": destination,
                "source_id": source["source_id"],
                "source_class": source["source_class"],
                "source_path": str(source_path),
                "source_relative_path": source_relative_path,
                "source_uid": info.st_uid,
                "source_mode": stat.S_IMODE(info.st_mode),
                "source_identity_sha256": _identity_sha256(info),
                "size": len(raw),
                "sha256": digest,
            }
        )

    def _directory_before(
        self,
        descriptor: int,
        *,
        path: Path,
        field: str,
    ) -> tuple[os.stat_result, list[str]]:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(before.st_mode)
            or before.st_uid != self.evidence_uid
            or (
                self.source_gid is not None
                and before.st_gid != self.source_gid
            )
            or stat.S_IMODE(before.st_mode)
            != self.source_directory_mode
        ):
            raise _error(f"{field}_unsafe")
        inode_identity = (before.st_dev, before.st_ino)
        if inode_identity in self._forbidden_source_directories:
            raise _error("opaque_capture_source_destination_alias")
        previous_path = self._source_directory_aliases.get(inode_identity)
        if previous_path is not None and previous_path != str(path):
            raise _error("opaque_capture_source_directory_alias")
        self._source_directory_aliases[inode_identity] = str(path)
        _reject_fd_metadata(descriptor, field=field)
        remaining = (
            MAX_DIRECTORY_INVENTORY_ENTRIES
            - self.source_inventory_entries
        )
        entries = _bounded_entries(
            descriptor,
            maximum=remaining + 1,
            error_code="opaque_capture_source_inventory_exceeded",
        )
        if len(entries) > remaining:
            raise _error("opaque_capture_source_inventory_exceeded")
        return before, entries

    def _record_stable_directory(
        self,
        *,
        path: Path,
        descriptor: int,
        before: os.stat_result,
        entries_before: list[str],
        field: str,
    ) -> None:
        entries_after = _bounded_entries(
            descriptor,
            maximum=len(entries_before) + 1,
            error_code=f"{field}_changed_during_capture",
        )
        after = os.fstat(descriptor)
        _reject_fd_metadata(descriptor, field=field)
        if (
            entries_before != entries_after
            or _stat_identity(before) != _stat_identity(after)
        ):
            raise _error(f"{field}_changed_during_capture")
        key = str(path)
        existing = self.source_directories.get(key)
        value = (_stat_identity(after), tuple(entries_after))
        if existing is not None:
            if existing != value:
                raise _error(
                    "opaque_capture_source_directory_changed"
                )
            return
        if len(self.source_directories) >= self.limits["max_directories"]:
            raise _error(
                "opaque_capture_source_directory_count_exceeded"
            )
        self.source_inventory_entries += len(entries_after)
        if (
            self.source_inventory_entries
            > MAX_DIRECTORY_INVENTORY_ENTRIES
        ):
            raise _error("opaque_capture_source_inventory_exceeded")
        self.source_directories[key] = value

    def add_fixed_file(self, source: Mapping[str, Any]) -> None:
        source_path = Path(source["source_path"])
        destination = source["destination_path"]
        if len(Path(destination).parts) > self.limits["max_depth"]:
            raise _error("opaque_capture_tree_too_deep")
        parent_fd = _open_source_parent(
            source_path.parent,
            evidence_uid=self.evidence_uid,
            source_gid=self.source_gid,
            source_directory_mode=self.source_directory_mode,
            field=f"opaque_capture_source_{source['source_id']}_parent",
        )
        try:
            before, entries = self._directory_before(
                parent_fd,
                path=source_path.parent,
                field=f"opaque_capture_source_{source['source_id']}_parent",
            )
            raw, digest, info = _stable_open_source_file(
                parent_fd,
                source_path.name,
                evidence_uid=self.evidence_uid,
                source_gid=self.source_gid,
                source_file_mode=self.source_file_mode,
                maximum_file_bytes=self.limits["max_file_bytes"],
                field=f"opaque_capture_source_{source['source_id']}",
            )
            self._write_evidence_file(
                raw=raw,
                digest=digest,
                info=info,
                source=source,
                source_path=source_path,
                source_relative_path="",
                destination=destination,
            )
            self._record_stable_directory(
                path=source_path.parent,
                descriptor=parent_fd,
                before=before,
                entries_before=entries,
                field=f"opaque_capture_source_{source['source_id']}_parent",
            )
        finally:
            os.close(parent_fd)

    def add_tree(self, source: Mapping[str, Any]) -> None:
        source_root = Path(source["source_path"])
        destination_root = source["destination_path"]
        source_fd = _open_source_parent(
            source_root,
            evidence_uid=self.evidence_uid,
            source_gid=self.source_gid,
            source_directory_mode=self.source_directory_mode,
            field=f"opaque_capture_source_{source['source_id']}",
        )
        try:
            destination_fd = self.ensure_directory(destination_root)
            os.close(destination_fd)
            self._walk_tree(
                source=source,
                source_fd=source_fd,
                source_path=source_root,
                relative_source="",
                destination=destination_root,
                depth=len(Path(destination_root).parts),
            )
        finally:
            os.close(source_fd)

    def _walk_tree(
        self,
        *,
        source: Mapping[str, Any],
        source_fd: int,
        source_path: Path,
        relative_source: str,
        destination: str,
        depth: int,
    ) -> None:
        if depth > self.limits["max_depth"]:
            raise _error("opaque_capture_tree_too_deep")
        field = f"opaque_capture_source_{source['source_id']}_directory"
        before, entries = self._directory_before(
            source_fd,
            path=source_path,
            field=field,
        )
        for name in entries:
            try:
                named = os.stat(
                    name,
                    dir_fd=source_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise _error(f"{field}_entry_unreadable") from exc
            if named.st_uid != self.evidence_uid:
                raise _error(f"{field}_entry_owner_mismatch")
            child_source = source_path / name
            child_relative = (
                f"{relative_source}/{name}"
                if relative_source
                else name
            )
            child_destination = f"{destination}/{name}"
            if stat.S_ISDIR(named.st_mode):
                if (
                    (
                        self.source_gid is not None
                        and named.st_gid != self.source_gid
                    )
                    or stat.S_IMODE(named.st_mode)
                    != self.source_directory_mode
                ):
                    raise _error(f"{field}_entry_unsafe")
                try:
                    child_fd = os.open(
                        name,
                        _directory_flags(),
                        dir_fd=source_fd,
                    )
                except OSError as exc:
                    raise _error(f"{field}_entry_unreadable") from exc
                try:
                    opened = os.fstat(child_fd)
                    if _stat_identity(opened) != _stat_identity(named):
                        raise _error(f"{field}_entry_changed")
                    _reject_fd_metadata(child_fd, field=field)
                    destination_fd = self.ensure_directory(
                        child_destination
                    )
                    os.close(destination_fd)
                    self._walk_tree(
                        source=source,
                        source_fd=child_fd,
                        source_path=child_source,
                        relative_source=child_relative,
                        destination=child_destination,
                        depth=depth + 1,
                    )
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(named.st_mode):
                raw, digest, info = _stable_open_source_file(
                    source_fd,
                    name,
                    evidence_uid=self.evidence_uid,
                    source_gid=self.source_gid,
                    source_file_mode=self.source_file_mode,
                    maximum_file_bytes=self.limits["max_file_bytes"],
                    field=f"opaque_capture_source_{source['source_id']}_file",
                )
                self._write_evidence_file(
                    raw=raw,
                    digest=digest,
                    info=info,
                    source=source,
                    source_path=child_source,
                    source_relative_path=child_relative,
                    destination=child_destination,
                )
            else:
                raise _error(f"{field}_entry_unsafe")
        self._record_stable_directory(
            path=source_path,
            descriptor=source_fd,
            before=before,
            entries_before=entries,
            field=field,
        )

    def source_directory_manifest(self) -> list[dict[str, Any]]:
        return [
            {
                "path": path,
                "source_uid": identity[3],
                "source_mode": stat.S_IMODE(identity[2]),
                "source_identity_sha256": _sha256(
                    _canonical_json(list(identity))
                ),
                "entry_count": len(entries),
                "entries_sha256": _entries_sha256(entries),
            }
            for path, (identity, entries) in sorted(
                self.source_directories.items()
            )
        ]

    def revalidate_sources(self) -> None:
        """Prove the selected live namespace still matches the copied bytes."""

        for entry in self.files:
            _revalidate_one_source_file(
                entry,
                evidence_uid=self.evidence_uid,
                source_gid=self.source_gid,
                source_directory_mode=self.source_directory_mode,
                source_file_mode=self.source_file_mode,
                maximum_file_bytes=self.limits["max_file_bytes"],
            )
        for path, (expected_identity, expected_entries) in sorted(
            self.source_directories.items()
        ):
            descriptor = _open_source_parent(
                Path(path),
                evidence_uid=self.evidence_uid,
                source_gid=self.source_gid,
                source_directory_mode=self.source_directory_mode,
                field="opaque_capture_source_directory_revalidation",
            )
            try:
                info, entries = _stable_directory_inventory(
                    descriptor,
                    maximum=len(expected_entries) + 1,
                    field=(
                        "opaque_capture_source_directory_revalidation"
                    ),
                    error_code=(
                        "opaque_capture_source_directory_changed"
                    ),
                )
            finally:
                os.close(descriptor)
            if (
                tuple(entries) != expected_entries
                or _stat_identity(info) != expected_identity
            ):
                raise _error(
                    "opaque_capture_source_directory_changed"
                )


def _validate_capture_parent(
    destination_parent: Path,
    *,
    capture_uid: int,
    capture_gid: int,
    evidence_uid: int,
    parent_mode: int = 0o710,
) -> int:
    return _open_absolute_directory(
        destination_parent,
        evidence_uid=evidence_uid,
        final_uid=capture_uid,
        final_gid=capture_gid,
        final_mode=parent_mode,
        field="opaque_capture_destination_parent",
    )


def _preflight_sources(
    plan: Mapping[str, Any],
    *,
    destination_parent: Path,
    destination_parent_fd: int,
    source_gid: int | None = None,
    source_directory_mode: int = PRIVATE_SOURCE_DIRECTORY_MODE,
    source_file_mode: int = PRIVATE_SOURCE_FILE_MODE,
) -> None:
    parent_info = os.fstat(destination_parent_fd)
    identities: set[tuple[int, int]] = {
        (parent_info.st_dev, parent_info.st_ino)
    }
    for source in plan["sources"]:
        source_path = Path(source["source_path"])
        if _paths_overlap(source_path, destination_parent):
            raise _error("opaque_capture_source_destination_overlap")
        if source["kind"] == "tree":
            descriptor = _open_source_parent(
                source_path,
                evidence_uid=plan["evidence_uid"],
                source_gid=source_gid,
                source_directory_mode=source_directory_mode,
                field=f"opaque_capture_source_{source['source_id']}",
            )
        else:
            parent_fd = _open_source_parent(
                source_path.parent,
                evidence_uid=plan["evidence_uid"],
                source_gid=source_gid,
                source_directory_mode=source_directory_mode,
                field=f"opaque_capture_source_{source['source_id']}_parent",
            )
            try:
                try:
                    descriptor = os.open(
                        source_path.name,
                        _read_file_flags(),
                        dir_fd=parent_fd,
                    )
                except OSError as exc:
                    raise _error(
                        f"opaque_capture_source_"
                        f"{source['source_id']}_unreadable"
                    ) from exc
            finally:
                os.close(parent_fd)
        try:
            if source["kind"] != "tree":
                info = os.fstat(descriptor)
                _validate_source_file_info(
                    info,
                    evidence_uid=plan["evidence_uid"],
                    source_gid=source_gid,
                    source_file_mode=source_file_mode,
                    maximum_file_bytes=plan["limits"][
                        "max_file_bytes"
                    ],
                    field=(
                        f"opaque_capture_source_"
                        f"{source['source_id']}"
                    ),
                )
                _reject_fd_metadata(
                    descriptor,
                    field=(
                        f"opaque_capture_source_"
                        f"{source['source_id']}"
                    ),
                )
            info = os.fstat(descriptor)
            identity = (info.st_dev, info.st_ino)
            if identity in identities:
                raise _error("opaque_capture_source_alias")
            identities.add(identity)
        finally:
            os.close(descriptor)


def _recursive_seal(
    descriptor: int,
    *,
    capture_uid: int,
    capture_gid: int,
    directory_mode: int,
    file_mode: int,
    counters: dict[str, int],
) -> None:
    entries = _bounded_entries(
        descriptor,
        maximum=(
            capture_plan.MAX_CAPTURE_FILES
            + capture_plan.MAX_CAPTURE_DIRECTORIES
            + 1
            - counters["entries"]
        ),
        error_code="opaque_capture_destination_inventory_exceeded",
    )
    for name in entries:
        try:
            info = os.stat(
                name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise _error(
                "opaque_capture_destination_unreadable"
            ) from exc
        counters["entries"] += 1
        if (
            counters["entries"]
            > capture_plan.MAX_CAPTURE_FILES
            + capture_plan.MAX_CAPTURE_DIRECTORIES
            + 1
        ):
            raise _error("opaque_capture_destination_inventory_exceeded")
        if stat.S_ISDIR(info.st_mode):
            try:
                child = os.open(
                    name,
                    _directory_flags(),
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise _error(
                    "opaque_capture_destination_unreadable"
                ) from exc
            try:
                opened = os.fstat(child)
                if (
                    _stat_identity(opened) != _stat_identity(info)
                    or opened.st_uid != capture_uid
                    or stat.S_IMODE(opened.st_mode) != 0o700
                ):
                    raise _error("opaque_capture_destination_unsafe")
                _recursive_seal(
                    child,
                    capture_uid=capture_uid,
                    capture_gid=capture_gid,
                    directory_mode=directory_mode,
                    file_mode=file_mode,
                    counters=counters,
                )
                os.fchown(child, capture_uid, capture_gid)
                os.fchmod(child, directory_mode)
                _reject_fd_metadata(
                    child,
                    field="opaque_capture_sealed_directory",
                )
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode):
            try:
                child = os.open(
                    name,
                    _read_file_flags(),
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise _error(
                    "opaque_capture_destination_unreadable"
                ) from exc
            try:
                opened = os.fstat(child)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or _stat_identity(opened) != _stat_identity(info)
                    or opened.st_uid != capture_uid
                    or opened.st_nlink != 1
                    or stat.S_IMODE(opened.st_mode) != 0o600
                ):
                    raise _error("opaque_capture_destination_unsafe")
                os.fchown(child, capture_uid, capture_gid)
                os.fchmod(child, file_mode)
                _reject_fd_metadata(
                    child,
                    field="opaque_capture_sealed_file",
                )
            finally:
                os.close(child)
        else:
            raise _error("opaque_capture_destination_entry_unsafe")
    os.fsync(descriptor)


def _seal_root(
    root_fd: int,
    *,
    capture_uid: int,
    capture_gid: int,
    directory_mode: int = SEALED_DIRECTORY_MODE,
    file_mode: int = SEALED_FILE_MODE,
) -> None:
    _recursive_seal(
        root_fd,
        capture_uid=capture_uid,
        capture_gid=capture_gid,
        directory_mode=directory_mode,
        file_mode=file_mode,
        counters={"entries": 0},
    )
    os.fchown(root_fd, capture_uid, capture_gid)
    os.fchmod(root_fd, directory_mode)
    _reject_fd_metadata(root_fd, field="opaque_capture_sealed_root")
    os.fsync(root_fd)


def _directory_record_matches(
    entry: Mapping[str, Any],
    *,
    evidence_uid: int,
    source_directory_mode: int = PRIVATE_SOURCE_DIRECTORY_MODE,
) -> bool:
    return (
        set(entry) == SOURCE_DIRECTORY_FIELDS
        and isinstance(entry.get("path"), str)
        and Path(entry["path"]).is_absolute()
        and type(entry.get("source_uid")) is int
        and entry.get("source_uid") == evidence_uid
        and type(entry.get("source_mode")) is int
        and entry.get("source_mode") == source_directory_mode
        and type(entry.get("entry_count")) is int
        and 0 <= entry["entry_count"] <= MAX_DIRECTORY_INVENTORY_ENTRIES
        and isinstance(entry.get("source_identity_sha256"), str)
        and bool(SHA256_RE.fullmatch(entry["source_identity_sha256"]))
        and isinstance(entry.get("entries_sha256"), str)
        and bool(SHA256_RE.fullmatch(entry["entries_sha256"]))
    )


def _source_for_file(
    entry: Mapping[str, Any],
    plan_sources: Mapping[str, Mapping[str, Any]],
    *,
    maximum_depth: int,
) -> Mapping[str, Any]:
    source_id = entry.get("source_id")
    source = plan_sources.get(source_id) if isinstance(source_id, str) else None
    if source is None or entry.get("source_class") != source["source_class"]:
        raise _error("opaque_capture_manifest_file_source_unbound")
    source_relative = _relative_path(
        entry.get("source_relative_path"),
        field="opaque_capture_manifest_source_relative_path",
        allow_empty=True,
        maximum_depth=maximum_depth,
    )
    source_path = _absolute_path(
        entry.get("source_path"),
        field="opaque_capture_manifest_file_source_path",
    )
    destination = _relative_path(
        entry.get("path"),
        field="opaque_capture_manifest_file_path",
        maximum_depth=maximum_depth,
    )
    if source["kind"] == "file":
        if (
            source_relative
            or source_path != Path(source["source_path"])
            or destination != source["destination_path"]
        ):
            raise _error("opaque_capture_manifest_file_source_unbound")
    else:
        if not source_relative:
            raise _error("opaque_capture_manifest_file_source_unbound")
        if (
            source_path
            != Path(source["source_path"]) / source_relative
            or destination
            != f"{source['destination_path']}/{source_relative}"
        ):
            raise _error("opaque_capture_manifest_file_source_unbound")
    return source


def _validate_manifest(
    manifest: Any,
    *,
    plan: Mapping[str, Any],
    plan_sha256: str,
    capture_uid: int,
    verifier_gid: int,
    source_directory_mode: int = PRIVATE_SOURCE_DIRECTORY_MODE,
    source_file_mode: int = PRIVATE_SOURCE_FILE_MODE,
) -> dict[str, Any]:
    if (
        not isinstance(manifest, dict)
        or set(manifest) != MANIFEST_FIELDS
        or manifest.get("schema_version") != OPAQUE_CAPTURE_SCHEMA
        or manifest.get("capture_policy_version")
        != capture_plan.CAPTURE_POLICY_VERSION
        or manifest.get("capture_plan_sha256") != plan_sha256
        or manifest.get("instance_slug") != plan["instance_slug"]
        or type(manifest.get("evidence_uid")) is not int
        or manifest.get("evidence_uid") != plan["evidence_uid"]
        or type(manifest.get("capture_uid")) is not int
        or manifest.get("capture_uid") != capture_uid
        or type(manifest.get("verifier_gid")) is not int
        or manifest.get("verifier_gid") != verifier_gid
        or not isinstance(manifest.get("limits"), dict)
        or manifest.get("limits") != plan["limits"]
        or any(
            type(value) is not int
            for value in manifest["limits"].values()
        )
        or not isinstance(manifest.get("lifecycle"), dict)
        or manifest.get("lifecycle") != plan["lifecycle"]
        or manifest.get("sources") != plan["sources"]
        or type(manifest.get("captured_at_unix")) is not int
        or not 1 <= manifest["captured_at_unix"] <= (1 << 53) - 1
    ):
        raise _error("opaque_capture_manifest_schema_invalid")

    files = manifest.get("files")
    directories = manifest.get("directories")
    source_directories = manifest.get("source_directories")
    if (
        not isinstance(files, list)
        or not isinstance(directories, list)
        or not isinstance(source_directories, list)
        or len(files) > plan["limits"]["max_files"]
        or len(directories) > plan["limits"]["max_directories"]
        or len(source_directories) > plan["limits"]["max_directories"]
        or type(manifest.get("file_count")) is not int
        or manifest.get("file_count") != len(files)
        or type(manifest.get("directory_count")) is not int
        or manifest.get("directory_count") != len(directories)
        or type(manifest.get("source_directory_count")) is not int
        or manifest.get("source_directory_count")
        != len(source_directories)
        or type(manifest.get("total_bytes")) is not int
        or not 0 <= manifest["total_bytes"] <= plan["limits"]["max_bytes"]
    ):
        raise _error("opaque_capture_manifest_inventory_invalid")

    previous = ""
    source_paths: set[str] = set()
    for entry in source_directories:
        if (
            not isinstance(entry, dict)
            or not _directory_record_matches(
                entry,
                evidence_uid=plan["evidence_uid"],
                source_directory_mode=source_directory_mode,
            )
            or entry["path"] <= previous
        ):
            raise _error(
                "opaque_capture_manifest_source_directory_invalid"
            )
        _absolute_path(
            entry["path"],
            field="opaque_capture_manifest_source_directory_path",
        )
        if entry["path"] in source_paths:
            raise _error(
                "opaque_capture_manifest_source_directory_invalid"
            )
        source_paths.add(entry["path"])
        previous = entry["path"]

    previous = ""
    directory_set: set[str] = set()
    for relative in directories:
        relative = _relative_path(
            relative,
            field="opaque_capture_manifest_directory_path",
            maximum_depth=plan["limits"]["max_depth"],
        )
        if relative <= previous or relative in directory_set:
            raise _error("opaque_capture_manifest_directory_invalid")
        directory_set.add(relative)
        previous = relative

    plan_sources = {
        source["source_id"]: source for source in plan["sources"]
    }
    fixed_parent_paths = {
        str(Path(source["source_path"]).parent)
        for source in plan["sources"]
        if source["kind"] == "file"
    }
    tree_sources = [
        source for source in plan["sources"] if source["kind"] == "tree"
    ]
    required_source_directories = set(fixed_parent_paths)
    required_source_directories.update(
        source["source_path"] for source in tree_sources
    )
    if not required_source_directories.issubset(source_paths):
        raise _error(
            "opaque_capture_manifest_source_directory_missing"
        )
    for source_directory in source_paths:
        if source_directory in fixed_parent_paths:
            continue
        matches: list[tuple[Mapping[str, Any], Path]] = []
        candidate = Path(source_directory)
        for source in tree_sources:
            root = Path(source["source_path"])
            try:
                relative = candidate.relative_to(root)
            except ValueError:
                continue
            matches.append((source, relative))
        if len(matches) != 1:
            raise _error(
                "opaque_capture_manifest_source_directory_unbound"
            )
        source, relative = matches[0]
        expected_destination = source["destination_path"]
        if relative.parts:
            expected_destination = (
                f"{expected_destination}/{relative.as_posix()}"
            )
        if expected_destination not in directory_set:
            raise _error(
                "opaque_capture_manifest_source_directory_unbound"
            )
    for source in tree_sources:
        destination_root = source["destination_path"]
        for destination in directory_set:
            if destination == destination_root:
                relative = ""
            elif destination.startswith(destination_root + "/"):
                relative = destination[len(destination_root) + 1 :]
            else:
                continue
            source_directory = source["source_path"]
            if relative:
                source_directory = str(
                    Path(source_directory) / relative
                )
            if source_directory not in source_paths:
                raise _error(
                    "opaque_capture_manifest_source_directory_missing"
                )

    previous = ""
    file_paths: set[str] = set()
    total_bytes = 0
    seen_fixed_sources: set[str] = set()
    for entry in files:
        if (
            not isinstance(entry, dict)
            or set(entry) != FILE_FIELDS
            or not isinstance(entry.get("path"), str)
            or entry["path"] <= previous
            or entry["path"] in file_paths
            or type(entry.get("source_uid")) is not int
            or entry.get("source_uid") != plan["evidence_uid"]
            or type(entry.get("source_mode")) is not int
            or entry.get("source_mode") != source_file_mode
            or type(entry.get("size")) is not int
            or not 0 <= entry["size"] <= plan["limits"]["max_file_bytes"]
            or not isinstance(entry.get("sha256"), str)
            or not SHA256_RE.fullmatch(entry["sha256"])
            or not isinstance(entry.get("source_identity_sha256"), str)
            or not SHA256_RE.fullmatch(
                entry["source_identity_sha256"]
            )
        ):
            raise _error("opaque_capture_manifest_file_invalid")
        source = _source_for_file(
            entry,
            plan_sources,
            maximum_depth=plan["limits"]["max_depth"],
        )
        if str(Path(entry["source_path"]).parent) not in source_paths:
            raise _error(
                "opaque_capture_manifest_source_directory_missing"
            )
        if source["kind"] == "file":
            if source["source_id"] in seen_fixed_sources:
                raise _error("opaque_capture_manifest_file_duplicate")
            seen_fixed_sources.add(source["source_id"])
        file_paths.add(entry["path"])
        previous = entry["path"]
        total_bytes += entry["size"]
    expected_fixed = {
        source["source_id"]
        for source in plan["sources"]
        if source["kind"] == "file"
    }
    if (
        seen_fixed_sources != expected_fixed
        or total_bytes != manifest["total_bytes"]
    ):
        raise _error("opaque_capture_manifest_file_inventory_invalid")

    for source in plan["sources"]:
        destination = source["destination_path"]
        if source["kind"] == "tree":
            if destination not in directory_set:
                raise _error(
                    "opaque_capture_manifest_tree_destination_missing"
                )
        else:
            parent = Path(destination).parent.as_posix()
            if parent != "." and parent not in directory_set:
                raise _error(
                    "opaque_capture_manifest_file_parent_missing"
                )
    return manifest


def _walk_sealed_inventory(
    descriptor: int,
    *,
    prefix: str,
    capture_uid: int,
    snapshot_gid: int,
    directory_mode: int,
    file_mode: int,
    plan: Mapping[str, Any],
    observed_files: dict[str, tuple[int, str]],
    observed_directories: set[str],
    counters: dict[str, int],
) -> None:
    directory_before = os.fstat(descriptor)
    _reject_fd_metadata(
        descriptor,
        field="opaque_capture_sealed_directory",
    )
    remaining = (
        plan["limits"]["max_files"]
        + plan["limits"]["max_directories"]
        + 1
        - counters["entries"]
    )
    entries = _bounded_entries(
        descriptor,
        maximum=remaining + 1,
        error_code="opaque_capture_sealed_inventory_exceeded",
    )
    if len(entries) > remaining:
        raise _error("opaque_capture_sealed_inventory_exceeded")
    for name in entries:
        relative = f"{prefix}/{name}" if prefix else name
        try:
            named = os.stat(
                name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise _error("opaque_capture_sealed_entry_unreadable") from exc
        counters["entries"] += 1
        if stat.S_ISDIR(named.st_mode):
            if (
                named.st_uid != capture_uid
                or named.st_gid != snapshot_gid
                or stat.S_IMODE(named.st_mode) != directory_mode
            ):
                raise _error("opaque_capture_sealed_directory_unsafe")
            try:
                child = os.open(
                    name,
                    _directory_flags(),
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise _error(
                    "opaque_capture_sealed_directory_unreadable"
                ) from exc
            try:
                opened = os.fstat(child)
                if _stat_identity(opened) != _stat_identity(named):
                    raise _error(
                        "opaque_capture_sealed_directory_changed"
                    )
                _reject_fd_metadata(
                    child,
                    field="opaque_capture_sealed_directory",
                )
                observed_directories.add(relative)
                _walk_sealed_inventory(
                    child,
                    prefix=relative,
                    capture_uid=capture_uid,
                    snapshot_gid=snapshot_gid,
                    directory_mode=directory_mode,
                    file_mode=file_mode,
                    plan=plan,
                    observed_files=observed_files,
                    observed_directories=observed_directories,
                    counters=counters,
                )
            finally:
                os.close(child)
        elif stat.S_ISREG(named.st_mode):
            if (
                named.st_uid != capture_uid
                or named.st_gid != snapshot_gid
                or named.st_nlink != 1
                or stat.S_IMODE(named.st_mode) != file_mode
            ):
                raise _error("opaque_capture_sealed_file_unsafe")
            try:
                child = os.open(
                    name,
                    _read_file_flags(),
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise _error(
                    "opaque_capture_sealed_file_unreadable"
                ) from exc
            try:
                opened = os.fstat(child)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or _stat_identity(opened)
                    != _stat_identity(named)
                ):
                    raise _error("opaque_capture_sealed_file_changed")
                _reject_fd_metadata(
                    child,
                    field="opaque_capture_sealed_file",
                )
                maximum = (
                    MAX_MANIFEST_BYTES
                    if relative == OPAQUE_CAPTURE_MANIFEST
                    else plan["limits"]["max_file_bytes"]
                )
                raw, digest = _read_open_file(
                    child,
                    maximum_bytes=maximum,
                    field="opaque_capture_sealed_file",
                )
                after = os.fstat(child)
                if (
                    len(raw) != opened.st_size
                    or _stat_identity(opened) != _stat_identity(after)
                ):
                    raise _error("opaque_capture_sealed_file_changed")
                observed_files[relative] = (len(raw), digest)
            finally:
                os.close(child)
        else:
            raise _error("opaque_capture_sealed_entry_unsafe")
    directory_after = os.fstat(descriptor)
    _reject_fd_metadata(
        descriptor,
        field="opaque_capture_sealed_directory",
    )
    if _stat_identity(directory_before) != _stat_identity(directory_after):
        raise _error("opaque_capture_sealed_directory_changed")


def verify_sealed_opaque_capture(
    snapshot_root: Path,
    *,
    plan: Mapping[str, Any],
    expected_plan_sha256: str,
    expected_capture_uid: int,
    expected_verifier_gid: int,
    expected_manifest_sha256: str | None = None,
    expected_manifest_capture_uid: int | None = None,
    expected_snapshot_gid: int | None = None,
    expected_directory_mode: int = SEALED_DIRECTORY_MODE,
    expected_file_mode: int = SEALED_FILE_MODE,
    expected_source_directory_mode: int = PRIVATE_SOURCE_DIRECTORY_MODE,
    expected_source_file_mode: int = PRIVATE_SOURCE_FILE_MODE,
) -> dict[str, Any]:
    """Verify the exact sealed snapshot inventory against its installed plan."""

    manifest_capture_uid = (
        expected_capture_uid
        if expected_manifest_capture_uid is None
        else expected_manifest_capture_uid
    )
    snapshot_gid = (
        expected_verifier_gid
        if expected_snapshot_gid is None
        else expected_snapshot_gid
    )
    if (
        type(expected_capture_uid) is not int
        or expected_capture_uid < 0
        or type(manifest_capture_uid) is not int
        or manifest_capture_uid < 0
        or type(expected_verifier_gid) is not int
        or expected_verifier_gid < 1
        or type(snapshot_gid) is not int
        or snapshot_gid < 1
        or type(expected_directory_mode) is not int
        or expected_directory_mode not in {
            SEALED_DIRECTORY_MODE,
            PROVISIONAL_DIRECTORY_MODE,
        }
        or type(expected_file_mode) is not int
        or expected_file_mode not in {
            SEALED_FILE_MODE,
            PROVISIONAL_FILE_MODE,
        }
        or type(expected_source_directory_mode) is not int
        or expected_source_directory_mode not in {
            PRIVATE_SOURCE_DIRECTORY_MODE,
            EXPORT_SOURCE_DIRECTORY_MODE,
        }
        or type(expected_source_file_mode) is not int
        or expected_source_file_mode not in {
            PRIVATE_SOURCE_FILE_MODE,
            EXPORT_SOURCE_FILE_MODE,
        }
        or (
            (expected_source_directory_mode, expected_source_file_mode)
            not in {
                (
                    PRIVATE_SOURCE_DIRECTORY_MODE,
                    PRIVATE_SOURCE_FILE_MODE,
                ),
                (
                    EXPORT_SOURCE_DIRECTORY_MODE,
                    EXPORT_SOURCE_FILE_MODE,
                ),
            }
        )
        or (
            (expected_directory_mode, expected_file_mode)
            not in {
                (SEALED_DIRECTORY_MODE, SEALED_FILE_MODE),
                (
                    PROVISIONAL_DIRECTORY_MODE,
                    PROVISIONAL_FILE_MODE,
                ),
            }
        )
        or (
            expected_manifest_sha256 is not None
            and (
                not isinstance(expected_manifest_sha256, str)
                or not SHA256_RE.fullmatch(expected_manifest_sha256)
            )
        )
    ):
        raise _error("opaque_capture_expected_identity_invalid")
    normalized = capture_plan.normalize_capture_plan(plan)
    actual_plan_sha256 = capture_plan.capture_plan_sha256(normalized)
    if (
        not isinstance(expected_plan_sha256, str)
        or not SHA256_RE.fullmatch(expected_plan_sha256)
        or actual_plan_sha256 != expected_plan_sha256
    ):
        raise _error("opaque_capture_plan_digest_mismatch")
    root = _absolute_path(snapshot_root, field="opaque_capture_snapshot_root")
    descriptor = _open_absolute_directory(
        root,
        evidence_uid=normalized["evidence_uid"],
        final_uid=expected_capture_uid,
        final_gid=snapshot_gid,
        final_mode=expected_directory_mode,
        field="opaque_capture_sealed_root",
    )
    try:
        observed_files: dict[str, tuple[int, str]] = {}
        observed_directories: set[str] = set()
        _walk_sealed_inventory(
            descriptor,
            prefix="",
            capture_uid=expected_capture_uid,
            snapshot_gid=snapshot_gid,
            directory_mode=expected_directory_mode,
            file_mode=expected_file_mode,
            plan=normalized,
            observed_files=observed_files,
            observed_directories=observed_directories,
            counters={"entries": 0},
        )
        raw_manifest, _, _ = _stable_open_sealed_file(
            descriptor,
            OPAQUE_CAPTURE_MANIFEST,
            owner_uid=expected_capture_uid,
            verifier_gid=snapshot_gid,
            file_mode=expected_file_mode,
            maximum_file_bytes=MAX_MANIFEST_BYTES,
            field="opaque_capture_manifest",
        )
    finally:
        os.close(descriptor)
    manifest = _parse_manifest(raw_manifest)
    manifest = _validate_manifest(
        manifest,
        plan=normalized,
        plan_sha256=actual_plan_sha256,
        capture_uid=manifest_capture_uid,
        verifier_gid=expected_verifier_gid,
        source_directory_mode=expected_source_directory_mode,
        source_file_mode=expected_source_file_mode,
    )
    canonical = _manifest_bytes(manifest)
    if raw_manifest != canonical:
        raise _error("opaque_capture_manifest_encoding_invalid")
    manifest_sha256 = _sha256(_canonical_json(manifest))
    if (
        expected_manifest_sha256 is not None
        and manifest_sha256 != expected_manifest_sha256
    ):
        raise _error("opaque_capture_manifest_digest_mismatch")
    expected_files = {
        entry["path"]: (entry["size"], entry["sha256"])
        for entry in manifest["files"]
    }
    expected_files[OPAQUE_CAPTURE_MANIFEST] = (
        len(raw_manifest),
        _sha256(raw_manifest),
    )
    if (
        observed_files != expected_files
        or observed_directories != set(manifest["directories"])
    ):
        raise _error("opaque_capture_sealed_inventory_mismatch")
    return manifest


def _revalidate_one_source_file(
    entry: Mapping[str, Any],
    *,
    evidence_uid: int,
    source_gid: int | None = None,
    source_directory_mode: int = PRIVATE_SOURCE_DIRECTORY_MODE,
    source_file_mode: int = PRIVATE_SOURCE_FILE_MODE,
    maximum_file_bytes: int,
) -> None:
    path = _absolute_path(
        entry["source_path"],
        field="opaque_capture_live_source_file_path",
    )
    parent_fd = _open_source_parent(
        path.parent,
        evidence_uid=evidence_uid,
        source_gid=source_gid,
        source_directory_mode=source_directory_mode,
        field="opaque_capture_live_source_file_parent",
    )
    try:
        raw, digest, info = _stable_open_source_file(
            parent_fd,
            path.name,
            evidence_uid=evidence_uid,
            source_gid=source_gid,
            source_file_mode=source_file_mode,
            maximum_file_bytes=maximum_file_bytes,
            field="opaque_capture_live_source_file",
        )
    finally:
        os.close(parent_fd)
    del raw
    if (
        digest != entry["sha256"]
        or _identity_sha256(info) != entry["source_identity_sha256"]
    ):
        raise _error("opaque_capture_live_source_file_changed")


def revalidate_live_opaque_sources(
    snapshot_root: Path,
    *,
    plan: Mapping[str, Any],
    expected_plan_sha256: str,
    expected_capture_uid: int,
    expected_verifier_gid: int,
    expected_manifest_sha256: str,
    expected_manifest_capture_uid: int | None = None,
    expected_snapshot_gid: int | None = None,
    expected_directory_mode: int = SEALED_DIRECTORY_MODE,
    expected_file_mode: int = SEALED_FILE_MODE,
    source_gid: int | None = None,
    source_directory_mode: int = PRIVATE_SOURCE_DIRECTORY_MODE,
    source_file_mode: int = PRIVATE_SOURCE_FILE_MODE,
) -> dict[str, Any]:
    """Recheck every live byte and directory identity after verifier exit."""

    normalized = capture_plan.normalize_capture_plan(plan)
    manifest = verify_sealed_opaque_capture(
        snapshot_root,
        plan=normalized,
        expected_plan_sha256=expected_plan_sha256,
        expected_capture_uid=expected_capture_uid,
        expected_verifier_gid=expected_verifier_gid,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_manifest_capture_uid=expected_manifest_capture_uid,
        expected_snapshot_gid=expected_snapshot_gid,
        expected_directory_mode=expected_directory_mode,
        expected_file_mode=expected_file_mode,
        expected_source_directory_mode=source_directory_mode,
        expected_source_file_mode=source_file_mode,
    )
    for entry in manifest["files"]:
        _revalidate_one_source_file(
            entry,
            evidence_uid=normalized["evidence_uid"],
            source_gid=source_gid,
            source_directory_mode=source_directory_mode,
            source_file_mode=source_file_mode,
            maximum_file_bytes=normalized["limits"]["max_file_bytes"],
        )
    for entry in manifest["source_directories"]:
        path = _absolute_path(
            entry["path"],
            field="opaque_capture_live_source_directory_path",
        )
        descriptor = _open_source_parent(
            path,
            evidence_uid=normalized["evidence_uid"],
            source_gid=source_gid,
            source_directory_mode=source_directory_mode,
            field="opaque_capture_live_source_directory",
        )
        try:
            info, entries = _stable_directory_inventory(
                descriptor,
                maximum=entry["entry_count"] + 1,
                field="opaque_capture_live_source_directory",
                error_code="opaque_capture_live_source_directory_changed",
            )
        finally:
            os.close(descriptor)
        if (
            len(entries) != entry["entry_count"]
            or _entries_sha256(entries) != entry["entries_sha256"]
            or _identity_sha256(info)
            != entry["source_identity_sha256"]
        ):
            raise _error("opaque_capture_live_source_directory_changed")
    return manifest


def _recursive_cleanup(
    descriptor: int,
    *,
    capture_uid: int,
    counters: dict[str, int],
) -> None:
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != capture_uid:
        raise _error("opaque_capture_cleanup_unsafe")
    os.fchmod(descriptor, 0o700)
    entries = _bounded_entries(
        descriptor,
        maximum=(
            capture_plan.MAX_CAPTURE_FILES
            + capture_plan.MAX_CAPTURE_DIRECTORIES
            + 1
            - counters["entries"]
        ),
        error_code="opaque_capture_cleanup_inventory_exceeded",
    )
    for name in entries:
        named = os.stat(
            name,
            dir_fd=descriptor,
            follow_symlinks=False,
        )
        counters["entries"] += 1
        if named.st_uid != capture_uid:
            raise _error("opaque_capture_cleanup_owner_mismatch")
        if stat.S_ISDIR(named.st_mode):
            try:
                child = os.open(
                    name,
                    _directory_flags(),
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise _error("opaque_capture_cleanup_unreadable") from exc
            try:
                _recursive_cleanup(
                    child,
                    capture_uid=capture_uid,
                    counters=counters,
                )
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=descriptor)
        else:
            os.unlink(name, dir_fd=descriptor)
    os.fsync(descriptor)


def _open_bound_capture_candidate(
    parent_fd: int,
    name: str,
    *,
    capture_uid: int,
    field: str,
) -> tuple[int, os.stat_result]:
    if not CAPTURE_NAME_RE.fullmatch(name):
        raise _error(f"{field}_name_invalid")
    try:
        named = os.stat(
            name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    if not stat.S_ISDIR(named.st_mode) or named.st_uid != capture_uid:
        raise _error(f"{field}_unsafe")
    try:
        descriptor = os.open(
            name,
            _directory_flags(),
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    try:
        opened = os.fstat(descriptor)
        if _stat_identity(opened) != _stat_identity(named):
            raise _error(f"{field}_changed")
        os.set_inheritable(descriptor, False)
        if os.get_inheritable(descriptor):
            raise _error(f"{field}_cloexec_failed")
        return descriptor, named
    except Exception:
        os.close(descriptor)
        raise


def _cleanup_open_capture_locked(
    parent_fd: int,
    name: str,
    descriptor: int,
    *,
    capture_uid: int,
    mismatch_code: str,
) -> None:
    """Delete the name bound to ``descriptor`` while both locks are held."""

    try:
        named = os.stat(
            name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise _error(mismatch_code) from exc
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(named.st_mode)
        or named.st_uid != capture_uid
        or _stat_identity(opened) != _stat_identity(named)
    ):
        raise _error(mismatch_code)
    _recursive_cleanup(
        descriptor,
        capture_uid=capture_uid,
        counters={"entries": 0},
    )
    try:
        os.rmdir(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError as exc:
        raise _error("opaque_capture_cleanup_remove_failed") from exc


def cleanup_opaque_capture(lease: OpaqueCaptureLease) -> None:
    """Consume a lease and delete exactly the directory it still names.

    A bare path is intentionally insufficient authority.  The root-only
    parent admission flock and snapshot descriptor remain held by ``lease``
    while this function checks the opened inode against the final name,
    performs descriptor-relative deletion, and fsyncs the parent.
    """

    if type(lease) is not OpaqueCaptureLease:
        raise _error("opaque_capture_cleanup_lease_required")
    if not lease.active:
        return
    descriptor = lease._require_active()
    parent_fd = lease._parent_fd
    deleted = False
    try:
        parent_info = os.fstat(parent_fd)
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != lease._capture_uid
            or parent_info.st_gid != lease._verifier_gid
            or stat.S_IMODE(parent_info.st_mode)
            != lease._destination_parent_mode
        ):
            raise _error("opaque_capture_cleanup_parent_changed")
        _reject_fd_metadata(
            parent_fd,
            field="opaque_capture_cleanup_parent",
        )
        if not _lock_exclusive(
            parent_fd,
            nonblocking=True,
            field="opaque_capture_cleanup_parent",
        ):
            raise _error("opaque_capture_cleanup_parent_lock_lost")
        if lease._snapshot_root.parent != lease._destination_parent:
            raise _error("opaque_capture_cleanup_path_unbound")
        if not CAPTURE_NAME_RE.fullmatch(lease._snapshot_root.name):
            raise _error("opaque_capture_cleanup_path_unbound")
        _cleanup_open_capture_locked(
            parent_fd,
            lease._snapshot_root.name,
            descriptor,
            capture_uid=lease._capture_uid,
            mismatch_code="opaque_capture_cleanup_lease_inode_mismatch",
        )
        deleted = True
    finally:
        if deleted:
            try:
                os.close(descriptor)
            finally:
                lease._root_fd = -1
            try:
                os.close(parent_fd)
            finally:
                lease._parent_fd = -1


def recover_stale_opaque_captures(
    destination_parent: Path,
    *,
    plan: Mapping[str, Any],
    capture_uid: int = 0,
    now_unix: int | None = None,
) -> list[str]:
    """Reap stale unlocked captures under the parent admission lock.

    The root-opened 0710 parent flock is the liveness authority.  If a
    coordinator lease is active, recovery cannot acquire it and returns
    without inspecting captures.  Once acquired, every age-eligible capture
    is orphaned even if a verifier has forged a flock on its readable 0550
    snapshot directory.
    """

    normalized = capture_plan.normalize_capture_plan(plan)
    parent = _absolute_path(
        destination_parent,
        field="opaque_capture_recovery_parent",
    )
    parent_fd = _validate_capture_parent(
        parent,
        capture_uid=capture_uid,
        capture_gid=normalized["verifier_gid"],
        evidence_uid=normalized["evidence_uid"],
    )
    try:
        if not _lock_exclusive(
            parent_fd,
            nonblocking=True,
            field="opaque_capture_recovery_parent",
        ):
            return []
        entries = _bounded_entries(
            parent_fd,
            maximum=normalized["lifecycle"]["max_capture_slots"] + 1,
            error_code="opaque_capture_slot_count_exceeded",
        )
        if len(entries) > normalized["lifecycle"]["max_capture_slots"]:
            raise _error("opaque_capture_slot_count_exceeded")
        current = int(time.time()) if now_unix is None else now_unix
        if type(current) is not int or current < 1:
            raise _error("opaque_capture_recovery_time_invalid")
        removed: list[str] = []
        for name in entries:
            if not CAPTURE_NAME_RE.fullmatch(name):
                raise _error("opaque_capture_parent_inventory_unsafe")
            descriptor, info = _open_bound_capture_candidate(
                parent_fd,
                name,
                capture_uid=capture_uid,
                field="opaque_capture_recovery_entry",
            )
            try:
                mode = stat.S_IMODE(info.st_mode)
                if name.endswith(".building"):
                    if mode not in {0o700, 0o550}:
                        raise _error(
                            "opaque_capture_recovery_entry_unsafe"
                        )
                    if mode == 0o550 and info.st_gid != normalized[
                        "verifier_gid"
                    ]:
                        raise _error(
                            "opaque_capture_recovery_entry_unsafe"
                        )
                elif (
                    mode != 0o550
                    or info.st_gid != normalized["verifier_gid"]
                ):
                    raise _error("opaque_capture_recovery_entry_unsafe")
                modified = max(
                    getattr(
                        info,
                        "st_mtime_ns",
                        int(info.st_mtime * 1_000_000_000),
                    ),
                    getattr(
                        info,
                        "st_ctime_ns",
                        int(info.st_ctime * 1_000_000_000),
                    ),
                ) // 1_000_000_000
                if (
                    current - modified
                    < normalized["lifecycle"][
                        "max_orphan_age_seconds"
                    ]
                ):
                    continue
                _cleanup_open_capture_locked(
                    parent_fd,
                    name,
                    descriptor,
                    capture_uid=capture_uid,
                    mismatch_code=(
                        "opaque_capture_recovery_entry_changed"
                    ),
                )
                removed.append(name)
            finally:
                os.close(descriptor)
        return removed
    finally:
        os.close(parent_fd)


def _capture_opaque_snapshot_from_plan(
    *,
    plan: Mapping[str, Any],
    plan_sha256: str,
    destination_parent: Path,
    capture_uid: int,
    capture_gid: int | None = None,
    destination_parent_mode: int = 0o710,
    sealed_directory_mode: int = SEALED_DIRECTORY_MODE,
    sealed_file_mode: int = SEALED_FILE_MODE,
    source_gid: int | None = None,
    source_directory_mode: int = PRIVATE_SOURCE_DIRECTORY_MODE,
    source_file_mode: int = PRIVATE_SOURCE_FILE_MODE,
    after_copy_hook: Callable[[], None] | None = None,
) -> OpaqueCaptureLease:
    """Create a leased snapshot; the hook is test-only fault injection.

    Production reaches this function only through ``capture_opaque_snapshot``
    with ``capture_uid == 0`` and no hook.  There is intentionally no
    production dict/path return mode.
    """

    if type(capture_uid) is not int or capture_uid < 0:
        raise _error("opaque_capture_identity_invalid")
    normalized = capture_plan.normalize_capture_plan(plan)
    output_gid = (
        normalized["verifier_gid"]
        if capture_gid is None
        else capture_gid
    )
    if (
        type(output_gid) is not int
        or output_gid < 1
        or type(destination_parent_mode) is not int
        or destination_parent_mode not in {0o700, 0o710}
        or (
            sealed_directory_mode,
            sealed_file_mode,
        )
        not in {
            (SEALED_DIRECTORY_MODE, SEALED_FILE_MODE),
            (
                PROVISIONAL_DIRECTORY_MODE,
                PROVISIONAL_FILE_MODE,
            ),
        }
        or (
            source_directory_mode,
            source_file_mode,
        )
        not in {
            (
                PRIVATE_SOURCE_DIRECTORY_MODE,
                PRIVATE_SOURCE_FILE_MODE,
            ),
            (
                EXPORT_SOURCE_DIRECTORY_MODE,
                EXPORT_SOURCE_FILE_MODE,
            ),
        }
        or (
            source_gid is not None
            and (type(source_gid) is not int or source_gid < 1)
        )
    ):
        raise _error("opaque_capture_identity_invalid")
    actual_plan_sha256 = capture_plan.capture_plan_sha256(normalized)
    if actual_plan_sha256 != plan_sha256:
        raise _error("opaque_capture_plan_digest_mismatch")
    parent = _absolute_path(
        destination_parent,
        field="opaque_capture_destination_parent",
    )
    parent_fd = _validate_capture_parent(
        parent,
        capture_uid=capture_uid,
        capture_gid=output_gid,
        evidence_uid=normalized["evidence_uid"],
        parent_mode=destination_parent_mode,
    )
    token = secrets.token_hex(16)
    building_name = f"opaque-capture-{token}.building"
    final_name = f"opaque-capture-{token}"
    final = parent / final_name
    root_fd: int | None = None
    current_name: str | None = None
    try:
        if not _lock_exclusive(
            parent_fd,
            nonblocking=True,
            field="opaque_capture_admission_parent",
        ):
            raise _error("opaque_capture_admission_busy")
        entries = _bounded_entries(
            parent_fd,
            maximum=normalized["lifecycle"]["max_capture_slots"],
            error_code="opaque_capture_slot_count_exceeded",
        )
        if len(entries) >= normalized["lifecycle"]["max_capture_slots"]:
            raise _error("opaque_capture_slot_count_exceeded")
        for name in entries:
            if not CAPTURE_NAME_RE.fullmatch(name):
                raise _error("opaque_capture_parent_inventory_unsafe")
        _preflight_sources(
            normalized,
            destination_parent=parent,
            destination_parent_fd=parent_fd,
            source_gid=source_gid,
            source_directory_mode=source_directory_mode,
            source_file_mode=source_file_mode,
        )
        try:
            os.mkdir(building_name, 0o700, dir_fd=parent_fd)
            current_name = building_name
            root_fd = os.open(
                building_name,
                _directory_flags(),
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise _error("opaque_capture_destination_create_failed") from exc
        root_info = os.fstat(root_fd)
        if (
            root_info.st_uid != capture_uid
            or stat.S_IMODE(root_info.st_mode) != 0o700
        ):
            raise _error("opaque_capture_destination_unsafe")
        _reject_fd_metadata(
            root_fd,
            field="opaque_capture_destination_root",
        )
        builder = _OpaqueCaptureBuilder(
            root_fd=root_fd,
            destination_parent_fd=parent_fd,
            plan=normalized,
            capture_uid=capture_uid,
            source_gid=source_gid,
            source_directory_mode=source_directory_mode,
            source_file_mode=source_file_mode,
        )
        for source in normalized["sources"]:
            if source["kind"] == "file":
                builder.add_fixed_file(source)
            else:
                builder.add_tree(source)
        if after_copy_hook is not None:
            after_copy_hook()
        builder.revalidate_sources()

        source_directories = builder.source_directory_manifest()
        files = sorted(builder.files, key=lambda item: item["path"])
        manifest = {
            "schema_version": OPAQUE_CAPTURE_SCHEMA,
            "capture_policy_version": capture_plan.CAPTURE_POLICY_VERSION,
            "capture_plan_sha256": actual_plan_sha256,
            "instance_slug": normalized["instance_slug"],
            "captured_at_unix": int(time.time()),
            "evidence_uid": normalized["evidence_uid"],
            "capture_uid": capture_uid,
            "verifier_gid": normalized["verifier_gid"],
            "limits": normalized["limits"],
            "lifecycle": normalized["lifecycle"],
            "sources": normalized["sources"],
            "directories": sorted(builder.directories),
            "source_directories": source_directories,
            "files": files,
            "file_count": len(files),
            "directory_count": len(builder.directories),
            "source_directory_count": len(source_directories),
            "total_bytes": builder.total_bytes,
        }
        _write_new_file(
            root_fd,
            OPAQUE_CAPTURE_MANIFEST,
            _manifest_bytes(manifest),
            owner_uid=capture_uid,
        )
        os.fsync(root_fd)
        os.set_inheritable(root_fd, False)
        if os.get_inheritable(root_fd):
            raise _error("opaque_capture_lease_cloexec_failed")
        _lock_exclusive(
            root_fd,
            field="opaque_capture_snapshot",
        )
        _seal_root(
            root_fd,
            capture_uid=capture_uid,
            capture_gid=output_gid,
            directory_mode=sealed_directory_mode,
            file_mode=sealed_file_mode,
        )
        os.rename(
            building_name,
            final_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        current_name = final_name
        os.fsync(parent_fd)
        manifest_sha256 = _sha256(_canonical_json(manifest))
        verified = verify_sealed_opaque_capture(
            final,
            plan=normalized,
            expected_plan_sha256=actual_plan_sha256,
            expected_capture_uid=capture_uid,
            expected_verifier_gid=normalized["verifier_gid"],
            expected_manifest_sha256=manifest_sha256,
            expected_snapshot_gid=output_gid,
            expected_directory_mode=sealed_directory_mode,
            expected_file_mode=sealed_file_mode,
            expected_source_directory_mode=source_directory_mode,
            expected_source_file_mode=source_file_mode,
        )
        lease = OpaqueCaptureLease(
            _token=_LEASE_CONSTRUCTION_TOKEN,
            root_fd=root_fd,
            parent_fd=parent_fd,
            snapshot_root=final,
            destination_parent=parent,
            destination_parent_mode=destination_parent_mode,
            capture_uid=capture_uid,
            verifier_gid=output_gid,
            evidence_uid=normalized["evidence_uid"],
            capture_manifest_sha256=manifest_sha256,
            capture_plan_sha256=actual_plan_sha256,
            manifest=verified,
        )
        # Ownership of both exact open-file descriptions has transferred.
        root_fd = None
        parent_fd = None
        return lease
    except Exception:
        if current_name is not None:
            cleanup_fd = root_fd
            opened_for_cleanup = False
            try:
                if cleanup_fd is None:
                    cleanup_fd, _ = _open_bound_capture_candidate(
                        parent_fd,
                        current_name,
                        capture_uid=capture_uid,
                        field="opaque_capture_failure_cleanup",
                    )
                    opened_for_cleanup = True
                _lock_exclusive(
                    cleanup_fd,
                    field="opaque_capture_failure_cleanup",
                )
                _cleanup_open_capture_locked(
                    parent_fd,
                    current_name,
                    cleanup_fd,
                    capture_uid=capture_uid,
                    mismatch_code=(
                        "opaque_capture_failure_cleanup_inode_mismatch"
                    ),
                )
            except OpaqueCaptureError as cleanup_error:
                raise _error(
                    "opaque_capture_failure_cleanup_failed"
                ) from cleanup_error
            finally:
                if opened_for_cleanup and cleanup_fd is not None:
                    os.close(cleanup_fd)
        raise
    finally:
        if root_fd is not None:
            os.close(root_fd)
        # On success the lease owns the parent description and retains its
        # root-only admission flock through the entire transaction.
        if parent_fd is not None:
            os.close(parent_fd)


def capture_opaque_snapshot(
    *,
    installed_plan_path: Path,
    destination_parent: Path,
) -> OpaqueCaptureLease:
    """Create one root-owned snapshot and return its exclusive lease."""

    if os.geteuid() != 0:
        raise _error("opaque_capture_requires_root")
    plan, plan_sha256 = capture_plan.read_installed_capture_plan(
        installed_plan_path,
        expected_owner_uid=0,
    )
    return _capture_opaque_snapshot_from_plan(
        plan=plan,
        plan_sha256=plan_sha256,
        destination_parent=destination_parent,
        capture_uid=0,
    )


def _capture_provisional_snapshot_for_adoption(
    *,
    plan: Mapping[str, Any],
    plan_sha256: str,
    destination_parent: Path,
    evidence_uid: int,
    capture_uid: int,
    export_gid: int,
) -> OpaqueCaptureLease:
    """Create one C:export 0500/0400 tree for root adoption.

    This child-only primitive neither adopts nor returns a root-readable
    object.  Evidence must already be exported as E:export 0750/0640, the
    per-session staging parent must be C:export 0700, and all four relevant
    identities are checked again by the v2 protocol before this function is
    reached.
    """

    normalized = capture_plan.normalize_capture_plan(plan)
    if (
        type(evidence_uid) is not int
        or evidence_uid < 1
        or type(capture_uid) is not int
        or capture_uid < 1
        or type(export_gid) is not int
        or export_gid < 1
        or evidence_uid != normalized["evidence_uid"]
        or evidence_uid == capture_uid
        or export_gid == normalized["verifier_gid"]
    ):
        raise _error("opaque_capture_adoption_identity_invalid")
    return _capture_opaque_snapshot_from_plan(
        plan=normalized,
        plan_sha256=plan_sha256,
        destination_parent=destination_parent,
        capture_uid=capture_uid,
        capture_gid=export_gid,
        destination_parent_mode=0o700,
        sealed_directory_mode=PROVISIONAL_DIRECTORY_MODE,
        sealed_file_mode=PROVISIONAL_FILE_MODE,
        source_gid=export_gid,
        source_directory_mode=EXPORT_SOURCE_DIRECTORY_MODE,
        source_file_mode=EXPORT_SOURCE_FILE_MODE,
    )
