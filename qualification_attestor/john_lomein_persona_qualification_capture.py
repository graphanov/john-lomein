"""Root-side sealed capture for persona qualification verification.

The evidence-producing account remains authoritative only for producing raw
qualification evidence.  This module copies one terminal run through
descriptor-relative, no-follow reads into a fresh root-controlled snapshot.
The snapshot is then sealed as ``root:<verifier-group>`` with read-only group
access so a distinct verifier identity can read but cannot rewrite it.

The module performs no model calls, imports no runtime-owned Python, opens no
signing key, and publishes no attestation.
"""

from __future__ import annotations

import hashlib
import ctypes
import errno
import json
import os
import pwd
import re
import secrets
import shutil
import stat
import sys
import time
import unicodedata
from pathlib import Path
from typing import Any

import yaml


CAPTURE_SCHEMA = "john-lomein.persona-qualification-capture.v1"
MAX_CAPTURE_FILES = 2_048
MAX_CAPTURE_DIRECTORIES = 4_096
MAX_CAPTURE_ENTRIES = MAX_CAPTURE_FILES + MAX_CAPTURE_DIRECTORIES
MAX_CAPTURE_BYTES = 128 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 16
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

PROFILE_NAMES = (
    "john-lomein-maintainer",
    "john-lomein-forge",
    "john-lomein-guide",
    "john-lomein-overwatch",
    "john-lomein-learning-steward",
)
SOURCE_CLASSES = frozenset(
    {
        "instance_manifest",
        "deployed_instance_manifest",
        "persona_receipt",
        "deployed_soul",
        "deployed_profile_config",
        "qualification_public_status",
        "qualification_public_latest",
        "qualification_public_run",
        "qualification_private_run",
    }
)


class QualificationCaptureError(ValueError):
    """A stable, public-safe capture rejection."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _error(code: str) -> QualificationCaptureError:
    return QualificationCaptureError(code)


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
        raise _error("capture_manifest_not_canonical") from exc


def _capture_manifest_file_bytes(manifest: Any) -> bytes:
    encoded = _canonical_json(manifest)
    if len(encoded) + 1 > MAX_MANIFEST_BYTES:
        raise _error("capture_manifest_too_large")
    return encoded + b"\n"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _error("capture_json_duplicate_field")
        result[key] = value
    return result


def _parse_json(raw: bytes, *, field: str) -> Any:
    if not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise _error(f"{field}_size_invalid")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _: (_ for _ in ()).throw(
                _error("capture_json_nonfinite")
            ),
        )
    except QualificationCaptureError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _error(f"{field}_invalid") from exc


def _absolute_path(value: Path | str, *, field: str) -> Path:
    text = os.fspath(value)
    if (
        not isinstance(text, str)
        or not text
        or len(text) > 4096
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


def _path_overlaps(left: Path, right: Path) -> bool:
    left_text = unicodedata.normalize("NFC", str(left).rstrip(os.sep)).casefold()
    right_text = unicodedata.normalize(
        "NFC", str(right).rstrip(os.sep)
    ).casefold()
    return (
        left_text == right_text
        or left_text.startswith(right_text + os.sep)
        or right_text.startswith(left_text + os.sep)
    )


def _path_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _manifest_identity_path(
    value: Any,
    *,
    evidence_home: Path,
    default: Path,
    field: str,
) -> Path:
    raw = str(value) if value not in (None, "") else str(default)
    if raw == "~":
        path = evidence_home
    elif raw.startswith("~/"):
        path = evidence_home / raw[2:]
    else:
        path = Path(raw)
    return _absolute_path(path, field=field)


def _captured_path_identities(
    instance_raw: bytes,
    *,
    runtime_root: Path,
    instance_slug: str,
    evidence_uid: int,
) -> dict[str, str]:
    """Bind canonical path identities while the trusted capturer can inspect them."""

    try:
        manifest = yaml.safe_load(instance_raw.decode("utf-8")) or {}
    except (UnicodeError, yaml.YAMLError) as exc:
        raise _error("instance_manifest_invalid") from exc
    if not isinstance(manifest, dict):
        raise _error("instance_manifest_invalid")
    try:
        account = pwd.getpwuid(evidence_uid)
    except (KeyError, OSError) as exc:
        raise _error("evidence_account_unavailable") from exc
    evidence_home = _absolute_path(
        Path(account.pw_dir),
        field="evidence_home_path",
    )
    target = manifest.get("target") or {}
    runtime = manifest.get("runtime") or {}
    if not isinstance(target, dict) or not isinstance(runtime, dict):
        raise _error("instance_manifest_path_config_invalid")
    checkout_source = _manifest_identity_path(
        target.get("local_checkout") or target.get("local"),
        evidence_home=evidence_home,
        default=(
            evidence_home
            / ".john-lomein"
            / "instances"
            / instance_slug
            / "work"
            / "repo"
        ),
        field="checkout_source_path",
    )
    runtime_source = _manifest_identity_path(
        runtime.get("hermes_home"),
        evidence_home=evidence_home,
        default=(
            evidence_home
            / ".john-lomein"
            / "instances"
            / instance_slug
            / "hermes"
        ),
        field="runtime_source_path",
    )
    try:
        checkout_identity = checkout_source.resolve(strict=False)
        runtime_identity = runtime_source.resolve(strict=False)
        captured_runtime_identity = runtime_root.resolve(strict=True)
    except OSError as exc:
        raise _error("instance_manifest_path_identity_unreadable") from exc
    if runtime_identity != captured_runtime_identity:
        raise _error("instance_manifest_runtime_source_mismatch")
    if _path_overlaps(checkout_identity, runtime_identity):
        raise _error("instance_manifest_runtime_checkout_overlap")
    return {
        "evidence_home": str(evidence_home),
        "checkout_source": str(checkout_source),
        "runtime_source": str(runtime_source),
        "checkout": str(checkout_identity),
        "runtime": str(runtime_identity),
    }


def _component(value: str, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "/" in value
        or "\x00" in value
        or unicodedata.normalize("NFC", value) != value
    ):
        raise _error(f"{field}_invalid")
    return value


def _reject_acl_or_xattrs(path: Path, *, field: str) -> None:
    try:
        attributes = os.listxattr(path, follow_symlinks=False)
    except (AttributeError, NotImplementedError):
        attributes = []
    except OSError as exc:
        raise _error(f"{field}_metadata_unreadable") from exc
    if attributes:
        raise _error(f"{field}_extended_metadata_unsupported")
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        libc.acl_get_file.argtypes = [ctypes.c_char_p, ctypes.c_int]
        libc.acl_get_file.restype = ctypes.c_void_p
        libc.acl_to_text.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ssize_t),
        ]
        libc.acl_to_text.restype = ctypes.c_void_p
        libc.acl_free.argtypes = [ctypes.c_void_p]
        acl = libc.acl_get_file(os.fsencode(path), 0x100)
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


def _validate_source_chain(path: Path, *, expected_uid: int, field: str) -> None:
    current = path
    trusted = {0, expected_uid}
    while True:
        try:
            info = current.lstat()
        except OSError as exc:
            raise _error(f"{field}_ancestor_unreadable") from exc
        if stat.S_ISLNK(info.st_mode):
            try:
                parent_info = current.parent.lstat()
            except OSError as exc:
                raise _error(f"{field}_ancestor_symlink") from exc
            if (
                info.st_uid != 0
                or parent_info.st_uid != 0
                or parent_info.st_mode & 0o022
            ):
                raise _error(f"{field}_ancestor_symlink")
            if current.parent == current:
                return
            current = current.parent
            continue
        if info.st_uid not in trusted:
            raise _error(f"{field}_ancestor_owner_mismatch")
        if info.st_mode & 0o022:
            if not (
                stat.S_ISDIR(info.st_mode)
                and info.st_mode & stat.S_ISVTX
                and info.st_uid == 0
            ):
                raise _error(f"{field}_ancestor_writable")
        _reject_acl_or_xattrs(current, field=f"{field}_ancestor")
        if current.parent == current:
            return
        current = current.parent


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _file_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _stat_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
    )


def _stat_identity_sha256(info: os.stat_result) -> str:
    return _sha256(_canonical_json(list(_stat_identity(info))))


def _directory_entries_sha256(entries: tuple[str, ...] | list[str]) -> str:
    return _sha256(_canonical_json(list(entries)))


def _bounded_directory_entries(
    directory_fd: int,
    *,
    maximum: int,
    error_code: str,
) -> list[str]:
    """List at most ``maximum`` entries without first allocating an unbounded list."""

    if maximum < 0:
        raise _error(error_code)
    names: list[str] = []
    try:
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                if len(names) >= maximum:
                    raise _error(error_code)
                names.append(entry.name)
    except QualificationCaptureError:
        raise
    except OSError as exc:
        raise _error(error_code) from exc
    return sorted(names)


def _open_source_directory(
    path: Path,
    *,
    expected_uid: int,
    field: str,
) -> int:
    _validate_source_chain(path, expected_uid=expected_uid, field=field)
    try:
        descriptor = os.open(path, _directory_flags())
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != expected_uid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise _error(f"{field}_unsafe")
    return descriptor


def _stable_source_file(
    parent_fd: int,
    name: str,
    *,
    full_path: Path,
    expected_uid: int,
    field: str,
) -> tuple[bytes, os.stat_result]:
    _component(name, field=field)
    try:
        descriptor = os.open(name, _file_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 <= before.st_size <= MAX_FILE_BYTES
        ):
            raise _error(f"{field}_unsafe")
        _reject_acl_or_xattrs(full_path, field=field)
        raw = bytearray()
        while len(raw) <= MAX_FILE_BYTES:
            chunk = os.read(
                descriptor,
                min(64 * 1024, MAX_FILE_BYTES + 1 - len(raw)),
            )
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        try:
            named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise _error(f"{field}_changed_during_read") from exc
        identity_before = _stat_identity(before)
        identity_after = _stat_identity(after)
        identity_named = _stat_identity(named)
        if (
            len(raw) != before.st_size
            or len(raw) > MAX_FILE_BYTES
            or identity_before != identity_after
            or identity_after != identity_named
        ):
            raise _error(f"{field}_changed_during_read")
        return bytes(raw), after
    finally:
        os.close(descriptor)


def _mkdir_at(parent_fd: int, name: str) -> int:
    _component(name, field="capture_destination_component")
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise _error("capture_destination_unreadable") from exc
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise _error("capture_destination_unsafe")
    return descriptor


def _write_file_at(parent_fd: int, name: str, raw: bytes) -> None:
    _component(name, field="capture_destination_file")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
    except OSError as exc:
        raise _error("capture_destination_write_failed") from exc
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise _error("capture_destination_write_failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class _CaptureBuilder:
    def __init__(
        self,
        *,
        snapshot_root: Path,
        expected_source_uid: int,
    ):
        self.snapshot_root = snapshot_root
        self.expected_source_uid = expected_source_uid
        self.files: list[dict[str, Any]] = []
        self.directories: set[str] = set()
        self.total_bytes = 0
        self.source_entry_count = 0
        self._source_files: list[
            tuple[Path, tuple[int, ...], str]
        ] = []
        self._source_directories: list[
            tuple[Path, tuple[int, ...], tuple[str, ...]]
        ] = []
        self.root_fd = os.open(snapshot_root, _directory_flags())

    def close(self) -> None:
        os.close(self.root_fd)

    def _destination_parent(self, relative_parent: str) -> int:
        descriptor = os.dup(self.root_fd)
        if not relative_parent:
            return descriptor
        try:
            accumulated_parts: list[str] = []
            for component in relative_parent.split("/"):
                next_descriptor = _mkdir_at(descriptor, component)
                os.close(descriptor)
                descriptor = next_descriptor
                accumulated_parts.append(component)
                accumulated = "/".join(accumulated_parts)
                if (
                    accumulated not in self.directories
                    and len(self.directories) >= MAX_CAPTURE_DIRECTORIES
                ):
                    raise _error("capture_directory_count_exceeded")
                self.directories.add(accumulated)
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def ensure_directory(self, relative: str) -> None:
        descriptor = self._destination_parent(relative)
        os.close(descriptor)

    def add_file(
        self,
        *,
        source_parent: Path,
        source_name: str,
        destination: str,
        source_class: str,
    ) -> bytes:
        source_fd = _open_source_directory(
            source_parent,
            expected_uid=self.expected_source_uid,
            field=f"{source_class}_parent",
        )
        try:
            raw, info = _stable_source_file(
                source_fd,
                source_name,
                full_path=source_parent / source_name,
                expected_uid=self.expected_source_uid,
                field=source_class,
            )
        finally:
            os.close(source_fd)
        self._record_file(
            raw=raw,
            source_path=source_parent / source_name,
            destination=destination,
            source_class=source_class,
            source_info=info,
        )
        return raw

    def _record_file(
        self,
        *,
        raw: bytes,
        source_path: Path,
        destination: str,
        source_class: str,
        source_info: os.stat_result,
    ) -> None:
        if len(self.files) >= MAX_CAPTURE_FILES:
            raise _error("capture_file_count_exceeded")
        self.total_bytes += len(raw)
        if self.total_bytes > MAX_CAPTURE_BYTES:
            raise _error("capture_size_exceeded")
        relative = Path(destination)
        if relative.is_absolute() or "." in relative.parts or ".." in relative.parts:
            raise _error("capture_destination_invalid")
        parent_text = relative.parent.as_posix()
        if parent_text == ".":
            parent_text = ""
        parent_fd = self._destination_parent(parent_text)
        try:
            _write_file_at(parent_fd, relative.name, raw)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        self.files.append(
            {
                "path": relative.as_posix(),
                "source": str(source_path),
                "source_class": source_class,
                "source_uid": source_info.st_uid,
                "source_mode": stat.S_IMODE(source_info.st_mode),
                "source_identity_sha256": _stat_identity_sha256(source_info),
                "size": len(raw),
                "sha256": _sha256(raw),
            }
        )
        self._source_files.append(
            (
                source_path,
                _stat_identity(source_info),
                _sha256(raw),
            )
        )

    def add_tree(
        self,
        *,
        source_root: Path,
        destination_root: str,
        source_class: str,
    ) -> None:
        source_fd = _open_source_directory(
            source_root,
            expected_uid=self.expected_source_uid,
            field=source_class,
        )
        try:
            self.ensure_directory(destination_root)
            self._walk_tree(
                source_fd=source_fd,
                source_path=source_root,
                destination=destination_root,
                source_class=source_class,
                depth=0,
            )
        finally:
            os.close(source_fd)

    def _walk_tree(
        self,
        *,
        source_fd: int,
        source_path: Path,
        destination: str,
        source_class: str,
        depth: int,
    ) -> None:
        if depth > MAX_DEPTH:
            raise _error("capture_tree_too_deep")
        try:
            directory_before = os.fstat(source_fd)
            before_entries = _bounded_directory_entries(
                source_fd,
                maximum=MAX_CAPTURE_ENTRIES - self.source_entry_count,
                error_code="capture_entry_count_exceeded",
            )
        except OSError as exc:
            raise _error(f"{source_class}_unreadable") from exc
        self.source_entry_count += len(before_entries)
        identities: set[str] = set()
        for name in before_entries:
            _component(name, field=f"{source_class}_entry")
            identity = unicodedata.normalize("NFC", name).casefold()
            if identity in identities:
                raise _error(f"{source_class}_entry_alias")
            identities.add(identity)
            try:
                info = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            except OSError as exc:
                raise _error(f"{source_class}_entry_unreadable") from exc
            if info.st_uid != self.expected_source_uid:
                raise _error(f"{source_class}_entry_owner_mismatch")
            child_source = source_path / name
            child_destination = f"{destination}/{name}"
            if stat.S_ISDIR(info.st_mode):
                if stat.S_IMODE(info.st_mode) != 0o700:
                    raise _error(f"{source_class}_directory_unsafe")
                _reject_acl_or_xattrs(
                    child_source,
                    field=f"{source_class}_directory",
                )
                try:
                    child_fd = os.open(
                        name,
                        _directory_flags(),
                        dir_fd=source_fd,
                    )
                except OSError as exc:
                    raise _error(f"{source_class}_directory_unreadable") from exc
                try:
                    opened = os.fstat(child_fd)
                    if (
                        opened.st_dev != info.st_dev
                        or opened.st_ino != info.st_ino
                        or opened.st_uid != self.expected_source_uid
                    ):
                        raise _error(f"{source_class}_directory_changed")
                    self.ensure_directory(child_destination)
                    self._walk_tree(
                        source_fd=child_fd,
                        source_path=child_source,
                        destination=child_destination,
                        source_class=source_class,
                        depth=depth + 1,
                    )
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(info.st_mode):
                raw, stable_info = _stable_source_file(
                    source_fd,
                    name,
                    full_path=child_source,
                    expected_uid=self.expected_source_uid,
                    field=source_class,
                )
                self._record_file(
                    raw=raw,
                    source_path=child_source,
                    destination=child_destination,
                    source_class=source_class,
                    source_info=stable_info,
                )
            else:
                raise _error(f"{source_class}_entry_unsafe")
        try:
            after_entries = _bounded_directory_entries(
                source_fd,
                maximum=len(before_entries) + 1,
                error_code=f"{source_class}_changed_during_capture",
            )
            directory_after = os.fstat(source_fd)
        except OSError as exc:
            raise _error(f"{source_class}_changed_during_capture") from exc
        before_identity = _stat_identity(directory_before)
        after_identity = _stat_identity(directory_after)
        if before_entries != after_entries or before_identity != after_identity:
            raise _error(f"{source_class}_changed_during_capture")
        self._source_directories.append(
            (
                source_path,
                after_identity,
                tuple(after_entries),
            )
        )

    def revalidate_sources(self) -> None:
        """Prove the complete selected source set stayed stable."""

        for path, expected_identity, expected_digest in self._source_files:
            parent_fd = _open_source_directory(
                path.parent,
                expected_uid=self.expected_source_uid,
                field="capture_source_revalidation_parent",
            )
            try:
                raw, info = _stable_source_file(
                    parent_fd,
                    path.name,
                    full_path=path,
                    expected_uid=self.expected_source_uid,
                    field="capture_source_revalidation",
                )
            finally:
                os.close(parent_fd)
            if (
                _stat_identity(info) != expected_identity
                or _sha256(raw) != expected_digest
            ):
                raise _error("capture_source_changed_after_copy")
        for path, expected_identity, expected_entries in self._source_directories:
            descriptor = _open_source_directory(
                path,
                expected_uid=self.expected_source_uid,
                field="capture_directory_revalidation",
            )
            try:
                info = os.fstat(descriptor)
                entries = tuple(
                    _bounded_directory_entries(
                        descriptor,
                        maximum=len(expected_entries) + 1,
                        error_code=(
                            "capture_directory_revalidation_unreadable"
                        ),
                    )
                )
            except OSError as exc:
                raise _error(
                    "capture_directory_revalidation_unreadable"
                ) from exc
            finally:
                os.close(descriptor)
            if (
                _stat_identity(info) != expected_identity
                or entries != expected_entries
            ):
                raise _error("capture_source_changed_after_copy")


def _select_run(status_raw: bytes) -> str:
    status = _parse_json(status_raw, field="qualification_status")
    if not isinstance(status, dict):
        raise _error("qualification_status_not_object")
    run_id = status.get("run_id")
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise _error("qualification_status_run_id_invalid")
    if (
        status.get("status") != "qualified"
        or status.get("reason") != "all-distinct-candidates-qualified"
        or status.get("summary_sha256") is None
        or status.get("public_reputation_eligible") is not False
    ):
        raise _error("qualification_status_not_capturable")
    return run_id


def _seal_snapshot(
    snapshot_root: Path,
    *,
    capture_uid: int,
    verifier_gid: int,
) -> None:
    paths = sorted(
        snapshot_root.rglob("*"),
        key=lambda item: len(item.relative_to(snapshot_root).parts),
        reverse=True,
    )
    for path in paths:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise _error("capture_destination_symlink")
        os.chown(path, capture_uid, verifier_gid, follow_symlinks=False)
        os.chmod(path, 0o550 if stat.S_ISDIR(info.st_mode) else 0o440)
        _reject_acl_or_xattrs(path, field="capture_destination")
    os.chown(snapshot_root, capture_uid, verifier_gid)
    os.chmod(snapshot_root, 0o550)
    _reject_acl_or_xattrs(snapshot_root, field="capture_destination_root")


def _capture_snapshot(
    *,
    instance_manifest: Path,
    qualification_public_root: Path,
    qualification_private_root: Path,
    instance_slug: str,
    expected_evidence_uid: int,
    snapshot_root: Path,
    capture_uid: int,
    verifier_gid: int,
) -> dict[str, Any]:
    """Low-level capture implementation; callers must provide a fresh root."""

    if not isinstance(expected_evidence_uid, int) or expected_evidence_uid < 1:
        raise _error("expected_evidence_uid_invalid")
    if not isinstance(capture_uid, int) or capture_uid < 0:
        raise _error("capture_uid_invalid")
    if not isinstance(verifier_gid, int) or verifier_gid < 1:
        raise _error("verifier_gid_invalid")
    if not isinstance(instance_slug, str) or not SLUG_RE.fullmatch(instance_slug):
        raise _error("instance_slug_invalid")
    instance_path = _absolute_path(
        instance_manifest,
        field="instance_manifest_path",
    )
    public_root = _absolute_path(
        qualification_public_root,
        field="qualification_public_root",
    )
    private_root = _absolute_path(
        qualification_private_root,
        field="qualification_private_root",
    )
    destination = _absolute_path(snapshot_root, field="snapshot_root")
    if any(
        _path_overlaps(destination, source)
        for source in (instance_path, public_root, private_root)
    ):
        raise _error("snapshot_overlaps_source")
    if public_root.name != "persona-qualification" or public_root.parent.name != "state":
        raise _error("qualification_public_root_layout_invalid")
    runtime_root = public_root.parent.parent
    if _path_overlaps(runtime_root, private_root):
        raise _error("qualification_source_roots_overlap")
    try:
        root_info = destination.lstat()
    except OSError as exc:
        raise _error("snapshot_root_unreadable") from exc
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != os.geteuid()
        or stat.S_IMODE(root_info.st_mode) != 0o700
        or any(destination.iterdir())
    ):
        raise _error("snapshot_root_not_fresh")

    builder = _CaptureBuilder(
        snapshot_root=destination,
        expected_source_uid=expected_evidence_uid,
    )
    try:
        builder.ensure_directory("checkout")
        instance_raw = builder.add_file(
            source_parent=instance_path.parent,
            source_name=instance_path.name,
            destination="instance/instance.yaml",
            source_class="instance_manifest",
        )
        path_identities = _captured_path_identities(
            instance_raw,
            runtime_root=runtime_root,
            instance_slug=instance_slug,
            evidence_uid=expected_evidence_uid,
        )
        builder.add_file(
            source_parent=runtime_root,
            source_name="instance.yaml",
            destination="runtime/instance.yaml",
            source_class="deployed_instance_manifest",
        )
        builder.add_file(
            source_parent=runtime_root / "state",
            source_name="john-lomein-persona.json",
            destination="runtime/state/john-lomein-persona.json",
            source_class="persona_receipt",
        )
        for profile in PROFILE_NAMES:
            source_profile = runtime_root / "profiles" / profile
            builder.add_file(
                source_parent=source_profile,
                source_name="SOUL.md",
                destination=f"runtime/profiles/{profile}/SOUL.md",
                source_class="deployed_soul",
            )
            builder.add_file(
                source_parent=source_profile,
                source_name="config.yaml",
                destination=f"runtime/profiles/{profile}/config.yaml",
                source_class="deployed_profile_config",
            )

        status_raw = builder.add_file(
            source_parent=public_root,
            source_name="status.json",
            destination=(
                "runtime/state/persona-qualification/status.json"
            ),
            source_class="qualification_public_status",
        )
        run_id = _select_run(status_raw)
        builder.add_file(
            source_parent=public_root,
            source_name="latest.json",
            destination=(
                "runtime/state/persona-qualification/latest.json"
            ),
            source_class="qualification_public_latest",
        )
        builder.add_tree(
            source_root=public_root / "reports" / run_id,
            destination_root=(
                f"runtime/state/persona-qualification/reports/{run_id}"
            ),
            source_class="qualification_public_run",
        )
        builder.add_tree(
            source_root=private_root / run_id,
            destination_root=f"private/{run_id}",
            source_class="qualification_private_run",
        )
        builder.revalidate_sources()
        builder.files.sort(key=lambda item: item["path"])
        directories = sorted(builder.directories)
        source_directories = sorted(
            (
                {
                    "path": str(path),
                    "source_uid": identity[6],
                    "source_mode": stat.S_IMODE(identity[5]),
                    "source_identity_sha256": _sha256(
                        _canonical_json(list(identity))
                    ),
                    "entry_count": len(entries),
                    "entries_sha256": _directory_entries_sha256(entries),
                }
                for path, identity, entries in builder._source_directories
            ),
            key=lambda item: item["path"],
        )
        manifest = {
            "schema_version": CAPTURE_SCHEMA,
            "instance_slug": instance_slug,
            "run_id": run_id,
            "captured_at_unix": int(time.time()),
            "observed_evidence_uid": expected_evidence_uid,
            "capture_uid": capture_uid,
            "verifier_gid": verifier_gid,
            "path_identities": path_identities,
            "source_roots": {
                "instance_manifest": str(instance_path),
                "runtime": str(runtime_root),
                "qualification_public": str(public_root),
                "qualification_private": str(private_root),
            },
            "layout": {
                "instance_manifest": "instance/instance.yaml",
                "checkout": "checkout",
                "runtime": "runtime",
                "private_root": "private",
            },
            "directories": directories,
            "source_directories": source_directories,
            "files": builder.files,
            "file_count": len(builder.files),
            "total_bytes": builder.total_bytes,
        }
        encoded_manifest = _canonical_json(manifest)
        _write_file_at(
            builder.root_fd,
            "capture-manifest.json",
            _capture_manifest_file_bytes(manifest),
        )
        os.fsync(builder.root_fd)
    finally:
        builder.close()

    _seal_snapshot(
        destination,
        capture_uid=capture_uid,
        verifier_gid=verifier_gid,
    )
    digest = _sha256(_canonical_json(manifest))
    verified = verify_sealed_capture(
        destination,
        expected_capture_uid=capture_uid,
        expected_verifier_gid=verifier_gid,
        expected_manifest_sha256=digest,
    )
    return {
        "snapshot_root": str(destination),
        "capture_manifest_sha256": digest,
        "manifest": verified,
    }


def capture_qualification_snapshot(
    *,
    instance_manifest: Path,
    qualification_public_root: Path,
    qualification_private_root: Path,
    instance_slug: str,
    expected_evidence_uid: int,
    destination_parent: Path,
    verifier_gid: int,
) -> dict[str, Any]:
    """Create one production snapshot as root and return its manifest digest."""

    if os.geteuid() != 0:
        raise _error("capture_requires_root")
    parent = _absolute_path(destination_parent, field="destination_parent")
    _validate_source_chain(parent, expected_uid=0, field="destination_parent")
    try:
        parent_info = parent.lstat()
    except OSError as exc:
        raise _error("destination_parent_unreadable") from exc
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != 0
        or parent_info.st_gid != verifier_gid
        or stat.S_IMODE(parent_info.st_mode) != 0o710
    ):
        raise _error("destination_parent_unsafe")
    snapshot = parent / f"capture-{secrets.token_hex(16)}"
    try:
        snapshot.mkdir(mode=0o700)
        return _capture_snapshot(
            instance_manifest=instance_manifest,
            qualification_public_root=qualification_public_root,
            qualification_private_root=qualification_private_root,
            instance_slug=instance_slug,
            expected_evidence_uid=expected_evidence_uid,
            snapshot_root=snapshot,
            capture_uid=0,
            verifier_gid=verifier_gid,
        )
    except Exception:
        if snapshot.exists() and snapshot.parent == parent:
            shutil.rmtree(snapshot)
        raise


def verify_sealed_capture(
    snapshot_root: Path,
    *,
    expected_capture_uid: int,
    expected_verifier_gid: int,
    expected_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """Verify exact sealed inventory before and after the verifier child."""

    if (
        isinstance(expected_capture_uid, bool)
        or not isinstance(expected_capture_uid, int)
        or expected_capture_uid < 0
        or isinstance(expected_verifier_gid, bool)
        or not isinstance(expected_verifier_gid, int)
        or expected_verifier_gid < 1
    ):
        raise _error("sealed_capture_expected_identity_invalid")
    root = _absolute_path(snapshot_root, field="snapshot_root")
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise _error("sealed_capture_unreadable") from exc
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != expected_capture_uid
        or root_info.st_gid != expected_verifier_gid
        or stat.S_IMODE(root_info.st_mode) != 0o550
    ):
        raise _error("sealed_capture_root_unsafe")
    _reject_acl_or_xattrs(root, field="sealed_capture_root")
    manifest_path = root / "capture-manifest.json"
    try:
        manifest_info = manifest_path.lstat()
        raw_manifest = manifest_path.read_bytes()
    except OSError as exc:
        raise _error("sealed_capture_manifest_unreadable") from exc
    if (
        not stat.S_ISREG(manifest_info.st_mode)
        or manifest_info.st_uid != expected_capture_uid
        or manifest_info.st_gid != expected_verifier_gid
        or manifest_info.st_nlink != 1
        or stat.S_IMODE(manifest_info.st_mode) != 0o440
        or len(raw_manifest) > MAX_MANIFEST_BYTES
    ):
        raise _error("sealed_capture_manifest_unsafe")
    _reject_acl_or_xattrs(
        manifest_path,
        field="sealed_capture_manifest",
    )
    manifest = _parse_json(
        raw_manifest,
        field="sealed_capture_manifest",
    )
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {
            "schema_version",
            "instance_slug",
            "run_id",
            "captured_at_unix",
            "observed_evidence_uid",
            "capture_uid",
            "verifier_gid",
            "source_roots",
            "path_identities",
            "layout",
            "directories",
            "source_directories",
            "files",
            "file_count",
            "total_bytes",
        }
        or manifest.get("schema_version") != CAPTURE_SCHEMA
    ):
        raise _error("sealed_capture_manifest_schema_invalid")
    canonical_manifest = _canonical_json(manifest)
    manifest_digest = _sha256(canonical_manifest)
    if (
        expected_manifest_sha256 is not None
        and manifest_digest != expected_manifest_sha256
    ):
        raise _error("sealed_capture_manifest_digest_mismatch")
    if (
        manifest.get("capture_uid") != expected_capture_uid
        or manifest.get("verifier_gid") != expected_verifier_gid
    ):
        raise _error("sealed_capture_identity_mismatch")
    if (
        not isinstance(manifest.get("instance_slug"), str)
        or not SLUG_RE.fullmatch(manifest["instance_slug"])
        or not isinstance(manifest.get("run_id"), str)
        or not RUN_ID_RE.fullmatch(manifest["run_id"])
    ):
        raise _error("sealed_capture_subject_invalid")
    observed_evidence_uid = manifest.get("observed_evidence_uid")
    captured_at_unix = manifest.get("captured_at_unix")
    if (
        isinstance(captured_at_unix, bool)
        or not isinstance(captured_at_unix, int)
        or captured_at_unix < 1
        or captured_at_unix > (1 << 53) - 1
        or
        not isinstance(observed_evidence_uid, int)
        or isinstance(observed_evidence_uid, bool)
        or observed_evidence_uid < 1
    ):
        raise _error("sealed_capture_evidence_uid_invalid")
    source_roots = manifest.get("source_roots")
    path_identities = manifest.get("path_identities")
    layout = manifest.get("layout")
    if (
        not isinstance(path_identities, dict)
        or set(path_identities)
        != {
            "evidence_home",
            "checkout_source",
            "runtime_source",
            "checkout",
            "runtime",
        }
        or any(
            not isinstance(value, str)
            or _absolute_path(value, field="sealed_capture_path_identity")
            != Path(value)
            for value in path_identities.values()
        )
        or _path_overlaps(
            Path(path_identities["checkout"]),
            Path(path_identities["runtime"]),
        )
        or not isinstance(source_roots, dict)
        or set(source_roots)
        != {
            "instance_manifest",
            "runtime",
            "qualification_public",
            "qualification_private",
        }
        or any(
            not isinstance(value, str)
            or _absolute_path(value, field="sealed_capture_source_root")
            != Path(value)
            for value in source_roots.values()
        )
        or not isinstance(layout, dict)
        or layout
        != {
            "instance_manifest": "instance/instance.yaml",
            "checkout": "checkout",
            "runtime": "runtime",
            "private_root": "private",
        }
    ):
        raise _error("sealed_capture_layout_invalid")

    raw_files = manifest.get("files")
    raw_directories = manifest.get("directories")
    raw_source_directories = manifest.get("source_directories")
    declared_file_count = manifest.get("file_count")
    declared_total_bytes = manifest.get("total_bytes")
    if (
        not isinstance(raw_files, list)
        or not isinstance(raw_directories, list)
        or not isinstance(raw_source_directories, list)
        or len(raw_files) > MAX_CAPTURE_FILES
        or len(raw_directories) > MAX_CAPTURE_DIRECTORIES
        or len(raw_source_directories) > MAX_CAPTURE_DIRECTORIES
        or isinstance(declared_file_count, bool)
        or not isinstance(declared_file_count, int)
        or len(raw_files) != declared_file_count
        or isinstance(declared_total_bytes, bool)
        or not isinstance(declared_total_bytes, int)
        or not 0 <= declared_total_bytes <= MAX_CAPTURE_BYTES
    ):
        raise _error("sealed_capture_inventory_invalid")
    expected_files = {"capture-manifest.json"}
    expected_directories: set[str] = set()
    total_bytes = 0
    previous_path = ""
    for entry in raw_files:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "source",
            "source_class",
            "source_uid",
            "source_mode",
            "source_identity_sha256",
            "size",
            "sha256",
        }:
            raise _error("sealed_capture_file_entry_invalid")
        relative = entry.get("path")
        if (
            not isinstance(relative, str)
            or not relative
            or relative <= previous_path
            or Path(relative).is_absolute()
            or "." in Path(relative).parts
            or ".." in Path(relative).parts
        ):
            raise _error("sealed_capture_file_path_invalid")
        source = entry.get("source")
        source_class = entry.get("source_class")
        size = entry.get("size")
        digest = entry.get("sha256")
        if (
            not isinstance(source, str)
            or _absolute_path(source, field="sealed_capture_file_source")
            != Path(source)
            or source_class not in SOURCE_CLASSES
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= MAX_FILE_BYTES
            or not isinstance(digest, str)
            or not SHA256_RE.fullmatch(digest)
            or not isinstance(entry.get("source_identity_sha256"), str)
            or not SHA256_RE.fullmatch(entry["source_identity_sha256"])
        ):
            raise _error("sealed_capture_file_entry_invalid")
        source_path = Path(source)
        source_root_for_class = (
            Path(source_roots["qualification_private"])
            if source_class == "qualification_private_run"
            else Path(source_roots["qualification_public"])
            if source_class.startswith("qualification_public_")
            else Path(source_roots["runtime"])
            if source_class
            in {
                "deployed_instance_manifest",
                "persona_receipt",
                "deployed_soul",
                "deployed_profile_config",
            }
            else Path(source_roots["instance_manifest"])
        )
        if source_class == "instance_manifest":
            source_is_bound = source_path == source_root_for_class
        else:
            source_is_bound = _path_within(
                source_path,
                source_root_for_class,
            )
        if not source_is_bound:
            raise _error("sealed_capture_file_source_unbound")
        previous_path = relative
        expected_files.add(relative)
        path = root / relative
        try:
            info = path.lstat()
            raw = path.read_bytes()
        except OSError as exc:
            raise _error("sealed_capture_file_unreadable") from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_capture_uid
            or info.st_gid != expected_verifier_gid
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o440
            or len(raw) != size
            or _sha256(raw) != digest
            or entry.get("source_uid") != observed_evidence_uid
            or entry.get("source_mode") != 0o600
        ):
            raise _error("sealed_capture_file_mismatch")
        _reject_acl_or_xattrs(path, field="sealed_capture_file")
        total_bytes += len(raw)
    if total_bytes != declared_total_bytes or total_bytes > MAX_CAPTURE_BYTES:
        raise _error("sealed_capture_size_mismatch")

    previous_source_directory = ""
    for entry in raw_source_directories:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "source_uid",
            "source_mode",
            "source_identity_sha256",
            "entry_count",
            "entries_sha256",
        }:
            raise _error("sealed_capture_source_directory_invalid")
        path = entry.get("path")
        if (
            not isinstance(path, str)
            or _absolute_path(path, field="sealed_capture_source_directory")
            != Path(path)
            or path <= previous_source_directory
            or entry.get("source_uid") != observed_evidence_uid
            or entry.get("source_mode") != 0o700
            or not isinstance(entry.get("entry_count"), int)
            or isinstance(entry.get("entry_count"), bool)
            or not 0 <= entry["entry_count"] <= MAX_CAPTURE_ENTRIES
            or not isinstance(entry.get("source_identity_sha256"), str)
            or not SHA256_RE.fullmatch(entry["source_identity_sha256"])
            or not isinstance(entry.get("entries_sha256"), str)
            or not SHA256_RE.fullmatch(entry["entries_sha256"])
        ):
            raise _error("sealed_capture_source_directory_invalid")
        previous_source_directory = path

    previous_directory = ""
    for relative in raw_directories:
        if (
            not isinstance(relative, str)
            or not relative
            or relative <= previous_directory
            or Path(relative).is_absolute()
            or "." in Path(relative).parts
            or ".." in Path(relative).parts
        ):
            raise _error("sealed_capture_directory_path_invalid")
        previous_directory = relative
        expected_directories.add(relative)
        try:
            info = (root / relative).lstat()
        except OSError as exc:
            raise _error("sealed_capture_directory_unreadable") from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != expected_capture_uid
            or info.st_gid != expected_verifier_gid
            or stat.S_IMODE(info.st_mode) != 0o550
        ):
            raise _error("sealed_capture_directory_mismatch")
        _reject_acl_or_xattrs(
            root / relative,
            field="sealed_capture_directory",
        )

    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    try:
        observed = root.rglob("*")
        observed_count = 0
        for path in observed:
            observed_count += 1
            if observed_count > MAX_CAPTURE_ENTRIES + 1:
                raise _error("sealed_capture_inventory_too_large")
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISREG(info.st_mode):
                observed_files.add(relative)
            elif stat.S_ISDIR(info.st_mode):
                observed_directories.add(relative)
            else:
                raise _error("sealed_capture_entry_unsafe")
    except OSError as exc:
        raise _error("sealed_capture_inventory_unreadable") from exc
    if (
        observed_files != expected_files
        or observed_directories != expected_directories
    ):
        raise _error("sealed_capture_inventory_mismatch")
    return manifest


def revalidate_live_capture_sources(
    snapshot_root: Path,
    *,
    expected_capture_uid: int,
    expected_verifier_gid: int,
    expected_evidence_uid: int,
    expected_manifest_sha256: str,
) -> dict[str, Any]:
    """Prove every captured live source still has its captured identity and bytes."""

    manifest = verify_sealed_capture(
        snapshot_root,
        expected_capture_uid=expected_capture_uid,
        expected_verifier_gid=expected_verifier_gid,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    if (
        isinstance(expected_evidence_uid, bool)
        or not isinstance(expected_evidence_uid, int)
        or expected_evidence_uid < 1
        or manifest["observed_evidence_uid"] != expected_evidence_uid
    ):
        raise _error("live_source_evidence_uid_mismatch")

    for entry in manifest["files"]:
        source = _absolute_path(
            entry["source"],
            field="live_source_file_path",
        )
        parent_fd = _open_source_directory(
            source.parent,
            expected_uid=expected_evidence_uid,
            field="live_source_file_parent",
        )
        try:
            raw, info = _stable_source_file(
                parent_fd,
                source.name,
                full_path=source,
                expected_uid=expected_evidence_uid,
                field="live_source_file",
            )
        finally:
            os.close(parent_fd)
        if (
            _sha256(raw) != entry["sha256"]
            or _stat_identity_sha256(info)
            != entry["source_identity_sha256"]
        ):
            raise _error("live_source_file_changed")

    for entry in manifest["source_directories"]:
        source = _absolute_path(
            entry["path"],
            field="live_source_directory_path",
        )
        descriptor = _open_source_directory(
            source,
            expected_uid=expected_evidence_uid,
            field="live_source_directory",
        )
        try:
            info = os.fstat(descriptor)
            entries = _bounded_directory_entries(
                descriptor,
                maximum=entry["entry_count"] + 1,
                error_code="live_source_directory_changed",
            )
        finally:
            os.close(descriptor)
        if (
            len(entries) != entry["entry_count"]
            or _directory_entries_sha256(entries)
            != entry["entries_sha256"]
            or _stat_identity_sha256(info)
            != entry["source_identity_sha256"]
        ):
            raise _error("live_source_directory_changed")
    return manifest
