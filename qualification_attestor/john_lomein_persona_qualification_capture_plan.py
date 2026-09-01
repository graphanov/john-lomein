#!/usr/bin/env python3
"""Strict root-owned plan for opaque persona-qualification capture.

This module deliberately imports only the Python standard library.  A
key-capable coordinator may validate this installed plan without importing
PyYAML, qualification runners, model adapters, or evidence-controlled code.
The future opaque sealer treats every selected file as bytes; semantic
qualification belongs exclusively to the confined verifier.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import stat
import sys
import unicodedata
from collections.abc import Mapping
from pathlib import Path
from typing import Any


CAPTURE_PLAN_SCHEMA = "john-lomein.persona-qualification-capture-plan.v1"
CAPTURE_POLICY_VERSION = "john-lomein.persona-opaque-capture-policy.v1"

MAX_PLAN_BYTES = 256 * 1024
MAX_PLAN_SOURCES = 128
MAX_CAPTURE_FILES = 4_096
MAX_CAPTURE_DIRECTORIES = 4_096
MAX_CAPTURE_BYTES = 128 * 1024 * 1024
MAX_CAPTURE_FILE_BYTES = 16 * 1024 * 1024
MAX_CAPTURE_DEPTH = 64
MAX_ORPHAN_AGE_SECONDS = 3_600
MAX_CAPTURE_SLOTS = 8

SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

PLAN_FIELDS = {
    "schema_version",
    "instance_slug",
    "evidence_uid",
    "verifier_gid",
    "sources",
    "limits",
    "lifecycle",
}
SOURCE_FIELDS = {
    "source_id",
    "source_class",
    "kind",
    "source_path",
    "destination_path",
}
LIMIT_FIELDS = {
    "max_files",
    "max_directories",
    "max_bytes",
    "max_file_bytes",
    "max_depth",
}
LIFECYCLE_FIELDS = {
    "retention",
    "max_capture_slots",
    "max_orphan_age_seconds",
}


class CapturePlanError(ValueError):
    """A stable rejection for installed opaque-capture plans."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _error(code: str) -> CapturePlanError:
    return CapturePlanError(code)


def _mapping(value: Any, *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _error(f"{field}_not_object")
    return value


def _strict_fields(
    value: Mapping[str, Any],
    *,
    field: str,
    expected: set[str],
) -> None:
    if set(value) != expected or any(not isinstance(key, str) for key in value):
        raise _error(f"{field}_fields_invalid")


def _integer(
    value: Any,
    *,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if (
        type(value) is not int
        or value < minimum
        or value > maximum
    ):
        raise _error(f"{field}_invalid")
    return value


def _absolute_path(value: Any, *, field: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4_096
        or "\x00" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise _error(f"{field}_invalid")
    path = Path(value)
    if (
        not path.is_absolute()
        or "." in path.parts
        or ".." in path.parts
        or value != str(path)
    ):
        raise _error(f"{field}_invalid")
    return path


def _relative_path(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 1_024
        or "\x00" in value
    ):
        raise _error(f"{field}_invalid")
    path = Path(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or "." in path.parts
        or ".." in path.parts
        or any(not part for part in path.parts)
        or len(path.parts) > MAX_CAPTURE_DEPTH
    ):
        raise _error(f"{field}_invalid")
    return value


def _identity(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _path_overlaps(left: Path, right: Path) -> bool:
    left_text = _identity(str(left).rstrip(os.sep))
    right_text = _identity(str(right).rstrip(os.sep))
    return (
        left_text == right_text
        or left_text.startswith(right_text + os.sep)
        or right_text.startswith(left_text + os.sep)
    )


def _relative_overlaps(left: str, right: str) -> bool:
    left_parts = tuple(_identity(part) for part in Path(left).parts)
    right_parts = tuple(_identity(part) for part in Path(right).parts)
    shared = min(len(left_parts), len(right_parts))
    return left_parts[:shared] == right_parts[:shared]


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
        raise _error("capture_plan_not_canonical") from exc


def capture_plan_sha256(value: Any) -> str:
    return hashlib.sha256(
        _canonical_json(normalize_capture_plan(value))
    ).hexdigest()


def _normalize_source(value: Any, *, evidence_uid: int) -> dict[str, Any]:
    source = _mapping(value, field="capture_plan_source")
    _strict_fields(
        source,
        field="capture_plan_source",
        expected=SOURCE_FIELDS,
    )
    source_id = source.get("source_id")
    source_class = source.get("source_class")
    if not isinstance(source_id, str) or not TOKEN_RE.fullmatch(source_id):
        raise _error("capture_plan_source_id_invalid")
    if (
        not isinstance(source_class, str)
        or not TOKEN_RE.fullmatch(source_class)
    ):
        raise _error("capture_plan_source_class_invalid")
    kind = source.get("kind")
    if kind not in {"file", "tree"}:
        raise _error("capture_plan_source_kind_invalid")
    source_path = _absolute_path(
        source.get("source_path"),
        field="capture_plan_source_path",
    )
    destination = _relative_path(
        source.get("destination_path"),
        field="capture_plan_destination_path",
    )
    # Ownership is intentionally not caller-selectable per source. Every live
    # source belongs to the one evidence identity pinned by the plan.
    del evidence_uid
    return {
        "source_id": source_id,
        "source_class": source_class,
        "kind": kind,
        "source_path": str(source_path),
        "destination_path": destination,
    }


def normalize_capture_plan(value: Any) -> dict[str, Any]:
    """Normalize the only plan shape accepted by the opaque sealer."""

    plan = _mapping(value, field="capture_plan")
    _strict_fields(plan, field="capture_plan", expected=PLAN_FIELDS)
    if plan.get("schema_version") != CAPTURE_PLAN_SCHEMA:
        raise _error("capture_plan_schema_unsupported")
    slug = plan.get("instance_slug")
    if not isinstance(slug, str) or not SLUG_RE.fullmatch(slug):
        raise _error("capture_plan_instance_slug_invalid")
    evidence_uid = _integer(
        plan.get("evidence_uid"),
        field="capture_plan_evidence_uid",
        minimum=1,
        maximum=(1 << 31) - 1,
    )
    verifier_gid = _integer(
        plan.get("verifier_gid"),
        field="capture_plan_verifier_gid",
        minimum=1,
        maximum=(1 << 31) - 1,
    )

    limits = _mapping(plan.get("limits"), field="capture_plan_limits")
    _strict_fields(
        limits,
        field="capture_plan_limits",
        expected=LIMIT_FIELDS,
    )
    normalized_limits = {
        "max_files": _integer(
            limits.get("max_files"),
            field="capture_plan_max_files",
            minimum=1,
            maximum=MAX_CAPTURE_FILES,
        ),
        "max_directories": _integer(
            limits.get("max_directories"),
            field="capture_plan_max_directories",
            minimum=1,
            maximum=MAX_CAPTURE_DIRECTORIES,
        ),
        "max_bytes": _integer(
            limits.get("max_bytes"),
            field="capture_plan_max_bytes",
            minimum=1,
            maximum=MAX_CAPTURE_BYTES,
        ),
        "max_file_bytes": _integer(
            limits.get("max_file_bytes"),
            field="capture_plan_max_file_bytes",
            minimum=1,
            maximum=MAX_CAPTURE_FILE_BYTES,
        ),
        "max_depth": _integer(
            limits.get("max_depth"),
            field="capture_plan_max_depth",
            minimum=1,
            maximum=MAX_CAPTURE_DEPTH,
        ),
    }
    if normalized_limits["max_file_bytes"] > normalized_limits["max_bytes"]:
        raise _error("capture_plan_file_limit_exceeds_total")

    lifecycle = _mapping(
        plan.get("lifecycle"),
        field="capture_plan_lifecycle",
    )
    _strict_fields(
        lifecycle,
        field="capture_plan_lifecycle",
        expected=LIFECYCLE_FIELDS,
    )
    if lifecycle.get("retention") != "ephemeral":
        raise _error("capture_plan_retention_unsupported")
    normalized_lifecycle = {
        "retention": "ephemeral",
        "max_capture_slots": _integer(
            lifecycle.get("max_capture_slots"),
            field="capture_plan_max_capture_slots",
            minimum=1,
            maximum=MAX_CAPTURE_SLOTS,
        ),
        "max_orphan_age_seconds": _integer(
            lifecycle.get("max_orphan_age_seconds"),
            field="capture_plan_max_orphan_age_seconds",
            minimum=1,
            maximum=MAX_ORPHAN_AGE_SECONDS,
        ),
    }

    raw_sources = plan.get("sources")
    if (
        not isinstance(raw_sources, list)
        or not raw_sources
        or len(raw_sources) > MAX_PLAN_SOURCES
    ):
        raise _error("capture_plan_source_count_invalid")
    sources = [
        _normalize_source(source, evidence_uid=evidence_uid)
        for source in raw_sources
    ]
    if [source["destination_path"] for source in sources] != sorted(
        source["destination_path"] for source in sources
    ):
        raise _error("capture_plan_sources_not_sorted")

    ids: set[str] = set()
    classes: set[str] = set()
    for source in sources:
        source_id = _identity(source["source_id"])
        source_class = _identity(source["source_class"])
        if source_id in ids:
            raise _error("capture_plan_source_id_duplicate")
        if source_class in classes:
            raise _error("capture_plan_source_class_duplicate")
        ids.add(source_id)
        classes.add(source_class)
    for index, source in enumerate(sources):
        source_path = Path(source["source_path"])
        destination = source["destination_path"]
        for other in sources[index + 1 :]:
            if _path_overlaps(source_path, Path(other["source_path"])):
                raise _error("capture_plan_source_paths_overlap")
            if _relative_overlaps(
                destination,
                other["destination_path"],
            ):
                raise _error("capture_plan_destination_paths_overlap")

    return {
        "schema_version": CAPTURE_PLAN_SCHEMA,
        "instance_slug": slug,
        "evidence_uid": evidence_uid,
        "verifier_gid": verifier_gid,
        "sources": sources,
        "limits": normalized_limits,
        "lifecycle": normalized_lifecycle,
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in pairs:
        if key in result:
            raise _error("capture_plan_duplicate_json_field")
        result[key] = item
    return result


def _parse_json(raw: bytes) -> Any:
    if not raw or len(raw) > MAX_PLAN_BYTES:
        raise _error("capture_plan_size_invalid")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _: (_ for _ in ()).throw(
                _error("capture_plan_nonfinite_number")
            ),
        )
    except CapturePlanError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _error("capture_plan_json_invalid") from exc


def _reject_fd_metadata(
    descriptor: int,
    *,
    field: str,
    permitted_attributes: frozenset[bytes] | None = None,
) -> None:
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
        attribute_bytes = libc.flistxattr(descriptor, None, 0, 0)
    elif sys.platform.startswith("linux"):
        if not hasattr(libc, "flistxattr"):
            raise _error(f"{field}_fd_metadata_unsupported")
        libc.flistxattr.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        libc.flistxattr.restype = ctypes.c_ssize_t
        attribute_bytes = libc.flistxattr(descriptor, None, 0)
    else:
        raise _error(f"{field}_fd_metadata_unsupported")
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
    # Codex/macOS may attach non-authorizing provenance metadata even to a
    # freshly created root-control file. It cannot grant access or influence
    # JSON parsing. Every other extended attribute remains fail-closed.
    if permitted_attributes is not None:
        permitted = permitted_attributes
    elif sys.platform == "darwin":
        permitted = frozenset({b"com.apple.provenance"})
    elif sys.platform.startswith("linux"):
        permitted = frozenset({b"security.selinux"})
    else:
        permitted = frozenset()
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


def _open_validated_parent_directory(
    path: Path,
    *,
    expected_owner_uid: int,
) -> int:
    """Walk a fixed absolute parent without following a mutable redirect."""

    if not path.is_absolute() or "." in path.parts or ".." in path.parts:
        raise _error("capture_plan_parent_unsafe")
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("capture_plan_nofollow_unsupported")
    flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(Path(path.anchor), flags)
    except OSError as exc:
        raise _error("capture_plan_parent_unreadable") from exc
    parent_attributes = (
        frozenset(
            {
                b"com.apple.provenance",
                b"com.apple.rootless",
            }
        )
        if sys.platform == "darwin"
        else frozenset({b"security.selinux"})
    )
    components = path.parts[1:]
    try:
        for index in range(len(components) + 1):
            info = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid not in {0, expected_owner_uid}
                or info.st_mode & 0o022
            ):
                raise _error("capture_plan_parent_unsafe")
            _reject_fd_metadata(
                descriptor,
                field="capture_plan_parent",
                permitted_attributes=parent_attributes,
            )
            if index == len(components):
                return descriptor
            try:
                child = os.open(
                    components[index],
                    flags,
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise _error("capture_plan_parent_unreadable") from exc
            os.close(descriptor)
            descriptor = child
    except Exception:
        os.close(descriptor)
        raise
    raise AssertionError("unreachable")


def _snapshot(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
        getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000)),
    )


def read_installed_capture_plan(
    path: Path,
    *,
    expected_owner_uid: int = 0,
) -> tuple[dict[str, Any], str]:
    """Read one immutable installed plan without following redirects."""

    plan_path = _absolute_path(
        str(path),
        field="installed_capture_plan_path",
    )
    parent_descriptor = _open_validated_parent_directory(
        plan_path.parent,
        expected_owner_uid=expected_owner_uid,
    )
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("capture_plan_nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(
            plan_path.name,
            flags,
            dir_fd=parent_descriptor,
        )
    except OSError as exc:
        os.close(parent_descriptor)
        raise _error("capture_plan_unreadable") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_owner_uid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size < 1
            or before.st_size > MAX_PLAN_BYTES
        ):
            raise _error("capture_plan_file_unsafe")
        _reject_fd_metadata(descriptor, field="capture_plan")
        raw = bytearray()
        while len(raw) <= MAX_PLAN_BYTES:
            chunk = os.read(
                descriptor,
                min(64 * 1024, MAX_PLAN_BYTES + 1 - len(raw)),
            )
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        named = os.stat(
            plan_path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            len(raw) != before.st_size
            or _snapshot(before) != _snapshot(after)
            or _snapshot(after) != _snapshot(named)
        ):
            raise _error("capture_plan_changed_during_read")
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)
    normalized = normalize_capture_plan(_parse_json(bytes(raw)))
    return normalized, hashlib.sha256(_canonical_json(normalized)).hexdigest()
