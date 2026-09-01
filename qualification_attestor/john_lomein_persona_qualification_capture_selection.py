#!/usr/bin/env python3
"""Root-owned sparse selection for one terminal persona-qualification run.

This staging contract is deliberately standard-library-only.  It binds the
operator-selected evidence identities, reads exactly one fixed ``status.json``
through descriptor-relative no-follow operations, and compiles an existing
opaque capture-plan v1 containing only the files needed to reproduce that run.

It is not a production activation switch.  Installing, consuming, or adopting
this contract requires a separate reviewed change.
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


CAPTURE_SELECTION_SCHEMA = (
    "john-lomein.persona-qualification-capture-selection.v1"
)
SELECTION_SCHEMA = CAPTURE_SELECTION_SCHEMA
CAPTURE_PLAN_SCHEMA = "john-lomein.persona-qualification-capture-plan.v1"
QUALIFICATION_STATUS_SCHEMA = (
    "john-lomein.persona-qualification-status.v1"
)

# This module is a contract and test seam only.  Adoption belongs in a
# separate installer/coordinator change with its own review.
PRODUCTION_ACTIVATION = False

MAX_SELECTION_BYTES = 256 * 1024
MAX_STATUS_BYTES = 2 * 1024 * 1024
MAX_CAPTURE_FILES = 4_096
MAX_CAPTURE_DIRECTORIES = 4_096
MAX_CAPTURE_BYTES = 128 * 1024 * 1024
MAX_CAPTURE_FILE_BYTES = 16 * 1024 * 1024
MAX_CAPTURE_DEPTH = 64
MAX_CAPTURE_SLOTS = 8
MAX_ORPHAN_AGE_SECONDS = 3_600
MAX_STATUS_CANDIDATES = 16
MAX_SAFE_ID = (1 << 31) - 1
MAX_SAFE_INTEGER = (1 << 53) - 1

SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

ROLE_PROFILES = {
    "maintainer": "john-lomein-maintainer",
    "forge": "john-lomein-forge",
    "guide": "john-lomein-guide",
    "overwatch": "john-lomein-overwatch",
    "learning_steward": "john-lomein-learning-steward",
}

SELECTION_FIELDS = {
    "schema_version",
    "instance_slug",
    "evidence_uid",
    "verifier_gid",
    "source_roots",
    "path_identities",
    "role_profiles",
    "limits",
    "lifecycle",
}
SOURCE_ROOT_FIELDS = {
    "instance_manifest",
    "runtime",
    "qualification_public",
    "qualification_private",
}
PATH_IDENTITY_FIELDS = {
    "evidence_home",
    "checkout_source",
    "runtime_source",
    "checkout",
    "runtime",
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
STATUS_FIELDS = {
    "schema_version",
    "status",
    "reason",
    "run_id",
    "binding_digest",
    "candidates",
    "summary_sha256",
    "started_at_unix",
    "run_deadline_unix",
    "qualified_at_unix",
    "expires_at_unix",
    "evidence_class",
    "public_reputation_eligible",
    "record_digest",
}


class CaptureSelectionError(ValueError):
    """Stable fail-closed rejection for capture-selection inputs."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _error(code: str) -> CaptureSelectionError:
    return CaptureSelectionError(code)


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
    if type(value) is not int or not minimum <= value <= maximum:
        raise _error(f"{field}_invalid")
    return value


def _digest(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise _error(f"{field}_invalid")
    return value


def _absolute_path(value: Any, *, field: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4_096
        or "\x00" in value
        or any(ord(character) < 32 for character in value)
        or unicodedata.normalize("NFC", value) != value
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


def _identity(value: str) -> str:
    return unicodedata.normalize("NFC", value.rstrip(os.sep)).casefold()


def _path_overlaps(left: Path, right: Path) -> bool:
    left_identity = _identity(str(left))
    right_identity = _identity(str(right))
    return (
        left_identity == right_identity
        or left_identity.startswith(right_identity + os.sep)
        or right_identity.startswith(left_identity + os.sep)
    )


def _path_contains(parent: Path, child: Path) -> bool:
    parent_identity = _identity(str(parent))
    child_identity = _identity(str(child))
    return (
        parent_identity == child_identity
        or child_identity.startswith(parent_identity + os.sep)
    )


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
        raise _error("capture_selection_not_canonical") from exc


def _retained_json(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _error("qualification_status_not_canonical") from exc


def _parse_json(raw: bytes, *, field: str, maximum: int) -> Any:
    if not raw or len(raw) > maximum:
        raise _error(f"{field}_size_invalid")

    def reject_duplicate_keys(
        pairs: list[tuple[str, Any]],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _error(f"{field}_duplicate_json_field")
            result[key] = value
        return result

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda _: (_ for _ in ()).throw(
                _error(f"{field}_nonfinite_number")
            ),
        )
    except CaptureSelectionError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _error(f"{field}_json_invalid") from exc


def _normalize_limits(value: Any) -> dict[str, int]:
    limits = _mapping(value, field="capture_selection_limits")
    _strict_fields(
        limits,
        field="capture_selection_limits",
        expected=LIMIT_FIELDS,
    )
    normalized = {
        "max_files": _integer(
            limits.get("max_files"),
            field="capture_selection_max_files",
            minimum=1,
            maximum=MAX_CAPTURE_FILES,
        ),
        "max_directories": _integer(
            limits.get("max_directories"),
            field="capture_selection_max_directories",
            minimum=1,
            maximum=MAX_CAPTURE_DIRECTORIES,
        ),
        "max_bytes": _integer(
            limits.get("max_bytes"),
            field="capture_selection_max_bytes",
            minimum=1,
            maximum=MAX_CAPTURE_BYTES,
        ),
        "max_file_bytes": _integer(
            limits.get("max_file_bytes"),
            field="capture_selection_max_file_bytes",
            minimum=1,
            maximum=MAX_CAPTURE_FILE_BYTES,
        ),
        "max_depth": _integer(
            limits.get("max_depth"),
            field="capture_selection_max_depth",
            minimum=1,
            maximum=MAX_CAPTURE_DEPTH,
        ),
    }
    if normalized["max_file_bytes"] > normalized["max_bytes"]:
        raise _error("capture_selection_file_limit_exceeds_total")
    return normalized


def _normalize_lifecycle(value: Any) -> dict[str, Any]:
    lifecycle = _mapping(
        value,
        field="capture_selection_lifecycle",
    )
    _strict_fields(
        lifecycle,
        field="capture_selection_lifecycle",
        expected=LIFECYCLE_FIELDS,
    )
    if lifecycle.get("retention") != "ephemeral":
        raise _error("capture_selection_retention_unsupported")
    return {
        "retention": "ephemeral",
        "max_capture_slots": _integer(
            lifecycle.get("max_capture_slots"),
            field="capture_selection_max_capture_slots",
            minimum=1,
            maximum=MAX_CAPTURE_SLOTS,
        ),
        "max_orphan_age_seconds": _integer(
            lifecycle.get("max_orphan_age_seconds"),
            field="capture_selection_max_orphan_age_seconds",
            minimum=1,
            maximum=MAX_ORPHAN_AGE_SECONDS,
        ),
    }


def normalize_capture_selection(value: Any) -> dict[str, Any]:
    """Normalize the one accepted sparse-selection shape."""

    selection = _mapping(value, field="capture_selection")
    _strict_fields(
        selection,
        field="capture_selection",
        expected=SELECTION_FIELDS,
    )
    if selection.get("schema_version") != CAPTURE_SELECTION_SCHEMA:
        raise _error("capture_selection_schema_unsupported")
    slug = selection.get("instance_slug")
    if not isinstance(slug, str) or not SLUG_RE.fullmatch(slug):
        raise _error("capture_selection_instance_slug_invalid")
    evidence_uid = _integer(
        selection.get("evidence_uid"),
        field="capture_selection_evidence_uid",
        minimum=1,
        maximum=MAX_SAFE_ID,
    )
    verifier_gid = _integer(
        selection.get("verifier_gid"),
        field="capture_selection_verifier_gid",
        minimum=1,
        maximum=MAX_SAFE_ID,
    )

    raw_roots = _mapping(
        selection.get("source_roots"),
        field="capture_selection_source_roots",
    )
    _strict_fields(
        raw_roots,
        field="capture_selection_source_roots",
        expected=SOURCE_ROOT_FIELDS,
    )
    source_roots = {
        name: str(
            _absolute_path(
                raw_roots.get(name),
                field=f"capture_selection_{name}_path",
            )
        )
        for name in sorted(SOURCE_ROOT_FIELDS)
    }

    raw_identities = _mapping(
        selection.get("path_identities"),
        field="capture_selection_path_identities",
    )
    _strict_fields(
        raw_identities,
        field="capture_selection_path_identities",
        expected=PATH_IDENTITY_FIELDS,
    )
    path_identities = {
        name: str(
            _absolute_path(
                raw_identities.get(name),
                field=f"capture_selection_{name}_identity",
            )
        )
        for name in sorted(PATH_IDENTITY_FIELDS)
    }

    raw_profiles = _mapping(
        selection.get("role_profiles"),
        field="capture_selection_role_profiles",
    )
    _strict_fields(
        raw_profiles,
        field="capture_selection_role_profiles",
        expected=set(ROLE_PROFILES),
    )
    if dict(raw_profiles) != ROLE_PROFILES:
        raise _error("capture_selection_role_profiles_mismatch")

    instance_path = Path(source_roots["instance_manifest"])
    runtime_root = Path(source_roots["runtime"])
    public_root = Path(source_roots["qualification_public"])
    private_root = Path(source_roots["qualification_private"])
    evidence_home = Path(path_identities["evidence_home"])
    checkout_source = Path(path_identities["checkout_source"])
    runtime_source = Path(path_identities["runtime_source"])
    checkout_identity = Path(path_identities["checkout"])
    runtime_identity = Path(path_identities["runtime"])

    if public_root != runtime_root / "state" / "persona-qualification":
        raise _error("capture_selection_public_root_layout_mismatch")
    if runtime_identity != runtime_root:
        raise _error("capture_selection_runtime_identity_mismatch")
    if (
        _path_overlaps(instance_path, runtime_root)
        or _path_overlaps(instance_path, private_root)
        or _path_overlaps(runtime_root, private_root)
    ):
        raise _error("capture_selection_source_roots_overlap")

    checkout_paths = (checkout_source, checkout_identity)
    runtime_paths = (runtime_source, runtime_identity)
    if any(
        _path_overlaps(checkout_path, runtime_path)
        for checkout_path in checkout_paths
        for runtime_path in runtime_paths
    ):
        raise _error("capture_selection_checkout_runtime_overlap")
    if any(
        _path_overlaps(private_root, checkout_path)
        for checkout_path in checkout_paths
    ):
        raise _error("capture_selection_private_checkout_overlap")
    if any(
        _path_overlaps(private_root, runtime_path)
        for runtime_path in runtime_paths
    ):
        raise _error("capture_selection_private_runtime_overlap")
    # A capture root may be below the evidence home, but it may never be the
    # whole home (or an ancestor of it).
    for broad_root in (
        runtime_root,
        private_root,
        checkout_source,
        runtime_source,
        checkout_identity,
        runtime_identity,
    ):
        if _path_contains(broad_root, evidence_home):
            raise _error("capture_selection_evidence_home_alias")

    return {
        "schema_version": CAPTURE_SELECTION_SCHEMA,
        "instance_slug": slug,
        "evidence_uid": evidence_uid,
        "verifier_gid": verifier_gid,
        "source_roots": source_roots,
        "path_identities": path_identities,
        "role_profiles": dict(ROLE_PROFILES),
        "limits": _normalize_limits(selection.get("limits")),
        "lifecycle": _normalize_lifecycle(selection.get("lifecycle")),
    }


def capture_selection_sha256(value: Any) -> str:
    return hashlib.sha256(
        _canonical_json(normalize_capture_selection(value))
    ).hexdigest()


def _reject_fd_metadata(
    descriptor: int,
    *,
    field: str,
    permitted_attributes: frozenset[bytes] | None = None,
) -> None:
    """Reject authorizing ACLs and all unrecognized extended metadata."""

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
    elif sys.platform.startswith("linux"):
        libc.flistxattr.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        attribute_bytes = libc.flistxattr(descriptor, None, 0)
    else:
        raise _error(f"{field}_fd_metadata_unsupported")
    if attribute_bytes < 0:
        raise _error(f"{field}_metadata_unreadable")
    attributes: set[bytes] = set()
    if attribute_bytes:
        buffer = ctypes.create_string_buffer(attribute_bytes)
        observed = (
            libc.flistxattr(descriptor, buffer, attribute_bytes, 0)
            if sys.platform == "darwin"
            else libc.flistxattr(descriptor, buffer, attribute_bytes)
        )
        if observed != attribute_bytes:
            raise _error(f"{field}_metadata_changed")
        attributes = {
            item
            for item in bytes(buffer.raw[:observed]).split(b"\x00")
            if item
        }
    if permitted_attributes is None:
        permitted_attributes = (
            frozenset({b"com.apple.provenance"})
            if sys.platform == "darwin"
            else frozenset({b"security.selinux"})
        )
    if not attributes.issubset(permitted_attributes):
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


def _directory_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("capture_selection_nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _open_validated_directory(
    path: Path,
    *,
    expected_owner_uid: int,
    field: str,
    exact_leaf_owner: bool,
    exact_leaf_mode: int | None,
) -> int:
    """Open an absolute directory chain without following any component."""

    if not path.is_absolute() or "." in path.parts or ".." in path.parts:
        raise _error(f"{field}_unsafe")
    owner_uid = _integer(
        expected_owner_uid,
        field=f"{field}_expected_owner_uid",
        minimum=0,
        maximum=MAX_SAFE_ID,
    )
    flags = _directory_flags()
    try:
        descriptor = os.open(Path(path.anchor), flags)
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    components = path.parts[1:]
    parent_attributes = (
        frozenset({b"com.apple.provenance", b"com.apple.rootless"})
        if sys.platform == "darwin"
        else frozenset({b"security.selinux"})
    )
    try:
        for index in range(len(components) + 1):
            info = os.fstat(descriptor)
            is_leaf = index == len(components)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid not in {0, owner_uid}
                or info.st_mode & 0o022
                or (
                    is_leaf
                    and exact_leaf_owner
                    and info.st_uid != owner_uid
                )
                or (
                    is_leaf
                    and exact_leaf_mode is not None
                    and stat.S_IMODE(info.st_mode) != exact_leaf_mode
                )
            ):
                raise _error(f"{field}_unsafe")
            _reject_fd_metadata(
                descriptor,
                field=field,
                permitted_attributes=parent_attributes,
            )
            if is_leaf:
                return descriptor
            try:
                child = os.open(
                    components[index],
                    flags,
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise _error(f"{field}_unreadable") from exc
            os.close(descriptor)
            descriptor = child
    except Exception:
        os.close(descriptor)
        raise
    raise AssertionError("unreachable")


def _snapshot(info: os.stat_result) -> tuple[int, ...]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_uid),
        int(info.st_gid),
        int(info.st_nlink),
        int(info.st_size),
        int(getattr(info, "st_mtime_ns", info.st_mtime * 1_000_000_000)),
        int(getattr(info, "st_ctime_ns", info.st_ctime * 1_000_000_000)),
    )


def _read_fixed_file(
    path: Path,
    *,
    expected_owner_uid: int,
    expected_mode: int,
    maximum: int,
    field: str,
    exact_parent_owner: bool,
    exact_parent_mode: int | None,
) -> bytes:
    parent_descriptor = _open_validated_directory(
        path.parent,
        expected_owner_uid=expected_owner_uid,
        field=f"{field}_parent",
        exact_leaf_owner=exact_parent_owner,
        exact_leaf_mode=exact_parent_mode,
    )
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
    except OSError as exc:
        os.close(parent_descriptor)
        raise _error(f"{field}_unreadable") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_owner_uid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != expected_mode
            or not 1 <= before.st_size <= maximum
        ):
            raise _error(f"{field}_file_unsafe")
        _reject_fd_metadata(descriptor, field=field)
        raw = bytearray()
        while len(raw) <= maximum:
            chunk = os.read(
                descriptor,
                min(64 * 1024, maximum + 1 - len(raw)),
            )
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        _reject_fd_metadata(descriptor, field=field)
        named = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            len(raw) != before.st_size
            or _snapshot(before) != _snapshot(after)
            or _snapshot(after) != _snapshot(named)
        ):
            raise _error(f"{field}_changed_during_read")
        return bytes(raw)
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)


def read_installed_capture_selection(
    path: Path,
    *,
    expected_owner_uid: int = 0,
) -> tuple[dict[str, Any], str]:
    """Read one root-owned installed selection through a no-follow chain."""

    selection_path = _absolute_path(
        str(path),
        field="installed_capture_selection_path",
    )
    raw = _read_fixed_file(
        selection_path,
        expected_owner_uid=expected_owner_uid,
        expected_mode=0o600,
        maximum=MAX_SELECTION_BYTES,
        field="capture_selection",
        exact_parent_owner=False,
        exact_parent_mode=None,
    )
    normalized = normalize_capture_selection(
        _parse_json(
            raw,
            field="capture_selection",
            maximum=MAX_SELECTION_BYTES,
        )
    )
    return normalized, hashlib.sha256(_canonical_json(normalized)).hexdigest()


def _normalize_terminal_status(value: Any) -> dict[str, Any]:
    status = _mapping(value, field="qualification_status")
    _strict_fields(
        status,
        field="qualification_status",
        expected=STATUS_FIELDS,
    )
    if status.get("schema_version") != QUALIFICATION_STATUS_SCHEMA:
        raise _error("qualification_status_schema_unsupported")
    if (
        status.get("status") != "qualified"
        or status.get("reason") != "all-distinct-candidates-qualified"
        or status.get("evidence_class") != "local_model_conformance"
        or status.get("public_reputation_eligible") is not False
    ):
        raise _error("qualification_status_not_terminal_qualified")
    run_id = status.get("run_id")
    if (
        not isinstance(run_id, str)
        or unicodedata.normalize("NFC", run_id) != run_id
        or not RUN_ID_RE.fullmatch(run_id)
    ):
        raise _error("qualification_status_run_id_invalid")
    _digest(
        status.get("binding_digest"),
        field="qualification_status_binding_digest",
    )
    _digest(
        status.get("summary_sha256"),
        field="qualification_status_summary_sha256",
    )

    candidates = status.get("candidates")
    if (
        not isinstance(candidates, list)
        or not 1 <= len(candidates) <= MAX_STATUS_CANDIDATES
    ):
        raise _error("qualification_status_candidates_invalid")
    candidate_ids: list[str] = []
    for raw_candidate in candidates:
        candidate = _mapping(
            raw_candidate,
            field="qualification_status_candidate",
        )
        _strict_fields(
            candidate,
            field="qualification_status_candidate",
            expected={"id", "slots", "status"},
        )
        candidate_id = candidate.get("id")
        slots = candidate.get("slots")
        if (
            not isinstance(candidate_id, str)
            or unicodedata.normalize("NFC", candidate_id) != candidate_id
            or not COMPONENT_RE.fullmatch(candidate_id)
            or candidate.get("status") != "qualified"
            or not isinstance(slots, list)
            or slots
            not in (
                ["primary"],
                ["fallback"],
                ["primary", "fallback"],
            )
        ):
            raise _error("qualification_status_candidate_invalid")
        candidate_ids.append(candidate_id)
    if (
        candidate_ids != sorted(candidate_ids)
        or len({_identity(item) for item in candidate_ids})
        != len(candidate_ids)
    ):
        raise _error("qualification_status_candidate_order_invalid")

    started_at = _integer(
        status.get("started_at_unix"),
        field="qualification_status_started_at_unix",
        minimum=1,
        maximum=MAX_SAFE_INTEGER,
    )
    deadline = _integer(
        status.get("run_deadline_unix"),
        field="qualification_status_run_deadline_unix",
        minimum=1,
        maximum=MAX_SAFE_INTEGER,
    )
    qualified_at = _integer(
        status.get("qualified_at_unix"),
        field="qualification_status_qualified_at_unix",
        minimum=1,
        maximum=MAX_SAFE_INTEGER,
    )
    expires_at = _integer(
        status.get("expires_at_unix"),
        field="qualification_status_expires_at_unix",
        minimum=1,
        maximum=MAX_SAFE_INTEGER,
    )
    if not started_at <= qualified_at <= deadline < expires_at:
        raise _error("qualification_status_timing_invalid")

    supplied_digest = _digest(
        status.get("record_digest"),
        field="qualification_status_record_digest",
    )
    unsigned = dict(status)
    unsigned.pop("record_digest")
    if hashlib.sha256(_canonical_json(unsigned)).hexdigest() != supplied_digest:
        raise _error("qualification_status_self_digest_invalid")
    return dict(status)


def parse_terminal_qualified_status(raw: bytes) -> dict[str, Any]:
    """Parse the exact retained terminal status used to select one run."""

    if not isinstance(raw, bytes):
        raise _error("qualification_status_bytes_invalid")
    status = _normalize_terminal_status(
        _parse_json(
            raw,
            field="qualification_status",
            maximum=MAX_STATUS_BYTES,
        )
    )
    if raw != _retained_json(status):
        raise _error("qualification_status_encoding_not_canonical")
    return status


def read_current_qualified_status(selection: Any) -> dict[str, Any]:
    """Read exactly ``<qualification_public>/status.json`` and select its run."""

    normalized = normalize_capture_selection(selection)
    public_root = Path(
        normalized["source_roots"]["qualification_public"]
    )
    raw = _read_fixed_file(
        public_root / "status.json",
        expected_owner_uid=normalized["evidence_uid"],
        expected_mode=0o600,
        maximum=MAX_STATUS_BYTES,
        field="qualification_status",
        exact_parent_owner=True,
        exact_parent_mode=0o700,
    )
    return parse_terminal_qualified_status(raw)


def select_current_run(selection: Any) -> str:
    """Return the fixed selector's terminal qualified run identifier."""

    return read_current_qualified_status(selection)["run_id"]


def _source(
    *,
    source_id: str,
    source_class: str,
    kind: str,
    source_path: Path,
    destination_path: str,
) -> dict[str, str]:
    return {
        "source_id": source_id,
        "source_class": source_class,
        "kind": kind,
        "source_path": str(source_path),
        "destination_path": destination_path,
    }


def _validated_run_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or unicodedata.normalize("NFC", value) != value
        or not RUN_ID_RE.fullmatch(value)
    ):
        raise _error("capture_selection_run_id_invalid")
    return value


def compile_concrete_capture_plan(
    selection: Any,
    run_id: str,
) -> dict[str, Any]:
    """Purely compile the only plan allowed for one selected run."""

    normalized = normalize_capture_selection(selection)
    selected_run = _validated_run_id(run_id)
    roots = normalized["source_roots"]
    instance_path = Path(roots["instance_manifest"])
    runtime_root = Path(roots["runtime"])
    public_root = Path(roots["qualification_public"])
    private_root = Path(roots["qualification_private"])

    sources = [
        _source(
            source_id="instance",
            source_class="instance_manifest",
            kind="file",
            source_path=instance_path,
            destination_path="instance/instance.yaml",
        ),
        _source(
            source_id="private-current-run",
            source_class="qualification_private_run",
            kind="tree",
            source_path=private_root / selected_run,
            destination_path=f"private/{selected_run}",
        ),
        _source(
            source_id="runtime-instance",
            source_class="deployed_instance_manifest",
            kind="file",
            source_path=runtime_root / "instance.yaml",
            destination_path="runtime/instance.yaml",
        ),
    ]
    for role, profile in ROLE_PROFILES.items():
        profile_root = runtime_root / "profiles" / profile
        sources.extend(
            (
                _source(
                    source_id=f"profile-{role}-soul",
                    source_class=f"deployed_soul:{role}",
                    kind="file",
                    source_path=profile_root / "SOUL.md",
                    destination_path=(
                        f"runtime/profiles/{profile}/SOUL.md"
                    ),
                ),
                _source(
                    source_id=f"profile-{role}-config",
                    source_class=f"deployed_profile_config:{role}",
                    kind="file",
                    source_path=profile_root / "config.yaml",
                    destination_path=(
                        f"runtime/profiles/{profile}/config.yaml"
                    ),
                ),
            )
        )
    sources.extend(
        (
            _source(
                source_id="persona-receipt",
                source_class="persona_receipt",
                kind="file",
                source_path=runtime_root
                / "state"
                / "john-lomein-persona.json",
                destination_path=(
                    "runtime/state/john-lomein-persona.json"
                ),
            ),
            _source(
                source_id="public-latest",
                source_class="qualification_public_latest",
                kind="file",
                source_path=public_root / "latest.json",
                destination_path=(
                    "runtime/state/persona-qualification/latest.json"
                ),
            ),
            _source(
                source_id="public-current-report",
                source_class="qualification_public_run",
                kind="tree",
                source_path=public_root / "reports" / selected_run,
                destination_path=(
                    "runtime/state/persona-qualification/reports/"
                    f"{selected_run}"
                ),
            ),
            _source(
                source_id="public-status",
                source_class="qualification_public_status",
                kind="file",
                source_path=public_root / "status.json",
                destination_path=(
                    "runtime/state/persona-qualification/status.json"
                ),
            ),
        )
    )
    sources.sort(key=lambda item: item["destination_path"])
    return {
        "schema_version": CAPTURE_PLAN_SCHEMA,
        "instance_slug": normalized["instance_slug"],
        "evidence_uid": normalized["evidence_uid"],
        "verifier_gid": normalized["verifier_gid"],
        "sources": sources,
        "limits": normalized["limits"],
        "lifecycle": normalized["lifecycle"],
    }


def validate_concrete_capture_plan(
    policy: Any,
    plan: Any,
    run_id: str,
) -> tuple[dict[str, Any], str]:
    """Require canonical equality with the selector's pure expected plan.

    A future verifier can reconstruct this expected value without duplicating
    any source-class, path, or destination-layout rules.  The returned digest
    is over the exact canonical plan-v1 bytes.
    """

    expected = compile_concrete_capture_plan(policy, run_id)
    if _canonical_json(plan) != _canonical_json(expected):
        raise _error("capture_selection_concrete_plan_mismatch")
    return expected, hashlib.sha256(_canonical_json(expected)).hexdigest()


def compile_current_run_capture_plan(selection: Any) -> dict[str, Any]:
    """Select the fixed status and compile its sparse capture-plan v1."""

    normalized = normalize_capture_selection(selection)
    status = read_current_qualified_status(normalized)
    return compile_concrete_capture_plan(normalized, status["run_id"])


def compile_capture_plan(selection: Any) -> dict[str, Any]:
    """Compatibility spelling for the sparse current-run compiler."""

    return compile_current_run_capture_plan(selection)
