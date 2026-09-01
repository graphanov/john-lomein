#!/usr/bin/env python3
"""Pure contract for binding root adoption into qualification evidence.

The privileged adoption implementation deliberately lives outside the
verifier bundle.  This module is the small, standard-library-only contract
shared by the coordinator and verifier: it strictly normalizes the root
receipt, re-observes the adopted tree through retained file descriptors, and
returns the exact dynamic fields that must survive into signed attestation
evidence.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import unicodedata
from collections.abc import Mapping
from pathlib import Path
from typing import Any


ADOPTION_RECEIPT_SCHEMA = (
    "john-lomein.persona-qualification-capture-adoption.v2"
)
ADOPTION_STATUS = "adopted"
ADOPTION_BINDING_SCHEMA = (
    "john-lomein.persona-qualification-capture-adoption-binding.v1"
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SESSION_ID_RE = re.compile(r"^[0-9a-f]{64}$")
CAPTURE_NAME_RE = re.compile(r"^opaque-capture-[0-9a-f]{32}$")
SLUG_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$"
)
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_CAPTURE_FILES = 4_096
MAX_CAPTURE_DIRECTORIES = 4_096
MAX_CAPTURE_BYTES = 128 * 1024 * 1024
MAX_CAPTURE_FILE_BYTES = 16 * 1024 * 1024
MAX_CAPTURE_DEPTH = 64
ADOPTED_DIRECTORY_MODE = 0o550
ADOPTED_FILE_MODE = 0o440
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
ADOPTION_LIMIT_FIELDS = frozenset(
    {
        "max_files",
        "max_directories",
        "max_bytes",
        "max_file_bytes",
        "max_depth",
    }
)

ADOPTION_RECEIPT_FIELDS = {
    "schema_version",
    "status",
    "session_id",
    "capture_adoption_policy_sha256",
    "capture_selection_sha256",
    "capture_plan_sha256",
    "capture_manifest_sha256",
    "capture_boundary_policy_sha256",
    "helper_activation_policy_sha256",
    "request_sha256",
    "capture_uid",
    "capture_gid",
    "adopted_uid",
    "verifier_uid",
    "verifier_gid",
    "final_name",
    "object_identity_sha256",
    "provisional_stat_sha256",
    "adopted_stat_sha256",
    "content_inventory_sha256",
    "file_count",
    "directory_count",
    "total_bytes",
    "child_pid",
    "child_exit_status",
    "child_stderr_sha256",
    "process_group_reaped",
    "staging_namespace_revoked",
    "same_filesystem",
    "rename_noreplace",
    "rename_primitive",
    "adopted_at_unix",
}

ADOPTION_EVIDENCE_FIELDS = {
    "capture_creator_uid",
    "capture_export_gid",
    "capture_adopted_uid",
    "capture_adoption_receipt_sha256",
    "capture_adoption_policy_sha256",
    "capture_object_identity_sha256",
    "capture_content_inventory_sha256",
    "capture_adopted_at_unix",
    "capture_request_sha256",
    "capture_boundary_policy_sha256",
    "capture_helper_activation_policy_sha256",
}
CAPTURE_ADOPTION_RESULT_EVIDENCE_FIELDS = frozenset(
    {
        "capture_creator_uid",
        "capture_export_gid",
        "capture_adopted_uid",
        "capture_adoption_policy_sha256",
        "capture_object_identity_sha256",
        "capture_content_inventory_sha256",
        "capture_request_sha256",
        "capture_boundary_policy_sha256",
        "capture_helper_activation_policy_sha256",
        "capture_adoption_provenance",
        "capture_adoption_provenance_sha256",
    }
)


class CaptureAdoptionBindingError(ValueError):
    """Stable, public-safe receipt or adopted-tree rejection."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _error(code: str) -> CaptureAdoptionBindingError:
    return CaptureAdoptionBindingError(code)


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
        raise _error("capture_adoption_binding_json_invalid") from exc


def _mapping(value: Any, *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _error(f"{field}_not_object")
    if any(not isinstance(key, str) for key in value):
        raise _error(f"{field}_fields_invalid")
    return value


def _integer(
    value: Any,
    *,
    field: str,
    minimum: int = 0,
    maximum: int = MAX_SAFE_INTEGER,
) -> int:
    if (
        type(value) is not int
        or value < minimum
        or value > maximum
    ):
        raise _error(f"{field}_invalid")
    return value


def _digest(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise _error(f"{field}_invalid")
    return value


def _slug(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not SLUG_RE.fullmatch(value):
        raise _error(f"{field}_invalid")
    return value


def _adoption_limits(value: Any) -> dict[str, int]:
    if (
        not isinstance(value, Mapping)
        or set(value) != ADOPTION_LIMIT_FIELDS
        or any(not isinstance(field, str) for field in value)
    ):
        raise _error("capture_adoption_expected_limits_invalid")
    limits = {
        "max_files": _integer(
            value["max_files"],
            field="capture_adoption_expected_max_files",
            minimum=1,
            maximum=MAX_CAPTURE_FILES,
        ),
        "max_directories": _integer(
            value["max_directories"],
            field="capture_adoption_expected_max_directories",
            minimum=1,
            maximum=MAX_CAPTURE_DIRECTORIES,
        ),
        "max_bytes": _integer(
            value["max_bytes"],
            field="capture_adoption_expected_max_bytes",
            minimum=1,
            maximum=MAX_CAPTURE_BYTES,
        ),
        "max_file_bytes": _integer(
            value["max_file_bytes"],
            field="capture_adoption_expected_max_file_bytes",
            minimum=1,
            maximum=MAX_CAPTURE_FILE_BYTES,
        ),
        "max_depth": _integer(
            value["max_depth"],
            field="capture_adoption_expected_max_depth",
            minimum=1,
            maximum=MAX_CAPTURE_DEPTH,
        ),
    }
    if limits["max_file_bytes"] > limits["max_bytes"]:
        raise _error(
            "capture_adoption_expected_file_limit_exceeds_total"
        )
    return limits


def _absolute_path(value: Any, *, field: str) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise _error(f"{field}_invalid")
    raw = os.fspath(value)
    if not isinstance(raw, str):
        raise _error(f"{field}_invalid")
    path = Path(raw)
    if (
        not raw
        or len(raw) > 4_096
        or "\x00" in raw
        or any(ord(character) < 32 for character in raw)
        or unicodedata.normalize("NFC", raw) != raw
        or not path.is_absolute()
        or "." in path.parts
        or ".." in path.parts
        or str(path) != raw
    ):
        raise _error(f"{field}_invalid")
    return path


def _component(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not CAPTURE_NAME_RE.fullmatch(value)
        or unicodedata.normalize("NFC", value) != value
    ):
        raise _error(f"{field}_invalid")
    return value


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


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def normalize_adoption_receipt(value: Any) -> dict[str, Any]:
    """Return the exact canonical root-adoption receipt."""

    receipt = _mapping(value, field="capture_adoption_receipt")
    if set(receipt) != ADOPTION_RECEIPT_FIELDS:
        raise _error("capture_adoption_receipt_fields_invalid")
    if receipt.get("schema_version") != ADOPTION_RECEIPT_SCHEMA:
        raise _error("capture_adoption_receipt_schema_unsupported")
    if receipt.get("status") != ADOPTION_STATUS:
        raise _error("capture_adoption_receipt_status_invalid")
    session_id = receipt.get("session_id")
    if (
        not isinstance(session_id, str)
        or not SESSION_ID_RE.fullmatch(session_id)
    ):
        raise _error("capture_adoption_receipt_session_id_invalid")

    capture_uid = _integer(
        receipt.get("capture_uid"),
        field="capture_adoption_receipt_capture_uid",
        minimum=1,
        maximum=(1 << 31) - 1,
    )
    capture_gid = _integer(
        receipt.get("capture_gid"),
        field="capture_adoption_receipt_capture_gid",
        minimum=1,
        maximum=(1 << 31) - 1,
    )
    adopted_uid = _integer(
        receipt.get("adopted_uid"),
        field="capture_adoption_receipt_adopted_uid",
        maximum=(1 << 31) - 1,
    )
    verifier_uid = _integer(
        receipt.get("verifier_uid"),
        field="capture_adoption_receipt_verifier_uid",
        minimum=1,
        maximum=(1 << 31) - 1,
    )
    verifier_gid = _integer(
        receipt.get("verifier_gid"),
        field="capture_adoption_receipt_verifier_gid",
        minimum=1,
        maximum=(1 << 31) - 1,
    )
    if capture_uid == verifier_uid:
        raise _error("capture_adoption_receipt_uid_separation_missing")
    if capture_gid == verifier_gid:
        raise _error("capture_adoption_receipt_group_separation_missing")

    digests = {
        field: _digest(
            receipt.get(field),
            field=f"capture_adoption_receipt_{field}",
        )
        for field in (
            "capture_adoption_policy_sha256",
            "capture_selection_sha256",
            "capture_plan_sha256",
            "capture_manifest_sha256",
            "capture_boundary_policy_sha256",
            "helper_activation_policy_sha256",
            "request_sha256",
            "object_identity_sha256",
            "provisional_stat_sha256",
            "adopted_stat_sha256",
            "content_inventory_sha256",
            "child_stderr_sha256",
        )
    }
    if digests["child_stderr_sha256"] != EMPTY_SHA256:
        raise _error("capture_adoption_receipt_child_stderr_not_empty")

    file_count = _integer(
        receipt.get("file_count"),
        field="capture_adoption_receipt_file_count",
        maximum=MAX_CAPTURE_FILES,
    )
    directory_count = _integer(
        receipt.get("directory_count"),
        field="capture_adoption_receipt_directory_count",
        minimum=1,
        maximum=MAX_CAPTURE_DIRECTORIES,
    )
    total_bytes = _integer(
        receipt.get("total_bytes"),
        field="capture_adoption_receipt_total_bytes",
        maximum=MAX_CAPTURE_BYTES,
    )
    child_pid = _integer(
        receipt.get("child_pid"),
        field="capture_adoption_receipt_child_pid",
        minimum=2,
        maximum=(1 << 31) - 1,
    )
    child_status = _integer(
        receipt.get("child_exit_status"),
        field="capture_adoption_receipt_child_exit_status",
    )
    if child_status != 0:
        raise _error("capture_adoption_receipt_child_exit_invalid")
    for field in (
        "process_group_reaped",
        "staging_namespace_revoked",
        "same_filesystem",
        "rename_noreplace",
    ):
        if receipt.get(field) is not True:
            raise _error(f"capture_adoption_receipt_{field}_invalid")
    primitive = receipt.get("rename_primitive")
    if primitive not in {
        "renameat2_noreplace",
        "renameatx_np_excl",
    }:
        raise _error("capture_adoption_receipt_rename_primitive_invalid")

    return {
        "schema_version": ADOPTION_RECEIPT_SCHEMA,
        "status": ADOPTION_STATUS,
        "session_id": session_id,
        **{
            field: digests[field]
            for field in (
                "capture_adoption_policy_sha256",
                "capture_selection_sha256",
                "capture_plan_sha256",
                "capture_manifest_sha256",
                "capture_boundary_policy_sha256",
                "helper_activation_policy_sha256",
                "request_sha256",
            )
        },
        "capture_uid": capture_uid,
        "capture_gid": capture_gid,
        "adopted_uid": adopted_uid,
        "verifier_uid": verifier_uid,
        "verifier_gid": verifier_gid,
        "final_name": _component(
            receipt.get("final_name"),
            field="capture_adoption_receipt_final_name",
        ),
        "object_identity_sha256": digests["object_identity_sha256"],
        "provisional_stat_sha256": digests["provisional_stat_sha256"],
        "adopted_stat_sha256": digests["adopted_stat_sha256"],
        "content_inventory_sha256": digests[
            "content_inventory_sha256"
        ],
        "file_count": file_count,
        "directory_count": directory_count,
        "total_bytes": total_bytes,
        "child_pid": child_pid,
        "child_exit_status": 0,
        "child_stderr_sha256": EMPTY_SHA256,
        "process_group_reaped": True,
        "staging_namespace_revoked": True,
        "same_filesystem": True,
        "rename_noreplace": True,
        "rename_primitive": primitive,
        "adopted_at_unix": _integer(
            receipt.get("adopted_at_unix"),
            field="capture_adoption_receipt_adopted_at_unix",
            minimum=1,
        ),
    }


def adoption_receipt_sha256(value: Any) -> str:
    return _sha256_json(normalize_adoption_receipt(value))


def _directory_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("capture_adoption_binding_nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _file_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("capture_adoption_binding_nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    return flags


def _entry_names(descriptor: int) -> list[str]:
    try:
        names = os.listdir(descriptor)
    except OSError as exc:
        raise _error("capture_adoption_binding_inventory_unreadable") from exc
    if len(names) > MAX_CAPTURE_FILES + MAX_CAPTURE_DIRECTORIES:
        raise _error("capture_adoption_binding_inventory_too_large")
    if (
        len(set(names)) != len(names)
        or any(
            not name
            or name in {".", ".."}
            or "/" in name
            or "\x00" in name
            or unicodedata.normalize("NFC", name) != name
            for name in names
        )
    ):
        raise _error("capture_adoption_binding_entry_name_invalid")
    return sorted(names)


def _read_file(
    parent_fd: int,
    name: str,
    named: os.stat_result,
    *,
    adopted_uid: int,
    verifier_gid: int,
    root_device: int,
) -> tuple[int, str]:
    try:
        descriptor = os.open(name, _file_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise _error("capture_adoption_binding_file_unreadable") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            _stable_object_tuple(named) != _stable_object_tuple(opened)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != root_device
            or opened.st_uid != adopted_uid
            or opened.st_gid != verifier_gid
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != ADOPTED_FILE_MODE
            or not 0 <= opened.st_size <= MAX_CAPTURE_FILE_BYTES
        ):
            raise _error("capture_adoption_binding_file_unsafe")
        before = _full_stat_tuple(opened)
        digest = hashlib.sha256()
        observed = 0
        os.lseek(descriptor, 0, os.SEEK_SET)
        while observed <= MAX_CAPTURE_FILE_BYTES:
            chunk = os.read(
                descriptor,
                min(
                    64 * 1024,
                    MAX_CAPTURE_FILE_BYTES + 1 - observed,
                ),
            )
            if not chunk:
                break
            observed += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        rebound = os.stat(
            name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if (
            observed > MAX_CAPTURE_FILE_BYTES
            or observed != opened.st_size
            or before != _full_stat_tuple(after)
            or _stable_object_tuple(after)
            != _stable_object_tuple(rebound)
        ):
            raise _error("capture_adoption_binding_file_changed")
        return observed, digest.hexdigest()
    finally:
        os.close(descriptor)


def _inventory_tree(
    descriptor: int,
    *,
    prefix: str,
    adopted_uid: int,
    verifier_gid: int,
    root_device: int,
    records: list[dict[str, Any]],
    counters: dict[str, int],
    depth: int,
) -> None:
    if depth > MAX_CAPTURE_DEPTH:
        raise _error("capture_adoption_binding_tree_too_deep")
    before = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(before.st_mode)
        or before.st_dev != root_device
        or before.st_uid != adopted_uid
        or before.st_gid != verifier_gid
        or stat.S_IMODE(before.st_mode) != ADOPTED_DIRECTORY_MODE
    ):
        raise _error("capture_adoption_binding_directory_unsafe")
    counters["directories"] += 1
    if counters["directories"] > MAX_CAPTURE_DIRECTORIES:
        raise _error("capture_adoption_binding_directory_count_exceeded")
    records.append({"path": prefix, "type": "directory"})
    for name in _entry_names(descriptor):
        relative = f"{prefix}/{name}" if prefix else name
        try:
            named = os.stat(
                name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise _error(
                "capture_adoption_binding_entry_unreadable"
            ) from exc
        if stat.S_ISDIR(named.st_mode):
            try:
                child = os.open(
                    name,
                    _directory_flags(),
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise _error(
                    "capture_adoption_binding_directory_unreadable"
                ) from exc
            try:
                if _stable_object_tuple(named) != _stable_object_tuple(
                    os.fstat(child)
                ):
                    raise _error(
                        "capture_adoption_binding_directory_inode_mismatch"
                    )
                _inventory_tree(
                    child,
                    prefix=relative,
                    adopted_uid=adopted_uid,
                    verifier_gid=verifier_gid,
                    root_device=root_device,
                    records=records,
                    counters=counters,
                    depth=depth + 1,
                )
            finally:
                os.close(child)
        elif stat.S_ISREG(named.st_mode):
            size, digest = _read_file(
                descriptor,
                name,
                named,
                adopted_uid=adopted_uid,
                verifier_gid=verifier_gid,
                root_device=root_device,
            )
            counters["files"] += 1
            counters["bytes"] += size
            if counters["files"] > MAX_CAPTURE_FILES:
                raise _error(
                    "capture_adoption_binding_file_count_exceeded"
                )
            if counters["bytes"] > MAX_CAPTURE_BYTES:
                raise _error("capture_adoption_binding_size_exceeded")
            records.append(
                {
                    "path": relative,
                    "type": "file",
                    "size": size,
                    "sha256": digest,
                }
            )
        else:
            raise _error("capture_adoption_binding_entry_type_unsafe")
    if _full_stat_tuple(before) != _full_stat_tuple(os.fstat(descriptor)):
        raise _error("capture_adoption_binding_directory_changed")


def verify_adoption_binding(
    receipt_value: Any,
    *,
    expected_receipt_sha256: str,
    snapshot_root: Path,
    expected_capture_uid: int,
    expected_export_gid: int,
    expected_adopted_uid: int,
    expected_verifier_uid: int,
    expected_verifier_gid: int,
    expected_capture_selection_sha256: str,
    expected_capture_plan_sha256: str,
    expected_capture_manifest_sha256: str,
    expected_request_sha256: str,
    expected_capture_boundary_policy_sha256: str,
    expected_helper_activation_policy_sha256: str,
    expected_session_id: str,
    verified_at_unix: int,
) -> dict[str, Any]:
    """Re-observe one adopted tree and return its signed evidence fields."""

    receipt = normalize_adoption_receipt(receipt_value)
    receipt_digest = _digest(
        expected_receipt_sha256,
        field="capture_adoption_expected_receipt_sha256",
    )
    if adoption_receipt_sha256(receipt) != receipt_digest:
        raise _error("capture_adoption_receipt_digest_mismatch")
    root = _absolute_path(
        snapshot_root,
        field="capture_adoption_snapshot_root",
    )
    expected = {
        "capture_uid": _integer(
            expected_capture_uid,
            field="capture_adoption_expected_capture_uid",
            minimum=1,
            maximum=(1 << 31) - 1,
        ),
        "capture_gid": _integer(
            expected_export_gid,
            field="capture_adoption_expected_export_gid",
            minimum=1,
            maximum=(1 << 31) - 1,
        ),
        "adopted_uid": _integer(
            expected_adopted_uid,
            field="capture_adoption_expected_adopted_uid",
            maximum=(1 << 31) - 1,
        ),
        "verifier_uid": _integer(
            expected_verifier_uid,
            field="capture_adoption_expected_verifier_uid",
            minimum=1,
            maximum=(1 << 31) - 1,
        ),
        "verifier_gid": _integer(
            expected_verifier_gid,
            field="capture_adoption_expected_verifier_gid",
            minimum=1,
            maximum=(1 << 31) - 1,
        ),
        "capture_selection_sha256": _digest(
            expected_capture_selection_sha256,
            field="capture_adoption_expected_selection_sha256",
        ),
        "capture_plan_sha256": _digest(
            expected_capture_plan_sha256,
            field="capture_adoption_expected_plan_sha256",
        ),
        "capture_manifest_sha256": _digest(
            expected_capture_manifest_sha256,
            field="capture_adoption_expected_manifest_sha256",
        ),
        "request_sha256": _digest(
            expected_request_sha256,
            field="capture_adoption_expected_request_sha256",
        ),
        "capture_boundary_policy_sha256": _digest(
            expected_capture_boundary_policy_sha256,
            field="capture_adoption_expected_boundary_policy_sha256",
        ),
        "helper_activation_policy_sha256": _digest(
            expected_helper_activation_policy_sha256,
            field="capture_adoption_expected_helper_policy_sha256",
        ),
    }
    for field, expected_value in expected.items():
        if receipt[field] != expected_value:
            raise _error(f"capture_adoption_receipt_{field}_mismatch")
    if root.name != receipt["final_name"]:
        raise _error("capture_adoption_receipt_final_name_mismatch")
    if (
        not isinstance(expected_session_id, str)
        or not SESSION_ID_RE.fullmatch(expected_session_id)
        or receipt["session_id"] != expected_session_id
    ):
        raise _error("capture_adoption_receipt_session_id_mismatch")
    verified_at = _integer(
        verified_at_unix,
        field="capture_adoption_verified_at_unix",
        minimum=1,
    )
    if receipt["adopted_at_unix"] > verified_at:
        raise _error("capture_adoption_receipt_time_invalid")

    try:
        descriptor = os.open(root, _directory_flags())
    except OSError as exc:
        raise _error("capture_adoption_snapshot_unreadable") from exc
    try:
        before = os.fstat(descriptor)
        if _sha256_json(list(_stable_object_tuple(before))) != receipt[
            "object_identity_sha256"
        ]:
            raise _error("capture_adoption_object_identity_mismatch")
        if _sha256_json(list(_full_stat_tuple(before))) != receipt[
            "adopted_stat_sha256"
        ]:
            raise _error("capture_adoption_stat_mismatch")
        records: list[dict[str, Any]] = []
        counters = {"files": 0, "directories": 0, "bytes": 0}
        _inventory_tree(
            descriptor,
            prefix="",
            adopted_uid=expected["adopted_uid"],
            verifier_gid=expected["verifier_gid"],
            root_device=before.st_dev,
            records=records,
            counters=counters,
            depth=0,
        )
        after = os.fstat(descriptor)
        if _full_stat_tuple(before) != _full_stat_tuple(after):
            raise _error("capture_adoption_snapshot_changed")
        inventory_digest = _sha256_json(
            sorted(records, key=lambda item: item["path"])
        )
        if (
            inventory_digest != receipt["content_inventory_sha256"]
            or counters["files"] != receipt["file_count"]
            or counters["directories"] != receipt["directory_count"]
            or counters["bytes"] != receipt["total_bytes"]
        ):
            raise _error("capture_adoption_inventory_mismatch")
    finally:
        os.close(descriptor)

    return {
        "capture_creator_uid": receipt["capture_uid"],
        "capture_export_gid": receipt["capture_gid"],
        "capture_adopted_uid": receipt["adopted_uid"],
        "capture_adoption_receipt_sha256": receipt_digest,
        "capture_adoption_policy_sha256": receipt[
            "capture_adoption_policy_sha256"
        ],
        "capture_object_identity_sha256": receipt[
            "object_identity_sha256"
        ],
        "capture_content_inventory_sha256": receipt[
            "content_inventory_sha256"
        ],
        "capture_adopted_at_unix": receipt["adopted_at_unix"],
        "capture_request_sha256": receipt["request_sha256"],
        "capture_boundary_policy_sha256": receipt[
            "capture_boundary_policy_sha256"
        ],
        "capture_helper_activation_policy_sha256": receipt[
            "helper_activation_policy_sha256"
        ],
    }


def verify_capture_adoption_result(
    result_value: Any,
    *,
    expected_result_sha256: str,
    snapshot_root: Path,
    expected_instance_slug: str,
    expected_capture_uid: int,
    expected_export_gid: int,
    expected_adopted_uid: int,
    expected_verifier_uid: int,
    expected_verifier_gid: int,
    expected_capture_adoption_policy_sha256: str,
    expected_capture_selection_sha256: str,
    expected_capture_plan_sha256: str,
    expected_capture_manifest_sha256: str,
    expected_request_sha256: str,
    expected_capture_boundary_policy_sha256: str,
    expected_helper_activation_policy_sha256: str,
    expected_session_id: str,
    expected_adoption_limits: Mapping[str, Any],
    verified_at_unix: int,
) -> dict[str, Any]:
    """Verify either adoption result without erasing its provenance kind.

    The reverse import is intentionally local: the pure tagged-union module
    imports this module for the historical normal-receipt normalizer.
    """

    from qualification_attestor import (
        john_lomein_persona_qualification_adoption_result
        as adoption_result,
    )

    try:
        result = adoption_result.normalize_capture_adoption_result(
            result_value
        )
        result_sha256 = adoption_result.capture_adoption_result_sha256(
            result
        )
    except adoption_result.CaptureAdoptionResultError as exc:
        raise _error(exc.code) from exc
    expected_result = _digest(
        expected_result_sha256,
        field="capture_adoption_expected_result_sha256",
    )
    if not hmac.compare_digest(result_sha256, expected_result):
        raise _error("capture_adoption_result_digest_mismatch")

    root = _absolute_path(
        snapshot_root,
        field="capture_adoption_snapshot_root",
    )
    expected_slug = _slug(
        expected_instance_slug,
        field="capture_adoption_expected_instance_slug",
    )
    capture_uid = _integer(
        expected_capture_uid,
        field="capture_adoption_expected_capture_uid",
        minimum=1,
        maximum=(1 << 31) - 1,
    )
    export_gid = _integer(
        expected_export_gid,
        field="capture_adoption_expected_export_gid",
        minimum=1,
        maximum=(1 << 31) - 1,
    )
    adopted_uid = _integer(
        expected_adopted_uid,
        field="capture_adoption_expected_adopted_uid",
        maximum=(1 << 31) - 1,
    )
    verifier_uid = _integer(
        expected_verifier_uid,
        field="capture_adoption_expected_verifier_uid",
        minimum=1,
        maximum=(1 << 31) - 1,
    )
    verifier_gid = _integer(
        expected_verifier_gid,
        field="capture_adoption_expected_verifier_gid",
        minimum=1,
        maximum=(1 << 31) - 1,
    )
    if adopted_uid != 0:
        raise _error("capture_adoption_result_adopted_uid_not_root")
    if capture_uid == verifier_uid or export_gid == verifier_gid:
        raise _error(
            "capture_adoption_result_identity_not_separate"
        )
    adoption_policy_sha256 = _digest(
        expected_capture_adoption_policy_sha256,
        field=(
            "capture_adoption_expected_adoption_policy_sha256"
        ),
    )
    selection_sha256 = _digest(
        expected_capture_selection_sha256,
        field="capture_adoption_expected_selection_sha256",
    )
    plan_sha256 = _digest(
        expected_capture_plan_sha256,
        field="capture_adoption_expected_plan_sha256",
    )
    manifest_sha256 = _digest(
        expected_capture_manifest_sha256,
        field="capture_adoption_expected_manifest_sha256",
    )
    request_sha256 = _digest(
        expected_request_sha256,
        field="capture_adoption_expected_request_sha256",
    )
    boundary_policy_sha256 = _digest(
        expected_capture_boundary_policy_sha256,
        field="capture_adoption_expected_boundary_policy_sha256",
    )
    helper_policy_sha256 = _digest(
        expected_helper_activation_policy_sha256,
        field="capture_adoption_expected_helper_policy_sha256",
    )
    if (
        not isinstance(expected_session_id, str)
        or not SESSION_ID_RE.fullmatch(expected_session_id)
    ):
        raise _error("capture_adoption_expected_session_id_invalid")
    limits = _adoption_limits(expected_adoption_limits)
    verified_at = _integer(
        verified_at_unix,
        field="capture_adoption_verified_at_unix",
        minimum=1,
    )

    if result["kind"] == adoption_result.NORMAL_ADOPTION_KIND:
        normal = verify_adoption_binding(
            result["evidence"],
            expected_receipt_sha256=result["evidence_sha256"],
            snapshot_root=root,
            expected_capture_uid=capture_uid,
            expected_export_gid=export_gid,
            expected_adopted_uid=adopted_uid,
            expected_verifier_uid=verifier_uid,
            expected_verifier_gid=verifier_gid,
            expected_capture_selection_sha256=selection_sha256,
            expected_capture_plan_sha256=plan_sha256,
            expected_capture_manifest_sha256=manifest_sha256,
            expected_request_sha256=request_sha256,
            expected_capture_boundary_policy_sha256=(
                boundary_policy_sha256
            ),
            expected_helper_activation_policy_sha256=(
                helper_policy_sha256
            ),
            expected_session_id=expected_session_id,
            verified_at_unix=verified_at,
        )
        if (
            normal["capture_adoption_policy_sha256"]
            != adoption_policy_sha256
        ):
            raise _error(
                "capture_adoption_receipt_"
                "capture_adoption_policy_sha256_mismatch"
            )
        common = {
            field: normal[field]
            for field in (
                "capture_creator_uid",
                "capture_export_gid",
                "capture_adopted_uid",
                "capture_adoption_policy_sha256",
                "capture_object_identity_sha256",
                "capture_content_inventory_sha256",
                "capture_request_sha256",
                "capture_boundary_policy_sha256",
                "capture_helper_activation_policy_sha256",
            )
        }
    else:
        recovered = result["evidence"]
        expected_recovered = {
            "instance_slug": expected_slug,
            "capture_session_id": expected_session_id,
            "capture_uid": capture_uid,
            "capture_export_gid": export_gid,
            "final_object_owner_uid": adopted_uid,
            "verifier_gid": verifier_gid,
            "final_object_group_gid": verifier_gid,
            "capture_adoption_policy_sha256": (
                adoption_policy_sha256
            ),
            "capture_selection_sha256": selection_sha256,
            "capture_plan_sha256": plan_sha256,
            "capture_manifest_sha256": manifest_sha256,
            "capture_request_sha256": request_sha256,
            "capture_boundary_policy_sha256": (
                boundary_policy_sha256
            ),
            "helper_activation_policy_sha256": (
                helper_policy_sha256
            ),
            "final_name": root.name,
            "adoption_limits": limits,
        }
        for field, expected_value in expected_recovered.items():
            if recovered[field] != expected_value:
                raise _error(
                    f"capture_adoption_recovered_{field}_mismatch"
                )

        try:
            descriptor = os.open(root, _directory_flags())
        except OSError as exc:
            raise _error(
                "capture_adoption_recovered_snapshot_unreadable"
            ) from exc
        try:
            before = os.fstat(descriptor)
            if before.st_dev != recovered[
                "final_parent_filesystem_device"
            ]:
                raise _error(
                    "capture_adoption_recovered_filesystem_device_mismatch"
                )
            if _sha256_json(
                list(_stable_object_tuple(before))
            ) != recovered["capture_object_identity_sha256"]:
                raise _error(
                    "capture_adoption_recovered_object_identity_mismatch"
                )
            if _sha256_json(
                list(_full_stat_tuple(before))
            ) != recovered["reconciled_final_object_stat_sha256"]:
                raise _error(
                    "capture_adoption_recovered_stat_mismatch"
                )
            if before.st_nlink != recovered["final_object_nlink"]:
                raise _error(
                    "capture_adoption_recovered_nlink_mismatch"
                )
            records: list[dict[str, Any]] = []
            counters = {"files": 0, "directories": 0, "bytes": 0}
            _inventory_tree(
                descriptor,
                prefix="",
                adopted_uid=adopted_uid,
                verifier_gid=verifier_gid,
                root_device=before.st_dev,
                records=records,
                counters=counters,
                depth=0,
            )
            after = os.fstat(descriptor)
            if _full_stat_tuple(before) != _full_stat_tuple(after):
                raise _error(
                    "capture_adoption_recovered_snapshot_changed"
                )
            inventory = sorted(
                records, key=lambda item: item["path"]
            )
            inventory_sha256 = _sha256_json(inventory)
            file_sizes = tuple(
                record["size"]
                for record in inventory
                if record["type"] == "file"
            )
            largest_file = max(file_sizes, default=0)
            maximum_depth = max(
                (
                    len(Path(record["path"]).parts)
                    for record in inventory
                    if (
                        record["type"] == "directory"
                        and record["path"]
                    )
                ),
                default=0,
            )
            observed_inventory = {
                "reconciled_content_inventory_sha256": (
                    inventory_sha256
                ),
                "reconciled_file_count": counters["files"],
                "reconciled_directory_count": counters[
                    "directories"
                ],
                "reconciled_total_bytes": counters["bytes"],
                "reconciled_largest_file_bytes": largest_file,
                "reconciled_maximum_depth": maximum_depth,
            }
            for field, observed in observed_inventory.items():
                if recovered[field] != observed:
                    raise _error(
                        f"capture_adoption_recovered_{field}_mismatch"
                    )
            if (
                counters["files"] > limits["max_files"]
                or counters["directories"]
                > limits["max_directories"]
                or counters["bytes"] > limits["max_bytes"]
                or largest_file > limits["max_file_bytes"]
                or maximum_depth > limits["max_depth"]
            ):
                raise _error(
                    "capture_adoption_recovered_inventory_limits_exceeded"
                )
        finally:
            os.close(descriptor)
        common = {
            "capture_creator_uid": recovered["capture_uid"],
            "capture_export_gid": recovered["capture_export_gid"],
            "capture_adopted_uid": recovered[
                "final_object_owner_uid"
            ],
            "capture_adoption_policy_sha256": recovered[
                "capture_adoption_policy_sha256"
            ],
            "capture_object_identity_sha256": recovered[
                "capture_object_identity_sha256"
            ],
            "capture_content_inventory_sha256": recovered[
                "reconciled_content_inventory_sha256"
            ],
            "capture_request_sha256": recovered[
                "capture_request_sha256"
            ],
            "capture_boundary_policy_sha256": recovered[
                "capture_boundary_policy_sha256"
            ],
            "capture_helper_activation_policy_sha256": recovered[
                "helper_activation_policy_sha256"
            ],
        }

    try:
        provenance = (
            adoption_result.project_capture_adoption_provenance(result)
        )
        provenance_sha256 = (
            adoption_result.capture_adoption_provenance_sha256(
                provenance
            )
        )
    except adoption_result.CaptureAdoptionResultError as exc:
        raise _error(exc.code) from exc
    bound = {
        **common,
        "capture_adoption_provenance": provenance,
        "capture_adoption_provenance_sha256": provenance_sha256,
    }
    if set(bound) != CAPTURE_ADOPTION_RESULT_EVIDENCE_FIELDS:
        raise AssertionError("capture adoption result evidence drift")
    return bound


__all__ = [
    "ADOPTION_LIMIT_FIELDS",
    "ADOPTION_BINDING_SCHEMA",
    "ADOPTION_EVIDENCE_FIELDS",
    "ADOPTION_RECEIPT_FIELDS",
    "ADOPTION_RECEIPT_SCHEMA",
    "ADOPTION_STATUS",
    "CAPTURE_ADOPTION_RESULT_EVIDENCE_FIELDS",
    "CaptureAdoptionBindingError",
    "adoption_receipt_sha256",
    "canonical_json",
    "normalize_adoption_receipt",
    "verify_adoption_binding",
    "verify_capture_adoption_result",
]
