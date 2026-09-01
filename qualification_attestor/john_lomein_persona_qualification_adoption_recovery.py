"""Dormant descriptor authority for one recovered adopted capture.

Recovered-adoption evidence is deliberately path-free.  It can describe the
object observed by crash reconciliation, but it must never become authority to
open an arbitrary caller-selected path.  This module is the narrow bridge from
the exact descriptor-bound transaction journal to a retained filesystem
object:

* production and canary entry points accept only an exact
  ``TransactionJournalSession`` and an already-open final-parent descriptor;
* the journal session performs its zero-input recovered-evidence mint;
* the final leaf name comes only from that canonical evidence; and
* all filesystem observation is relative to retained ``O_NOFOLLOW`` /
  ``O_CLOEXEC`` descriptors.

The original v1 lease remains a reconciled-head-only retain/revalidate
capability.  A side-by-side dormant v2 lease consumes the journal-owned v2
context and may perform exactly one descriptor-bound outer staging ACK before
verifier authority becomes available.  Neither lease signs, publishes, or
produces reconciliation evidence, and ``close`` never removes the recovered
object.  Production and v2 canary activation remain disabled.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import hmac
import json
import os
import stat
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from qualification_attestor import (
    john_lomein_persona_qualification_adoption_result as adoption_result,
)
from qualification_attestor import (
    john_lomein_persona_qualification_capture_adoption as capture_adoption,
)
from qualification_attestor import (
    john_lomein_persona_qualification_recovered_adoption_evidence
    as recovered_adoption,
)
from qualification_attestor import (
    john_lomein_persona_qualification_transaction_journal
    as transaction_journal,
)


PRODUCTION_ACTIVATION = False

RECOVERED_LEASE_BINDING_SCHEMA = (
    "john-lomein.persona-qualification-recovered-adoption-lease-binding.v1"
)
RECOVERED_ADOPTION_LEASE_BINDING_V2_SCHEMA = (
    transaction_journal.RECOVERED_ADOPTION_LEASE_BINDING_V2_SCHEMA
)
RECOVERED_LEASE_V2_PRODUCTION_ACTIVATION = False
RECOVERED_LEASE_V2_CANARY_ACTIVATION = False
FINAL_PARENT_MODE = capture_adoption.FINAL_PARENT_MODE
ADOPTED_DIRECTORY_MODE = capture_adoption.ADOPTED_DIRECTORY_MODE
ADOPTED_FILE_MODE = capture_adoption.ADOPTED_FILE_MODE
MAX_SAFE_INTEGER = (1 << 53) - 1

_LEASE_TOKEN = object()
_LEASE_V2_TOKEN = object()
_OUTER_ACK_TOKEN = object()

_RECOVERED_LEASE_BINDING_V2_FIELDS = (
    transaction_journal.RECOVERED_ADOPTION_LEASE_BINDING_V2_FIELDS
)


class RecoveredAdoptionRecoveryError(RuntimeError):
    """Stable fail-closed error from the recovered-object authority boundary."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _error(code: str) -> RecoveredAdoptionRecoveryError:
    return RecoveredAdoptionRecoveryError(code)


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise _error("adoption_recovery_json_invalid") from exc


def _canonical_copy(value: Mapping[str, Any]) -> dict[str, Any]:
    decoded = json.loads(_canonical_json(value).decode("ascii"))
    if not isinstance(decoded, dict):
        raise AssertionError("canonical adoption-recovery value is not an object")
    return decoded


def normalize_recovered_adoption_lease_binding_v2(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Delegate to the journal-owned canonical v2 lease contract."""

    if (
        not isinstance(value, Mapping)
        or any(type(key) is not str for key in value)
        or frozenset(value) != _RECOVERED_LEASE_BINDING_V2_FIELDS
    ):
        raise _error(
            "adoption_recovery_v2_lease_binding_fields_invalid"
        )
    try:
        return (
            transaction_journal
            .normalize_recovered_adoption_lease_binding_v2(
                value
            )
        )
    except transaction_journal.TransactionJournalError as exc:
        raise _error(exc.code) from exc


def recovered_adoption_lease_binding_v2_sha256(
    value: Mapping[str, Any],
) -> str:
    """Delegate to the journal-owned canonical v2 lease digest."""

    try:
        return (
            transaction_journal
            .recovered_adoption_lease_binding_v2_sha256(value)
        )
    except transaction_journal.TransactionJournalError as exc:
        raise _error(exc.code) from exc


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
        raise _error(f"adoption_recovery_{field}_invalid")
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


def _object_identity_sha256(info: os.stat_result) -> str:
    return hashlib.sha256(
        _canonical_json(list(_stable_object_tuple(info)))
    ).hexdigest()


def _full_stat_sha256(info: os.stat_result) -> str:
    return hashlib.sha256(
        _canonical_json(list(_full_stat_tuple(info)))
    ).hexdigest()


def _directory_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("adoption_recovery_nofollow_unsupported")
    if not hasattr(os, "O_CLOEXEC"):
        raise _error("adoption_recovery_cloexec_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    return flags


def _file_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("adoption_recovery_nofollow_unsupported")
    if not hasattr(os, "O_CLOEXEC"):
        raise _error("adoption_recovery_cloexec_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    # A name can be replaced after the no-following lstat and before open.
    # O_NONBLOCK keeps a raced FIFO/device from turning a fail-closed type
    # check into an unbounded privileged-process hang.  The post-open fstat
    # below still requires an exact regular file.
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    return flags


def _assert_cloexec(descriptor: int, *, field: str) -> None:
    try:
        os.set_inheritable(descriptor, False)
        if os.get_inheritable(descriptor):
            raise _error(f"adoption_recovery_{field}_inheritable")
    except RecoveredAdoptionRecoveryError:
        raise
    except OSError as exc:
        raise _error(f"adoption_recovery_{field}_unreadable") from exc


def _retain_parent_descriptor(final_parent_fd: Any) -> int:
    descriptor = _integer(
        final_parent_fd,
        field="final_parent_fd",
        maximum=(1 << 31) - 1,
    )
    try:
        source_info = os.fstat(descriptor)
        source_inheritable = os.get_inheritable(descriptor)
    except OSError as exc:
        raise _error("adoption_recovery_final_parent_fd_unreadable") from exc
    if not stat.S_ISDIR(source_info.st_mode):
        raise _error("adoption_recovery_final_parent_not_directory")
    if source_inheritable:
        raise _error("adoption_recovery_final_parent_fd_inheritable")
    try:
        retained = os.open(".", _directory_flags(), dir_fd=descriptor)
    except OSError as exc:
        raise _error("adoption_recovery_final_parent_open_failed") from exc
    try:
        _assert_cloexec(retained, field="retained_final_parent_fd")
        retained_info = os.fstat(retained)
        if _stable_object_tuple(source_info) != _stable_object_tuple(
            retained_info
        ):
            raise _error("adoption_recovery_final_parent_fd_rebound")
        try:
            fcntl.flock(retained, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise _error("adoption_recovery_final_parent_busy") from exc
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise _error("adoption_recovery_final_parent_busy") from exc
            raise _error("adoption_recovery_final_parent_lock_failed") from exc
        return retained
    except BaseException:
        os.close(retained)
        raise


def _reject_metadata(descriptor: int, *, field: str) -> None:
    try:
        capture_adoption._reject_fd_metadata(
            descriptor,
            field=f"adoption_recovery_{field}",
        )
    except capture_adoption.CaptureAdoptionError as exc:
        raise _error(exc.code) from exc


def _validate_name(name: Any) -> str:
    if (
        not isinstance(name, str)
        or not name
        or name in {".", ".."}
        or "/" in name
        or "\x00" in name
        or unicodedata.normalize("NFC", name) != name
    ):
        raise _error("adoption_recovery_entry_name_invalid")
    return name


def _bounded_entries(
    descriptor: int,
    *,
    maximum: int,
    field: str,
) -> list[str]:
    scan_fd = -1
    try:
        scan_fd = os.open(".", _directory_flags(), dir_fd=descriptor)
        values: list[str] = []
        with os.scandir(scan_fd) as entries:
            for entry in entries:
                values.append(_validate_name(entry.name))
                if len(values) > maximum:
                    raise _error(f"adoption_recovery_{field}_too_many")
        return sorted(values)
    except RecoveredAdoptionRecoveryError:
        raise
    except OSError as exc:
        raise _error(f"adoption_recovery_{field}_unreadable") from exc
    finally:
        if scan_fd >= 0:
            try:
                os.close(scan_fd)
            except OSError:
                pass


def _open_bound_directory(
    parent_fd: int,
    name: str,
    *,
    field: str,
) -> tuple[int, os.stat_result]:
    try:
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(
            name,
            _directory_flags(),
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise _error(f"adoption_recovery_{field}_unreadable") from exc
    try:
        _assert_cloexec(descriptor, field=f"{field}_fd")
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(named.st_mode)
            or _stable_object_tuple(named)
            != _stable_object_tuple(opened)
        ):
            raise _error(f"adoption_recovery_{field}_inode_mismatch")
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _open_bound_file(
    parent_fd: int,
    name: str,
    *,
    field: str,
) -> tuple[int, os.stat_result]:
    try:
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(name, _file_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise _error(f"adoption_recovery_{field}_unreadable") from exc
    try:
        _assert_cloexec(descriptor, field=f"{field}_fd")
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(named.st_mode)
            or _stable_object_tuple(named)
            != _stable_object_tuple(opened)
        ):
            raise _error(f"adoption_recovery_{field}_inode_mismatch")
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _validate_directory_info(
    info: os.stat_result,
    *,
    owner_uid: int,
    verifier_gid: int,
    root_device: int,
    field: str,
) -> None:
    if (
        not stat.S_ISDIR(info.st_mode)
        or int(info.st_dev) != root_device
        or int(info.st_uid) != owner_uid
        or int(info.st_gid) != verifier_gid
        or stat.S_IMODE(info.st_mode) != ADOPTED_DIRECTORY_MODE
    ):
        raise _error(f"adoption_recovery_{field}_unsafe")


def _validate_file_info(
    info: os.stat_result,
    *,
    owner_uid: int,
    verifier_gid: int,
    root_device: int,
    maximum_bytes: int,
    field: str,
) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or int(info.st_dev) != root_device
        or int(info.st_uid) != owner_uid
        or int(info.st_gid) != verifier_gid
        or int(info.st_nlink) != 1
        or stat.S_IMODE(info.st_mode) != ADOPTED_FILE_MODE
        or not 0 <= int(info.st_size) <= maximum_bytes
    ):
        raise _error(f"adoption_recovery_{field}_unsafe")


def _read_file_digest(
    descriptor: int,
    *,
    maximum_bytes: int,
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
        raise _error("adoption_recovery_file_unreadable") from exc
    if observed > maximum_bytes:
        raise _error("adoption_recovery_file_too_large")
    return observed, digest.hexdigest()


@dataclass(frozen=True)
class _InventoryObservation:
    content_sha256: str
    file_count: int
    directory_count: int
    total_bytes: int
    largest_file_bytes: int
    maximum_depth: int

    def as_binding(self) -> dict[str, Any]:
        return {
            "reconciled_content_inventory_sha256": self.content_sha256,
            "reconciled_file_count": self.file_count,
            "reconciled_directory_count": self.directory_count,
            "reconciled_total_bytes": self.total_bytes,
            "reconciled_largest_file_bytes": self.largest_file_bytes,
            "reconciled_maximum_depth": self.maximum_depth,
        }


@dataclass
class _InventoryBuilder:
    records: list[dict[str, Any]]
    files: int = 0
    directories: int = 0
    total_bytes: int = 0
    largest_file_bytes: int = 0
    maximum_depth: int = 0


def _inventory_tree(
    descriptor: int,
    *,
    prefix: str,
    depth: int,
    owner_uid: int,
    verifier_gid: int,
    root_device: int,
    limits: Mapping[str, int],
    inventory: _InventoryBuilder,
) -> None:
    if depth > limits["max_depth"]:
        raise _error("adoption_recovery_tree_too_deep")
    before = os.fstat(descriptor)
    _validate_directory_info(
        before,
        owner_uid=owner_uid,
        verifier_gid=verifier_gid,
        root_device=root_device,
        field="directory",
    )
    _reject_metadata(descriptor, field="directory")
    inventory.directories += 1
    inventory.maximum_depth = max(inventory.maximum_depth, depth)
    if inventory.directories > limits["max_directories"]:
        raise _error("adoption_recovery_directory_count_exceeded")
    inventory.records.append({"path": prefix, "type": "directory"})

    remaining = (
        limits["max_files"]
        + limits["max_directories"]
        - inventory.files
        - inventory.directories
    )
    entries = _bounded_entries(
        descriptor,
        maximum=max(0, remaining),
        field="directory_inventory",
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
            raise _error("adoption_recovery_entry_unreadable") from exc
        if stat.S_ISDIR(named.st_mode):
            child, opened = _open_bound_directory(
                descriptor,
                name,
                field="directory",
            )
            try:
                if _stable_object_tuple(named) != _stable_object_tuple(
                    opened
                ):
                    raise _error(
                        "adoption_recovery_directory_inode_mismatch"
                    )
                _inventory_tree(
                    child,
                    prefix=relative,
                    depth=depth + 1,
                    owner_uid=owner_uid,
                    verifier_gid=verifier_gid,
                    root_device=root_device,
                    limits=limits,
                    inventory=inventory,
                )
            finally:
                os.close(child)
        elif stat.S_ISREG(named.st_mode):
            child, opened = _open_bound_file(
                descriptor,
                name,
                field="file",
            )
            try:
                _validate_file_info(
                    opened,
                    owner_uid=owner_uid,
                    verifier_gid=verifier_gid,
                    root_device=root_device,
                    maximum_bytes=limits["max_file_bytes"],
                    field="file",
                )
                _reject_metadata(child, field="file")
                file_before = _full_stat_tuple(opened)
                size, digest = _read_file_digest(
                    child,
                    maximum_bytes=limits["max_file_bytes"],
                )
                after = os.fstat(child)
                rebound = os.stat(
                    name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if (
                    size != int(opened.st_size)
                    or file_before != _full_stat_tuple(after)
                    or _stable_object_tuple(after)
                    != _stable_object_tuple(rebound)
                ):
                    raise _error("adoption_recovery_file_changed")
                inventory.files += 1
                inventory.total_bytes += size
                inventory.largest_file_bytes = max(
                    inventory.largest_file_bytes,
                    size,
                )
                if inventory.files > limits["max_files"]:
                    raise _error(
                        "adoption_recovery_file_count_exceeded"
                    )
                if inventory.total_bytes > limits["max_bytes"]:
                    raise _error("adoption_recovery_size_exceeded")
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
            raise _error("adoption_recovery_entry_type_unsafe")
    after = os.fstat(descriptor)
    if _full_stat_tuple(before) != _full_stat_tuple(after):
        raise _error("adoption_recovery_directory_changed")


def _observe_inventory(
    root_fd: int,
    *,
    owner_uid: int,
    verifier_gid: int,
    limits: Mapping[str, int],
) -> _InventoryObservation:
    root = os.fstat(root_fd)
    inventory = _InventoryBuilder(records=[])
    _inventory_tree(
        root_fd,
        prefix="",
        depth=0,
        owner_uid=owner_uid,
        verifier_gid=verifier_gid,
        root_device=int(root.st_dev),
        limits=limits,
        inventory=inventory,
    )
    content_sha256 = hashlib.sha256(
        _canonical_json(
            sorted(inventory.records, key=lambda item: item["path"])
        )
    ).hexdigest()
    return _InventoryObservation(
        content_sha256=content_sha256,
        file_count=inventory.files,
        directory_count=inventory.directories,
        total_bytes=inventory.total_bytes,
        largest_file_bytes=inventory.largest_file_bytes,
        maximum_depth=inventory.maximum_depth,
    )


def _validate_final_parent(
    parent_fd: int,
    *,
    evidence: Mapping[str, Any],
    owner_uid: int,
    verifier_gid: int,
) -> os.stat_result:
    try:
        info = os.fstat(parent_fd)
    except OSError as exc:
        raise _error("adoption_recovery_final_parent_unreadable") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or int(info.st_uid) != owner_uid
        or int(info.st_gid) != verifier_gid
        or stat.S_IMODE(info.st_mode) != FINAL_PARENT_MODE
    ):
        raise _error("adoption_recovery_final_parent_unsafe")
    if int(info.st_dev) != evidence["final_parent_filesystem_device"]:
        raise _error(
            "adoption_recovery_final_parent_filesystem_device_mismatch"
        )
    if not hmac.compare_digest(
        _object_identity_sha256(info),
        evidence["final_parent_identity_sha256"],
    ):
        raise _error("adoption_recovery_final_parent_identity_mismatch")
    _reject_metadata(parent_fd, field="final_parent")
    return info


def _bound_name_matches(
    parent_fd: int,
    final_name: str,
    root_fd: int,
) -> bool:
    try:
        named = os.stat(
            final_name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        opened = os.fstat(root_fd)
    except OSError:
        return False
    return (
        stat.S_ISDIR(named.st_mode)
        and _stable_object_tuple(named) == _stable_object_tuple(opened)
    )


def _validate_bound_object(
    parent_fd: int,
    root_fd: int,
    *,
    evidence: Mapping[str, Any],
    owner_uid: int,
    verifier_gid: int,
) -> tuple[os.stat_result, _InventoryObservation]:
    final_name = evidence["final_name"]
    if not _bound_name_matches(parent_fd, final_name, root_fd):
        raise _error("adoption_recovery_final_name_rebound")
    try:
        root_before = os.fstat(root_fd)
    except OSError as exc:
        raise _error("adoption_recovery_root_unreadable") from exc
    _validate_directory_info(
        root_before,
        owner_uid=owner_uid,
        verifier_gid=verifier_gid,
        root_device=int(root_before.st_dev),
        field="root",
    )
    if (
        int(root_before.st_dev)
        != evidence["final_parent_filesystem_device"]
    ):
        raise _error("adoption_recovery_object_filesystem_device_mismatch")
    if int(root_before.st_nlink) != evidence["final_object_nlink"]:
        raise _error("adoption_recovery_root_nlink_mismatch")
    if not hmac.compare_digest(
        _object_identity_sha256(root_before),
        evidence["capture_object_identity_sha256"],
    ):
        raise _error("adoption_recovery_object_identity_mismatch")
    if not hmac.compare_digest(
        _full_stat_sha256(root_before),
        evidence["reconciled_final_object_stat_sha256"],
    ):
        raise _error("adoption_recovery_object_stat_mismatch")

    inventory = _observe_inventory(
        root_fd,
        owner_uid=owner_uid,
        verifier_gid=verifier_gid,
        limits=evidence["adoption_limits"],
    )
    expected_inventory = {
        field: evidence[field]
        for field in (
            "reconciled_content_inventory_sha256",
            "reconciled_file_count",
            "reconciled_directory_count",
            "reconciled_total_bytes",
            "reconciled_largest_file_bytes",
            "reconciled_maximum_depth",
        )
    }
    if inventory.as_binding() != expected_inventory:
        raise _error("adoption_recovery_inventory_mismatch")
    root_after = os.fstat(root_fd)
    if (
        _full_stat_tuple(root_before) != _full_stat_tuple(root_after)
        or not _bound_name_matches(parent_fd, final_name, root_fd)
    ):
        raise _error("adoption_recovery_object_changed")
    return root_after, inventory


def _build_binding(
    *,
    evidence: Mapping[str, Any],
    live_snapshot: (
        transaction_journal.TransactionJournalLiveSnapshot
    ),
    evidence_sha256: str,
    result_sha256: str,
    provenance_sha256: str,
    root_info: os.stat_result,
    inventory: _InventoryObservation,
) -> dict[str, Any]:
    try:
        snapshot_session_id = live_snapshot.session_id
        snapshot_state = live_snapshot.state
        snapshot_revision = live_snapshot.revision
        snapshot_head = live_snapshot.head_record_sha256
    except transaction_journal.TransactionJournalError as exc:
        raise _error(exc.code) from exc
    if (
        snapshot_session_id != evidence["capture_session_id"]
        or snapshot_state != "adoption_reconciled"
        or not hmac.compare_digest(
            snapshot_head,
            evidence["adoption_reconciliation_record_sha256"],
        )
    ):
        raise _error("adoption_recovery_journal_head_binding_mismatch")
    return {
        "schema_version": RECOVERED_LEASE_BINDING_SCHEMA,
        "transaction_journal_schema": evidence[
            "transaction_journal_schema"
        ],
        "transaction_journal_head_revision": snapshot_revision,
        "transaction_journal_head_record_sha256": snapshot_head,
        "capture_session_id": evidence["capture_session_id"],
        "final_parent_identity_sha256": evidence[
            "final_parent_identity_sha256"
        ],
        "capture_object_identity_sha256": _object_identity_sha256(
            root_info
        ),
        "reconciled_final_object_stat_sha256": _full_stat_sha256(
            root_info
        ),
        "reconciled_content_inventory_sha256": (
            inventory.content_sha256
        ),
        "recovered_adoption_evidence_sha256": evidence_sha256,
        "capture_adoption_result_sha256": result_sha256,
        "capture_adoption_provenance_sha256": provenance_sha256,
    }


def _read_recovered_context_v2(
    session: Any,
    context: Any,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    """Read one exact journal-owned context under its bound session lock."""

    if (
        type(session)
        is not transaction_journal.TransactionJournalSession
        or type(context)
        is not transaction_journal.RecoveredAdoptionJournalContext
    ):
        raise _error(
            "adoption_recovery_v2_journal_context_required"
        )
    try:
        with session._operation_lock:
            contents = context._contents_for_session(
                session, session._live_snapshot_binding
            )
    except transaction_journal.TransactionJournalError as exc:
        raise _error(exc.code) from exc
    if type(contents) is not tuple or len(contents) != 5:
        raise _error(
            "adoption_recovery_v2_journal_context_invalid"
        )
    raw_evidence, raw_result, raw_provenance, raw_binding, raw_continuation = (
        contents
    )
    try:
        evidence = (
            recovered_adoption.normalize_recovered_adoption_evidence(
                raw_evidence
            )
        )
        result = adoption_result.normalize_capture_adoption_result(
            raw_result
        )
        provenance = (
            adoption_result.normalize_capture_adoption_provenance(
                raw_provenance
            )
        )
        binding = (
            transaction_journal
            .normalize_recovered_adoption_journal_binding(
                raw_binding
            )
        )
        continuation = (
            transaction_journal
            .normalize_recovered_adoption_continuation(
                raw_continuation
            )
        )
    except (
        recovered_adoption.RecoveredAdoptionEvidenceError,
        adoption_result.CaptureAdoptionResultError,
        transaction_journal.TransactionJournalError,
    ) as exc:
        raise _error(
            "adoption_recovery_v2_journal_context_invalid"
        ) from exc
    if (
        _canonical_json(evidence) != _canonical_json(raw_evidence)
        or _canonical_json(result) != _canonical_json(raw_result)
        or _canonical_json(provenance)
        != _canonical_json(raw_provenance)
        or _canonical_json(binding) != _canonical_json(raw_binding)
        or _canonical_json(continuation)
        != _canonical_json(raw_continuation)
        or result["kind"] != adoption_result.RECOVERED_ADOPTION_KIND
        or result["evidence"] != evidence
        or provenance
        != adoption_result.project_capture_adoption_provenance(
            result
        )
    ):
        raise _error(
            "adoption_recovery_v2_journal_context_changed"
        )
    evidence_sha256 = (
        recovered_adoption.recovered_adoption_evidence_sha256(
            evidence
        )
    )
    result_sha256 = (
        adoption_result.capture_adoption_result_sha256(result)
    )
    provenance_sha256 = (
        adoption_result.capture_adoption_provenance_sha256(
            provenance
        )
    )
    if (
        binding["capture_session_id"]
        != evidence["capture_session_id"]
        or binding["transaction_journal_schema"]
        != evidence["transaction_journal_schema"]
        or not hmac.compare_digest(
            binding["final_parent_identity_sha256"],
            evidence["final_parent_identity_sha256"],
        )
        or not hmac.compare_digest(
            binding["capture_object_identity_sha256"],
            evidence["capture_object_identity_sha256"],
        )
        or not hmac.compare_digest(
            binding["reconciled_final_object_stat_sha256"],
            evidence["reconciled_final_object_stat_sha256"],
        )
        or not hmac.compare_digest(
            binding["reconciled_content_inventory_sha256"],
            evidence["reconciled_content_inventory_sha256"],
        )
        or not hmac.compare_digest(
            binding["recovered_adoption_evidence_sha256"],
            evidence_sha256,
        )
        or not hmac.compare_digest(
            binding["capture_adoption_result_sha256"],
            result_sha256,
        )
        or not hmac.compare_digest(
            binding["capture_adoption_provenance_sha256"],
            provenance_sha256,
        )
        or not hmac.compare_digest(
            continuation["recovered_adoption_evidence_sha256"],
            evidence_sha256,
        )
        or not hmac.compare_digest(
            continuation["capture_adoption_result_sha256"],
            result_sha256,
        )
        or not hmac.compare_digest(
            continuation["capture_adoption_provenance_sha256"],
            provenance_sha256,
        )
    ):
        raise _error(
            "adoption_recovery_v2_journal_context_binding_changed"
        )
    return evidence, result, provenance, binding, continuation


def _build_binding_v2(
    *,
    journal_binding: Mapping[str, Any],
    evidence: Mapping[str, Any],
    evidence_sha256: str,
    result_sha256: str,
    provenance_sha256: str,
    root_info: os.stat_result,
    inventory: _InventoryObservation,
) -> dict[str, Any]:
    try:
        normalized_journal = (
            transaction_journal
            .normalize_recovered_adoption_journal_binding(
                journal_binding
            )
        )
    except transaction_journal.TransactionJournalError as exc:
        raise _error(exc.code) from exc
    observed_object_identity = _object_identity_sha256(root_info)
    observed_object_stat = _full_stat_sha256(root_info)
    observed_inventory = inventory.content_sha256
    if (
        normalized_journal["capture_session_id"]
        != evidence["capture_session_id"]
        or normalized_journal["transaction_journal_schema"]
        != evidence["transaction_journal_schema"]
        or not hmac.compare_digest(
            normalized_journal["final_parent_identity_sha256"],
            evidence["final_parent_identity_sha256"],
        )
        or not hmac.compare_digest(
            normalized_journal["capture_object_identity_sha256"],
            observed_object_identity,
        )
        or not hmac.compare_digest(
            normalized_journal[
                "reconciled_final_object_stat_sha256"
            ],
            observed_object_stat,
        )
        or not hmac.compare_digest(
            normalized_journal[
                "reconciled_content_inventory_sha256"
            ],
            observed_inventory,
        )
        or not hmac.compare_digest(
            normalized_journal[
                "recovered_adoption_evidence_sha256"
            ],
            evidence_sha256,
        )
        or not hmac.compare_digest(
            normalized_journal[
                "capture_adoption_result_sha256"
            ],
            result_sha256,
        )
        or not hmac.compare_digest(
            normalized_journal[
                "capture_adoption_provenance_sha256"
            ],
            provenance_sha256,
        )
    ):
        raise _error(
            "adoption_recovery_v2_lease_binding_mismatch"
        )
    return normalize_recovered_adoption_lease_binding_v2(
        {
            **normalized_journal,
            "schema_version": (
                RECOVERED_ADOPTION_LEASE_BINDING_V2_SCHEMA
            ),
        }
    )


class RecoveredAdoptedCaptureLease:
    """Creator-bound retained authority for one recovered adopted object.

    Claim getters return defensive copies only while the reconciled journal
    head remains current.  They do not replace the mandatory pre-verifier and
    post-verifier filesystem gates.
    """

    __slots__ = (
        "_parent_fd",
        "_root_fd",
        "_owner_pid",
        "_expected_owner_uid",
        "_expected_verifier_gid",
        "_session",
        "_live_snapshot",
        "_evidence_json",
        "_result_json",
        "_provenance_json",
        "_evidence_sha256",
        "_result_sha256",
        "_provenance_sha256",
        "_pre_binding_json",
        "_closed",
    )

    def __init__(
        self,
        *,
        _token: object,
        parent_fd: int,
        root_fd: int,
        expected_owner_uid: int,
        expected_verifier_gid: int,
        session: transaction_journal.TransactionJournalSession,
        live_snapshot: transaction_journal.TransactionJournalLiveSnapshot,
        evidence: Mapping[str, Any],
        result: Mapping[str, Any],
        provenance: Mapping[str, Any],
    ) -> None:
        if _token is not _LEASE_TOKEN:
            raise TypeError(
                "RecoveredAdoptedCaptureLease cannot be constructed directly"
            )
        _assert_cloexec(parent_fd, field="retained_final_parent_fd")
        _assert_cloexec(root_fd, field="retained_root_fd")
        evidence_json = _canonical_json(evidence)
        result_json = _canonical_json(result)
        provenance_json = _canonical_json(provenance)
        evidence_sha256 = (
            recovered_adoption.recovered_adoption_evidence_sha256(
                evidence
            )
        )
        result_sha256 = (
            adoption_result.capture_adoption_result_sha256(result)
        )
        provenance_sha256 = (
            adoption_result.capture_adoption_provenance_sha256(
                provenance
            )
        )

        # Descriptor ownership transfers only after every fallible canonical
        # binding operation has completed.  The caller remains responsible for
        # both descriptors if construction raises.
        self._parent_fd = -1
        self._root_fd = -1
        self._closed = True
        self._owner_pid = os.getpid()
        self._expected_owner_uid = expected_owner_uid
        self._expected_verifier_gid = expected_verifier_gid
        self._session = session
        self._live_snapshot = live_snapshot
        self._evidence_json = evidence_json
        self._result_json = result_json
        self._provenance_json = provenance_json
        self._evidence_sha256 = evidence_sha256
        self._result_sha256 = result_sha256
        self._provenance_sha256 = provenance_sha256
        self._pre_binding_json: bytes | None = None
        self._parent_fd = parent_fd
        self._root_fd = root_fd
        self._closed = False

    @property
    def active(self) -> bool:
        return (
            not self._closed
            and os.getpid() == self._owner_pid
            and self._parent_fd >= 0
            and self._root_fd >= 0
        )

    def _require_active(self) -> None:
        if os.getpid() != self._owner_pid:
            raise _error("adoption_recovery_lease_creator_process_mismatch")
        if not self.active:
            raise _error("adoption_recovery_lease_closed")
        _assert_cloexec(
            self._parent_fd,
            field="retained_final_parent_fd",
        )
        _assert_cloexec(self._root_fd, field="retained_root_fd")

    def _assert_journal_head_current(self) -> None:
        try:
            self._session.assert_live_snapshot_current(
                self._live_snapshot
            )
        except transaction_journal.TransactionJournalError as exc:
            raise _error(exc.code) from exc

    def _require_current_authority(self) -> None:
        self._require_active()
        self._assert_journal_head_current()

    @property
    def recovered_adoption_evidence(self) -> dict[str, Any]:
        self._require_current_authority()
        return json.loads(self._evidence_json.decode("ascii"))

    @property
    def recovered_adoption_evidence_sha256(self) -> str:
        self._require_current_authority()
        return self._evidence_sha256

    @property
    def capture_adoption_result(self) -> dict[str, Any]:
        self._require_current_authority()
        return json.loads(self._result_json.decode("ascii"))

    @property
    def capture_adoption_result_sha256(self) -> str:
        self._require_current_authority()
        return self._result_sha256

    @property
    def capture_adoption_provenance(self) -> dict[str, Any]:
        self._require_current_authority()
        return json.loads(self._provenance_json.decode("ascii"))

    @property
    def capture_adoption_provenance_sha256(self) -> str:
        self._require_current_authority()
        return self._provenance_sha256

    @property
    def capture_session_id(self) -> str:
        return self.recovered_adoption_evidence["capture_session_id"]

    @property
    def final_name(self) -> str:
        return self.recovered_adoption_evidence["final_name"]

    def _revalidate(self) -> dict[str, Any]:
        self._require_active()
        self._assert_journal_head_current()
        evidence = json.loads(self._evidence_json.decode("ascii"))
        try:
            normalized_evidence = (
                recovered_adoption.normalize_recovered_adoption_evidence(
                    evidence
                )
            )
            result = adoption_result.normalize_capture_adoption_result(
                json.loads(self._result_json.decode("ascii"))
            )
            provenance = (
                adoption_result.normalize_capture_adoption_provenance(
                    json.loads(self._provenance_json.decode("ascii"))
                )
            )
        except (
            recovered_adoption.RecoveredAdoptionEvidenceError,
            adoption_result.CaptureAdoptionResultError,
        ) as exc:
            raise _error(
                "adoption_recovery_lease_canonical_binding_invalid"
            ) from exc
        if (
            _canonical_json(normalized_evidence) != self._evidence_json
            or _canonical_json(result) != self._result_json
            or _canonical_json(provenance) != self._provenance_json
            or result["evidence"] != normalized_evidence
            or provenance
            != adoption_result.project_capture_adoption_provenance(result)
        ):
            raise _error(
                "adoption_recovery_lease_canonical_binding_changed"
            )
        parent_before = _validate_final_parent(
            self._parent_fd,
            evidence=normalized_evidence,
            owner_uid=self._expected_owner_uid,
            verifier_gid=self._expected_verifier_gid,
        )
        root_info, inventory = _validate_bound_object(
            self._parent_fd,
            self._root_fd,
            evidence=normalized_evidence,
            owner_uid=self._expected_owner_uid,
            verifier_gid=self._expected_verifier_gid,
        )
        parent_after = _validate_final_parent(
            self._parent_fd,
            evidence=normalized_evidence,
            owner_uid=self._expected_owner_uid,
            verifier_gid=self._expected_verifier_gid,
        )
        if _full_stat_tuple(parent_before) != _full_stat_tuple(parent_after):
            raise _error("adoption_recovery_final_parent_changed")
        self._assert_journal_head_current()
        return _build_binding(
            evidence=normalized_evidence,
            live_snapshot=self._live_snapshot,
            evidence_sha256=self._evidence_sha256,
            result_sha256=self._result_sha256,
            provenance_sha256=self._provenance_sha256,
            root_info=root_info,
            inventory=inventory,
        )

    def pre_verifier_revalidate(self) -> dict[str, Any]:
        binding = self._revalidate()
        encoded = _canonical_json(binding)
        if (
            self._pre_binding_json is not None
            and self._pre_binding_json != encoded
        ):
            raise _error("adoption_recovery_pre_verifier_binding_changed")
        self._pre_binding_json = encoded
        return _canonical_copy(binding)

    def post_verifier_revalidate(self) -> dict[str, Any]:
        self._require_active()
        if self._pre_binding_json is None:
            raise _error("adoption_recovery_pre_verifier_binding_required")
        binding = self._revalidate()
        if _canonical_json(binding) != self._pre_binding_json:
            raise _error("adoption_recovery_post_verifier_binding_changed")
        return _canonical_copy(binding)

    def _descriptor_numbers_for_test(self) -> tuple[int, int]:
        self._require_active()
        return self._parent_fd, self._root_fd

    def close(self) -> None:
        if os.getpid() != self._owner_pid:
            raise _error("adoption_recovery_lease_creator_process_mismatch")
        if self._closed:
            return
        close_error: OSError | None = None
        for field in ("_root_fd", "_parent_fd"):
            descriptor = getattr(self, field)
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError as exc:
                    close_error = close_error or exc
                finally:
                    setattr(self, field, -1)
        self._session = None
        self._live_snapshot = None
        self._closed = True
        if close_error is not None:
            raise _error(
                "adoption_recovery_lease_descriptor_close_failed"
            ) from close_error

    def __enter__(self) -> "RecoveredAdoptedCaptureLease":
        self._require_active()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        del exc_type, exc, traceback
        self.close()
        return False

    def __copy__(self) -> Any:
        raise TypeError("RecoveredAdoptedCaptureLease is not copyable")

    def __deepcopy__(self, memo: Any) -> Any:
        del memo
        raise TypeError("RecoveredAdoptedCaptureLease is not copyable")

    def __reduce__(self) -> Any:
        raise TypeError("RecoveredAdoptedCaptureLease is not serializable")

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError("RecoveredAdoptedCaptureLease is not serializable")

    def __getstate__(self) -> Any:
        raise TypeError("RecoveredAdoptedCaptureLease is not serializable")

    def __del__(self) -> None:
        # A forked child must be allowed to discard its copies without gaining
        # use of the creator-bound public close operation.  Descriptor closure
        # has no namespace side effect.
        for field in ("_root_fd", "_parent_fd"):
            descriptor = getattr(self, field, -1)
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                try:
                    setattr(self, field, -1)
                except BaseException:
                    pass


class RecoveredAdoptionOuterAckOperation:
    """Linear lease-owned wrapper around one exact journal ACK operation."""

    __slots__ = (
        "__lease",
        "__journal_operation",
        "__owner_pid",
        "__pre_binding_json",
        "__state",
    )

    def __init__(
        self,
        *,
        _token: object,
        lease: RecoveredAdoptedCaptureLeaseV2,
        journal_operation: (
            transaction_journal.RecoveredAdoptionTombstoneAckOperation
        ),
        pre_binding: Mapping[str, Any],
    ) -> None:
        if _token is not _OUTER_ACK_TOKEN:
            raise TypeError(
                "RecoveredAdoptionOuterAckOperation cannot be "
                "constructed directly"
            )
        if (
            type(lease) is not RecoveredAdoptedCaptureLeaseV2
            or type(journal_operation)
            is not (
                transaction_journal
                .RecoveredAdoptionTombstoneAckOperation
            )
        ):
            raise _error(
                "adoption_recovery_v2_outer_ack_operation_invalid"
            )
        self.__lease = lease
        self.__journal_operation = journal_operation
        self.__owner_pid = os.getpid()
        self.__pre_binding_json = _canonical_json(
            normalize_recovered_adoption_lease_binding_v2(
                pre_binding
            )
        )
        self.__state = "open"

    @property
    def state(self) -> str:
        if os.getpid() != self.__owner_pid:
            raise _error(
                "adoption_recovery_v2_outer_ack_creator_process_mismatch"
            )
        return self.__state

    def _contents_for_lease(
        self,
        lease: RecoveredAdoptedCaptureLeaseV2,
    ) -> tuple[
        transaction_journal.RecoveredAdoptionTombstoneAckOperation,
        bytes,
    ]:
        if os.getpid() != self.__owner_pid:
            raise _error(
                "adoption_recovery_v2_outer_ack_creator_process_mismatch"
            )
        if self.__lease is not lease or self.__state != "open":
            raise _error(
                "adoption_recovery_v2_outer_ack_operation_spent"
            )
        return self.__journal_operation, self.__pre_binding_json

    def _set_state(self, expected: str, selected: str) -> None:
        if self.__state != expected:
            raise _error(
                "adoption_recovery_v2_outer_ack_operation_spent"
            )
        self.__state = selected

    def commit(
        self,
        control: Any,
    ) -> transaction_journal.RecoveredAdoptionContinuationClearance:
        return self.__lease._commit_outer_ack(self, control)

    def cancel(self) -> None:
        self.__lease._cancel_outer_ack(self)

    def __copy__(self) -> Any:
        raise TypeError(
            "RecoveredAdoptionOuterAckOperation is not copyable"
        )

    def __deepcopy__(self, memo: Any) -> Any:
        del memo
        raise TypeError(
            "RecoveredAdoptionOuterAckOperation is not copyable"
        )

    def __reduce__(self) -> Any:
        raise TypeError(
            "RecoveredAdoptionOuterAckOperation is not serializable"
        )

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError(
            "RecoveredAdoptionOuterAckOperation is not serializable"
        )

    def __getstate__(self) -> Any:
        raise TypeError(
            "RecoveredAdoptionOuterAckOperation is not serializable"
        )

    def __del__(self) -> None:
        if (
            getattr(self, "_RecoveredAdoptionOuterAckOperation__state", None)
            == "open"
            and os.getpid()
            == getattr(
                self,
                "_RecoveredAdoptionOuterAckOperation__owner_pid",
                -1,
            )
        ):
            try:
                self.cancel()
            except BaseException:
                pass


class RecoveredAdoptedCaptureLeaseV2:
    """Future ACK-aware retained authority for one recovered adopted object.

    A reconciled-head lease may inspect its canonical claims and reserve the
    exact outer tombstone acknowledgement, but verifier authority is withheld
    until the durable enriched ACK successor has been rebound.  A lease minted
    directly from that exact successor is verifier-eligible immediately.
    """

    __slots__ = (
        "_parent_fd",
        "_root_fd",
        "_owner_pid",
        "_expected_owner_uid",
        "_expected_verifier_gid",
        "_session",
        "_context",
        "_evidence_json",
        "_result_json",
        "_provenance_json",
        "_continuation_json",
        "_journal_binding_json",
        "_evidence_sha256",
        "_result_sha256",
        "_provenance_sha256",
        "_pre_binding_json",
        "_active_ack",
        "_flow_state",
        "_closed",
    )

    def __init__(
        self,
        *,
        _token: object,
        parent_fd: int,
        root_fd: int,
        expected_owner_uid: int,
        expected_verifier_gid: int,
        session: transaction_journal.TransactionJournalSession,
        context: transaction_journal.RecoveredAdoptionJournalContext,
        evidence: Mapping[str, Any],
        result: Mapping[str, Any],
        provenance: Mapping[str, Any],
        journal_binding: Mapping[str, Any],
        continuation: Mapping[str, Any],
    ) -> None:
        if _token is not _LEASE_V2_TOKEN:
            raise TypeError(
                "RecoveredAdoptedCaptureLeaseV2 cannot be "
                "constructed directly"
            )
        if (
            type(session)
            is not transaction_journal.TransactionJournalSession
            or type(context)
            is not transaction_journal.RecoveredAdoptionJournalContext
        ):
            raise _error(
                "adoption_recovery_v2_journal_context_required"
            )
        _assert_cloexec(parent_fd, field="v2_retained_final_parent_fd")
        _assert_cloexec(root_fd, field="v2_retained_root_fd")
        normalized_binding = (
            normalize_recovered_adoption_lease_binding_v2(
                journal_binding
            )
        )
        state = normalized_binding[
            "transaction_journal_head_state"
        ]
        if state not in {
            "adoption_reconciled",
            "staging_tombstone_acked",
        }:
            raise _error(
                "adoption_recovery_v2_journal_head_state_invalid"
            )
        evidence_json = _canonical_json(evidence)
        result_json = _canonical_json(result)
        provenance_json = _canonical_json(provenance)
        continuation_json = _canonical_json(continuation)
        evidence_sha256 = (
            recovered_adoption.recovered_adoption_evidence_sha256(
                evidence
            )
        )
        result_sha256 = (
            adoption_result.capture_adoption_result_sha256(result)
        )
        provenance_sha256 = (
            adoption_result.capture_adoption_provenance_sha256(
                provenance
            )
        )

        # Descriptor ownership transfers only after all canonical operations.
        self._parent_fd = -1
        self._root_fd = -1
        self._closed = True
        self._owner_pid = os.getpid()
        self._expected_owner_uid = expected_owner_uid
        self._expected_verifier_gid = expected_verifier_gid
        self._session = session
        self._context = context
        self._evidence_json = evidence_json
        self._result_json = result_json
        self._provenance_json = provenance_json
        self._continuation_json = continuation_json
        self._journal_binding_json = _canonical_json(
            normalized_binding
        )
        self._evidence_sha256 = evidence_sha256
        self._result_sha256 = result_sha256
        self._provenance_sha256 = provenance_sha256
        self._pre_binding_json: bytes | None = None
        self._active_ack: RecoveredAdoptionOuterAckOperation | None = (
            None
        )
        self._flow_state = (
            "reconciled"
            if state == "adoption_reconciled"
            else "acked"
        )
        self._parent_fd = parent_fd
        self._root_fd = root_fd
        self._closed = False

    @property
    def active(self) -> bool:
        return (
            not self._closed
            and os.getpid() == self._owner_pid
            and self._parent_fd >= 0
            and self._root_fd >= 0
        )

    @property
    def flow_state(self) -> str:
        self._require_active()
        return self._flow_state

    def _require_active(self) -> None:
        if os.getpid() != self._owner_pid:
            raise _error(
                "adoption_recovery_v2_lease_creator_process_mismatch"
            )
        if not self.active:
            raise _error("adoption_recovery_v2_lease_closed")
        _assert_cloexec(
            self._parent_fd,
            field="v2_retained_final_parent_fd",
        )
        _assert_cloexec(
            self._root_fd,
            field="v2_retained_root_fd",
        )

    def _require_claim_authority(self) -> None:
        self._require_active()
        if self._flow_state == "ack_failed":
            raise _error(
                "adoption_recovery_v2_outer_ack_failed"
            )

    def _read_and_compare_context(
        self,
        context: Any,
    ) -> tuple[
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
    ]:
        self._require_claim_authority()
        (
            evidence,
            result,
            provenance,
            binding,
            continuation,
        ) = _read_recovered_context_v2(self._session, context)
        if (
            _canonical_json(evidence) != self._evidence_json
            or _canonical_json(result) != self._result_json
            or _canonical_json(provenance) != self._provenance_json
            or _canonical_json(continuation)
            != self._continuation_json
            or not hmac.compare_digest(
                recovered_adoption
                .recovered_adoption_evidence_sha256(evidence),
                self._evidence_sha256,
            )
            or not hmac.compare_digest(
                adoption_result.capture_adoption_result_sha256(
                    result
                ),
                self._result_sha256,
            )
            or not hmac.compare_digest(
                adoption_result
                .capture_adoption_provenance_sha256(provenance),
                self._provenance_sha256,
            )
        ):
            raise _error(
                "adoption_recovery_v2_retained_claims_changed"
            )
        return evidence, result, provenance, binding, continuation

    def _revalidate_against_context(
        self,
        context: Any,
        *,
        require_retained_binding: bool,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        (
            evidence,
            _result,
            _provenance,
            journal_binding,
            _continuation,
        ) = self._read_and_compare_context(context)
        if (
            require_retained_binding
            and _canonical_json(journal_binding)
            != self._journal_binding_json
        ):
            raise _error(
                "adoption_recovery_v2_journal_binding_changed"
            )
        parent_before = _validate_final_parent(
            self._parent_fd,
            evidence=evidence,
            owner_uid=self._expected_owner_uid,
            verifier_gid=self._expected_verifier_gid,
        )
        root_info, inventory = _validate_bound_object(
            self._parent_fd,
            self._root_fd,
            evidence=evidence,
            owner_uid=self._expected_owner_uid,
            verifier_gid=self._expected_verifier_gid,
        )
        parent_after = _validate_final_parent(
            self._parent_fd,
            evidence=evidence,
            owner_uid=self._expected_owner_uid,
            verifier_gid=self._expected_verifier_gid,
        )
        if _full_stat_tuple(parent_before) != _full_stat_tuple(
            parent_after
        ):
            raise _error(
                "adoption_recovery_v2_final_parent_changed"
            )
        # Re-read after the complete descriptor-relative tree observation.
        (
            evidence_after,
            _result_after,
            _provenance_after,
            binding_after,
            _continuation_after,
        ) = self._read_and_compare_context(context)
        if (
            evidence_after != evidence
            or binding_after != journal_binding
        ):
            raise _error(
                "adoption_recovery_v2_context_changed_during_revalidation"
            )
        binding = _build_binding_v2(
            journal_binding=journal_binding,
            evidence=evidence,
            evidence_sha256=self._evidence_sha256,
            result_sha256=self._result_sha256,
            provenance_sha256=self._provenance_sha256,
            root_info=root_info,
            inventory=inventory,
        )
        return binding, journal_binding

    def _revalidate_current(self) -> dict[str, Any]:
        binding, _journal_binding = self._revalidate_against_context(
            self._context,
            require_retained_binding=True,
        )
        return binding

    @property
    def recovered_adoption_evidence(self) -> dict[str, Any]:
        self._read_and_compare_context(self._context)
        return json.loads(self._evidence_json.decode("ascii"))

    @property
    def recovered_adoption_evidence_sha256(self) -> str:
        self._read_and_compare_context(self._context)
        return self._evidence_sha256

    @property
    def capture_adoption_result(self) -> dict[str, Any]:
        self._read_and_compare_context(self._context)
        return json.loads(self._result_json.decode("ascii"))

    @property
    def capture_adoption_result_sha256(self) -> str:
        self._read_and_compare_context(self._context)
        return self._result_sha256

    @property
    def capture_adoption_provenance(self) -> dict[str, Any]:
        self._read_and_compare_context(self._context)
        return json.loads(self._provenance_json.decode("ascii"))

    @property
    def capture_adoption_provenance_sha256(self) -> str:
        self._read_and_compare_context(self._context)
        return self._provenance_sha256

    @property
    def recovered_adoption_continuation(self) -> dict[str, Any]:
        self._read_and_compare_context(self._context)
        return json.loads(
            self._continuation_json.decode("ascii")
        )

    @property
    def recovered_adoption_lease_binding(self) -> dict[str, Any]:
        return _canonical_copy(self._revalidate_current())

    @property
    def capture_session_id(self) -> str:
        return self.recovered_adoption_evidence[
            "capture_session_id"
        ]

    @property
    def final_name(self) -> str:
        return self.recovered_adoption_evidence["final_name"]

    def begin_outer_ack(
        self,
    ) -> RecoveredAdoptionOuterAckOperation:
        self._require_active()
        if (
            self._flow_state != "reconciled"
            or self._active_ack is not None
            or self._pre_binding_json is not None
        ):
            raise _error(
                "adoption_recovery_v2_outer_ack_not_available"
            )
        pre_binding = self._revalidate_current()
        if (
            pre_binding["transaction_journal_head_state"]
            != "adoption_reconciled"
            or pre_binding[
                "staging_tombstone_acked_record_sha256"
            ]
            is not None
        ):
            raise _error(
                "adoption_recovery_v2_outer_ack_head_invalid"
            )
        operation: (
            transaction_journal.RecoveredAdoptionTombstoneAckOperation
            | None
        ) = None
        try:
            operation = (
                self._session
                .begin_recovered_adoption_tombstone_ack()
            )
            if (
                type(operation)
                is not (
                    transaction_journal
                    .RecoveredAdoptionTombstoneAckOperation
                )
            ):
                raise _error(
                    "adoption_recovery_v2_outer_ack_operation_invalid"
                )
            operation_context = operation.journal_context
            (
                _evidence,
                _result,
                _provenance,
                operation_binding,
                _continuation,
            ) = self._read_and_compare_context(operation_context)
            if (
                _canonical_json(operation_binding)
                != self._journal_binding_json
            ):
                raise _error(
                    "adoption_recovery_v2_outer_ack_context_mismatch"
                )
            wrapper = RecoveredAdoptionOuterAckOperation(
                _token=_OUTER_ACK_TOKEN,
                lease=self,
                journal_operation=operation,
                pre_binding=pre_binding,
            )
        except transaction_journal.TransactionJournalError as exc:
            cancellation_error: BaseException | None = None
            if operation is not None:
                cancellation_error = (
                    self._cancel_reserved_journal_operation(operation)
                )
                if cancellation_error is not None:
                    self._flow_state = "ack_failed"
            if (
                cancellation_error is not None
                and not isinstance(cancellation_error, Exception)
            ):
                raise cancellation_error
            raise _error(exc.code) from exc
        except BaseException:
            cancellation_error = None
            if operation is not None:
                cancellation_error = (
                    self._cancel_reserved_journal_operation(operation)
                )
                if cancellation_error is not None:
                    self._flow_state = "ack_failed"
            if (
                cancellation_error is not None
                and not isinstance(cancellation_error, Exception)
            ):
                raise cancellation_error
            raise
        self._active_ack = wrapper
        self._flow_state = "ack_reserved"
        return wrapper

    def _require_ack_wrapper(
        self,
        wrapper: Any,
    ) -> tuple[
        transaction_journal.RecoveredAdoptionTombstoneAckOperation,
        bytes,
    ]:
        self._require_active()
        if (
            type(wrapper) is not RecoveredAdoptionOuterAckOperation
            or self._active_ack is not wrapper
            or self._flow_state != "ack_reserved"
        ):
            raise _error(
                "adoption_recovery_v2_outer_ack_operation_invalid"
            )
        return wrapper._contents_for_lease(self)

    def _cancel_reserved_journal_operation(
        self,
        operation: (
            transaction_journal.RecoveredAdoptionTombstoneAckOperation
        ),
    ) -> BaseException | None:
        """Release one reservation even if its public cancel boundary aborts."""

        try:
            operation.cancel()
        except BaseException as exc:
            # The journal cancellation is side-effect free and exact-type /
            # session bound.  Retrying the internal boundary can only release
            # this reservation or fail closed; it cannot acknowledge staging.
            try:
                self._session._cancel_recovered_adoption_tombstone_ack(
                    operation
                )
            except BaseException:
                pass
            return exc
        return None

    def _cancel_outer_ack(
        self,
        wrapper: Any,
    ) -> None:
        operation, _pre_binding_json = self._require_ack_wrapper(
            wrapper
        )
        cancellation_error = self._cancel_reserved_journal_operation(
            operation
        )
        if cancellation_error is not None:
            wrapper._set_state("open", "failed")
            self._active_ack = None
            self._flow_state = "ack_failed"
            if isinstance(
                cancellation_error,
                transaction_journal.TransactionJournalError,
            ):
                raise _error(
                    cancellation_error.code
                ) from cancellation_error
            raise cancellation_error
        wrapper._set_state("open", "cancelled")
        self._active_ack = None
        self._flow_state = "reconciled"

    @staticmethod
    def _assert_exact_ack_transition(
        pre_binding: Mapping[str, Any],
        post_binding: Mapping[str, Any],
        committed_record_sha256: str,
    ) -> None:
        pre = normalize_recovered_adoption_lease_binding_v2(
            pre_binding
        )
        post = normalize_recovered_adoption_lease_binding_v2(
            post_binding
        )
        mutable = {
            "transaction_journal_head_state",
            "transaction_journal_head_revision",
            "transaction_journal_head_record_sha256",
            "staging_tombstone_acked_record_sha256",
        }
        if (
            pre["transaction_journal_head_state"]
            != "adoption_reconciled"
            or pre["staging_tombstone_acked_record_sha256"]
            is not None
            or post["transaction_journal_head_state"]
            != "staging_tombstone_acked"
            or post["transaction_journal_head_revision"]
            != pre["transaction_journal_head_revision"] + 1
            or not hmac.compare_digest(
                post["transaction_journal_head_record_sha256"],
                committed_record_sha256,
            )
            or not hmac.compare_digest(
                post["staging_tombstone_acked_record_sha256"],
                committed_record_sha256,
            )
            or any(
                pre[field] != post[field]
                for field in _RECOVERED_LEASE_BINDING_V2_FIELDS
                if field not in mutable
            )
        ):
            raise _error(
                "adoption_recovery_v2_outer_ack_transition_invalid"
            )

    def _commit_outer_ack(
        self,
        wrapper: Any,
        control: Any,
    ) -> transaction_journal.RecoveredAdoptionContinuationClearance:
        operation, expected_pre_json = self._require_ack_wrapper(
            wrapper
        )
        from qualification_attestor import (
            john_lomein_persona_qualification_capture_staging
            as capture_staging,
        )

        if (
            type(control)
            is not capture_staging.InstalledCaptureStagingControl
        ):
            cancellation_error = (
                self._cancel_reserved_journal_operation(operation)
            )
            wrapper._set_state("open", "failed")
            self._active_ack = None
            self._flow_state = "ack_failed"
            if (
                cancellation_error is not None
                and not isinstance(cancellation_error, Exception)
            ):
                raise cancellation_error
            raise _error(
                "adoption_recovery_v2_installed_staging_control_required"
            )
        try:
            pre_binding = self._revalidate_current()
            if _canonical_json(pre_binding) != expected_pre_json:
                raise _error(
                    "adoption_recovery_v2_outer_ack_pre_binding_changed"
                )
            wrapper._set_state("open", "committing")
            clearance = operation.commit(control)
            if (
                type(clearance)
                is not (
                    transaction_journal
                    .RecoveredAdoptionContinuationClearance
                )
            ):
                raise _error(
                    "adoption_recovery_v2_outer_ack_clearance_invalid"
                )
            committed_sha256 = clearance.committed_record_sha256
            post_context = clearance.journal_context
            if (
                type(post_context)
                is not (
                    transaction_journal
                    .RecoveredAdoptionJournalContext
                )
            ):
                raise _error(
                    "adoption_recovery_v2_outer_ack_context_invalid"
                )
            if (
                _canonical_json(
                    clearance.recovered_adoption_continuation
                )
                != self._continuation_json
            ):
                raise _error(
                    "adoption_recovery_v2_outer_ack_continuation_changed"
                )
            post_binding, post_journal_binding = (
                self._revalidate_against_context(
                    post_context,
                    require_retained_binding=False,
                )
            )
            self._assert_exact_ack_transition(
                pre_binding,
                post_binding,
                committed_sha256,
            )
        except transaction_journal.TransactionJournalError as exc:
            if wrapper.state == "open":
                wrapper._set_state("open", "failed")
            elif wrapper.state == "committing":
                wrapper._set_state("committing", "failed")
            self._active_ack = None
            self._flow_state = "ack_failed"
            raise _error(exc.code) from exc
        except BaseException:
            if wrapper.state == "open":
                wrapper._set_state("open", "failed")
            elif wrapper.state == "committing":
                wrapper._set_state("committing", "failed")
            self._active_ack = None
            self._flow_state = "ack_failed"
            raise
        self._context = post_context
        self._journal_binding_json = _canonical_json(
            post_journal_binding
        )
        self._active_ack = None
        self._flow_state = "acked"
        wrapper._set_state("committing", "committed")
        return clearance

    def pre_verifier_revalidate(self) -> dict[str, Any]:
        self._require_active()
        if self._flow_state != "acked" or self._active_ack is not None:
            raise _error(
                "adoption_recovery_v2_outer_ack_clearance_required"
            )
        binding = self._revalidate_current()
        encoded = _canonical_json(binding)
        if (
            self._pre_binding_json is not None
            and self._pre_binding_json != encoded
        ):
            raise _error(
                "adoption_recovery_v2_pre_verifier_binding_changed"
            )
        self._pre_binding_json = encoded
        return _canonical_copy(binding)

    def post_verifier_revalidate(self) -> dict[str, Any]:
        self._require_active()
        if (
            self._flow_state != "acked"
            or self._active_ack is not None
            or self._pre_binding_json is None
        ):
            raise _error(
                "adoption_recovery_v2_pre_verifier_binding_required"
            )
        binding = self._revalidate_current()
        if _canonical_json(binding) != self._pre_binding_json:
            raise _error(
                "adoption_recovery_v2_post_verifier_binding_changed"
            )
        return _canonical_copy(binding)

    def _descriptor_numbers_for_test(self) -> tuple[int, int]:
        self._require_active()
        return self._parent_fd, self._root_fd

    def close(self) -> None:
        if os.getpid() != self._owner_pid:
            raise _error(
                "adoption_recovery_v2_lease_creator_process_mismatch"
            )
        if self._closed:
            return
        cancellation_error: BaseException | None = None
        if self._active_ack is not None:
            try:
                self._active_ack.cancel()
            except BaseException as exc:
                cancellation_error = exc
        close_error: OSError | None = None
        for field in ("_root_fd", "_parent_fd"):
            descriptor = getattr(self, field)
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError as exc:
                    close_error = close_error or exc
                finally:
                    setattr(self, field, -1)
        self._session = None
        self._context = None
        self._active_ack = None
        self._closed = True
        if close_error is not None:
            raise _error(
                "adoption_recovery_v2_lease_descriptor_close_failed"
            ) from close_error
        if cancellation_error is not None:
            raise _error(
                "adoption_recovery_v2_outer_ack_cancel_failed"
            ) from cancellation_error

    def __enter__(self) -> RecoveredAdoptedCaptureLeaseV2:
        self._require_active()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        del exc_type, exc, traceback
        self.close()
        return False

    def __copy__(self) -> Any:
        raise TypeError(
            "RecoveredAdoptedCaptureLeaseV2 is not copyable"
        )

    def __deepcopy__(self, memo: Any) -> Any:
        del memo
        raise TypeError(
            "RecoveredAdoptedCaptureLeaseV2 is not copyable"
        )

    def __reduce__(self) -> Any:
        raise TypeError(
            "RecoveredAdoptedCaptureLeaseV2 is not serializable"
        )

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError(
            "RecoveredAdoptedCaptureLeaseV2 is not serializable"
        )

    def __getstate__(self) -> Any:
        raise TypeError(
            "RecoveredAdoptedCaptureLeaseV2 is not serializable"
        )

    def __del__(self) -> None:
        for field in ("_root_fd", "_parent_fd"):
            descriptor = getattr(self, field, -1)
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                try:
                    setattr(self, field, -1)
                except BaseException:
                    pass


def _recover_impl(
    session: Any,
    final_parent_fd: Any,
    *,
    expected_owner_uid: int,
    expected_verifier_gid: int | None,
) -> RecoveredAdoptedCaptureLease:
    if type(session) is not transaction_journal.TransactionJournalSession:
        raise _error(
            "adoption_recovery_transaction_journal_session_required"
        )
    owner_uid = _integer(
        expected_owner_uid,
        field="expected_owner_uid",
        maximum=(1 << 31) - 1,
    )
    explicit_gid = (
        None
        if expected_verifier_gid is None
        else _integer(
            expected_verifier_gid,
            field="expected_verifier_gid",
            minimum=1,
            maximum=(1 << 31) - 1,
        )
    )
    parent_fd = _retain_parent_descriptor(final_parent_fd)
    root_fd = -1
    try:
        try:
            live_snapshot = session.live_snapshot()
            minted = session.mint_recovered_adoption_evidence()
            evidence = (
                recovered_adoption.normalize_recovered_adoption_evidence(
                    minted
                )
            )
        except (
            transaction_journal.TransactionJournalError,
            recovered_adoption.RecoveredAdoptionEvidenceError,
        ) as exc:
            raise _error(exc.code) from exc
        verifier_gid = evidence["verifier_gid"]
        if explicit_gid is not None and explicit_gid != verifier_gid:
            raise _error("adoption_recovery_expected_verifier_gid_mismatch")
        actual_gid = verifier_gid if explicit_gid is None else explicit_gid
        parent_before = _validate_final_parent(
            parent_fd,
            evidence=evidence,
            owner_uid=owner_uid,
            verifier_gid=actual_gid,
        )
        root_fd, _opened = _open_bound_directory(
            parent_fd,
            evidence["final_name"],
            field="root",
        )
        root_info, inventory = _validate_bound_object(
            parent_fd,
            root_fd,
            evidence=evidence,
            owner_uid=owner_uid,
            verifier_gid=actual_gid,
        )
        parent_after = _validate_final_parent(
            parent_fd,
            evidence=evidence,
            owner_uid=owner_uid,
            verifier_gid=actual_gid,
        )
        if _full_stat_tuple(parent_before) != _full_stat_tuple(parent_after):
            raise _error("adoption_recovery_final_parent_changed")
        try:
            session.assert_live_snapshot_current(live_snapshot)
        except transaction_journal.TransactionJournalError as exc:
            raise _error(exc.code) from exc

        evidence_digest = (
            recovered_adoption.recovered_adoption_evidence_sha256(
                evidence
            )
        )
        try:
            result = adoption_result.build_capture_adoption_result(
                adoption_result.RECOVERED_ADOPTION_KIND,
                evidence,
            )
            provenance = (
                adoption_result.project_capture_adoption_provenance(
                    result
                )
            )
        except adoption_result.CaptureAdoptionResultError as exc:
            raise _error(exc.code) from exc
        # Build once before transfer so every digest and filesystem observation
        # is known-good while all authority is still local to this function.
        _build_binding(
            evidence=evidence,
            live_snapshot=live_snapshot,
            evidence_sha256=evidence_digest,
            result_sha256=(
                adoption_result.capture_adoption_result_sha256(result)
            ),
            provenance_sha256=(
                adoption_result.capture_adoption_provenance_sha256(
                    provenance
                )
            ),
            root_info=root_info,
            inventory=inventory,
        )
        try:
            session.assert_live_snapshot_current(live_snapshot)
        except transaction_journal.TransactionJournalError as exc:
            raise _error(exc.code) from exc
        lease = RecoveredAdoptedCaptureLease(
            _token=_LEASE_TOKEN,
            parent_fd=parent_fd,
            root_fd=root_fd,
            expected_owner_uid=owner_uid,
            expected_verifier_gid=actual_gid,
            session=session,
            live_snapshot=live_snapshot,
            evidence=evidence,
            result=result,
            provenance=provenance,
        )
        parent_fd = -1
        root_fd = -1
        return lease
    finally:
        if root_fd >= 0:
            os.close(root_fd)
        if parent_fd >= 0:
            os.close(parent_fd)


def _recover_v2_impl(
    session: Any,
    final_parent_fd: Any,
    *,
    expected_owner_uid: int,
    expected_verifier_gid: int | None,
) -> RecoveredAdoptedCaptureLeaseV2:
    if type(session) is not transaction_journal.TransactionJournalSession:
        raise _error(
            "adoption_recovery_v2_transaction_journal_session_required"
        )
    owner_uid = _integer(
        expected_owner_uid,
        field="v2_expected_owner_uid",
        maximum=(1 << 31) - 1,
    )
    explicit_gid = (
        None
        if expected_verifier_gid is None
        else _integer(
            expected_verifier_gid,
            field="v2_expected_verifier_gid",
            minimum=1,
            maximum=(1 << 31) - 1,
        )
    )
    parent_fd = _retain_parent_descriptor(final_parent_fd)
    root_fd = -1
    try:
        try:
            context = (
                session.mint_recovered_adoption_journal_context()
            )
        except transaction_journal.TransactionJournalError as exc:
            raise _error(exc.code) from exc
        (
            evidence,
            result,
            provenance,
            journal_binding,
            continuation,
        ) = _read_recovered_context_v2(session, context)
        verifier_gid = evidence["verifier_gid"]
        if explicit_gid is not None and explicit_gid != verifier_gid:
            raise _error(
                "adoption_recovery_v2_expected_verifier_gid_mismatch"
            )
        actual_gid = verifier_gid if explicit_gid is None else explicit_gid
        parent_before = _validate_final_parent(
            parent_fd,
            evidence=evidence,
            owner_uid=owner_uid,
            verifier_gid=actual_gid,
        )
        root_fd, _opened = _open_bound_directory(
            parent_fd,
            evidence["final_name"],
            field="v2_root",
        )
        root_info, inventory = _validate_bound_object(
            parent_fd,
            root_fd,
            evidence=evidence,
            owner_uid=owner_uid,
            verifier_gid=actual_gid,
        )
        parent_after = _validate_final_parent(
            parent_fd,
            evidence=evidence,
            owner_uid=owner_uid,
            verifier_gid=actual_gid,
        )
        if _full_stat_tuple(parent_before) != _full_stat_tuple(
            parent_after
        ):
            raise _error(
                "adoption_recovery_v2_final_parent_changed"
            )
        evidence_sha256 = (
            recovered_adoption.recovered_adoption_evidence_sha256(
                evidence
            )
        )
        result_sha256 = (
            adoption_result.capture_adoption_result_sha256(result)
        )
        provenance_sha256 = (
            adoption_result.capture_adoption_provenance_sha256(
                provenance
            )
        )
        binding = _build_binding_v2(
            journal_binding=journal_binding,
            evidence=evidence,
            evidence_sha256=evidence_sha256,
            result_sha256=result_sha256,
            provenance_sha256=provenance_sha256,
            root_info=root_info,
            inventory=inventory,
        )
        (
            evidence_after,
            result_after,
            provenance_after,
            binding_after,
            continuation_after,
        ) = _read_recovered_context_v2(session, context)
        if (
            _canonical_json(evidence_after)
            != _canonical_json(evidence)
            or _canonical_json(result_after)
            != _canonical_json(result)
            or _canonical_json(provenance_after)
            != _canonical_json(provenance)
            or _canonical_json(binding_after)
            != _canonical_json(journal_binding)
            or _canonical_json(continuation_after)
            != _canonical_json(continuation)
            or _canonical_json(binding)
            != _canonical_json(journal_binding)
        ):
            raise _error(
                "adoption_recovery_v2_context_changed_during_recovery"
            )
        lease = RecoveredAdoptedCaptureLeaseV2(
            _token=_LEASE_V2_TOKEN,
            parent_fd=parent_fd,
            root_fd=root_fd,
            expected_owner_uid=owner_uid,
            expected_verifier_gid=actual_gid,
            session=session,
            context=context,
            evidence=evidence,
            result=result,
            provenance=provenance,
            journal_binding=journal_binding,
            continuation=continuation,
        )
        parent_fd = -1
        root_fd = -1
        return lease
    finally:
        if root_fd >= 0:
            os.close(root_fd)
        if parent_fd >= 0:
            os.close(parent_fd)


def recover_adopted_capture(
    session: transaction_journal.TransactionJournalSession,
    final_parent_fd: int,
) -> RecoveredAdoptedCaptureLease:
    """Production entry point; intentionally disabled."""

    if not PRODUCTION_ACTIVATION:
        raise _error("adoption_recovery_production_disabled")
    if os.getuid() != 0 or os.geteuid() != 0:
        raise _error("adoption_recovery_requires_root")
    return _recover_impl(
        session,
        final_parent_fd,
        expected_owner_uid=0,
        expected_verifier_gid=None,
    )


def recover_adopted_capture_canary(
    session: transaction_journal.TransactionJournalSession,
    final_parent_fd: int,
) -> RecoveredAdoptedCaptureLease:
    """Exercise the real root boundary without enabling production."""

    if os.getuid() != 0 or os.geteuid() != 0:
        raise _error("adoption_recovery_canary_requires_root")
    return _recover_impl(
        session,
        final_parent_fd,
        expected_owner_uid=0,
        expected_verifier_gid=None,
    )


def _recover_adopted_capture_for_test(
    session: transaction_journal.TransactionJournalSession,
    final_parent_fd: int,
    *,
    expected_owner_uid: int,
    expected_verifier_gid: int,
) -> RecoveredAdoptedCaptureLease:
    """Unprivileged mechanical seam with the production validation sequence."""

    return _recover_impl(
        session,
        final_parent_fd,
        expected_owner_uid=expected_owner_uid,
        expected_verifier_gid=expected_verifier_gid,
    )


def recover_adopted_capture_v2(
    session: transaction_journal.TransactionJournalSession,
    final_parent_fd: int,
) -> RecoveredAdoptedCaptureLeaseV2:
    """Future ACK-aware production entry point; intentionally inert."""

    if not RECOVERED_LEASE_V2_PRODUCTION_ACTIVATION:
        raise _error(
            "adoption_recovery_v2_production_disabled"
        )
    if os.getuid() != 0 or os.geteuid() != 0:
        raise _error("adoption_recovery_v2_requires_root")
    return _recover_v2_impl(
        session,
        final_parent_fd,
        expected_owner_uid=0,
        expected_verifier_gid=None,
    )


def recover_adopted_capture_v2_canary(
    session: transaction_journal.TransactionJournalSession,
    final_parent_fd: int,
) -> RecoveredAdoptedCaptureLeaseV2:
    """Future installed canary entry point; intentionally inert."""

    if not RECOVERED_LEASE_V2_CANARY_ACTIVATION:
        raise _error(
            "adoption_recovery_v2_canary_disabled"
        )
    if os.getuid() != 0 or os.geteuid() != 0:
        raise _error("adoption_recovery_v2_canary_requires_root")
    return _recover_v2_impl(
        session,
        final_parent_fd,
        expected_owner_uid=0,
        expected_verifier_gid=None,
    )


def _recover_adopted_capture_v2_for_test(
    session: transaction_journal.TransactionJournalSession,
    final_parent_fd: int,
    *,
    expected_owner_uid: int,
    expected_verifier_gid: int,
) -> RecoveredAdoptedCaptureLeaseV2:
    """Unprivileged seam for the exact future descriptor sequence."""

    return _recover_v2_impl(
        session,
        final_parent_fd,
        expected_owner_uid=expected_owner_uid,
        expected_verifier_gid=expected_verifier_gid,
    )


__all__ = [
    "ADOPTED_DIRECTORY_MODE",
    "ADOPTED_FILE_MODE",
    "FINAL_PARENT_MODE",
    "PRODUCTION_ACTIVATION",
    "RECOVERED_ADOPTION_LEASE_BINDING_V2_SCHEMA",
    "RECOVERED_LEASE_BINDING_SCHEMA",
    "RECOVERED_LEASE_V2_CANARY_ACTIVATION",
    "RECOVERED_LEASE_V2_PRODUCTION_ACTIVATION",
    "RecoveredAdoptedCaptureLease",
    "RecoveredAdoptedCaptureLeaseV2",
    "RecoveredAdoptionOuterAckOperation",
    "RecoveredAdoptionRecoveryError",
    "normalize_recovered_adoption_lease_binding_v2",
    "recovered_adoption_lease_binding_v2_sha256",
    "recover_adopted_capture",
    "recover_adopted_capture_canary",
    "recover_adopted_capture_v2",
    "recover_adopted_capture_v2_canary",
]
