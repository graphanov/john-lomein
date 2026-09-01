#!/usr/bin/env python3
"""Reconcile legacy memory state into John Lomein's model-hidden boundary.

The first run migrates the pre-boundary Mnemosyne and learning trees. Later
runs quarantine any legacy Mnemosyne tree recreated by an external Hermes
administrative command. Late residue is never merged into the steward's
canonical memory automatically.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Sequence


MARKER_TEXT = "john-lomein model-memory-boundary/v1\n"
MARKER_NAME = ".model-memory-boundary-v1"
QUARANTINE_DIRECTORY = "legacy-mnemosyne"


class MemoryBoundaryError(RuntimeError):
    """Raised when migration cannot prove a safe filesystem transition."""


def _lexical_absolute(path: str | Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def _exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_directory(path: Path, label: str, *, uid: int) -> None:
    if path.is_symlink():
        raise MemoryBoundaryError(f"unsafe {label} symlink: {path}")
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise MemoryBoundaryError(f"missing {label}: {path}") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != uid
        or info.st_mode & 0o022
    ):
        raise MemoryBoundaryError(f"unsafe {label}: {path}")


def validate_tree(root: Path, label: str, *, uid: int | None = None) -> None:
    """Reject links, non-regular leaves, foreign owners, and unsafe modes."""

    owner = os.geteuid() if uid is None else uid
    if not _exists(root):
        return
    if root.is_symlink() or not root.is_dir():
        raise MemoryBoundaryError(f"unsafe {label} root: {root}")
    for directory, names, files in os.walk(root, followlinks=False):
        current = Path(directory)
        _validate_directory(current, f"{label} directory", uid=owner)
        for name in [*names, *files]:
            path = current / name
            entry = path.lstat()
            if stat.S_ISLNK(entry.st_mode):
                raise MemoryBoundaryError(f"unsafe {label} symlink: {path}")
            if stat.S_ISDIR(entry.st_mode):
                continue
            if (
                not stat.S_ISREG(entry.st_mode)
                or entry.st_uid != owner
                or entry.st_nlink != 1
                or entry.st_mode & 0o022
            ):
                raise MemoryBoundaryError(f"unsafe {label} file: {path}")


def seal_tree(root: Path) -> None:
    """Make a previously validated private tree owner-only."""

    if not root.exists():
        return
    for directory, names, files in os.walk(root, followlinks=False):
        current = Path(directory)
        os.chmod(current, 0o700)
        for name in names:
            path = current / name
            if path.is_dir() and not path.is_symlink():
                os.chmod(path, 0o700)
        for name in files:
            os.chmod(current / name, 0o600)


def _ensure_private_root(private: Path, *, uid: int) -> None:
    private.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    private.mkdir(parents=True, exist_ok=True, mode=0o700)
    for label, directory in (
        ("private boundary parent", private.parent),
        ("private steward root", private),
    ):
        _validate_directory(directory, label, uid=uid)
        os.chmod(directory, 0o700)


def _validate_marker(marker: Path, *, uid: int) -> None:
    if marker.is_symlink():
        raise MemoryBoundaryError("unsafe model-memory boundary marker")
    try:
        info = marker.lstat()
    except FileNotFoundError as exc:
        raise MemoryBoundaryError("missing model-memory boundary marker") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != uid
        or info.st_nlink != 1
        or info.st_mode & 0o077
    ):
        raise MemoryBoundaryError("unsafe model-memory boundary marker")
    try:
        contents = marker.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise MemoryBoundaryError(
            "unreadable model-memory boundary marker"
        ) from exc
    if contents != MARKER_TEXT:
        raise MemoryBoundaryError("invalid model-memory boundary marker")


def _write_marker(marker: Path) -> None:
    temporary = marker.with_name(f".{marker.name}.tmp-{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(temporary, flags, 0o600)
        data = MARKER_TEXT.encode("utf-8")
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, marker)
        os.chmod(marker, 0o600)
        _fsync_directory(marker.parent)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _move_initial_tree(source: Path, target: Path, label: str) -> bool:
    if not source.exists():
        return False
    if target.exists() and any(target.iterdir()):
        raise MemoryBoundaryError(
            f"both legacy and private {label} roots contain data"
        )
    if target.exists():
        target.rmdir()
    os.replace(source, target)
    _fsync_directory(source.parent)
    _fsync_directory(target.parent)
    return True


def _quarantine_late_memory(
    legacy: Path,
    private: Path,
    *,
    uid: int,
) -> Path | None:
    if not _exists(legacy):
        return None
    validate_tree(legacy, "late legacy Mnemosyne", uid=uid)
    quarantine = private / "quarantine" / QUARANTINE_DIRECTORY
    quarantine.mkdir(parents=True, exist_ok=True, mode=0o700)
    validate_tree(private / "quarantine", "memory quarantine", uid=uid)
    os.chmod(private / "quarantine", 0o700)
    os.chmod(quarantine, 0o700)

    identity = legacy.lstat()
    stem = f"residue-{identity.st_mtime_ns:x}-{identity.st_ino:x}"
    destination = quarantine / stem
    if _exists(destination):
        raise MemoryBoundaryError(
            f"legacy Mnemosyne quarantine collision: {destination}"
        )
    os.replace(legacy, destination)
    _fsync_directory(legacy.parent)
    _fsync_directory(quarantine)
    seal_tree(destination)
    validate_tree(destination, "quarantined legacy Mnemosyne", uid=uid)
    return destination


def reconcile_memory_boundary(
    runtime_home: str | Path,
    private_root: str | Path,
    projection_root: str | Path,
) -> dict[str, Any]:
    """Migrate once, then quarantine any late-created legacy memory residue."""

    home = _lexical_absolute(runtime_home)
    private = _lexical_absolute(private_root)
    projection = _lexical_absolute(projection_root)
    expected_private = home / "private" / "learning-steward"
    expected_projection = home / "state" / "learning"
    if private != expected_private:
        raise MemoryBoundaryError(
            f"non-canonical private steward root: {private}"
        )
    if projection != expected_projection:
        raise MemoryBoundaryError(
            f"non-canonical learning projection root: {projection}"
        )
    if _exists(home) and (home.is_symlink() or not home.is_dir()):
        raise MemoryBoundaryError(f"unsafe runtime home: {home}")

    uid = os.geteuid()
    marker = private / MARKER_NAME
    legacy_memory = home / "mnemosyne"
    legacy_learning = home / "state" / "learning"
    target_memory = private / "mnemosyne"
    target_learning = private / "learning"
    initial_memory_migrated = False
    initial_learning_migrated = False

    if marker.is_symlink():
        raise MemoryBoundaryError("unsafe model-memory boundary marker")
    if not marker.exists():
        validate_tree(legacy_memory, "Mnemosyne migration", uid=uid)
        validate_tree(legacy_learning, "learning-state migration", uid=uid)
        _ensure_private_root(private, uid=uid)
        initial_memory_migrated = _move_initial_tree(
            legacy_memory,
            target_memory,
            "Mnemosyne",
        )
        initial_learning_migrated = _move_initial_tree(
            legacy_learning,
            target_learning,
            "learning",
        )
        if initial_learning_migrated:
            brief = target_learning / "current-operating-brief.md"
            if brief.exists():
                projection.mkdir(parents=True, exist_ok=True, mode=0o700)
                _validate_directory(
                    projection,
                    "learning projection",
                    uid=uid,
                )
                os.replace(brief, projection / brief.name)
                _fsync_directory(target_learning)
                _fsync_directory(projection)
        _write_marker(marker)
    else:
        _ensure_private_root(private, uid=uid)
        _validate_marker(marker, uid=uid)

    validate_tree(target_memory, "private Mnemosyne", uid=uid)
    validate_tree(target_learning, "private learning state", uid=uid)
    quarantine_root = private / "quarantine"
    validate_tree(quarantine_root, "memory quarantine", uid=uid)
    seal_tree(target_memory)
    seal_tree(target_learning)
    seal_tree(quarantine_root)

    quarantined = _quarantine_late_memory(
        legacy_memory,
        private,
        uid=uid,
    )
    return {
        "schema_version": "john_lomein_memory_boundary_migration/v1",
        "status": "ok",
        "initial_memory_migrated": initial_memory_migrated,
        "initial_learning_migrated": initial_learning_migrated,
        "late_legacy_quarantined": quarantined is not None,
        "quarantine_path": str(quarantined) if quarantined else None,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="reconcile John Lomein's private model-memory boundary"
    )
    parser.add_argument("--runtime-home", required=True)
    parser.add_argument("--private-root", required=True)
    parser.add_argument("--projection-root", required=True)
    parser.add_argument("--quiet", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = reconcile_memory_boundary(
            args.runtime_home,
            args.private_root,
            args.projection_root,
        )
    except MemoryBoundaryError as exc:
        print(f"memory boundary migration failed: {exc}", file=sys.stderr)
        return 2
    if not args.quiet:
        print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
