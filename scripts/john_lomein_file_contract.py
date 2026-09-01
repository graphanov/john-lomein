#!/usr/bin/env python3
"""Stable regular-file reads for local John Lomein product contracts."""

from __future__ import annotations

import os
import stat
from pathlib import Path


class StableFileError(ValueError):
    """A path-free stable-file failure with a bounded classification."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _trusted_system_directory_symlink(
    info: os.stat_result,
    parent_info: os.stat_result,
    target_info: os.stat_result,
) -> bool:
    """Return whether one ancestor is an immutable system directory alias."""

    return (
        info.st_uid == 0
        and parent_info.st_uid == 0
        and not parent_info.st_mode & 0o022
        and stat.S_ISDIR(target_info.st_mode)
    )


def _directory_chain(path: Path) -> tuple[tuple[int, ...], ...]:
    absolute = Path(os.path.abspath(path.expanduser()))
    parent = absolute.parent
    current = Path(parent.anchor)
    components = [current]
    for component in parent.parts[1:]:
        current /= component
        components.append(current)
    snapshot: list[tuple[int, ...]] = []
    for component in components:
        try:
            info = component.lstat()
        except OSError as exc:
            raise StableFileError("unreadable") from exc
        if stat.S_ISLNK(info.st_mode):
            try:
                parent_info = component.parent.stat()
                target_info = component.stat()
            except OSError as exc:
                raise StableFileError("unreadable") from exc
            if not _trusted_system_directory_symlink(
                info,
                parent_info,
                target_info,
            ):
                raise StableFileError("unsafe")
            snapshot.append(
                (
                    info.st_dev,
                    info.st_ino,
                    stat.S_IFMT(info.st_mode),
                    target_info.st_dev,
                    target_info.st_ino,
                    stat.S_IFMT(target_info.st_mode),
                )
            )
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise StableFileError("unsafe")
        snapshot.append((info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)))
    return tuple(snapshot)


def directory_chain_identity(path: str | Path) -> tuple[tuple[int, ...], ...]:
    """Validate and bind the existing directory chain above one path."""

    return _directory_chain(Path(path))


def _metadata_matches(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_ctime_ns == right.st_ctime_ns
        and left.st_uid == right.st_uid
        and left.st_nlink == right.st_nlink
        and stat.S_IMODE(left.st_mode) == stat.S_IMODE(right.st_mode)
        and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
    )


def read_stable_regular(
    path: str | Path,
    *,
    maximum_bytes: int,
    owner_only: bool,
) -> bytes:
    """Read one bounded file while rejecting mutable names and metadata."""

    source = Path(path)
    chain_before = _directory_chain(source)
    try:
        named_before = source.lstat()
    except FileNotFoundError as exc:
        raise StableFileError("missing") from exc
    except OSError as exc:
        raise StableFileError("unreadable") from exc
    unsafe_mode = (
        bool(named_before.st_mode & 0o077)
        if owner_only
        else bool(named_before.st_mode & 0o022)
    )
    if (
        stat.S_ISLNK(named_before.st_mode)
        or not stat.S_ISREG(named_before.st_mode)
        or named_before.st_nlink != 1
        or named_before.st_size > maximum_bytes
        or named_before.st_uid not in {0, os.geteuid()}
        or not named_before.st_mode & stat.S_IRUSR
        or unsafe_mode
    ):
        raise StableFileError("unsafe")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise StableFileError("unreadable") from exc
    primary_error: BaseException | None = None
    try:
        try:
            opened = os.fstat(descriptor)
            if not _metadata_matches(named_before, opened):
                raise StableFileError("ambiguous")
            chunks: list[bytes] = []
            remaining = maximum_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            try:
                named_after = source.lstat()
            except OSError as exc:
                raise StableFileError("ambiguous") from exc
            if (
                len(raw) > maximum_bytes
                or not _metadata_matches(opened, after)
                or not _metadata_matches(after, named_after)
                or _directory_chain(source) != chain_before
            ):
                raise StableFileError("ambiguous")
            return raw
        except OSError as exc:
            raise StableFileError("unreadable") from exc
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            if primary_error is None:
                raise StableFileError("unreadable") from exc
