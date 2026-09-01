#!/usr/bin/env python3
"""Fail-closed filesystem contract for Hermes' shared gateway token locks.

Hermes coordinates gateways that share a Discord token below the real user's
home, independently of any John Lomein instance or profile.  This module keeps
that shared surface flat and private:

* the path is always ``<real-home>/.local/state/hermes/gateway-locks``;
* parent directories are real, owner-owned and not group/world-writable;
* the gateway-lock directory itself has mode 0700;
* lock entries are single-link, owner-owned regular files with mode 0600.

The preparation API is for trusted setup code.  It may create and chmod the
controlled directories and chmod safe regular entries, but it never follows a
symlink, removes an entry, or reads/writes lock-file contents.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path


GATEWAY_LOCK_RELATIVE_PARTS = (".local", "state", "hermes", "gateway-locks")
DIRECTORY_MODE = 0o700
LOCK_FILE_MODE = 0o600
RUNTIME_LOCK_FILE_MODES = frozenset({0o600, 0o700})
MAX_LOCK_ENTRIES = 4096


class GatewayLockContractError(RuntimeError):
    """Raised when the shared gateway-lock surface cannot be proven safe."""


def _fail(code: str) -> GatewayLockContractError:
    return GatewayLockContractError(code)


def _real_home_path(real_user_home: os.PathLike[str] | str) -> Path:
    try:
        raw = os.fspath(real_user_home)
    except TypeError:
        raise _fail("gateway_lock_home_invalid") from None
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise _fail("gateway_lock_home_invalid")
    home = Path(raw)
    if not home.is_absolute() or home == Path(home.anchor):
        raise _fail("gateway_lock_home_not_absolute")
    if ".." in home.parts or home != Path(os.path.normpath(raw)):
        raise _fail("gateway_lock_home_not_normalized")
    return home


def gateway_lock_root(real_user_home: os.PathLike[str] | str) -> Path:
    """Derive Hermes' exact default shared lock root from a real user home."""

    return _real_home_path(real_user_home).joinpath(*GATEWAY_LOCK_RELATIVE_PARTS)


def _owner_uid(expected_owner_uid: int | None) -> int:
    uid = os.geteuid() if expected_owner_uid is None else expected_owner_uid
    if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
        raise _fail("gateway_lock_owner_uid_invalid")
    return uid


def _directory_open_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise _fail("gateway_lock_nofollow_unsupported")
    return os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _safe_directory(
    info: os.stat_result,
    *,
    owner_uid: int,
    exact_private_mode: bool,
) -> bool:
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid:
        return False
    mode = stat.S_IMODE(info.st_mode)
    if exact_private_mode:
        return mode == DIRECTORY_MODE
    return not bool(mode & 0o022)


def _open_real_home(home: Path, *, owner_uid: int) -> int:
    """Open every absolute component with O_NOFOLLOW, returning the home fd."""

    flags = _directory_open_flags()
    try:
        current_fd = os.open(home.anchor, flags)
    except OSError:
        raise _fail("gateway_lock_home_ancestry_unsafe") from None
    try:
        for component in home.parts[1:]:
            try:
                next_fd = os.open(component, flags, dir_fd=current_fd)
            except OSError:
                raise _fail("gateway_lock_home_ancestry_unsafe") from None
            os.close(current_fd)
            current_fd = next_fd
        try:
            info = os.fstat(current_fd)
        except OSError:
            raise _fail("gateway_lock_home_stat_failed") from None
        if not _safe_directory(
            info,
            owner_uid=owner_uid,
            exact_private_mode=False,
        ):
            raise _fail("gateway_lock_home_unsafe")
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _stat_at(parent_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        raise _fail("gateway_lock_component_stat_failed") from None


def _open_controlled_directory(
    parent_fd: int,
    name: str,
    *,
    owner_uid: int,
    prepare: bool,
    private: bool,
) -> int:
    before = _stat_at(parent_fd, name)
    if before is None:
        if not prepare:
            raise _fail("gateway_lock_root_missing")
        try:
            os.mkdir(name, DIRECTORY_MODE, dir_fd=parent_fd)
        except FileExistsError:
            before = _stat_at(parent_fd, name)
        except OSError:
            raise _fail("gateway_lock_directory_create_failed") from None
        else:
            before = _stat_at(parent_fd, name)
    if before is None or not stat.S_ISDIR(before.st_mode):
        raise _fail("gateway_lock_component_unsafe_type")
    if before.st_uid != owner_uid:
        raise _fail("gateway_lock_component_wrong_owner")

    if prepare and private:
        try:
            os.chmod(
                name,
                DIRECTORY_MODE,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except OSError:
            raise _fail("gateway_lock_directory_mode_failed") from None

    try:
        child_fd = os.open(name, _directory_open_flags(), dir_fd=parent_fd)
    except OSError:
        raise _fail("gateway_lock_component_unsafe") from None
    try:
        after = os.fstat(child_fd)
        if not _same_inode(before, after):
            raise _fail("gateway_lock_component_changed")
        if not _safe_directory(
            after,
            owner_uid=owner_uid,
            exact_private_mode=private,
        ):
            raise _fail("gateway_lock_directory_unsafe")
        return child_fd
    except BaseException:
        os.close(child_fd)
        raise


def _open_lock_root(
    home: Path,
    *,
    owner_uid: int,
    prepare: bool,
) -> int:
    current_fd = _open_real_home(home, owner_uid=owner_uid)
    try:
        for index, component in enumerate(GATEWAY_LOCK_RELATIVE_PARTS):
            next_fd = _open_controlled_directory(
                current_fd,
                component,
                owner_uid=owner_uid,
                prepare=prepare,
                private=index == len(GATEWAY_LOCK_RELATIVE_PARTS) - 1,
            )
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _safe_lock_file(info: os.stat_result, *, owner_uid: int) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == owner_uid
        and info.st_nlink == 1
    )


def _validate_or_prepare_entry(
    root_fd: int,
    name: str,
    *,
    owner_uid: int,
    prepare: bool,
) -> None:
    before = _stat_at(root_fd, name)
    if before is None:
        raise _fail("gateway_lock_entry_changed")
    if not stat.S_ISREG(before.st_mode):
        raise _fail("gateway_lock_entry_unsafe_type")
    if before.st_uid != owner_uid:
        raise _fail("gateway_lock_entry_wrong_owner")
    if before.st_nlink != 1:
        raise _fail("gateway_lock_entry_hardlinked")

    if prepare:
        try:
            os.chmod(
                name,
                LOCK_FILE_MODE,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
        except OSError:
            raise _fail("gateway_lock_entry_mode_failed") from None

    flags = (
        os.O_RDONLY
        | os.O_NONBLOCK
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        entry_fd = os.open(name, flags, dir_fd=root_fd)
    except OSError:
        raise _fail("gateway_lock_entry_open_failed") from None
    try:
        after = os.fstat(entry_fd)
        if not _same_inode(before, after):
            raise _fail("gateway_lock_entry_changed")
        if not _safe_lock_file(after, owner_uid=owner_uid):
            raise _fail("gateway_lock_entry_unsafe")
        if prepare:
            try:
                os.fchmod(entry_fd, LOCK_FILE_MODE)
                after = os.fstat(entry_fd)
            except OSError:
                raise _fail("gateway_lock_entry_mode_failed") from None
        allowed_modes = {LOCK_FILE_MODE} if prepare else RUNTIME_LOCK_FILE_MODES
        if stat.S_IMODE(after.st_mode) not in allowed_modes:
            raise _fail("gateway_lock_entry_mode_unsafe")
    finally:
        os.close(entry_fd)


def _check_entries(root_fd: int, *, owner_uid: int, prepare: bool) -> None:
    try:
        names = os.listdir(root_fd)
    except OSError:
        raise _fail("gateway_lock_root_unreadable") from None
    if len(names) > MAX_LOCK_ENTRIES:
        raise _fail("gateway_lock_entry_limit_exceeded")
    for name in sorted(names):
        _validate_or_prepare_entry(
            root_fd,
            name,
            owner_uid=owner_uid,
            prepare=prepare,
        )


def validate_gateway_lock_root(
    real_user_home: os.PathLike[str] | str,
    *,
    expected_owner_uid: int | None = None,
) -> Path:
    """Validate the complete shared lock surface without changing it."""

    home = _real_home_path(real_user_home)
    owner_uid = _owner_uid(expected_owner_uid)
    root_fd = _open_lock_root(home, owner_uid=owner_uid, prepare=False)
    try:
        _check_entries(root_fd, owner_uid=owner_uid, prepare=False)
    finally:
        os.close(root_fd)
    return gateway_lock_root(home)


def prepare_gateway_lock_root(
    real_user_home: os.PathLike[str] | str,
    *,
    expected_owner_uid: int | None = None,
) -> Path:
    """Create/normalize the shared lock surface without touching its contents."""

    home = _real_home_path(real_user_home)
    owner_uid = _owner_uid(expected_owner_uid)
    root_fd = _open_lock_root(home, owner_uid=owner_uid, prepare=True)
    try:
        _check_entries(root_fd, owner_uid=owner_uid, prepare=True)
    finally:
        os.close(root_fd)
    return gateway_lock_root(home)
