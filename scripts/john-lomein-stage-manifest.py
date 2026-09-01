#!/usr/bin/env python3
"""Stage and revalidate one setup transaction's instance manifest."""

from __future__ import annotations

import hashlib
import os
import secrets
import shlex
import stat
import sys
from pathlib import Path

from john_lomein_file_contract import StableFileError, read_stable_regular


MAX_MANIFEST_BYTES = 1024 * 1024


class SetupManifestError(RuntimeError):
    """A bounded setup-manifest failure."""


def _manifest_path(argument: str | Path) -> Path:
    supplied = Path(argument).expanduser()
    try:
        supplied_info = supplied.lstat()
    except FileNotFoundError:
        supplied_info = None
    except OSError as exc:
        raise SetupManifestError("instance manifest path is unreadable") from exc
    if supplied_info is not None and stat.S_ISLNK(supplied_info.st_mode):
        raise SetupManifestError("instance manifest path is unsafe")
    if supplied_info is not None and stat.S_ISDIR(supplied_info.st_mode):
        primary = supplied / "instance.yaml"
        legacy = supplied / "bot.yaml"
        present: dict[Path, bool] = {}
        for candidate in (primary, legacy):
            try:
                candidate.lstat()
                present[candidate] = True
            except FileNotFoundError:
                present[candidate] = False
            except OSError as exc:
                raise SetupManifestError(
                    "instance manifest path is unreadable"
                ) from exc
        if present[primary] and present[legacy]:
            raise SetupManifestError(
                "instance has more than one authoritative manifest candidate"
            )
        manifest = primary if present[primary] else legacy
    else:
        manifest = supplied
    return Path(os.path.abspath(manifest))


def _stable_mode_600(path: Path) -> bytes:
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise SetupManifestError("instance manifest is missing") from exc
    except OSError as exc:
        raise SetupManifestError("instance manifest is unreadable") from exc
    if stat.S_IMODE(before.st_mode) != 0o600:
        raise SetupManifestError("instance manifest must have mode 0600")
    try:
        raw = read_stable_regular(
            path,
            maximum_bytes=MAX_MANIFEST_BYTES,
            owner_only=True,
        )
    except StableFileError as exc:
        raise SetupManifestError(
            f"instance manifest stable read failed: {exc.code}"
        ) from exc
    try:
        after = path.lstat()
    except OSError as exc:
        raise SetupManifestError(
            "instance manifest changed during stable read"
        ) from exc
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        before.st_uid,
        before.st_nlink,
        stat.S_IMODE(before.st_mode),
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_uid,
        after.st_nlink,
        stat.S_IMODE(after.st_mode),
    )
    if identity_after != identity_before:
        raise SetupManifestError("instance manifest changed during stable read")
    return raw


def _write_snapshot(destination: Path, raw: bytes) -> None:
    parent = destination.parent
    try:
        parent_info = parent.lstat()
    except OSError as exc:
        raise SetupManifestError("setup snapshot directory is unavailable") from exc
    if (
        stat.S_ISLNK(parent_info.st_mode)
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.geteuid()
        or parent_info.st_mode & 0o022
    ):
        raise SetupManifestError("setup snapshot directory is unsafe")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        parent_descriptor = os.open(parent, directory_flags)
    except OSError as exc:
        raise SetupManifestError(
            "setup snapshot directory could not be bound safely"
        ) from exc
    snapshot_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    created = False
    operation_error: BaseException | None = None
    try:
        try:
            opened_parent = os.fstat(parent_descriptor)
            if (
                not stat.S_ISDIR(opened_parent.st_mode)
                or opened_parent.st_uid != os.geteuid()
                or opened_parent.st_mode & 0o022
                or (opened_parent.st_dev, opened_parent.st_ino)
                != (parent_info.st_dev, parent_info.st_ino)
            ):
                raise SetupManifestError(
                    "setup snapshot directory binding is ambiguous"
                )
            if stat.S_IMODE(opened_parent.st_mode) != 0o700:
                os.fchmod(parent_descriptor, 0o700)
            tightened = os.fstat(parent_descriptor)
            named_tightened = parent.lstat()
            if (
                not stat.S_ISDIR(tightened.st_mode)
                or tightened.st_uid != os.geteuid()
                or stat.S_IMODE(tightened.st_mode) != 0o700
                or (tightened.st_dev, tightened.st_ino)
                != (parent_info.st_dev, parent_info.st_ino)
                or (named_tightened.st_dev, named_tightened.st_ino)
                != (tightened.st_dev, tightened.st_ino)
                or stat.S_IMODE(named_tightened.st_mode) != 0o700
            ):
                raise SetupManifestError(
                    "instance directory mode-0700 reconciliation was ambiguous"
                )
            descriptor = os.open(
                destination.name,
                snapshot_flags,
                0o600,
                dir_fd=parent_descriptor,
            )
            created = True
            try:
                primary_error: BaseException | None = None
                try:
                    try:
                        view = memoryview(raw)
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                raise SetupManifestError(
                                    "setup manifest snapshot write did not complete"
                                )
                            view = view[written:]
                        os.fsync(descriptor)
                        os.fchmod(descriptor, 0o400)
                        info = os.fstat(descriptor)
                        if (
                            not stat.S_ISREG(info.st_mode)
                            or info.st_uid != os.geteuid()
                            or info.st_nlink != 1
                            or stat.S_IMODE(info.st_mode) != 0o400
                            or info.st_size != len(raw)
                        ):
                            raise SetupManifestError(
                                "setup manifest snapshot metadata is unsafe"
                            )
                    except OSError as exc:
                        raise SetupManifestError(
                            "setup manifest snapshot write failed"
                        ) from exc
                except BaseException as exc:
                    primary_error = exc
                    raise
                finally:
                    try:
                        os.close(descriptor)
                    except OSError as exc:
                        if primary_error is None:
                            raise SetupManifestError(
                                "setup manifest snapshot descriptor close failed"
                            ) from exc
                named_snapshot = os.stat(
                    destination.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (
                    named_snapshot.st_dev != info.st_dev
                    or named_snapshot.st_ino != info.st_ino
                    or stat.S_IMODE(named_snapshot.st_mode) != 0o400
                ):
                    raise SetupManifestError(
                        "setup manifest snapshot name is ambiguous"
                    )
            except OSError as exc:
                raise SetupManifestError(
                    "setup manifest snapshot validation failed"
                ) from exc
            parent_after = os.fstat(parent_descriptor)
            named_parent_after = parent.lstat()
            if (
                (parent_after.st_dev, parent_after.st_ino)
                != (tightened.st_dev, tightened.st_ino)
                or (named_parent_after.st_dev, named_parent_after.st_ino)
                != (tightened.st_dev, tightened.st_ino)
                or stat.S_IMODE(parent_after.st_mode) != 0o700
                or stat.S_IMODE(named_parent_after.st_mode) != 0o700
            ):
                raise SetupManifestError(
                    "setup snapshot directory changed during staging"
                )
        except OSError as exc:
            raise SetupManifestError(
                "setup manifest snapshot staging failed"
            ) from exc
    except BaseException as exc:
        operation_error = exc

    if operation_error is not None:
        cleanup_error: OSError | None = None
        if created:
            try:
                os.unlink(destination.name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
            except OSError as exc:
                cleanup_error = exc
        try:
            os.close(parent_descriptor)
        except OSError:
            pass
        if cleanup_error is not None:
            raise SetupManifestError(
                f"{operation_error}; partial snapshot cleanup failed"
            ) from operation_error
        raise operation_error

    try:
        os.close(parent_descriptor)
    except OSError as exc:
        try:
            os.unlink(destination.name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        except OSError as cleanup_exc:
            raise SetupManifestError(
                "setup snapshot directory descriptor close failed; "
                "partial snapshot cleanup failed"
            ) from cleanup_exc
        raise SetupManifestError(
            "setup snapshot directory descriptor close failed"
        ) from exc


def _adjacent_snapshot(source: Path) -> Path:
    for _ in range(32):
        candidate = source.parent / (
            f".{source.name}.john-lomein-setup-"
            f"{secrets.token_hex(12)}.yaml"
        )
        if not candidate.exists() and not candidate.is_symlink():
            return candidate
    raise SetupManifestError("setup manifest snapshot name is unavailable")


def stage(
    argument: str | Path,
    destination: str | Path | None = None,
) -> dict[str, str]:
    source = _manifest_path(argument)
    raw = _stable_mode_600(source)
    snapshot = (
        _adjacent_snapshot(source)
        if destination is None
        else Path(os.path.abspath(Path(destination).expanduser()))
    )
    _write_snapshot(snapshot, raw)
    return {
        "JOHN_LOMEIN_SETUP_MANIFEST_SOURCE": str(source),
        "JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT": str(snapshot),
        "JOHN_LOMEIN_SETUP_MANIFEST_SHA256": hashlib.sha256(raw).hexdigest(),
    }


def verify(source: str | Path, expected_sha256: str) -> None:
    if (
        len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise SetupManifestError("setup manifest digest is invalid")
    bound_source = Path(os.path.abspath(Path(source).expanduser()))
    if bound_source.name not in {"instance.yaml", "bot.yaml"}:
        raise SetupManifestError("setup manifest source binding is invalid")
    raw = _stable_mode_600(bound_source)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise SetupManifestError(
            "instance manifest changed during setup transaction"
        )


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if len(args) in {2, 3} and args[0] == "stage":
            binding = stage(
                args[1],
                args[2] if len(args) == 3 else None,
            )
            for key, value in binding.items():
                print(f"{key}={shlex.quote(value)}")
            return 0
        if len(args) == 3 and args[0] == "verify":
            verify(args[1], args[2])
            return 0
    except SetupManifestError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(
        "usage: john-lomein-stage-manifest.py "
        "stage INSTANCE [SNAPSHOT] | verify MANIFEST SHA256",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
