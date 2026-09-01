#!/usr/bin/env python3
"""Build one dormant macOS capture-role native-bundle engineering specimen.

This is a local packaging tool, not an installer or a provenance authority.
It copies an operator-supplied CPython runtime and the exact standard-library
capture-child closure, builds the v3 complete-inventory manifest, and proves
that the relocated interpreter can import that closure under ``-I -S -B``.

The emitted manifest is external to the measured bundle so it cannot create a
self-referential inventory.  The machine-readable stdout record is explicitly
an engineering build report.  It is not an activation receipt, does not make
an upstream-origin claim, and cannot enable the protected production route.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


PRODUCT_ROOT = Path(__file__).resolve().parents[1]
if str(PRODUCT_ROOT) not in sys.path:
    sys.path.insert(0, str(PRODUCT_ROOT))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_native_bundle as native_bundle,
)


BUILD_REPORT_SCHEMA = (
    "john-lomein.persona-qualification-capture-native-bundle-build-report.v1"
)
ARTIFACT_CLASS = "local-engineering-specimen"
SOURCE_ACQUISITION = "operator-supplied-local-runtime"
UPSTREAM_PROVENANCE = "not-attested-or-claimed"
PRODUCTION_ACTIVATION = False
ACTIVATION_RECEIPT_ISSUED = False

CAPTURE_PACKAGE = "qualification_attestor"
CAPTURE_MODULE_FILES = (
    "__init__.py",
    "john_lomein_persona_qualification_capture_child.py",
    "john_lomein_persona_qualification_capture_plan.py",
    "john_lomein_persona_qualification_capture_protocol.py",
    "john_lomein_persona_qualification_opaque_capture.py",
)
CAPTURE_IMPORTS = (
    "qualification_attestor.john_lomein_persona_qualification_capture_plan",
    "qualification_attestor.john_lomein_persona_qualification_capture_protocol",
    "qualification_attestor.john_lomein_persona_qualification_opaque_capture",
    "qualification_attestor.john_lomein_persona_qualification_capture_child",
)
CAPTURE_ENTRYPOINT = (
    "app/qualification_attestor/"
    "john_lomein_persona_qualification_capture_child.py"
)

ALLOWED_PLATFORM_XATTRS = frozenset(
    {
        "com.apple.provenance",
        "com.apple.rootless",
    }
)
SITE_ROOT_NAMES = frozenset({"site-packages", "dist-packages"})
CACHE_DIRECTORY_NAMES = frozenset(
    {
        "__pycache__",
        ".cache",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
    }
)
FORBIDDEN_METADATA_NAMES = frozenset(
    {
        ".DS_Store",
        ".git",
        ".hg",
        ".svn",
    }
)
MAX_SOURCE_FILE_BYTES = native_bundle.MAX_FILE_BYTES
MAX_NATIVE_CLOSURE_ADDITIONS = 64


class CaptureBundleBuildError(RuntimeError):
    """Stable build rejection with no evidence-controlled exception text."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _error(code: str) -> CaptureBundleBuildError:
    return CaptureBundleBuildError(code)


@dataclass(frozen=True)
class RuntimeProbe:
    executable: Path
    runtime_root: Path
    stdlib: Path
    libpython: Path
    libpython_name: str
    implementation: str
    version: str
    abi_tag: str
    architecture: str


@dataclass(frozen=True)
class CaptureBundleBuildResult:
    bundle_root: Path
    manifest_path: Path
    manifest: Mapping[str, Any]
    report: Mapping[str, Any]


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise _error("capture_bundle_build_json_invalid") from exc


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _stable_stat(info: os.stat_result) -> tuple[int, ...]:
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


def _directory_open_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("capture_bundle_build_nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _file_open_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("capture_bundle_build_nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _validated_name(name: Any) -> str:
    if (
        not isinstance(name, str)
        or not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or "\x00" in name
        or len(os.fsencode(name)) > 255
        or unicodedata.normalize("NFC", name) != name
    ):
        raise _error("capture_bundle_build_source_name_invalid")
    return name


def _safe_environment() -> dict[str, str]:
    return {
        "HOME": "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": "/private/tmp",
        "TZ": "UTC",
    }


def _run_checked(
    command: Sequence[str],
    *,
    code: str,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            list(command),
            check=False,
            capture_output=True,
            env=dict(environment) if environment is not None else _safe_environment(),
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise _error(code) from exc
    if completed.returncode != 0:
        raise _error(code)
    return completed


def _parse_one_canonical_json_line(raw: str, *, code: str) -> dict[str, Any]:
    if not raw.endswith("\n") or raw.count("\n") != 1:
        raise _error(code)
    encoded = raw[:-1].encode("utf-8", "strict")
    try:
        value = json.loads(encoded)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _error(code) from exc
    if not isinstance(value, dict) or _canonical_json_bytes(value) != encoded:
        raise _error(code)
    return value


def _real_regular_file(
    value: Path | str,
    *,
    code: str,
) -> Path:
    supplied = Path(value)
    if not supplied.is_absolute():
        raise _error(f"{code}_not_absolute")
    try:
        result = supplied.resolve(strict=True)
        info = result.lstat()
    except OSError as exc:
        raise _error(f"{code}_unreadable") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size < 1
        or info.st_size > MAX_SOURCE_FILE_BYTES
    ):
        raise _error(f"{code}_unsafe")
    return result


def _real_directory(value: Path | str, *, code: str) -> Path:
    supplied = Path(value)
    if not supplied.is_absolute():
        raise _error(f"{code}_not_absolute")
    try:
        result = supplied.resolve(strict=True)
        info = result.lstat()
    except OSError as exc:
        raise _error(f"{code}_unreadable") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise _error(f"{code}_unsafe")
    return result


_RUNTIME_PROBE = r"""
import json
import os
import platform
import sys
import sysconfig

value = {
    "abi_tag": "cp%d%d" % (sys.version_info.major, sys.version_info.minor),
    "architecture": platform.machine().lower(),
    "base_executable": os.path.realpath(sys._base_executable),
    "base_prefix": os.path.realpath(sys.base_prefix),
    "executable": os.path.realpath(sys.executable),
    "implementation": sys.implementation.name,
    "ldlibrary": sysconfig.get_config_var("LDLIBRARY"),
    "libdir": os.path.realpath(sysconfig.get_config_var("LIBDIR")),
    "pythonframework": sysconfig.get_config_var("PYTHONFRAMEWORK"),
    "stdlib": os.path.realpath(sysconfig.get_path("stdlib")),
    "system": platform.system().lower(),
    "version": "%d.%d.%d" % sys.version_info[:3],
}
print(json.dumps(value, allow_nan=False, ensure_ascii=False,
                 separators=(",", ":"), sort_keys=True))
"""


def _runtime_library_from_probe(
    value: Mapping[str, Any],
    *,
    runtime_root: Path,
    major: str,
    minor: str,
) -> tuple[Path, str]:
    ldlibrary = value.get("ldlibrary")
    libdir = value.get("libdir")
    framework = value.get("pythonframework")
    if (
        isinstance(ldlibrary, str)
        and "/" not in ldlibrary
        and "\\" not in ldlibrary
        and ldlibrary.startswith("libpython")
        and ldlibrary.endswith(".dylib")
        and libdir == str(runtime_root / "lib")
        and framework in {"", None}
    ):
        return runtime_root / "lib" / ldlibrary, ldlibrary
    framework_names = {"Python", "Python3"}
    framework_library_name = (
        ldlibrary == framework
        or (
            isinstance(ldlibrary, str)
            and "/" not in ldlibrary
            and "\\" not in ldlibrary
            and ldlibrary.startswith("libpython")
            and ldlibrary.endswith(".dylib")
        )
    )
    if (
        framework in framework_names
        and framework_library_name
    ):
        return (
            runtime_root / framework,
            f"libpython{major}.{minor}.dylib",
        )
    raise _error("capture_bundle_build_libpython_layout_invalid")


def probe_runtime(trusted_python: Path | str) -> RuntimeProbe:
    """Resolve and interrogate one operator-designated real CPython."""

    if sys.platform != "darwin":
        raise _error("capture_bundle_build_platform_unsupported")
    executable = _real_regular_file(
        trusted_python,
        code="capture_bundle_build_python",
    )
    completed = _run_checked(
        [
            str(executable),
            "-I",
            "-S",
            "-B",
            "-c",
            _RUNTIME_PROBE,
        ],
        code="capture_bundle_build_python_probe_failed",
    )
    value = _parse_one_canonical_json_line(
        completed.stdout,
        code="capture_bundle_build_python_probe_invalid",
    )
    expected_fields = {
        "abi_tag",
        "architecture",
        "base_executable",
        "base_prefix",
        "executable",
        "implementation",
        "ldlibrary",
        "libdir",
        "pythonframework",
        "stdlib",
        "system",
        "version",
    }
    if set(value) != expected_fields:
        raise _error("capture_bundle_build_python_probe_fields_invalid")
    architecture = {
        "aarch64": "arm64",
        "amd64": "x86_64",
    }.get(value.get("architecture"), value.get("architecture"))
    if (
        value.get("system") != "darwin"
        or value.get("implementation") != "cpython"
        or architecture not in native_bundle.ARCHITECTURES
        or value.get("executable") != str(executable)
        or value.get("base_executable") != str(executable)
        or not isinstance(value.get("version"), str)
        or not native_bundle.PYTHON_VERSION_RE.fullmatch(value["version"])
        or not isinstance(value.get("abi_tag"), str)
        or not native_bundle.ABI_TAG_RE.fullmatch(value["abi_tag"])
    ):
        raise _error("capture_bundle_build_python_probe_policy_mismatch")
    major, minor, _micro = value["version"].split(".")
    if value["abi_tag"] != f"cp{major}{minor}":
        raise _error("capture_bundle_build_python_probe_abi_mismatch")

    runtime_root = Path(value["base_prefix"])
    expected_root = executable.parent.parent
    if runtime_root != expected_root or runtime_root.resolve() != runtime_root:
        raise _error("capture_bundle_build_python_layout_invalid")
    stdlib = _real_directory(
        Path(value["stdlib"]),
        code="capture_bundle_build_stdlib",
    )
    expected_stdlib = runtime_root / "lib" / f"python{major}.{minor}"
    if stdlib != expected_stdlib:
        raise _error("capture_bundle_build_stdlib_layout_invalid")
    libpython_path, libpython_name = _runtime_library_from_probe(
        value,
        runtime_root=runtime_root,
        major=major,
        minor=minor,
    )
    libpython = _real_regular_file(
        libpython_path,
        code="capture_bundle_build_libpython",
    )
    return RuntimeProbe(
        executable=executable,
        runtime_root=runtime_root,
        stdlib=stdlib,
        libpython=libpython,
        libpython_name=libpython_name,
        implementation="cpython",
        version=value["version"],
        abi_tag=value["abi_tag"],
        architecture=architecture,
    )


def _open_source_regular(path: Path, *, code: str) -> tuple[int, os.stat_result]:
    try:
        named = path.lstat()
    except OSError as exc:
        raise _error(f"{code}_unreadable") from exc
    if (
        not stat.S_ISREG(named.st_mode)
        or named.st_nlink != 1
        or named.st_size < 0
        or named.st_size > MAX_SOURCE_FILE_BYTES
    ):
        raise _error(f"{code}_unsafe")
    try:
        descriptor = os.open(path, _file_open_flags())
    except OSError as exc:
        raise _error(f"{code}_unreadable") from exc
    opened = os.fstat(descriptor)
    if _stable_stat(named) != _stable_stat(opened):
        os.close(descriptor)
        raise _error(f"{code}_replaced")
    return descriptor, opened


def _copy_open_regular(
    source_fd: int,
    source_info: os.stat_result,
    destination: Path,
    *,
    code: str,
) -> str:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        destination_fd = os.open(destination, flags, 0o600)
    except OSError as exc:
        raise _error(f"{code}_destination_unwritable") from exc
    digest = hashlib.sha256()
    observed = 0
    try:
        os.lseek(source_fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(source_fd, 128 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            if observed > MAX_SOURCE_FILE_BYTES:
                raise _error(f"{code}_too_large")
            digest.update(chunk)
            offset = 0
            while offset < len(chunk):
                written = os.write(destination_fd, chunk[offset:])
                if written <= 0:
                    raise _error(f"{code}_destination_write_failed")
                offset += written
        os.fsync(destination_fd)
    except OSError as exc:
        raise _error(f"{code}_copy_failed") from exc
    finally:
        os.close(destination_fd)
    after = os.fstat(source_fd)
    if (
        observed != source_info.st_size
        or _stable_stat(after) != _stable_stat(source_info)
    ):
        raise _error(f"{code}_changed_during_copy")
    return digest.hexdigest()


def _copy_regular_file(source: Path, destination: Path, *, code: str) -> str:
    descriptor, info = _open_source_regular(source, code=code)
    try:
        return _copy_open_regular(
            descriptor,
            info,
            destination,
            code=code,
        )
    finally:
        os.close(descriptor)


def _copy_stdlib_tree(source: Path, destination: Path) -> None:
    """Copy the complete non-site stdlib while excluding generated bytecode.

    A canonical top-level site/dist-packages tree is outside the requested
    runtime and is omitted wholesale.  Any nested package root is ambiguous
    and rejected.  ``__pycache__`` directories are generated runtime state and
    are omitted; other cache roots and loose bytecode are rejected.
    """

    try:
        source_fd = os.open(source, _directory_open_flags())
    except OSError as exc:
        raise _error("capture_bundle_build_stdlib_unreadable") from exc
    destination.mkdir(mode=0o700)

    def walk(
        descriptor: int,
        destination_directory: Path,
        *,
        depth: int,
    ) -> None:
        before = os.fstat(descriptor)
        if not stat.S_ISDIR(before.st_mode):
            raise _error("capture_bundle_build_stdlib_directory_unsafe")
        try:
            raw_names = os.listdir(descriptor)
        except OSError as exc:
            raise _error("capture_bundle_build_stdlib_unreadable") from exc
        names = [_validated_name(name) for name in raw_names]
        if len({name.casefold() for name in names}) != len(names):
            raise _error("capture_bundle_build_stdlib_case_collision")
        for name in sorted(names):
            folded = name.casefold()
            try:
                named = os.stat(
                    name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise _error("capture_bundle_build_stdlib_entry_unreadable") from exc
            if stat.S_ISLNK(named.st_mode):
                raise _error("capture_bundle_build_stdlib_symlink_forbidden")
            if name in FORBIDDEN_METADATA_NAMES:
                raise _error("capture_bundle_build_stdlib_metadata_forbidden")
            if stat.S_ISDIR(named.st_mode):
                if folded in SITE_ROOT_NAMES:
                    if depth == 0:
                        continue
                    raise _error(
                        "capture_bundle_build_stdlib_nested_site_root_forbidden"
                    )
                if folded == "__pycache__":
                    continue
                if folded in CACHE_DIRECTORY_NAMES:
                    raise _error("capture_bundle_build_stdlib_cache_forbidden")
                try:
                    child_fd = os.open(
                        name,
                        _directory_open_flags(),
                        dir_fd=descriptor,
                    )
                except OSError as exc:
                    raise _error(
                        "capture_bundle_build_stdlib_directory_unreadable"
                    ) from exc
                try:
                    if _stable_stat(named) != _stable_stat(os.fstat(child_fd)):
                        raise _error(
                            "capture_bundle_build_stdlib_entry_replaced"
                        )
                    child_destination = destination_directory / name
                    child_destination.mkdir(mode=0o700)
                    walk(
                        child_fd,
                        child_destination,
                        depth=depth + 1,
                    )
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(named.st_mode):
                raise _error("capture_bundle_build_stdlib_special_forbidden")
            if folded.endswith((".pyc", ".pyo")):
                raise _error("capture_bundle_build_stdlib_bytecode_forbidden")
            if named.st_nlink != 1:
                raise _error("capture_bundle_build_stdlib_hardlink_forbidden")
            try:
                child_fd = os.open(
                    name,
                    _file_open_flags(),
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise _error(
                    "capture_bundle_build_stdlib_file_unreadable"
                ) from exc
            try:
                opened = os.fstat(child_fd)
                if _stable_stat(named) != _stable_stat(opened):
                    raise _error("capture_bundle_build_stdlib_entry_replaced")
                _copy_open_regular(
                    child_fd,
                    opened,
                    destination_directory / name,
                    code="capture_bundle_build_stdlib_file",
                )
            finally:
                os.close(child_fd)
        if _stable_stat(before) != _stable_stat(os.fstat(descriptor)):
            raise _error("capture_bundle_build_stdlib_changed_during_copy")

    try:
        walk(source_fd, destination, depth=0)
    finally:
        os.close(source_fd)


def _copy_capture_package(product_root: Path, destination_app: Path) -> None:
    source_package = product_root / CAPTURE_PACKAGE
    try:
        source_info = source_package.lstat()
    except OSError as exc:
        raise _error("capture_bundle_build_product_package_unreadable") from exc
    if not stat.S_ISDIR(source_info.st_mode) or source_package.is_symlink():
        raise _error("capture_bundle_build_product_package_unsafe")
    destination_app.mkdir(mode=0o700)
    destination_package = destination_app / CAPTURE_PACKAGE
    destination_package.mkdir(mode=0o700)
    for name in CAPTURE_MODULE_FILES:
        _copy_regular_file(
            source_package / name,
            destination_package / name,
            code="capture_bundle_build_product_module",
        )
    if sorted(path.name for path in destination_package.iterdir()) != sorted(
        CAPTURE_MODULE_FILES
    ):
        raise _error("capture_bundle_build_product_closure_mismatch")


def _read_macho(path: Path, *, relative: str) -> dict[str, Any] | None:
    descriptor, info = _open_source_regular(
        path,
        code="capture_bundle_build_macho",
    )
    try:
        prefix = bytearray()
        remaining = native_bundle.MAX_LOAD_COMMAND_BYTES + 32
        while remaining:
            chunk = os.read(descriptor, min(128 * 1024, remaining))
            if not chunk:
                break
            prefix.extend(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if _stable_stat(info) != _stable_stat(after):
            raise _error("capture_bundle_build_macho_changed_during_read")
    finally:
        os.close(descriptor)
    if bytes(prefix[:4]) not in native_bundle.MACHO_MAGICS:
        return None
    try:
        return native_bundle._inspect_macho(  # noqa: SLF001
            bytes(prefix),
            path=relative,
            sha256=_sha256_file(path),
        )
    except native_bundle.NativeBundleError as exc:
        raise _error(exc.code) from exc


def _sha256_file(path: Path) -> str:
    descriptor, info = _open_source_regular(
        path,
        code="capture_bundle_build_digest",
    )
    digest = hashlib.sha256()
    observed = 0
    try:
        while True:
            chunk = os.read(descriptor, 128 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            observed += len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if observed != info.st_size or _stable_stat(info) != _stable_stat(after):
        raise _error("capture_bundle_build_digest_source_changed")
    return digest.hexdigest()


def _iter_regular_output_files(bundle_root: Path) -> list[tuple[str, Path]]:
    result: list[tuple[str, Path]] = []
    for directory, directories, files in os.walk(
        bundle_root,
        topdown=True,
        followlinks=False,
    ):
        root = Path(directory)
        for name in directories:
            path = root / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise _error("capture_bundle_build_output_unsafe")
        for name in files:
            path = root / name
            info = path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_nlink != 1
            ):
                raise _error("capture_bundle_build_output_unsafe")
            result.append((path.relative_to(bundle_root).as_posix(), path))
    return sorted(result)


def _all_macho_objects(bundle_root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for relative, path in _iter_regular_output_files(bundle_root):
        parsed = _read_macho(path, relative=relative)
        if parsed is not None:
            result[relative] = parsed
    return dict(sorted(result.items()))


def _dependency_candidates(
    install_name: str,
    *,
    source: Mapping[str, Any],
    executable_path: str,
) -> list[str]:
    if install_name.startswith("/"):
        return []
    try:
        if install_name == "@rpath" or install_name.startswith("@rpath/"):
            suffix = install_name[len("@rpath") :].lstrip("/")
            result = []
            for rpath in source["rpaths"]:
                base = native_bundle._resolve_base_expression(  # noqa: SLF001
                    rpath,
                    source_path=source["path"],
                    executable_path=executable_path,
                )
                result.append(
                    native_bundle._relative_path(  # noqa: SLF001
                        os.path.normpath(f"{base}/{suffix}"),
                        field="capture_bundle_build_dependency",
                    )
                )
            return sorted(set(result))
        if install_name.startswith(("@loader_path", "@executable_path")):
            return [
                native_bundle._resolve_base_expression(  # noqa: SLF001
                    install_name,
                    source_path=source["path"],
                    executable_path=executable_path,
                )
            ]
    except native_bundle.NativeBundleError as exc:
        raise _error(exc.code) from exc
    raise _error("capture_bundle_build_macho_install_name_unsupported")


def _copy_colocated_native_dependencies(
    *,
    bundle_root: Path,
    probe: RuntimeProbe,
    executable_relative: str,
) -> tuple[list[str], list[dict[str, Any]]]:
    """Close missing @rpath dependencies only from the probed runtime's lib."""

    transformations: list[dict[str, Any]] = []
    additions = 0
    while True:
        objects = _all_macho_objects(bundle_root)
        object_paths = set(objects)
        missing: dict[str, Path] = {}
        for parsed in objects.values():
            source = parsed["object"]
            for dependency in parsed["raw_dependencies"]:
                install_name = dependency["install_name"]
                if install_name.startswith("/"):
                    if not (
                        install_name.startswith("/usr/lib/")
                        or install_name.startswith("/System/Library/")
                    ):
                        raise _error(
                            "capture_bundle_build_external_native_dependency"
                        )
                    continue
                candidates = _dependency_candidates(
                    install_name,
                    source=source,
                    executable_path=executable_relative,
                )
                present = [path for path in candidates if path in object_paths]
                if len(present) == 1:
                    continue
                if len(present) > 1:
                    raise _error(
                        "capture_bundle_build_native_dependency_ambiguous"
                    )
                source_candidates: list[tuple[str, Path]] = []
                for candidate in candidates:
                    relative = PurePosixPath(candidate)
                    if relative.parent != PurePosixPath("python/lib"):
                        continue
                    source_path = probe.runtime_root / Path(
                        *relative.parts[1:]
                    )
                    try:
                        info = source_path.lstat()
                    except OSError:
                        continue
                    if (
                        stat.S_ISREG(info.st_mode)
                        and not stat.S_ISLNK(info.st_mode)
                    ):
                        source_candidates.append((candidate, source_path))
                if len(source_candidates) != 1:
                    raise _error(
                        "capture_bundle_build_native_dependency_missing"
                    )
                target_relative, source_path = source_candidates[0]
                previous = missing.get(target_relative)
                if previous is not None and previous != source_path:
                    raise _error(
                        "capture_bundle_build_native_dependency_ambiguous"
                    )
                missing[target_relative] = source_path
        if not missing:
            break
        for relative, source in sorted(missing.items()):
            additions += 1
            if additions > MAX_NATIVE_CLOSURE_ADDITIONS:
                raise _error(
                    "capture_bundle_build_native_dependency_limit_exceeded"
                )
            destination = bundle_root / Path(*PurePosixPath(relative).parts)
            _copy_regular_file(
                source,
                destination,
                code="capture_bundle_build_native_dependency",
            )
            transformations.append(
                {
                    "operation": "copy-colocated-native-dependency",
                    "path": relative,
                    "source_sha256": _sha256_file(source),
                }
            )
    return sorted(object_paths), transformations


def _normalize_libpython_id(
    destination: Path,
    *,
    relative: str,
) -> list[dict[str, Any]]:
    parsed = _read_macho(destination, relative=relative)
    if parsed is None or parsed["object"]["file_type"] != "dylib":
        raise _error("capture_bundle_build_libpython_not_dylib")
    expected = f"@rpath/{destination.name}"
    observed = parsed["object"]["install_name"]
    if observed == expected:
        return []
    _run_checked(
        ["/usr/bin/install_name_tool", "-id", expected, str(destination)],
        code="capture_bundle_build_install_name_rewrite_failed",
    )
    _run_checked(
        [
            "/usr/bin/codesign",
            "--force",
            "--sign",
            "-",
            "--timestamp=none",
            str(destination),
        ],
        code="capture_bundle_build_adhoc_sign_failed",
    )
    _run_checked(
        ["/usr/bin/codesign", "--verify", "--strict", str(destination)],
        code="capture_bundle_build_adhoc_signature_invalid",
    )
    reparsed = _read_macho(destination, relative=relative)
    if reparsed is None or reparsed["object"]["install_name"] != expected:
        raise _error("capture_bundle_build_install_name_rewrite_unproven")
    return [
        {
            "codesign_observation": "adhoc-signature-verified-after-change",
            "new_install_name": expected,
            "old_install_name": observed,
            "operation": "rewrite-libpython-lc-id-and-adhoc-sign",
            "path": relative,
        }
    ]


def _strip_nonplatform_xattrs(path: Path) -> None:
    flags = (
        _directory_open_flags()
        if stat.S_ISDIR(path.lstat().st_mode)
        else _file_open_flags()
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _error("capture_bundle_build_metadata_unreadable") from exc
    libc = ctypes.CDLL(None, use_errno=True)
    if not hasattr(libc, "flistxattr") or not hasattr(
        libc,
        "fremovexattr",
    ):
        os.close(descriptor)
        raise _error("capture_bundle_build_metadata_api_unsupported")
    libc.flistxattr.argtypes = [
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_int,
    ]
    libc.flistxattr.restype = ctypes.c_ssize_t
    libc.fremovexattr.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    libc.fremovexattr.restype = ctypes.c_int
    try:
        size = libc.flistxattr(descriptor, None, 0, 0)
        if size < 0:
            raise _error("capture_bundle_build_metadata_unreadable")
        attributes: set[bytes] = set()
        if size:
            buffer = ctypes.create_string_buffer(size)
            observed = libc.flistxattr(
                descriptor,
                buffer,
                size,
                0,
            )
            if observed != size:
                raise _error("capture_bundle_build_metadata_changed")
            attributes = {
                item
                for item in bytes(buffer.raw[:observed]).split(b"\x00")
                if item
            }
        for attribute in attributes:
            try:
                decoded = attribute.decode("utf-8", "strict")
            except UnicodeError as exc:
                raise _error(
                    "capture_bundle_build_metadata_name_invalid"
                ) from exc
            if decoded in ALLOWED_PLATFORM_XATTRS:
                continue
            if libc.fremovexattr(descriptor, attribute, 0) != 0:
                raise _error("capture_bundle_build_metadata_strip_failed")
    finally:
        os.close(descriptor)


def _strip_tree_metadata(bundle_root: Path, paths: Sequence[Path]) -> None:
    if sys.platform == "darwin":
        # One recursive invocation removes inherited extended ACLs without
        # spawning thousands of per-file processes.
        _run_checked(
            ["/bin/chmod", "-RN", str(bundle_root)],
            code="capture_bundle_build_acl_strip_failed",
        )
    for path in paths:
        _strip_nonplatform_xattrs(path)


def _strip_external_metadata(path: Path) -> None:
    if sys.platform == "darwin":
        _run_checked(
            ["/bin/chmod", "-N", str(path)],
            code="capture_bundle_build_acl_strip_failed",
        )
    _strip_nonplatform_xattrs(path)


def _seal_bundle(bundle_root: Path, *, executable_relative: str) -> None:
    paths: list[Path] = [bundle_root]
    for directory, directories, files in os.walk(
        bundle_root,
        topdown=False,
        followlinks=False,
    ):
        root = Path(directory)
        paths.extend(root / name for name in files)
        paths.extend(root / name for name in directories)
    # Strip inherited ACLs/xattrs before removing write access.
    for path in sorted(set(paths), key=lambda item: len(item.parts), reverse=True):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise _error("capture_bundle_build_output_symlink_forbidden")
    _strip_tree_metadata(
        bundle_root,
        sorted(set(paths), key=lambda item: len(item.parts), reverse=True),
    )
    executable = bundle_root / Path(*PurePosixPath(executable_relative).parts)
    for relative, path in _iter_regular_output_files(bundle_root):
        path.chmod(0o555 if path == executable else 0o444)
    for directory, directories, _files in os.walk(
        bundle_root,
        topdown=False,
        followlinks=False,
    ):
        root = Path(directory)
        for name in directories:
            (root / name).chmod(0o555)
        root.chmod(0o555)


def _path_classes(
    bundle_root: Path,
    *,
    executable_relative: str,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, dict[str, str]],
]:
    root_info = bundle_root.lstat()
    owner_id = "engineering-builder-owner"
    ownership = [
        {
            "gid": int(root_info.st_gid),
            "id": owner_id,
            "uid": int(root_info.st_uid),
        }
    ]
    modes = [
        {
            "id": "directory-readonly",
            "mode": 0o555,
            "object_type": "directory",
        },
        {
            "id": "file-executable",
            "mode": 0o555,
            "object_type": "file",
        },
        {
            "id": "file-readonly",
            "mode": 0o444,
            "object_type": "file",
        },
    ]
    bindings: dict[str, dict[str, str]] = {
        ".": {
            "mode_class": "directory-readonly",
            "ownership_class": owner_id,
        }
    }
    for directory, directories, files in os.walk(
        bundle_root,
        topdown=True,
        followlinks=False,
    ):
        root = Path(directory)
        relative_root = root.relative_to(bundle_root)
        for name in directories:
            relative = (
                relative_root / name
                if relative_root.parts
                else Path(name)
            ).as_posix()
            bindings[relative] = {
                "mode_class": "directory-readonly",
                "ownership_class": owner_id,
            }
        for name in files:
            relative = (
                relative_root / name
                if relative_root.parts
                else Path(name)
            ).as_posix()
            bindings[relative] = {
                "mode_class": (
                    "file-executable"
                    if relative == executable_relative
                    else "file-readonly"
                ),
                "ownership_class": owner_id,
            }
    return ownership, modes, dict(sorted(bindings.items()))


def _runtime_policy(
    *,
    bundle_root: Path,
    probe: RuntimeProbe,
    executable_relative: str,
    stdlib_relative: str,
) -> dict[str, Any]:
    entrypoint = bundle_root / Path(*PurePosixPath(CAPTURE_ENTRYPOINT).parts)
    lib_dynload = f"{stdlib_relative}/lib-dynload"
    sys_path = ["app", stdlib_relative]
    if (bundle_root / Path(*PurePosixPath(lib_dynload).parts)).is_dir():
        sys_path.append(lib_dynload)
    return {
        "abi_tag": probe.abi_tag,
        "entrypoint": {
            "execution": "runpy.run_path",
            "path": CAPTURE_ENTRYPOINT,
            "role": "capture",
            "sha256": _sha256_file(entrypoint),
        },
        "environment": {
            "allowlist": list(native_bundle.REQUIRED_ENVIRONMENT),
            "clear": True,
            "values": dict(sorted(_safe_environment().items())),
        },
        "executable_path": executable_relative,
        "implementation": "cpython",
        "invocation": {
            "bytecode_write": False,
            "executable": "bundle-relative",
            "flags": ["-I", "-S", "-B"],
            "isolated": True,
            "site_import": False,
        },
        "stdlib_paths": [stdlib_relative],
        "sys_path": sys_path,
        "vendor_paths": [],
        "version": probe.version,
    }


def _system_dependency_allowlist(
    bundle_root: Path,
) -> tuple[list[str], list[dict[str, Any]]]:
    objects = _all_macho_objects(bundle_root)
    allowlist: set[str] = set()
    observations: list[dict[str, Any]] = []
    for relative, parsed in objects.items():
        for dependency in parsed["raw_dependencies"]:
            install_name = dependency["install_name"]
            if not install_name.startswith("/"):
                continue
            if not (
                install_name.startswith("/usr/lib/")
                or install_name.startswith("/System/Library/")
            ):
                raise _error(
                    "capture_bundle_build_external_native_dependency"
                )
            allowlist.add(install_name)
        observations.append(
            {
                "architecture": parsed["object"]["architecture"],
                "file_type": parsed["object"]["file_type"],
                "minimum_macos": parsed["object"]["minimum_macos"],
                "path": relative,
                "sha256": parsed["object"]["sha256"],
            }
        )
    return sorted(allowlist), observations


_RELOCATION_CANARY = r"""
import importlib
import json
import os
import sys

bundle = os.path.realpath(sys.argv[1])
runtime = os.path.realpath(os.path.join(bundle, "python"))
app = os.path.realpath(os.path.join(bundle, "app"))
if os.path.realpath(sys.prefix) != runtime:
    raise SystemExit(91)
sys.path.insert(0, app)
expected = json.loads(sys.argv[2])
observed = []
for name in expected:
    module = importlib.import_module(name)
    path = os.path.realpath(module.__file__)
    if os.path.commonpath([path, app]) != app:
        raise SystemExit(92)
    observed.append(name)
for path in sys.path:
    if not path:
        continue
    resolved = os.path.realpath(path)
    if os.path.commonpath([resolved, bundle]) != bundle:
        raise SystemExit(93)
if "site" in sys.modules or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit(94)
value = {
    "bytecode_disabled": True,
    "closure_imported": observed,
    "isolated": True,
    "relocated_prefix": runtime,
    "site_imported": False,
}
print(json.dumps(value, allow_nan=False, ensure_ascii=False,
                 separators=(",", ":"), sort_keys=True))
"""


def _run_relocation_canary(
    *,
    bundle_root: Path,
    executable_relative: str,
) -> dict[str, Any]:
    executable = bundle_root / Path(
        *PurePosixPath(executable_relative).parts
    )
    completed = _run_checked(
        [
            str(executable),
            "-I",
            "-S",
            "-B",
            "-c",
            _RELOCATION_CANARY,
            str(bundle_root),
            _canonical_json_bytes(list(CAPTURE_IMPORTS)).decode("utf-8"),
        ],
        code="capture_bundle_build_relocation_canary_failed",
    )
    value = _parse_one_canonical_json_line(
        completed.stdout,
        code="capture_bundle_build_relocation_canary_invalid",
    )
    expected = {
        "bytecode_disabled": True,
        "closure_imported": list(CAPTURE_IMPORTS),
        "isolated": True,
        "relocated_prefix": str(bundle_root / "python"),
        "site_imported": False,
    }
    if value != expected:
        raise _error("capture_bundle_build_relocation_canary_mismatch")
    return value


def _prepare_empty_destination(destination: Path | str) -> tuple[Path, int]:
    supplied = Path(destination)
    if not supplied.is_absolute():
        raise _error("capture_bundle_build_destination_not_absolute")
    try:
        resolved = supplied.resolve(strict=True)
        info = resolved.lstat()
    except OSError as exc:
        raise _error("capture_bundle_build_destination_unreadable") from exc
    if (
        resolved != supplied
        or not stat.S_ISDIR(info.st_mode)
        or supplied.is_symlink()
    ):
        raise _error("capture_bundle_build_destination_not_canonical")
    try:
        entries = os.listdir(resolved)
    except OSError as exc:
        raise _error("capture_bundle_build_destination_unreadable") from exc
    if entries:
        raise _error("capture_bundle_build_destination_not_empty")
    return resolved, stat.S_IMODE(info.st_mode)


def external_manifest_path(bundle_root: Path) -> Path:
    return bundle_root.with_name(
        f"{bundle_root.name}."
        "engineering-specimen.native-bundle-manifest.v3.json"
    )


def _make_tree_writable(bundle_root: Path) -> None:
    if not bundle_root.exists() or bundle_root.is_symlink():
        return
    for directory, directories, files in os.walk(
        bundle_root,
        topdown=True,
        followlinks=False,
    ):
        root = Path(directory)
        try:
            root.chmod(0o700)
        except OSError:
            pass
        for name in directories:
            path = root / name
            if not path.is_symlink():
                try:
                    path.chmod(0o700)
                except OSError:
                    pass
        for name in files:
            path = root / name
            if not path.is_symlink():
                try:
                    path.chmod(0o600)
                except OSError:
                    pass


def _rollback(
    bundle_root: Path,
    *,
    original_mode: int,
    manifest_path: Path,
) -> None:
    try:
        if manifest_path.exists() and not manifest_path.is_symlink():
            manifest_path.chmod(0o600)
            manifest_path.unlink()
    except OSError:
        pass
    _make_tree_writable(bundle_root)
    try:
        for entry in list(bundle_root.iterdir()):
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry)
            else:
                entry.unlink()
        bundle_root.chmod(original_mode)
    except OSError:
        pass


def _write_external_manifest(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise _error("capture_bundle_build_manifest_destination_unwritable") from exc
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise _error("capture_bundle_build_manifest_write_failed")
            offset += written
        os.fsync(descriptor)
    except OSError as exc:
        raise _error("capture_bundle_build_manifest_write_failed") from exc
    finally:
        os.close(descriptor)
    _strip_external_metadata(path)
    path.chmod(0o444)


def build_capture_native_bundle(
    *,
    trusted_python: Path | str,
    product_root: Path | str,
    empty_output_destination: Path | str,
) -> CaptureBundleBuildResult:
    """Build, measure, verify, and relocate one capture engineering specimen."""

    probe = probe_runtime(trusted_python)
    source_product_root = _real_directory(
        product_root,
        code="capture_bundle_build_product_root",
    )
    bundle_root, original_mode = _prepare_empty_destination(
        empty_output_destination
    )
    manifest_path = external_manifest_path(bundle_root)
    if manifest_path.exists() or manifest_path.is_symlink():
        raise _error("capture_bundle_build_manifest_destination_exists")

    major, minor, _micro = probe.version.split(".")
    executable_relative = "python/bin/python"
    libpython_relative = f"python/lib/{probe.libpython_name}"
    stdlib_relative = f"python/lib/python{major}.{minor}"
    transformations: list[dict[str, Any]] = []
    try:
        (bundle_root / "python" / "bin").mkdir(
            parents=True,
            mode=0o700,
        )
        (bundle_root / "python" / "lib").mkdir(mode=0o700)
        executable_destination = bundle_root / executable_relative
        libpython_destination = bundle_root / libpython_relative
        source_executable_sha256 = _copy_regular_file(
            probe.executable,
            executable_destination,
            code="capture_bundle_build_python_copy",
        )
        source_libpython_sha256 = _copy_regular_file(
            probe.libpython,
            libpython_destination,
            code="capture_bundle_build_libpython_copy",
        )
        _copy_stdlib_tree(
            probe.stdlib,
            bundle_root / stdlib_relative,
        )
        _copy_capture_package(
            source_product_root,
            bundle_root / "app",
        )

        executable_macho = _read_macho(
            executable_destination,
            relative=executable_relative,
        )
        if (
            executable_macho is None
            or executable_macho["object"]["file_type"] != "execute"
            or executable_macho["object"]["architecture"] != probe.architecture
        ):
            raise _error("capture_bundle_build_python_macho_invalid")
        transformations.extend(
            _normalize_libpython_id(
                libpython_destination,
                relative=libpython_relative,
            )
        )
        _objects, additions = _copy_colocated_native_dependencies(
            bundle_root=bundle_root,
            probe=probe,
            executable_relative=executable_relative,
        )
        transformations.extend(additions)

        allowlist, macho_observations = _system_dependency_allowlist(
            bundle_root
        )
        object_minimums = [
            item["minimum_macos"] for item in macho_observations
        ]
        if not object_minimums:
            raise _error("capture_bundle_build_macho_inventory_empty")
        minimum_macos = max(
            object_minimums,
            key=lambda value: tuple(
                int(component) for component in value.split(".")
            ),
        )

        _seal_bundle(
            bundle_root,
            executable_relative=executable_relative,
        )
        ownership, modes, path_classes = _path_classes(
            bundle_root,
            executable_relative=executable_relative,
        )
        runtime = _runtime_policy(
            bundle_root=bundle_root,
            probe=probe,
            executable_relative=executable_relative,
            stdlib_relative=stdlib_relative,
        )
        manifest = native_bundle.build_native_bundle_manifest(
            bundle_root,
            role="capture",
            platform_policy={
                "architecture": probe.architecture,
                "binary_format": "mach-o-64-little-endian",
                "minimum_macos": minimum_macos,
                "system": "darwin",
            },
            ownership_classes=ownership,
            mode_classes=modes,
            path_classes=path_classes,
            python_runtime=runtime,
            wheel_provenance=[],
            system_dependency_allowlist=allowlist,
        )
        manifest_raw = native_bundle.retained_native_bundle_manifest_bytes(
            manifest
        )
        verified_digest = native_bundle.verify_native_bundle(
            bundle_root,
            manifest_raw,
            enforce_host_platform=True,
            enforce_root_control=False,
        )
        relocation = _run_relocation_canary(
            bundle_root=bundle_root,
            executable_relative=executable_relative,
        )
        # The canary uses -B and the sealed tree.  Exact re-verification proves
        # it did not create bytecode or otherwise mutate the specimen.
        if (
            native_bundle.verify_native_bundle(
                bundle_root,
                manifest_raw,
                enforce_host_platform=True,
                enforce_root_control=False,
            )
            != verified_digest
        ):
            raise _error("capture_bundle_build_post_canary_verify_mismatch")
        _write_external_manifest(manifest_path, manifest_raw)
        report = {
            "activation_receipt_issued": False,
            "artifact_class": ARTIFACT_CLASS,
            "bundle_id": manifest["bundle_id"],
            "bundle_root": str(bundle_root),
            "host_observation": {
                "architecture": platform.machine().lower(),
                "macos_version": platform.mac_ver()[0],
                "system": platform.system().lower(),
            },
            "manifest_path": str(manifest_path),
            "manifest_sha256": native_bundle.native_bundle_manifest_sha256(
                manifest
            ),
            "native_objects": macho_observations,
            "production_activation": False,
            "provenance": {
                "source_acquisition": SOURCE_ACQUISITION,
                "source_executable_sha256": source_executable_sha256,
                "source_libpython_sha256": source_libpython_sha256,
                "upstream_provenance": UPSTREAM_PROVENANCE,
            },
            "relocation_canary": relocation,
            "runtime_observation": {
                "abi_tag": probe.abi_tag,
                "architecture": probe.architecture,
                "implementation": probe.implementation,
                "source_executable": str(probe.executable),
                "version": probe.version,
            },
            "schema_version": BUILD_REPORT_SCHEMA,
            "transformations": sorted(
                transformations,
                key=lambda item: (
                    item["path"],
                    item["operation"],
                ),
            ),
            "v3_bundle_verification": "exact-rescan-passed-engineering-owner",
        }
        return CaptureBundleBuildResult(
            bundle_root=bundle_root,
            manifest_path=manifest_path,
            manifest=manifest,
            report=report,
        )
    except BaseException:
        _rollback(
            bundle_root,
            original_mode=original_mode,
            manifest_path=manifest_path,
        )
        raise


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build a non-activating macOS capture native-bundle engineering "
            "specimen from a trusted local CPython."
        )
    )
    parser.add_argument("trusted_python")
    parser.add_argument("product_root")
    parser.add_argument("empty_output_destination")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _argument_parser().parse_args(argv)
    try:
        result = build_capture_native_bundle(
            trusted_python=Path(arguments.trusted_python),
            product_root=Path(arguments.product_root),
            empty_output_destination=Path(
                arguments.empty_output_destination
            ),
        )
    except (CaptureBundleBuildError, native_bundle.NativeBundleError) as exc:
        code = getattr(exc, "code", "capture_bundle_build_failed")
        print(code, file=sys.stderr)
        return 2
    print(_canonical_json_bytes(result.report).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
