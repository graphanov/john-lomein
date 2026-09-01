#!/usr/bin/env python3
"""Dormant v3 native-bundle manifest and verifier contract.

This module proves a deliberately narrow fact: one declared macOS
qualification bundle has the exact root-relative filesystem inventory,
Python launch policy, wheel provenance, and thin 64-bit Mach-O dependency
graph recorded in its canonical manifest.

It is not an installer, activation switch, privileged canary, code-signature
verifier, notarization verifier, or activation-receipt issuer.  The protected
qualification route does not consume this module yet.  Those omissions are
represented explicitly rather than hidden behind a green structural check.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import platform as host_platform
import posixpath
import re
import stat
import struct
import sys
import unicodedata
import urllib.parse
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any


NATIVE_BUNDLE_MANIFEST_SCHEMA = (
    "john-lomein.persona-qualification-native-bundle-manifest.v3"
)
PRODUCTION_ACTIVATION = False
ACTIVATION_RECEIPTS_AVAILABLE = False
ACTIVATION_RECEIPT_SCHEMA = None

MAX_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 200_000
MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024 * 1024
MAX_LOAD_COMMAND_BYTES = 16 * 1024 * 1024
MAX_LOAD_COMMANDS = 4_096
MAX_PATH_BYTES = 4_096
MAX_DEPTH = 128

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TOKEN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
BUNDLE_ID_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?@[0-9a-f]{64}$"
)
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}$")
PYTHON_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
ABI_TAG_RE = re.compile(r"^cp[0-9]{2,3}$")
WHEEL_NAME_RE = re.compile(r"^[A-Za-z0-9_.+-]{1,240}\.whl$")
WHEEL_TAG_RE = re.compile(r"^[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+$")
DISTRIBUTION_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")

ROLES = {
    "capture",
    "coordinator",
    "public-verifier",
    "verifier",
}
ARCHITECTURES = {"arm64", "x86_64"}
OBJECT_TYPES = {"directory", "file"}
MACHO_FILE_TYPES = {
    2: "execute",
    6: "dylib",
    8: "bundle",
}
CPU_TYPES = {
    0x0100000C: "arm64",
    0x01000007: "x86_64",
}

MH_MAGIC_64 = 0xFEEDFACF
LC_REQ_DYLD = 0x80000000
FAT_MAGICS = {
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}
MACHO_MAGICS = FAT_MAGICS | {
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xce",
}

LC_LOAD_DYLIB = 0x0000000C
LC_ID_DYLIB = 0x0000000D
LC_LOAD_DYLINKER = 0x0000000E
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_LAZY_LOAD_DYLIB = 0x00000020
LC_REEXPORT_DYLIB = 0x8000001F
LC_LOAD_UPWARD_DYLIB = 0x80000023
LC_UUID = 0x0000001B
LC_RPATH = 0x8000001C
LC_VERSION_MIN_MACOSX = 0x00000024
LC_DYLD_ENVIRONMENT = 0x00000027
LC_BUILD_VERSION = 0x00000032
LC_DYLD_INFO_ONLY = 0x80000022
LC_MAIN = 0x80000028
LC_DYLD_EXPORTS_TRIE = 0x80000033
LC_DYLD_CHAINED_FIXUPS = 0x80000034

SYSTEM_DYLINKER = "/usr/lib/dyld"

# These commands either select an alternate execution entrypoint/loader,
# introduce legacy dependency lookup semantics, or describe encrypted/fileset
# images outside the standalone qualification-bundle model.
UNSUPPORTED_LOADER_COMMANDS = {
    0x00000004,  # LC_THREAD
    0x00000005,  # LC_UNIXTHREAD
    0x00000006,  # LC_LOADFVMLIB
    0x00000007,  # LC_IDFVMLIB
    0x00000009,  # LC_FVMFILE
    0x0000000F,  # LC_ID_DYLINKER
    0x00000010,  # LC_PREBOUND_DYLIB
    0x00000011,  # LC_ROUTINES
    0x00000012,  # LC_SUB_FRAMEWORK
    0x00000013,  # LC_SUB_UMBRELLA
    0x00000014,  # LC_SUB_CLIENT
    0x00000015,  # LC_SUB_LIBRARY
    0x0000001A,  # LC_ROUTINES_64
    0x00000021,  # LC_ENCRYPTION_INFO
    0x0000002C,  # LC_ENCRYPTION_INFO_64
    0x80000035,  # LC_FILESET_ENTRY
}
KNOWN_REQUIRED_DYLD_COMMANDS = {
    LC_LOAD_WEAK_DYLIB,
    LC_REEXPORT_DYLIB,
    LC_LOAD_UPWARD_DYLIB,
    LC_RPATH,
    LC_DYLD_INFO_ONLY,
    LC_MAIN,
    LC_DYLD_EXPORTS_TRIE,
    LC_DYLD_CHAINED_FIXUPS,
}

DYLIB_COMMAND_NAMES = {
    LC_LOAD_DYLIB: "LC_LOAD_DYLIB",
    LC_LOAD_WEAK_DYLIB: "LC_LOAD_WEAK_DYLIB",
    LC_LAZY_LOAD_DYLIB: "LC_LAZY_LOAD_DYLIB",
    LC_REEXPORT_DYLIB: "LC_REEXPORT_DYLIB",
    LC_LOAD_UPWARD_DYLIB: "LC_LOAD_UPWARD_DYLIB",
}

REQUIRED_ENVIRONMENT = (
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "TMPDIR",
    "TZ",
)

FILESYSTEM_POLICY = {
    "acl": "forbidden",
    "bytecode": "forbidden-pyc-and-pyo",
    "cache_directories": "forbidden-__pycache__",
    "extended_attributes": "forbidden-except-macos-platform-security-labels",
    "hardlinks": "forbidden",
    "inspection": "descriptor-relative-no-follow",
    "inventory": "complete-root-relative-files-and-directories",
    "path_encoding": "utf-8-nfc-casefold-unique",
    "platform_xattr_allowlist": [
        "com.apple.provenance",
        "com.apple.rootless",
    ],
    "special_files": "forbidden",
    "symlinks": "forbidden",
    "unexpected_entries": "forbidden",
}

ACTIVATION_STATE = {
    "activation_receipt_schema": None,
    "activation_receipts_available": False,
    "native_closure_status": "unproven-for-live-installation",
    "privileged_canaries": "unproven",
    "production_activation": False,
}

MANIFEST_FIELDS = {
    "schema_version",
    "bundle_id",
    "role",
    "platform",
    "filesystem_policy",
    "ownership_classes",
    "mode_classes",
    "python_runtime",
    "wheel_provenance",
    "macho",
    "inventory",
    "activation",
    "digests",
}
PLATFORM_FIELDS = {
    "system",
    "architecture",
    "binary_format",
    "minimum_macos",
}
OWNERSHIP_FIELDS = {"id", "uid", "gid"}
MODE_FIELDS = {"id", "object_type", "mode"}
CLASS_BINDING_FIELDS = {"ownership_class", "mode_class"}
DIRECTORY_FIELDS = {
    "path",
    "mode",
    "uid",
    "gid",
    "ownership_class",
    "mode_class",
}
FILE_FIELDS = DIRECTORY_FIELDS | {
    "size",
    "sha256",
    "content_type",
}
INVENTORY_FIELDS = {
    "directories",
    "files",
    "directory_count",
    "file_count",
    "total_bytes",
}
RUNTIME_FIELDS = {
    "implementation",
    "version",
    "abi_tag",
    "executable_path",
    "stdlib_paths",
    "vendor_paths",
    "sys_path",
    "entrypoint",
    "invocation",
    "environment",
}
ENTRYPOINT_FIELDS = {"role", "path", "sha256", "execution"}
INVOCATION_FIELDS = {
    "executable",
    "flags",
    "isolated",
    "site_import",
    "bytecode_write",
}
ENVIRONMENT_FIELDS = {"clear", "allowlist", "values"}
WHEEL_FIELDS = {
    "distribution",
    "version",
    "wheel_filename",
    "wheel_sha256",
    "source_url",
    "wheel_tags",
    "installer",
    "record_path",
    "record_sha256",
    "installed_paths",
    "installed_paths_sha256",
}
MACHO_FIELDS = {
    "format",
    "objects",
    "dependencies",
    "system_dependency_allowlist",
    "graph_status",
}
MACHO_OBJECT_FIELDS = {
    "path",
    "sha256",
    "architecture",
    "cpu_subtype",
    "file_type",
    "flags",
    "uuid",
    "minimum_macos",
    "sdk",
    "install_name",
    "install_name_current_version",
    "install_name_compatibility_version",
    "rpaths",
    "load_commands_sha256",
}
MACHO_EDGE_FIELDS = {
    "source_path",
    "source_architecture",
    "load_command",
    "install_name",
    "current_version",
    "compatibility_version",
    "target_class",
    "target_path",
    "target_sha256",
}
DIGEST_FIELDS = {
    "bundle_content_sha256",
    "filesystem_policy_sha256",
    "inventory_sha256",
    "ownership_policy_sha256",
    "python_runtime_sha256",
    "wheel_provenance_sha256",
    "macho_graph_sha256",
}


class NativeBundleError(ValueError):
    """Stable, public-safe native-bundle rejection."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _error(code: str) -> NativeBundleError:
    return NativeBundleError(code)


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
    if (
        any(not isinstance(key, str) for key in value)
        or set(value) != expected
    ):
        raise _error(f"{field}_fields_invalid")


def _sequence(value: Any, *, field: str) -> Sequence[Any]:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes, bytearray))
    ):
        raise _error(f"{field}_not_array")
    return value


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


def _boolean(value: Any, *, field: str) -> bool:
    if type(value) is not bool:
        raise _error(f"{field}_invalid")
    return value


def _text(
    value: Any,
    *,
    field: str,
    maximum: int = 4_096,
    allow_empty: bool = False,
) -> str:
    try:
        encoded = value.encode("utf-8", "strict") if isinstance(value, str) else b""
    except UnicodeError as exc:
        raise _error(f"{field}_invalid") from exc
    if (
        not isinstance(value, str)
        or (not value and not allow_empty)
        or len(encoded) > maximum
        or "\x00" in value
        or any(ord(character) < 32 for character in value)
        or unicodedata.normalize("NFC", value) != value
    ):
        raise _error(f"{field}_invalid")
    return value


def _token(value: Any, *, field: str) -> str:
    text = _text(value, field=field, maximum=128)
    if not TOKEN_RE.fullmatch(text):
        raise _error(f"{field}_invalid")
    return text


def _sha256(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise _error(f"{field}_invalid")
    return value


def canonical_json_bytes(value: Any) -> bytes:
    """Encode the digest form used by every v3 sub-object."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise _error("native_bundle_json_invalid") from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def retained_native_bundle_manifest_bytes(value: Any) -> bytes:
    normalized = normalize_native_bundle_manifest(value)
    return canonical_json_bytes(normalized) + b"\n"


def native_bundle_manifest_sha256(value: Any) -> str:
    normalized = normalize_native_bundle_manifest(value)
    return _digest(normalized)


def parse_native_bundle_manifest(raw: bytes) -> dict[str, Any]:
    """Parse only the one canonical retained representation."""

    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise _error("native_bundle_manifest_size_invalid")

    def reject_duplicates(
        pairs: list[tuple[str, Any]],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _error("native_bundle_manifest_duplicate_field")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(
                _error("native_bundle_manifest_nonfinite_number")
            ),
        )
    except NativeBundleError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _error("native_bundle_manifest_json_invalid") from exc
    normalized = normalize_native_bundle_manifest(value)
    if raw != canonical_json_bytes(normalized) + b"\n":
        raise _error("native_bundle_manifest_encoding_not_canonical")
    return normalized


def _relative_path(
    value: Any,
    *,
    field: str,
    allow_root: bool = False,
) -> str:
    text = _text(value, field=field, maximum=MAX_PATH_BYTES)
    if "\\" in text or text.startswith("/") or text.endswith("/"):
        raise _error(f"{field}_invalid")
    if text == ".":
        if allow_root:
            return text
        raise _error(f"{field}_invalid")
    parts = text.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise _error(f"{field}_invalid")
    if len(parts) > MAX_DEPTH:
        raise _error(f"{field}_too_deep")
    if str(PurePosixPath(text)) != text:
        raise _error(f"{field}_invalid")
    return text


def _absolute_path(value: Any, *, field: str) -> str:
    text = _text(value, field=field, maximum=MAX_PATH_BYTES)
    path = PurePosixPath(text)
    if (
        "\\" in text
        or not text.startswith("/")
        or text != str(path)
        or "." in path.parts
        or ".." in path.parts
    ):
        raise _error(f"{field}_invalid")
    return text


def _sorted_unique_strings(
    value: Any,
    *,
    field: str,
    normalizer,
    maximum: int = MAX_ENTRIES,
) -> list[str]:
    items = _sequence(value, field=field)
    if len(items) > maximum:
        raise _error(f"{field}_too_many")
    normalized = [
        normalizer(item, field=f"{field}_item")
        for item in items
    ]
    if normalized != sorted(normalized) or len(set(normalized)) != len(
        normalized
    ):
        raise _error(f"{field}_not_sorted_unique")
    return normalized


def _casefold_unique(paths: Sequence[str], *, field: str) -> None:
    observed: set[str] = set()
    for path in paths:
        key = unicodedata.normalize("NFC", path).casefold()
        if key in observed:
            raise _error(f"{field}_case_collision")
        observed.add(key)


def _relative_paths_overlap(left: str, right: str) -> bool:
    left_key = left.casefold()
    right_key = right.casefold()
    return (
        left_key == right_key
        or left_key.startswith(right_key + "/")
        or right_key.startswith(left_key + "/")
    )


def _normalize_platform(value: Any) -> dict[str, Any]:
    source = _mapping(value, field="native_bundle_platform")
    _strict_fields(
        source,
        field="native_bundle_platform",
        expected=PLATFORM_FIELDS,
    )
    system = _text(source.get("system"), field="native_bundle_platform_system")
    if system != "darwin":
        raise _error("native_bundle_platform_system_unsupported")
    architecture = _text(
        source.get("architecture"),
        field="native_bundle_platform_architecture",
    )
    if architecture not in ARCHITECTURES:
        raise _error("native_bundle_platform_architecture_unsupported")
    binary_format = _text(
        source.get("binary_format"),
        field="native_bundle_platform_binary_format",
    )
    if binary_format != "mach-o-64-little-endian":
        raise _error("native_bundle_platform_binary_format_unsupported")
    minimum_macos = _text(
        source.get("minimum_macos"),
        field="native_bundle_platform_minimum_macos",
    )
    if not VERSION_RE.fullmatch(minimum_macos):
        raise _error("native_bundle_platform_minimum_macos_invalid")
    return {
        "system": system,
        "architecture": architecture,
        "binary_format": binary_format,
        "minimum_macos": minimum_macos,
    }


def _normalize_ownership_classes(value: Any) -> list[dict[str, Any]]:
    source = _sequence(value, field="native_bundle_ownership_classes")
    if not source or len(source) > 64:
        raise _error("native_bundle_ownership_classes_count_invalid")
    result: list[dict[str, Any]] = []
    for item in source:
        record = _mapping(item, field="native_bundle_ownership_class")
        _strict_fields(
            record,
            field="native_bundle_ownership_class",
            expected=OWNERSHIP_FIELDS,
        )
        result.append(
            {
                "id": _token(
                    record.get("id"),
                    field="native_bundle_ownership_class_id",
                ),
                "uid": _integer(
                    record.get("uid"),
                    field="native_bundle_ownership_class_uid",
                    minimum=0,
                    maximum=(1 << 31) - 1,
                ),
                "gid": _integer(
                    record.get("gid"),
                    field="native_bundle_ownership_class_gid",
                    minimum=0,
                    maximum=(1 << 31) - 1,
                ),
            }
        )
    if result != sorted(result, key=lambda item: item["id"]):
        raise _error("native_bundle_ownership_classes_not_sorted")
    if len({item["id"] for item in result}) != len(result):
        raise _error("native_bundle_ownership_class_duplicate")
    return result


def _normalize_mode_classes(value: Any) -> list[dict[str, Any]]:
    source = _sequence(value, field="native_bundle_mode_classes")
    if not source or len(source) > 64:
        raise _error("native_bundle_mode_classes_count_invalid")
    result: list[dict[str, Any]] = []
    for item in source:
        record = _mapping(item, field="native_bundle_mode_class")
        _strict_fields(
            record,
            field="native_bundle_mode_class",
            expected=MODE_FIELDS,
        )
        object_type = _text(
            record.get("object_type"),
            field="native_bundle_mode_class_object_type",
        )
        if object_type not in OBJECT_TYPES:
            raise _error("native_bundle_mode_class_object_type_invalid")
        mode = _integer(
            record.get("mode"),
            field="native_bundle_mode_class_mode",
            minimum=0,
            maximum=0o7777,
        )
        if mode & 0o222 or mode & 0o7000:
            raise _error("native_bundle_mode_class_mutable_or_special")
        if object_type == "directory" and mode & 0o500 != 0o500:
            raise _error("native_bundle_directory_mode_not_traversable")
        if object_type == "file" and not mode & 0o400:
            raise _error("native_bundle_file_mode_not_readable")
        result.append(
            {
                "id": _token(
                    record.get("id"),
                    field="native_bundle_mode_class_id",
                ),
                "object_type": object_type,
                "mode": mode,
            }
        )
    if result != sorted(result, key=lambda item: item["id"]):
        raise _error("native_bundle_mode_classes_not_sorted")
    if len({item["id"] for item in result}) != len(result):
        raise _error("native_bundle_mode_class_duplicate")
    return result


def _normalize_class_bindings(
    value: Any,
    *,
    ownership: Mapping[str, Mapping[str, Any]],
    modes: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, str]]:
    source = _mapping(value, field="native_bundle_path_classes")
    if not source or len(source) > MAX_ENTRIES:
        raise _error("native_bundle_path_classes_count_invalid")
    result: dict[str, dict[str, str]] = {}
    for raw_path, raw_binding in source.items():
        path = _relative_path(
            raw_path,
            field="native_bundle_path_class_path",
            allow_root=True,
        )
        binding = _mapping(
            raw_binding,
            field="native_bundle_path_class_binding",
        )
        _strict_fields(
            binding,
            field="native_bundle_path_class_binding",
            expected=CLASS_BINDING_FIELDS,
        )
        ownership_class = _token(
            binding.get("ownership_class"),
            field="native_bundle_path_ownership_class",
        )
        mode_class = _token(
            binding.get("mode_class"),
            field="native_bundle_path_mode_class",
        )
        if ownership_class not in ownership:
            raise _error("native_bundle_path_ownership_class_unknown")
        if mode_class not in modes:
            raise _error("native_bundle_path_mode_class_unknown")
        result[path] = {
            "ownership_class": ownership_class,
            "mode_class": mode_class,
        }
    if list(source) != sorted(result):
        raise _error("native_bundle_path_classes_not_sorted")
    _casefold_unique(list(result), field="native_bundle_path_classes")
    if "." not in result:
        raise _error("native_bundle_root_class_missing")
    return result


def _normalize_environment(value: Any) -> dict[str, Any]:
    source = _mapping(value, field="native_bundle_environment")
    _strict_fields(
        source,
        field="native_bundle_environment",
        expected=ENVIRONMENT_FIELDS,
    )
    if _boolean(
        source.get("clear"),
        field="native_bundle_environment_clear",
    ) is not True:
        raise _error("native_bundle_environment_not_cleared")
    allowlist = _sorted_unique_strings(
        source.get("allowlist"),
        field="native_bundle_environment_allowlist",
        normalizer=lambda item, field: _text(item, field=field, maximum=64),
        maximum=64,
    )
    if tuple(allowlist) != REQUIRED_ENVIRONMENT:
        raise _error("native_bundle_environment_allowlist_invalid")
    if any(not ENV_NAME_RE.fullmatch(name) for name in allowlist):
        raise _error("native_bundle_environment_name_invalid")
    values_source = _mapping(
        source.get("values"),
        field="native_bundle_environment_values",
    )
    if set(values_source) != set(allowlist) or list(values_source) != sorted(
        values_source
    ):
        raise _error("native_bundle_environment_values_fields_invalid")
    values = {
        name: _text(
            values_source[name],
            field=f"native_bundle_environment_value_{name}",
            maximum=4_096,
        )
        for name in sorted(values_source)
    }
    _absolute_path(values["HOME"], field="native_bundle_environment_home")
    _absolute_path(values["TMPDIR"], field="native_bundle_environment_tmpdir")
    path_parts = values["PATH"].split(":")
    if not path_parts or any(
        not part
        or _absolute_path(
            part,
            field="native_bundle_environment_path_component",
        )
        != part
        for part in path_parts
    ):
        raise _error("native_bundle_environment_path_invalid")
    return {
        "clear": True,
        "allowlist": allowlist,
        "values": values,
    }


def _normalize_runtime(value: Any, *, role: str) -> dict[str, Any]:
    source = _mapping(value, field="native_bundle_python_runtime")
    _strict_fields(
        source,
        field="native_bundle_python_runtime",
        expected=RUNTIME_FIELDS,
    )
    if source.get("implementation") != "cpython":
        raise _error("native_bundle_python_implementation_unsupported")
    version = _text(
        source.get("version"),
        field="native_bundle_python_version",
    )
    if not PYTHON_VERSION_RE.fullmatch(version):
        raise _error("native_bundle_python_version_invalid")
    abi_tag = _text(
        source.get("abi_tag"),
        field="native_bundle_python_abi_tag",
    )
    if not ABI_TAG_RE.fullmatch(abi_tag):
        raise _error("native_bundle_python_abi_tag_invalid")
    major, minor, _ = version.split(".")
    if abi_tag != f"cp{major}{minor}":
        raise _error("native_bundle_python_abi_version_mismatch")
    executable_path = _relative_path(
        source.get("executable_path"),
        field="native_bundle_python_executable_path",
    )
    stdlib_paths = _sorted_unique_strings(
        source.get("stdlib_paths"),
        field="native_bundle_python_stdlib_paths",
        normalizer=lambda item, field: _relative_path(
            item,
            field=field,
        ),
    )
    if not stdlib_paths:
        raise _error("native_bundle_python_stdlib_paths_empty")
    vendor_paths = _sorted_unique_strings(
        source.get("vendor_paths"),
        field="native_bundle_python_vendor_paths",
        normalizer=lambda item, field: _relative_path(
            item,
            field=field,
        ),
    )
    sys_path_source = _sequence(
        source.get("sys_path"),
        field="native_bundle_python_sys_path",
    )
    sys_path = [
        _relative_path(
            item,
            field="native_bundle_python_sys_path_item",
            allow_root=True,
        )
        for item in sys_path_source
    ]
    if (
        not sys_path
        or len(sys_path) > 128
        or len(set(sys_path)) != len(sys_path)
        or not set(stdlib_paths).issubset(sys_path)
        or not set(vendor_paths).issubset(sys_path)
    ):
        raise _error("native_bundle_python_sys_path_invalid")
    _casefold_unique(sys_path, field="native_bundle_python_sys_path")
    import_roots = stdlib_paths + vendor_paths
    for index, left in enumerate(import_roots):
        for right in import_roots[index + 1 :]:
            if _relative_paths_overlap(left, right):
                raise _error("native_bundle_python_import_roots_overlap")

    entry_source = _mapping(
        source.get("entrypoint"),
        field="native_bundle_python_entrypoint",
    )
    _strict_fields(
        entry_source,
        field="native_bundle_python_entrypoint",
        expected=ENTRYPOINT_FIELDS,
    )
    entry_role = _text(
        entry_source.get("role"),
        field="native_bundle_python_entrypoint_role",
    )
    if entry_role != role:
        raise _error("native_bundle_python_entrypoint_role_mismatch")
    execution = _text(
        entry_source.get("execution"),
        field="native_bundle_python_entrypoint_execution",
    )
    if execution != "runpy.run_path":
        raise _error("native_bundle_python_entrypoint_execution_invalid")
    entrypoint = {
        "role": entry_role,
        "path": _relative_path(
            entry_source.get("path"),
            field="native_bundle_python_entrypoint_path",
        ),
        "sha256": _sha256(
            entry_source.get("sha256"),
            field="native_bundle_python_entrypoint_sha256",
        ),
        "execution": execution,
    }

    invocation_source = _mapping(
        source.get("invocation"),
        field="native_bundle_python_invocation",
    )
    _strict_fields(
        invocation_source,
        field="native_bundle_python_invocation",
        expected=INVOCATION_FIELDS,
    )
    if invocation_source.get("executable") != "bundle-relative":
        raise _error("native_bundle_python_invocation_executable_invalid")
    flags = list(
        _sequence(
            invocation_source.get("flags"),
            field="native_bundle_python_invocation_flags",
        )
    )
    if flags != ["-I", "-S", "-B"]:
        raise _error("native_bundle_python_invocation_flags_invalid")
    invocation = {
        "executable": "bundle-relative",
        "flags": flags,
        "isolated": _boolean(
            invocation_source.get("isolated"),
            field="native_bundle_python_invocation_isolated",
        ),
        "site_import": _boolean(
            invocation_source.get("site_import"),
            field="native_bundle_python_invocation_site_import",
        ),
        "bytecode_write": _boolean(
            invocation_source.get("bytecode_write"),
            field="native_bundle_python_invocation_bytecode_write",
        ),
    }
    if invocation != {
        "executable": "bundle-relative",
        "flags": ["-I", "-S", "-B"],
        "isolated": True,
        "site_import": False,
        "bytecode_write": False,
    }:
        raise _error("native_bundle_python_invocation_policy_invalid")
    return {
        "implementation": "cpython",
        "version": version,
        "abi_tag": abi_tag,
        "executable_path": executable_path,
        "stdlib_paths": stdlib_paths,
        "vendor_paths": vendor_paths,
        "sys_path": sys_path,
        "entrypoint": entrypoint,
        "invocation": invocation,
        "environment": _normalize_environment(source.get("environment")),
    }


def _normalize_url(value: Any, *, field: str) -> str:
    text = _text(value, field=field, maximum=2_048)
    parsed = urllib.parse.urlsplit(text)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.geturl() != text
    ):
        raise _error(f"{field}_invalid")
    return text


def _normalize_wheels(value: Any) -> list[dict[str, Any]]:
    source = _sequence(value, field="native_bundle_wheel_provenance")
    if len(source) > 1_024:
        raise _error("native_bundle_wheel_provenance_too_many")
    result: list[dict[str, Any]] = []
    for item in source:
        record = _mapping(item, field="native_bundle_wheel")
        _strict_fields(
            record,
            field="native_bundle_wheel",
            expected=WHEEL_FIELDS,
        )
        distribution = _text(
            record.get("distribution"),
            field="native_bundle_wheel_distribution",
            maximum=128,
        )
        if not DISTRIBUTION_RE.fullmatch(distribution):
            raise _error("native_bundle_wheel_distribution_invalid")
        version = _text(
            record.get("version"),
            field="native_bundle_wheel_version",
            maximum=128,
        )
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+!-]{0,126}", version):
            raise _error("native_bundle_wheel_version_invalid")
        filename = _text(
            record.get("wheel_filename"),
            field="native_bundle_wheel_filename",
            maximum=244,
        )
        if not WHEEL_NAME_RE.fullmatch(filename):
            raise _error("native_bundle_wheel_filename_invalid")
        tags = _sorted_unique_strings(
            record.get("wheel_tags"),
            field="native_bundle_wheel_tags",
            normalizer=lambda item, field: _text(
                item,
                field=field,
                maximum=256,
            ),
            maximum=128,
        )
        if not tags or any(not WHEEL_TAG_RE.fullmatch(tag) for tag in tags):
            raise _error("native_bundle_wheel_tags_invalid")
        filename_stem = filename[:-4]
        try:
            _prefix, python_tag, abi_tag, platform_tag = filename_stem.rsplit(
                "-",
                3,
            )
        except ValueError as exc:
            raise _error("native_bundle_wheel_filename_invalid") from exc
        filename_tag = f"{python_tag}-{abi_tag}-{platform_tag}"
        expected_prefix = (
            f"{distribution.replace('-', '_')}-"
            f"{version.replace('-', '_')}-"
        ).casefold()
        if (
            not filename_stem.casefold().startswith(expected_prefix)
            or filename_tag not in tags
        ):
            raise _error("native_bundle_wheel_filename_provenance_mismatch")
        installer = _text(
            record.get("installer"),
            field="native_bundle_wheel_installer",
            maximum=32,
        )
        if installer not in {"manual-wheel-extract", "pip", "uv"}:
            raise _error("native_bundle_wheel_installer_invalid")
        installed_paths = _sorted_unique_strings(
            record.get("installed_paths"),
            field="native_bundle_wheel_installed_paths",
            normalizer=lambda item, field: _relative_path(item, field=field),
        )
        if not installed_paths:
            raise _error("native_bundle_wheel_installed_paths_empty")
        installed_digest = _sha256(
            record.get("installed_paths_sha256"),
            field="native_bundle_wheel_installed_paths_sha256",
        )
        if installed_digest != _digest(installed_paths):
            raise _error("native_bundle_wheel_installed_paths_digest_mismatch")
        result.append(
            {
                "distribution": distribution,
                "version": version,
                "wheel_filename": filename,
                "wheel_sha256": _sha256(
                    record.get("wheel_sha256"),
                    field="native_bundle_wheel_sha256",
                ),
                "source_url": _normalize_url(
                    record.get("source_url"),
                    field="native_bundle_wheel_source_url",
                ),
                "wheel_tags": tags,
                "installer": installer,
                "record_path": _relative_path(
                    record.get("record_path"),
                    field="native_bundle_wheel_record_path",
                ),
                "record_sha256": _sha256(
                    record.get("record_sha256"),
                    field="native_bundle_wheel_record_sha256",
                ),
                "installed_paths": installed_paths,
                "installed_paths_sha256": installed_digest,
            }
        )
    if result != sorted(result, key=lambda item: item["distribution"]):
        raise _error("native_bundle_wheel_provenance_not_sorted")
    if len({item["distribution"] for item in result}) != len(result):
        raise _error("native_bundle_wheel_distribution_duplicate")
    return result


def _directory_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("native_bundle_nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _file_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _error("native_bundle_nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _open_canonical_bundle_root(
    root: Path,
) -> tuple[int, tuple[os.stat_result, ...]]:
    """Open an absolute canonical root one component at a time.

    A single ``open(path, O_NOFOLLOW)`` protects only the last component.
    Qualification bundles must not inherit authority through an ancestor
    symlink, mutable shared directory, or directory controlled by an unrelated
    account.  The returned descriptor is the final root; intermediate
    descriptors are closed only after the next component has been opened.
    """

    raw = os.fspath(root)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise _error("native_bundle_root_path_invalid")
    absolute = os.path.abspath(raw)
    if raw != absolute:
        raise _error("native_bundle_root_path_not_absolute")
    if (
        os.path.normpath(raw) != raw
        or unicodedata.normalize("NFC", raw) != raw
        or os.path.realpath(raw) != raw
    ):
        raise _error("native_bundle_root_path_not_canonical")
    components = [component for component in raw.split("/") if component]
    descriptor: int | None = None
    observed: list[os.stat_result] = []
    try:
        descriptor = os.open("/", _directory_flags())
        root_stat = os.fstat(descriptor)
        _reject_fd_metadata(descriptor, field="native_bundle_root_ancestor")
        observed.append(root_stat)
        for component in components:
            try:
                aliases = [
                    name
                    for name in os.listdir(descriptor)
                    if name.casefold() == component.casefold()
                ]
            except OSError as exc:
                raise _error("native_bundle_root_unreadable") from exc
            if aliases != [component]:
                raise _error("native_bundle_root_path_not_canonical")
            next_descriptor = os.open(
                component,
                _directory_flags(),
                dir_fd=descriptor,
            )
            try:
                next_stat = os.fstat(next_descriptor)
                if not stat.S_ISDIR(next_stat.st_mode):
                    raise _error("native_bundle_root_ancestor_unsafe")
                _reject_fd_metadata(
                    next_descriptor,
                    field="native_bundle_root_ancestor",
                )
            except BaseException:
                os.close(next_descriptor)
                raise
            os.close(descriptor)
            descriptor = next_descriptor
            observed.append(next_stat)
        final_owner = int(observed[-1].st_uid)
        for ancestor in observed[:-1]:
            if (
                not stat.S_ISDIR(ancestor.st_mode)
                or stat.S_IMODE(ancestor.st_mode) & 0o022
                or int(ancestor.st_uid) not in {0, final_owner}
            ):
                raise _error("native_bundle_root_ancestor_unsafe")
        result = descriptor
        descriptor = None
        return result, tuple(observed)
    except NativeBundleError:
        raise
    except OSError as exc:
        raise _error("native_bundle_root_unreadable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


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


def _reject_fd_metadata(descriptor: int, *, field: str) -> None:
    """Reject ACLs and every non-platform xattr on the open inode.

    Current macOS creates ``com.apple.provenance`` on ordinary new inodes and
    may recreate it immediately after removal.  ``com.apple.rootless`` is
    likewise an OS authority label.  They cannot carry caller-selected bundle
    authority, so v3 names those two exceptions explicitly and rejects every
    other attribute.  Linux has no exception.
    """

    libc = ctypes.CDLL(None, use_errno=True)
    if not hasattr(libc, "flistxattr"):
        raise _error(f"{field}_metadata_inspection_unsupported")
    libc.flistxattr.restype = ctypes.c_ssize_t
    if sys.platform == "darwin":
        libc.flistxattr.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_int,
        ]
        size = libc.flistxattr(descriptor, None, 0, 0)
        permitted = {
            b"com.apple.provenance",
            b"com.apple.rootless",
        }
    elif sys.platform.startswith("linux"):
        libc.flistxattr.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        size = libc.flistxattr(descriptor, None, 0)
        permitted = set()
    else:
        raise _error(f"{field}_metadata_inspection_unsupported")
    if size < 0:
        raise _error(f"{field}_metadata_unreadable")
    attributes: set[bytes] = set()
    if size:
        buffer = ctypes.create_string_buffer(size)
        observed = (
            libc.flistxattr(descriptor, buffer, size, 0)
            if sys.platform == "darwin"
            else libc.flistxattr(descriptor, buffer, size)
        )
        if observed != size:
            raise _error(f"{field}_metadata_changed")
        attributes = {
            item
            for item in bytes(buffer.raw[:observed]).split(b"\x00")
            if item
        }
    if not attributes.issubset(permitted):
        raise _error(f"{field}_extended_attributes_forbidden")
    if sys.platform != "darwin":
        return
    if not hasattr(libc, "acl_get_fd_np"):
        raise _error(f"{field}_acl_inspection_unsupported")
    libc.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    libc.acl_get_fd_np.restype = ctypes.c_void_p
    libc.acl_free.argtypes = [ctypes.c_void_p]
    ctypes.set_errno(0)
    acl = libc.acl_get_fd_np(descriptor, 0x100)
    if acl:
        libc.acl_free(acl)
        raise _error(f"{field}_acl_forbidden")
    if ctypes.get_errno() != errno.ENOENT:
        raise _error(f"{field}_acl_unreadable")


def _read_regular_file(
    descriptor: int,
    *,
    field: str,
) -> tuple[int, str, bytes]:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 0
        or before.st_size > MAX_FILE_BYTES
    ):
        raise _error(f"{field}_unsafe")
    _reject_fd_metadata(descriptor, field=field)
    digest = hashlib.sha256()
    observed = 0
    prefix = bytearray()
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while observed <= MAX_FILE_BYTES:
            chunk = os.read(
                descriptor,
                min(128 * 1024, MAX_FILE_BYTES + 1 - observed),
            )
            if not chunk:
                break
            digest.update(chunk)
            observed += len(chunk)
            if len(prefix) < MAX_LOAD_COMMAND_BYTES + 32:
                remaining = MAX_LOAD_COMMAND_BYTES + 32 - len(prefix)
                prefix.extend(chunk[:remaining])
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    after = os.fstat(descriptor)
    if (
        observed != before.st_size
        or _stable_stat(before) != _stable_stat(after)
    ):
        raise _error(f"{field}_changed_during_read")
    return observed, digest.hexdigest(), bytes(prefix)


def _validate_name(name: Any, *, field: str) -> str:
    text = _text(name, field=field, maximum=255)
    if text in {".", ".."} or "/" in text or "\\" in text:
        raise _error(f"{field}_invalid")
    if text.casefold() == "__pycache__":
        raise _error("native_bundle_python_cache_directory_forbidden")
    if text.casefold().endswith((".pyc", ".pyo")):
        raise _error("native_bundle_python_bytecode_forbidden")
    return text


def _scan_bundle(
    root: Path,
    *,
    ownership: Mapping[str, Mapping[str, Any]],
    modes: Mapping[str, Mapping[str, Any]],
    path_classes: Mapping[str, Mapping[str, str]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        root_fd, root_chain = _open_canonical_bundle_root(root)
    except OSError as exc:
        raise _error("native_bundle_root_unreadable") from exc
    parsed_macho: list[dict[str, Any]] = []
    directories: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    total_bytes = 0
    observed_paths: list[str] = []

    def classification(
        relative: str,
        info: os.stat_result,
        *,
        object_type: str,
    ) -> dict[str, Any]:
        binding = path_classes.get(relative)
        if binding is None:
            raise _error("native_bundle_unexpected_entry")
        owner = ownership[binding["ownership_class"]]
        mode_class = modes[binding["mode_class"]]
        mode = stat.S_IMODE(info.st_mode)
        if (
            owner["uid"] != info.st_uid
            or owner["gid"] != info.st_gid
            or mode_class["object_type"] != object_type
            or mode_class["mode"] != mode
        ):
            raise _error("native_bundle_class_binding_mismatch")
        return {
            "path": relative,
            "mode": mode,
            "uid": int(info.st_uid),
            "gid": int(info.st_gid),
            "ownership_class": binding["ownership_class"],
            "mode_class": binding["mode_class"],
        }

    def walk(descriptor: int, relative: str, depth: int) -> None:
        nonlocal total_bytes
        if depth > MAX_DEPTH:
            raise _error("native_bundle_inventory_too_deep")
        before = os.fstat(descriptor)
        if not stat.S_ISDIR(before.st_mode):
            raise _error("native_bundle_directory_unsafe")
        _reject_fd_metadata(descriptor, field="native_bundle_directory")
        directories.append(
            classification(relative, before, object_type="directory")
        )
        observed_paths.append(relative)
        if len(directories) + len(files) > MAX_ENTRIES:
            raise _error("native_bundle_inventory_too_many_entries")
        try:
            names = os.listdir(descriptor)
        except OSError as exc:
            raise _error("native_bundle_directory_unreadable") from exc
        normalized_names = [
            _validate_name(name, field="native_bundle_entry_name")
            for name in names
        ]
        if len(set(name.casefold() for name in normalized_names)) != len(
            normalized_names
        ):
            raise _error("native_bundle_directory_case_collision")
        for name in sorted(normalized_names):
            child_relative = name if relative == "." else f"{relative}/{name}"
            try:
                named = os.stat(
                    name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise _error("native_bundle_entry_unreadable") from exc
            if stat.S_ISLNK(named.st_mode):
                raise _error("native_bundle_symlink_forbidden")
            if stat.S_ISDIR(named.st_mode):
                try:
                    child_fd = os.open(
                        name,
                        _directory_flags(),
                        dir_fd=descriptor,
                    )
                except OSError as exc:
                    raise _error("native_bundle_directory_unreadable") from exc
                try:
                    if _stable_stat(named) != _stable_stat(
                        os.fstat(child_fd)
                    ):
                        raise _error("native_bundle_entry_replaced")
                    walk(child_fd, child_relative, depth + 1)
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(named.st_mode):
                raise _error("native_bundle_special_file_forbidden")
            try:
                child_fd = os.open(
                    name,
                    _file_flags(),
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise _error("native_bundle_file_unreadable") from exc
            try:
                opened = os.fstat(child_fd)
                if _stable_stat(named) != _stable_stat(opened):
                    raise _error("native_bundle_entry_replaced")
                size, digest, prefix = _read_regular_file(
                    child_fd,
                    field="native_bundle_file",
                )
                content_type = (
                    "mach-o"
                    if prefix[:4] in MACHO_MAGICS
                    else "data"
                )
                record = classification(
                    child_relative,
                    opened,
                    object_type="file",
                )
                record.update(
                    {
                        "size": size,
                        "sha256": digest,
                        "content_type": content_type,
                    }
                )
                files.append(record)
                observed_paths.append(child_relative)
                if len(directories) + len(files) > MAX_ENTRIES:
                    raise _error("native_bundle_inventory_too_many_entries")
                total_bytes += size
                if total_bytes > MAX_TOTAL_BYTES:
                    raise _error("native_bundle_inventory_too_large")
                if content_type == "mach-o":
                    parsed_macho.append(
                        _inspect_macho(
                            prefix,
                            path=child_relative,
                            sha256=digest,
                        )
                    )
            finally:
                os.close(child_fd)
        after = os.fstat(descriptor)
        if _stable_stat(before) != _stable_stat(after):
            raise _error("native_bundle_directory_changed_during_scan")

    try:
        if _stable_stat(root_chain[-1]) != _stable_stat(os.fstat(root_fd)):
            raise _error("native_bundle_root_replaced")
        walk(root_fd, ".", 0)
    finally:
        os.close(root_fd)
    if set(observed_paths) != set(path_classes):
        raise _error("native_bundle_declared_entry_missing")
    _casefold_unique(observed_paths, field="native_bundle_inventory")
    directories.sort(key=lambda item: item["path"])
    files.sort(key=lambda item: item["path"])
    return (
        {
            "directories": directories,
            "files": files,
            "directory_count": len(directories),
            "file_count": len(files),
            "total_bytes": total_bytes,
        },
        parsed_macho,
    )


def _packed_version(value: int) -> str:
    return f"{value >> 16}.{(value >> 8) & 0xff}.{value & 0xff}"


def _version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(component) for component in value.split("."))


def _macho_string(
    command: bytes,
    offset: int,
    *,
    field: str,
) -> str:
    if offset < 8 or offset >= len(command):
        raise _error(f"{field}_offset_invalid")
    terminator = command.find(b"\x00", offset)
    if terminator < 0:
        raise _error(f"{field}_unterminated")
    try:
        value = command[offset:terminator].decode("utf-8")
    except UnicodeError as exc:
        raise _error(f"{field}_encoding_invalid") from exc
    return _text(value, field=field, maximum=MAX_PATH_BYTES)


def _inspect_macho(
    prefix: bytes,
    *,
    path: str,
    sha256: str,
) -> dict[str, Any]:
    if prefix[:4] in FAT_MAGICS:
        raise _error("native_bundle_fat_macho_unsupported")
    if len(prefix) < 32:
        raise _error("native_bundle_macho_header_truncated")
    try:
        (
            magic,
            raw_cpu_type,
            raw_cpu_subtype,
            raw_file_type,
            command_count,
            command_bytes,
            flags,
            _reserved,
        ) = struct.unpack_from("<IiiIIIII", prefix, 0)
    except struct.error as exc:
        raise _error("native_bundle_macho_header_invalid") from exc
    if magic != MH_MAGIC_64:
        raise _error("native_bundle_macho_format_unsupported")
    cpu_type = raw_cpu_type & 0xFFFFFFFF
    architecture = CPU_TYPES.get(cpu_type)
    if architecture is None:
        raise _error("native_bundle_macho_architecture_unsupported")
    file_type = MACHO_FILE_TYPES.get(raw_file_type)
    if file_type is None:
        raise _error("native_bundle_macho_file_type_unsupported")
    if (
        command_count > MAX_LOAD_COMMANDS
        or command_bytes > MAX_LOAD_COMMAND_BYTES
        or 32 + command_bytes > len(prefix)
    ):
        raise _error("native_bundle_macho_load_commands_invalid")

    dependencies: list[dict[str, Any]] = []
    rpaths: list[str] = []
    identifier: str | None = None
    identifier_current_version: str | None = None
    identifier_compatibility_version: str | None = None
    dynamic_linker: str | None = None
    object_uuid: str | None = None
    minimum_macos: str | None = None
    sdk: str | None = None
    offset = 32
    command_region = prefix[offset : offset + command_bytes]
    for _index in range(command_count):
        if offset + 8 > 32 + command_bytes:
            raise _error("native_bundle_macho_load_command_truncated")
        command_id, command_size = struct.unpack_from("<II", prefix, offset)
        if (
            command_size < 8
            or command_size % 8
            or offset + command_size > 32 + command_bytes
        ):
            raise _error("native_bundle_macho_load_command_size_invalid")
        command = prefix[offset : offset + command_size]
        if command_id in UNSUPPORTED_LOADER_COMMANDS:
            raise _error("native_bundle_macho_loader_command_unsupported")
        if (
            command_id & LC_REQ_DYLD
            and command_id not in KNOWN_REQUIRED_DYLD_COMMANDS
        ):
            raise _error(
                "native_bundle_macho_required_loader_command_unknown"
            )
        if command_id in DYLIB_COMMAND_NAMES or command_id == LC_ID_DYLIB:
            if command_size < 24:
                raise _error("native_bundle_macho_dylib_command_invalid")
            (
                _cmd,
                _size,
                name_offset,
                _timestamp,
                current_version,
                compatibility_version,
            ) = struct.unpack_from("<IIIIII", command, 0)
            if name_offset < 24:
                raise _error("native_bundle_macho_dylib_name_offset_invalid")
            install_name = _macho_string(
                command,
                name_offset,
                field="native_bundle_macho_install_name",
            )
            if command_id == LC_ID_DYLIB:
                if identifier is not None:
                    raise _error("native_bundle_macho_duplicate_install_name")
                identifier = install_name
                identifier_current_version = _packed_version(
                    current_version
                )
                identifier_compatibility_version = _packed_version(
                    compatibility_version
                )
            else:
                dependencies.append(
                    {
                        "load_command": DYLIB_COMMAND_NAMES[command_id],
                        "install_name": install_name,
                        "current_version": _packed_version(current_version),
                        "compatibility_version": _packed_version(
                            compatibility_version
                        ),
                    }
                )
        elif command_id == LC_RPATH:
            if command_size < 12:
                raise _error("native_bundle_macho_rpath_command_invalid")
            path_offset = struct.unpack_from("<I", command, 8)[0]
            if path_offset < 12:
                raise _error("native_bundle_macho_rpath_offset_invalid")
            rpaths.append(
                _macho_string(
                    command,
                    path_offset,
                    field="native_bundle_macho_rpath",
                )
            )
        elif command_id == LC_LOAD_DYLINKER:
            if command_size < 12 or dynamic_linker is not None:
                raise _error("native_bundle_macho_dylinker_command_invalid")
            name_offset = struct.unpack_from("<I", command, 8)[0]
            if name_offset < 12:
                raise _error("native_bundle_macho_dylinker_offset_invalid")
            dynamic_linker = _macho_string(
                command,
                name_offset,
                field="native_bundle_macho_dylinker_path",
            )
            if dynamic_linker != SYSTEM_DYLINKER:
                raise _error("native_bundle_macho_dylinker_not_allowed")
        elif command_id == LC_DYLD_ENVIRONMENT:
            # This command injects environment assignments directly into
            # dyld.  It would bypass the qualification launcher's exact,
            # cleared environment contract, so no bundle role may carry it.
            raise _error("native_bundle_macho_dyld_environment_forbidden")
        elif command_id == LC_UUID:
            if command_size != 24 or object_uuid is not None:
                raise _error("native_bundle_macho_uuid_command_invalid")
            object_uuid = str(uuid.UUID(bytes=command[8:24]))
        elif command_id == LC_BUILD_VERSION:
            if command_size < 24 or minimum_macos is not None:
                raise _error("native_bundle_macho_build_version_invalid")
            _cmd, _size, platform_id, minimum, sdk_value, tool_count = (
                struct.unpack_from("<IIIIII", command, 0)
            )
            if platform_id != 1 or command_size != 24 + tool_count * 8:
                raise _error("native_bundle_macho_platform_unsupported")
            minimum_macos = _packed_version(minimum)
            sdk = _packed_version(sdk_value)
        elif command_id == LC_VERSION_MIN_MACOSX:
            if command_size != 16 or minimum_macos is not None:
                raise _error("native_bundle_macho_minimum_version_invalid")
            _cmd, _size, minimum, sdk_value = struct.unpack_from(
                "<IIII",
                command,
                0,
            )
            minimum_macos = _packed_version(minimum)
            sdk = _packed_version(sdk_value)
        offset += command_size
    if offset != 32 + command_bytes:
        raise _error("native_bundle_macho_load_command_count_mismatch")
    if minimum_macos is None or sdk is None:
        raise _error("native_bundle_macho_platform_version_missing")
    if file_type == "dylib" and identifier is None:
        raise _error("native_bundle_macho_dylib_install_name_missing")
    if file_type != "dylib" and identifier is not None:
        raise _error("native_bundle_macho_install_name_unexpected")
    if file_type == "execute" and dynamic_linker != SYSTEM_DYLINKER:
        raise _error("native_bundle_macho_dylinker_missing")
    if file_type != "execute" and dynamic_linker is not None:
        raise _error("native_bundle_macho_dylinker_unexpected")
    if len(set(rpaths)) != len(rpaths):
        raise _error("native_bundle_macho_rpath_duplicate")
    dependencies.sort(
        key=lambda item: (
            item["load_command"],
            item["install_name"],
            item["current_version"],
            item["compatibility_version"],
        )
    )
    return {
        "object": {
            "path": path,
            "sha256": sha256,
            "architecture": architecture,
            "cpu_subtype": raw_cpu_subtype & 0xFFFFFFFF,
            "file_type": file_type,
            "flags": flags,
            "uuid": object_uuid,
            "minimum_macos": minimum_macos,
            "sdk": sdk,
            "install_name": identifier,
            "install_name_current_version": identifier_current_version,
            "install_name_compatibility_version": (
                identifier_compatibility_version
            ),
            "rpaths": sorted(rpaths),
            "load_commands_sha256": hashlib.sha256(command_region).hexdigest(),
        },
        "raw_dependencies": dependencies,
    }


def _normalize_dyld_expression(
    value: str,
    *,
    field: str,
) -> str:
    text = _text(value, field=field, maximum=MAX_PATH_BYTES)
    allowed = ("@executable_path", "@loader_path", "@rpath")
    if not any(text == prefix or text.startswith(prefix + "/") for prefix in allowed):
        raise _error(f"{field}_invalid")
    if "\\" in text or "//" in text:
        raise _error(f"{field}_invalid")
    return text


def _normalize_rpath(value: Any, *, field: str) -> str:
    text = _normalize_dyld_expression(value, field=field)
    if text == "@rpath" or text.startswith("@rpath/"):
        raise _error(f"{field}_nested_rpath_unsupported")
    return text


def _resolve_base_expression(
    expression: str,
    *,
    source_path: str,
    executable_path: str,
) -> str:
    expression = _normalize_dyld_expression(
        expression,
        field="native_bundle_macho_dyld_expression",
    )
    if expression == "@loader_path" or expression.startswith(
        "@loader_path/"
    ):
        base = posixpath.dirname(source_path)
        suffix = expression[len("@loader_path") :].lstrip("/")
    elif expression == "@executable_path" or expression.startswith(
        "@executable_path/"
    ):
        base = posixpath.dirname(executable_path)
        suffix = expression[len("@executable_path") :].lstrip("/")
    else:
        raise _error("native_bundle_macho_nested_rpath_unsupported")
    candidate = posixpath.normpath(posixpath.join(base, suffix))
    return _relative_path(
        candidate,
        field="native_bundle_macho_resolved_path",
    )


def _resolve_dependency(
    install_name: str,
    *,
    source: Mapping[str, Any],
    executable_path: str,
    file_map: Mapping[str, Mapping[str, Any]],
    object_paths: set[str],
    all_objects: Sequence[Mapping[str, Any]],
    system_allowlist: set[str],
) -> tuple[str, str, str | None]:
    if install_name.startswith("/"):
        absolute = _absolute_path(
            install_name,
            field="native_bundle_macho_system_dependency",
        )
        if (
            not (
                absolute.startswith("/usr/lib/")
                or absolute.startswith("/System/Library/")
            )
            or absolute not in system_allowlist
        ):
            raise _error("native_bundle_macho_system_dependency_not_allowed")
        return "macos-system", absolute, None

    if install_name == "@rpath" or install_name.startswith("@rpath/"):
        suffix = install_name[len("@rpath") :].lstrip("/")
        candidates: set[str] = set()
        for rpath in source["rpaths"]:
            base = _resolve_base_expression(
                rpath,
                source_path=source["path"],
                executable_path=executable_path,
            )
            candidate = _relative_path(
                posixpath.normpath(posixpath.join(base, suffix)),
                field="native_bundle_macho_resolved_dependency",
            )
            if candidate in file_map:
                candidates.add(candidate)
        if len(candidates) != 1:
            raise _error("native_bundle_macho_rpath_resolution_ambiguous")
        # dyld can inherit LC_RPATH entries from the dependency chain.  V3
        # deliberately adopts a conservative policy: the source image must
        # resolve the dependency by itself, and every rpath anywhere in the
        # closed graph must either miss or resolve to that same inode path.
        # This over-approximates every possible chain and prevents an inherited
        # run-path from shadowing the source-owned target.
        chain_candidates: set[str] = set()
        for context in all_objects:
            for rpath in context["rpaths"]:
                base = _resolve_base_expression(
                    rpath,
                    source_path=context["path"],
                    executable_path=executable_path,
                )
                candidate = _relative_path(
                    posixpath.normpath(posixpath.join(base, suffix)),
                    field="native_bundle_macho_resolved_dependency",
                )
                if candidate in file_map:
                    chain_candidates.add(candidate)
        if chain_candidates != candidates:
            raise _error("native_bundle_macho_rpath_chain_ambiguous")
        target = next(iter(candidates))
    elif install_name.startswith(("@loader_path", "@executable_path")):
        target = _resolve_base_expression(
            install_name,
            source_path=source["path"],
            executable_path=executable_path,
        )
    else:
        raise _error("native_bundle_macho_install_name_unsupported")
    if target == source["path"]:
        raise _error("native_bundle_macho_self_dependency")
    if target not in file_map or target not in object_paths:
        raise _error("native_bundle_macho_dependency_target_missing")
    return "bundle", target, file_map[target]["sha256"]


def _build_macho_graph(
    parsed: Sequence[Mapping[str, Any]],
    *,
    inventory: Mapping[str, Any],
    platform_policy: Mapping[str, Any],
    executable_path: str,
    system_dependency_allowlist: Any,
) -> dict[str, Any]:
    allowlist = _sorted_unique_strings(
        system_dependency_allowlist,
        field="native_bundle_macho_system_dependency_allowlist",
        normalizer=lambda item, field: _absolute_path(item, field=field),
        maximum=4_096,
    )
    if any(
        not (
            path.startswith("/usr/lib/")
            or path.startswith("/System/Library/")
        )
        for path in allowlist
    ):
        raise _error("native_bundle_macho_system_allowlist_path_invalid")
    file_map = {item["path"]: item for item in inventory["files"]}
    objects = [dict(item["object"]) for item in parsed]
    objects.sort(key=lambda item: item["path"])
    if len({item["path"] for item in objects}) != len(objects):
        raise _error("native_bundle_macho_object_duplicate")
    object_paths = {item["path"] for item in objects}
    actual_macho = {
        item["path"]
        for item in inventory["files"]
        if item["content_type"] == "mach-o"
    }
    if object_paths != actual_macho:
        raise _error("native_bundle_macho_inventory_mismatch")
    for item in objects:
        if item["architecture"] != platform_policy["architecture"]:
            raise _error("native_bundle_macho_platform_architecture_mismatch")
        if _version_tuple(item["sdk"]) < _version_tuple(
            item["minimum_macos"]
        ):
            raise _error("native_bundle_macho_sdk_precedes_minimum")
    if objects and max(
        (_version_tuple(item["minimum_macos"]) for item in objects)
    ) != _version_tuple(platform_policy["minimum_macos"]):
        raise _error("native_bundle_macho_minimum_platform_mismatch")
    raw_by_path = {
        item["object"]["path"]: item["raw_dependencies"]
        for item in parsed
    }
    edges: list[dict[str, Any]] = []
    used_system: set[str] = set()
    for source in objects:
        for dependency in raw_by_path[source["path"]]:
            target_class, target_path, target_sha = _resolve_dependency(
                dependency["install_name"],
                source=source,
                executable_path=executable_path,
                file_map=file_map,
                object_paths=object_paths,
                all_objects=objects,
                system_allowlist=set(allowlist),
            )
            if target_class == "macos-system":
                used_system.add(target_path)
            edges.append(
                {
                    "source_path": source["path"],
                    "source_architecture": source["architecture"],
                    "load_command": dependency["load_command"],
                    "install_name": dependency["install_name"],
                    "current_version": dependency["current_version"],
                    "compatibility_version": dependency[
                        "compatibility_version"
                    ],
                    "target_class": target_class,
                    "target_path": target_path,
                    "target_sha256": target_sha,
                }
            )
    edges.sort(
        key=lambda item: (
            item["source_path"],
            item["source_architecture"],
            item["load_command"],
            item["install_name"],
            item["target_class"],
            item["target_path"],
        )
    )
    if used_system != set(allowlist):
        raise _error("native_bundle_macho_system_allowlist_not_exact")
    return {
        "format": "mach-o-64-little-endian",
        "objects": objects,
        "dependencies": edges,
        "system_dependency_allowlist": allowlist,
        "graph_status": "parsed-and-resolved-against-complete-inventory",
    }


def _normalize_inventory(
    value: Any,
    *,
    ownership: Mapping[str, Mapping[str, Any]],
    modes: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    source = _mapping(value, field="native_bundle_inventory")
    _strict_fields(
        source,
        field="native_bundle_inventory",
        expected=INVENTORY_FIELDS,
    )

    def normalize_record(
        raw: Any,
        *,
        object_type: str,
    ) -> dict[str, Any]:
        record = _mapping(raw, field="native_bundle_inventory_record")
        expected = (
            DIRECTORY_FIELDS if object_type == "directory" else FILE_FIELDS
        )
        _strict_fields(
            record,
            field="native_bundle_inventory_record",
            expected=expected,
        )
        path = _relative_path(
            record.get("path"),
            field="native_bundle_inventory_path",
            allow_root=object_type == "directory",
        )
        ownership_class = _token(
            record.get("ownership_class"),
            field="native_bundle_inventory_ownership_class",
        )
        mode_class = _token(
            record.get("mode_class"),
            field="native_bundle_inventory_mode_class",
        )
        if ownership_class not in ownership or mode_class not in modes:
            raise _error("native_bundle_inventory_class_unknown")
        owner = ownership[ownership_class]
        mode_policy = modes[mode_class]
        uid = _integer(
            record.get("uid"),
            field="native_bundle_inventory_uid",
            minimum=0,
            maximum=(1 << 31) - 1,
        )
        gid = _integer(
            record.get("gid"),
            field="native_bundle_inventory_gid",
            minimum=0,
            maximum=(1 << 31) - 1,
        )
        mode = _integer(
            record.get("mode"),
            field="native_bundle_inventory_mode",
            minimum=0,
            maximum=0o7777,
        )
        if (
            uid != owner["uid"]
            or gid != owner["gid"]
            or object_type != mode_policy["object_type"]
            or mode != mode_policy["mode"]
        ):
            raise _error("native_bundle_inventory_class_binding_mismatch")
        result: dict[str, Any] = {
            "path": path,
            "mode": mode,
            "uid": uid,
            "gid": gid,
            "ownership_class": ownership_class,
            "mode_class": mode_class,
        }
        if object_type == "file":
            result.update(
                {
                    "size": _integer(
                        record.get("size"),
                        field="native_bundle_inventory_file_size",
                        minimum=0,
                        maximum=MAX_FILE_BYTES,
                    ),
                    "sha256": _sha256(
                        record.get("sha256"),
                        field="native_bundle_inventory_file_sha256",
                    ),
                    "content_type": _text(
                        record.get("content_type"),
                        field="native_bundle_inventory_content_type",
                    ),
                }
            )
            if result["content_type"] not in {"data", "mach-o"}:
                raise _error("native_bundle_inventory_content_type_invalid")
        return result

    directory_source = _sequence(
        source.get("directories"),
        field="native_bundle_inventory_directories",
    )
    file_source = _sequence(
        source.get("files"),
        field="native_bundle_inventory_files",
    )
    if len(directory_source) + len(file_source) > MAX_ENTRIES:
        raise _error("native_bundle_inventory_too_many_entries")
    directories = [
        normalize_record(item, object_type="directory")
        for item in directory_source
    ]
    files = [
        normalize_record(item, object_type="file")
        for item in file_source
    ]
    if (
        directories != sorted(directories, key=lambda item: item["path"])
        or files != sorted(files, key=lambda item: item["path"])
    ):
        raise _error("native_bundle_inventory_not_sorted")
    all_paths = [item["path"] for item in directories + files]
    if len(set(all_paths)) != len(all_paths):
        raise _error("native_bundle_inventory_path_duplicate")
    _casefold_unique(all_paths, field="native_bundle_inventory")
    if not directories or directories[0]["path"] != ".":
        raise _error("native_bundle_inventory_root_missing")
    directory_paths = {item["path"] for item in directories}
    for path in all_paths:
        if path == ".":
            continue
        parent = posixpath.dirname(path) or "."
        if parent not in directory_paths:
            raise _error("native_bundle_inventory_parent_missing")
        name = posixpath.basename(path)
        _validate_name(name, field="native_bundle_inventory_name")
    total_bytes = sum(item["size"] for item in files)
    if total_bytes > MAX_TOTAL_BYTES:
        raise _error("native_bundle_inventory_too_large")
    expected_counts = {
        "directory_count": len(directories),
        "file_count": len(files),
        "total_bytes": total_bytes,
    }
    for field, expected in expected_counts.items():
        if source.get(field) != expected:
            raise _error(f"native_bundle_inventory_{field}_mismatch")
    return {
        "directories": directories,
        "files": files,
        **expected_counts,
    }


def _normalize_macho(value: Any) -> dict[str, Any]:
    source = _mapping(value, field="native_bundle_macho")
    _strict_fields(
        source,
        field="native_bundle_macho",
        expected=MACHO_FIELDS,
    )
    if source.get("format") != "mach-o-64-little-endian":
        raise _error("native_bundle_macho_format_invalid")
    if (
        source.get("graph_status")
        != "parsed-and-resolved-against-complete-inventory"
    ):
        raise _error("native_bundle_macho_graph_status_invalid")
    objects_source = _sequence(
        source.get("objects"),
        field="native_bundle_macho_objects",
    )
    edges_source = _sequence(
        source.get("dependencies"),
        field="native_bundle_macho_dependencies",
    )
    if len(objects_source) + len(edges_source) > MAX_ENTRIES:
        raise _error("native_bundle_macho_graph_too_large")
    objects: list[dict[str, Any]] = []
    for raw in objects_source:
        item = _mapping(raw, field="native_bundle_macho_object")
        _strict_fields(
            item,
            field="native_bundle_macho_object",
            expected=MACHO_OBJECT_FIELDS,
        )
        architecture = _text(
            item.get("architecture"),
            field="native_bundle_macho_object_architecture",
        )
        if architecture not in ARCHITECTURES:
            raise _error("native_bundle_macho_object_architecture_invalid")
        file_type = _text(
            item.get("file_type"),
            field="native_bundle_macho_object_file_type",
        )
        if file_type not in set(MACHO_FILE_TYPES.values()):
            raise _error("native_bundle_macho_object_file_type_invalid")
        raw_uuid = item.get("uuid")
        if raw_uuid is not None:
            raw_uuid = _text(
                raw_uuid,
                field="native_bundle_macho_object_uuid",
                maximum=36,
            )
            try:
                if str(uuid.UUID(raw_uuid)) != raw_uuid:
                    raise ValueError
            except ValueError as exc:
                raise _error("native_bundle_macho_object_uuid_invalid") from exc
        install_name = item.get("install_name")
        if install_name is not None:
            install_name = _text(
                install_name,
                field="native_bundle_macho_object_install_name",
                maximum=MAX_PATH_BYTES,
            )
        install_name_current_version = item.get(
            "install_name_current_version"
        )
        install_name_compatibility_version = item.get(
            "install_name_compatibility_version"
        )
        if install_name is None:
            if (
                install_name_current_version is not None
                or install_name_compatibility_version is not None
            ):
                raise _error(
                    "native_bundle_macho_object_install_versions_unexpected"
                )
        else:
            install_name_current_version = _text(
                install_name_current_version,
                field=(
                    "native_bundle_macho_object_install_name_current_version"
                ),
            )
            install_name_compatibility_version = _text(
                install_name_compatibility_version,
                field=(
                    "native_bundle_macho_object_install_name_compatibility_"
                    "version"
                ),
            )
            if (
                not VERSION_RE.fullmatch(install_name_current_version)
                or not VERSION_RE.fullmatch(
                    install_name_compatibility_version
                )
            ):
                raise _error(
                    "native_bundle_macho_object_install_versions_invalid"
                )
        rpaths = _sorted_unique_strings(
            item.get("rpaths"),
            field="native_bundle_macho_object_rpaths",
            normalizer=lambda entry, field: _normalize_rpath(
                entry,
                field=field,
            ),
            maximum=256,
        )
        objects.append(
            {
                "path": _relative_path(
                    item.get("path"),
                    field="native_bundle_macho_object_path",
                ),
                "sha256": _sha256(
                    item.get("sha256"),
                    field="native_bundle_macho_object_sha256",
                ),
                "architecture": architecture,
                "cpu_subtype": _integer(
                    item.get("cpu_subtype"),
                    field="native_bundle_macho_object_cpu_subtype",
                    minimum=0,
                    maximum=(1 << 32) - 1,
                ),
                "file_type": file_type,
                "flags": _integer(
                    item.get("flags"),
                    field="native_bundle_macho_object_flags",
                    minimum=0,
                    maximum=(1 << 32) - 1,
                ),
                "uuid": raw_uuid,
                "minimum_macos": _text(
                    item.get("minimum_macos"),
                    field="native_bundle_macho_object_minimum_macos",
                ),
                "sdk": _text(
                    item.get("sdk"),
                    field="native_bundle_macho_object_sdk",
                ),
                "install_name": install_name,
                "install_name_current_version": (
                    install_name_current_version
                ),
                "install_name_compatibility_version": (
                    install_name_compatibility_version
                ),
                "rpaths": rpaths,
                "load_commands_sha256": _sha256(
                    item.get("load_commands_sha256"),
                    field="native_bundle_macho_object_load_commands_sha256",
                ),
            }
        )
        if (
            not VERSION_RE.fullmatch(objects[-1]["minimum_macos"])
            or not VERSION_RE.fullmatch(objects[-1]["sdk"])
        ):
            raise _error("native_bundle_macho_object_platform_version_invalid")
        if (file_type == "dylib") != (install_name is not None):
            raise _error("native_bundle_macho_object_install_name_invalid")
    if objects != sorted(objects, key=lambda item: item["path"]):
        raise _error("native_bundle_macho_objects_not_sorted")
    if len({item["path"] for item in objects}) != len(objects):
        raise _error("native_bundle_macho_object_duplicate")

    edges: list[dict[str, Any]] = []
    for raw in edges_source:
        item = _mapping(raw, field="native_bundle_macho_dependency")
        _strict_fields(
            item,
            field="native_bundle_macho_dependency",
            expected=MACHO_EDGE_FIELDS,
        )
        command = _text(
            item.get("load_command"),
            field="native_bundle_macho_dependency_command",
        )
        if command not in set(DYLIB_COMMAND_NAMES.values()):
            raise _error("native_bundle_macho_dependency_command_invalid")
        architecture = _text(
            item.get("source_architecture"),
            field="native_bundle_macho_dependency_architecture",
        )
        if architecture not in ARCHITECTURES:
            raise _error("native_bundle_macho_dependency_architecture_invalid")
        target_class = _text(
            item.get("target_class"),
            field="native_bundle_macho_dependency_target_class",
        )
        if target_class not in {"bundle", "macos-system"}:
            raise _error("native_bundle_macho_dependency_target_class_invalid")
        target_path = (
            _relative_path(
                item.get("target_path"),
                field="native_bundle_macho_dependency_target_path",
            )
            if target_class == "bundle"
            else _absolute_path(
                item.get("target_path"),
                field="native_bundle_macho_dependency_target_path",
            )
        )
        target_sha = item.get("target_sha256")
        if target_class == "bundle":
            target_sha = _sha256(
                target_sha,
                field="native_bundle_macho_dependency_target_sha256",
            )
        elif target_sha is not None:
            raise _error(
                "native_bundle_macho_system_dependency_digest_unexpected"
            )
        edge = {
            "source_path": _relative_path(
                item.get("source_path"),
                field="native_bundle_macho_dependency_source_path",
            ),
            "source_architecture": architecture,
            "load_command": command,
            "install_name": _text(
                item.get("install_name"),
                field="native_bundle_macho_dependency_install_name",
                maximum=MAX_PATH_BYTES,
            ),
            "current_version": _text(
                item.get("current_version"),
                field="native_bundle_macho_dependency_current_version",
            ),
            "compatibility_version": _text(
                item.get("compatibility_version"),
                field="native_bundle_macho_dependency_compatibility_version",
            ),
            "target_class": target_class,
            "target_path": target_path,
            "target_sha256": target_sha,
        }
        if (
            not VERSION_RE.fullmatch(edge["current_version"])
            or not VERSION_RE.fullmatch(edge["compatibility_version"])
        ):
            raise _error("native_bundle_macho_dependency_version_invalid")
        edges.append(edge)
    edge_key = lambda item: (
        item["source_path"],
        item["source_architecture"],
        item["load_command"],
        item["install_name"],
        item["target_class"],
        item["target_path"],
    )
    if edges != sorted(edges, key=edge_key):
        raise _error("native_bundle_macho_dependencies_not_sorted")
    if len({edge_key(item) for item in edges}) != len(edges):
        raise _error("native_bundle_macho_dependency_duplicate")
    allowlist = _sorted_unique_strings(
        source.get("system_dependency_allowlist"),
        field="native_bundle_macho_system_dependency_allowlist",
        normalizer=lambda item, field: _absolute_path(item, field=field),
        maximum=4_096,
    )
    if any(
        not (
            path.startswith("/usr/lib/")
            or path.startswith("/System/Library/")
        )
        for path in allowlist
    ):
        raise _error("native_bundle_macho_system_allowlist_path_invalid")
    return {
        "format": "mach-o-64-little-endian",
        "objects": objects,
        "dependencies": edges,
        "system_dependency_allowlist": allowlist,
        "graph_status": "parsed-and-resolved-against-complete-inventory",
    }


def _validate_cross_bindings(
    *,
    role: str,
    platform_policy: Mapping[str, Any],
    ownership_classes: Sequence[Mapping[str, Any]],
    mode_classes: Sequence[Mapping[str, Any]],
    runtime: Mapping[str, Any],
    wheels: Sequence[Mapping[str, Any]],
    macho: Mapping[str, Any],
    inventory: Mapping[str, Any],
) -> None:
    del ownership_classes, mode_classes
    file_map = {item["path"]: item for item in inventory["files"]}
    directory_paths = {item["path"] for item in inventory["directories"]}
    executable = file_map.get(runtime["executable_path"])
    if (
        executable is None
        or executable["content_type"] != "mach-o"
        or not executable["mode"] & 0o100
    ):
        raise _error("native_bundle_python_executable_invalid")
    entrypoint = file_map.get(runtime["entrypoint"]["path"])
    if (
        entrypoint is None
        or entrypoint["content_type"] != "data"
        or not runtime["entrypoint"]["path"].endswith(".py")
        or entrypoint["sha256"] != runtime["entrypoint"]["sha256"]
        or runtime["entrypoint"]["role"] != role
    ):
        raise _error("native_bundle_python_entrypoint_mismatch")
    for path in (
        list(runtime["stdlib_paths"])
        + list(runtime["vendor_paths"])
        + list(runtime["sys_path"])
    ):
        if path not in directory_paths:
            raise _error("native_bundle_python_path_missing")

    claimed_paths: set[str] = set()
    for wheel in wheels:
        if wheel["record_path"] not in wheel["installed_paths"]:
            raise _error("native_bundle_wheel_record_not_installed")
        record_file = file_map.get(wheel["record_path"])
        if (
            record_file is None
            or record_file["sha256"] != wheel["record_sha256"]
        ):
            raise _error("native_bundle_wheel_record_digest_mismatch")
        for path in wheel["installed_paths"]:
            if path not in file_map:
                raise _error("native_bundle_wheel_installed_path_missing")
            if path in claimed_paths:
                raise _error("native_bundle_wheel_installed_path_duplicate")
            if not any(
                path.startswith(root + "/")
                for root in runtime["vendor_paths"]
                if root != "."
            ):
                raise _error("native_bundle_wheel_path_outside_vendor_root")
            claimed_paths.add(path)
    vendor_files = {
        path
        for path in file_map
        if any(
            path.startswith(root + "/")
            for root in runtime["vendor_paths"]
            if root != "."
        )
    }
    if claimed_paths != vendor_files:
        raise _error("native_bundle_wheel_vendor_inventory_mismatch")

    object_map = {item["path"]: item for item in macho["objects"]}
    actual_macho = {
        path
        for path, item in file_map.items()
        if item["content_type"] == "mach-o"
    }
    if set(object_map) != actual_macho:
        raise _error("native_bundle_macho_inventory_mismatch")
    if object_map[runtime["executable_path"]]["file_type"] != "execute":
        raise _error("native_bundle_python_executable_file_type_invalid")
    for path, item in object_map.items():
        if (
            item["sha256"] != file_map[path]["sha256"]
            or item["architecture"] != platform_policy["architecture"]
        ):
            raise _error("native_bundle_macho_object_binding_mismatch")
    if object_map and max(
        (_version_tuple(item["minimum_macos"]) for item in object_map.values())
    ) != _version_tuple(platform_policy["minimum_macos"]):
        raise _error("native_bundle_macho_minimum_platform_mismatch")
    used_system: set[str] = set()
    for edge in macho["dependencies"]:
        source = object_map.get(edge["source_path"])
        if (
            source is None
            or source["architecture"] != edge["source_architecture"]
        ):
            raise _error("native_bundle_macho_edge_source_mismatch")
        if edge["target_class"] == "bundle":
            target = object_map.get(edge["target_path"])
            if (
                target is None
                or target["sha256"] != edge["target_sha256"]
            ):
                raise _error("native_bundle_macho_edge_target_mismatch")
        else:
            used_system.add(edge["target_path"])
    if used_system != set(macho["system_dependency_allowlist"]):
        raise _error("native_bundle_macho_system_allowlist_not_exact")


def _expected_digests(
    *,
    role: str,
    platform_policy: Mapping[str, Any],
    ownership_classes: Sequence[Mapping[str, Any]],
    mode_classes: Sequence[Mapping[str, Any]],
    runtime: Mapping[str, Any],
    wheels: Sequence[Mapping[str, Any]],
    macho: Mapping[str, Any],
    inventory: Mapping[str, Any],
) -> dict[str, str]:
    bundle_content = {
        "role": role,
        "platform": platform_policy,
        "filesystem_policy": FILESYSTEM_POLICY,
        "ownership_classes": ownership_classes,
        "mode_classes": mode_classes,
        "python_runtime": runtime,
        "wheel_provenance": wheels,
        "macho": macho,
        "inventory": inventory,
    }
    return {
        "bundle_content_sha256": _digest(bundle_content),
        "filesystem_policy_sha256": _digest(FILESYSTEM_POLICY),
        "inventory_sha256": _digest(inventory),
        "ownership_policy_sha256": _digest(
            {
                "ownership_classes": ownership_classes,
                "mode_classes": mode_classes,
            }
        ),
        "python_runtime_sha256": _digest(runtime),
        "wheel_provenance_sha256": _digest(wheels),
        "macho_graph_sha256": _digest(macho),
    }


def normalize_native_bundle_manifest(value: Any) -> dict[str, Any]:
    source = _mapping(value, field="native_bundle_manifest")
    _strict_fields(
        source,
        field="native_bundle_manifest",
        expected=MANIFEST_FIELDS,
    )
    if source.get("schema_version") != NATIVE_BUNDLE_MANIFEST_SCHEMA:
        raise _error("native_bundle_manifest_schema_unsupported")
    bundle_id = _text(
        source.get("bundle_id"),
        field="native_bundle_id",
        maximum=192,
    )
    if not BUNDLE_ID_RE.fullmatch(bundle_id):
        raise _error("native_bundle_id_invalid")
    role = _text(source.get("role"), field="native_bundle_role")
    if role not in ROLES:
        raise _error("native_bundle_role_invalid")
    platform_policy = _normalize_platform(source.get("platform"))
    if source.get("filesystem_policy") != FILESYSTEM_POLICY:
        raise _error("native_bundle_filesystem_policy_invalid")
    ownership_classes = _normalize_ownership_classes(
        source.get("ownership_classes")
    )
    mode_classes = _normalize_mode_classes(source.get("mode_classes"))
    ownership = {item["id"]: item for item in ownership_classes}
    modes = {item["id"]: item for item in mode_classes}
    runtime = _normalize_runtime(source.get("python_runtime"), role=role)
    wheels = _normalize_wheels(source.get("wheel_provenance"))
    inventory = _normalize_inventory(
        source.get("inventory"),
        ownership=ownership,
        modes=modes,
    )
    macho = _normalize_macho(source.get("macho"))
    if source.get("activation") != ACTIVATION_STATE:
        raise _error("native_bundle_activation_state_invalid")
    _validate_cross_bindings(
        role=role,
        platform_policy=platform_policy,
        ownership_classes=ownership_classes,
        mode_classes=mode_classes,
        runtime=runtime,
        wheels=wheels,
        macho=macho,
        inventory=inventory,
    )
    expected_digests = _expected_digests(
        role=role,
        platform_policy=platform_policy,
        ownership_classes=ownership_classes,
        mode_classes=mode_classes,
        runtime=runtime,
        wheels=wheels,
        macho=macho,
        inventory=inventory,
    )
    digest_source = _mapping(
        source.get("digests"),
        field="native_bundle_digests",
    )
    _strict_fields(
        digest_source,
        field="native_bundle_digests",
        expected=DIGEST_FIELDS,
    )
    supplied_digests = {
        field: _sha256(
            digest_source.get(field),
            field=f"native_bundle_digest_{field}",
        )
        for field in sorted(DIGEST_FIELDS)
    }
    if supplied_digests != expected_digests:
        raise _error("native_bundle_digest_mismatch")
    if bundle_id != f"{role}@{expected_digests['bundle_content_sha256']}":
        raise _error("native_bundle_id_content_mismatch")
    return {
        "schema_version": NATIVE_BUNDLE_MANIFEST_SCHEMA,
        "bundle_id": bundle_id,
        "role": role,
        "platform": platform_policy,
        "filesystem_policy": dict(FILESYSTEM_POLICY),
        "ownership_classes": ownership_classes,
        "mode_classes": mode_classes,
        "python_runtime": runtime,
        "wheel_provenance": wheels,
        "macho": macho,
        "inventory": inventory,
        "activation": dict(ACTIVATION_STATE),
        "digests": expected_digests,
    }


def build_native_bundle_manifest(
    bundle_root: Path | str,
    *,
    bundle_id: str | None = None,
    role: str,
    platform_policy: Mapping[str, Any],
    ownership_classes: Sequence[Mapping[str, Any]],
    mode_classes: Sequence[Mapping[str, Any]],
    path_classes: Mapping[str, Mapping[str, str]],
    python_runtime: Mapping[str, Any],
    wheel_provenance: Sequence[Mapping[str, Any]],
    system_dependency_allowlist: Sequence[str],
) -> dict[str, Any]:
    """Build v3 only from a predeclared complete path/class inventory."""

    root = Path(bundle_root)
    normalized_platform = _normalize_platform(platform_policy)
    normalized_role = _text(role, field="native_bundle_role")
    if normalized_role not in ROLES:
        raise _error("native_bundle_role_invalid")
    normalized_bundle_id: str | None = None
    if bundle_id is not None:
        normalized_bundle_id = _text(
            bundle_id,
            field="native_bundle_id",
            maximum=192,
        )
        if not BUNDLE_ID_RE.fullmatch(normalized_bundle_id):
            raise _error("native_bundle_id_invalid")
    normalized_ownership = _normalize_ownership_classes(ownership_classes)
    normalized_modes = _normalize_mode_classes(mode_classes)
    ownership = {item["id"]: item for item in normalized_ownership}
    modes = {item["id"]: item for item in normalized_modes}
    normalized_bindings = _normalize_class_bindings(
        path_classes,
        ownership=ownership,
        modes=modes,
    )
    runtime = _normalize_runtime(python_runtime, role=normalized_role)
    wheels = _normalize_wheels(wheel_provenance)
    inventory, parsed_macho = _scan_bundle(
        root,
        ownership=ownership,
        modes=modes,
        path_classes=normalized_bindings,
    )
    macho = _build_macho_graph(
        parsed_macho,
        inventory=inventory,
        platform_policy=normalized_platform,
        executable_path=runtime["executable_path"],
        system_dependency_allowlist=system_dependency_allowlist,
    )
    _validate_cross_bindings(
        role=normalized_role,
        platform_policy=normalized_platform,
        ownership_classes=normalized_ownership,
        mode_classes=normalized_modes,
        runtime=runtime,
        wheels=wheels,
        macho=macho,
        inventory=inventory,
    )
    digests = _expected_digests(
        role=normalized_role,
        platform_policy=normalized_platform,
        ownership_classes=normalized_ownership,
        mode_classes=normalized_modes,
        runtime=runtime,
        wheels=wheels,
        macho=macho,
        inventory=inventory,
    )
    derived_bundle_id = (
        f"{normalized_role}@{digests['bundle_content_sha256']}"
    )
    if normalized_bundle_id is None:
        normalized_bundle_id = derived_bundle_id
    elif normalized_bundle_id != derived_bundle_id:
        raise _error("native_bundle_id_content_mismatch")
    result = {
        "schema_version": NATIVE_BUNDLE_MANIFEST_SCHEMA,
        "bundle_id": normalized_bundle_id,
        "role": normalized_role,
        "platform": normalized_platform,
        "filesystem_policy": dict(FILESYSTEM_POLICY),
        "ownership_classes": normalized_ownership,
        "mode_classes": normalized_modes,
        "python_runtime": runtime,
        "wheel_provenance": wheels,
        "macho": macho,
        "inventory": inventory,
        "activation": dict(ACTIVATION_STATE),
        "digests": digests,
    }
    return normalize_native_bundle_manifest(result)


def verify_native_bundle(
    bundle_root: Path | str,
    manifest: Mapping[str, Any] | bytes,
    *,
    enforce_host_platform: bool = True,
    enforce_root_control: bool = True,
) -> str:
    """Rescan and exact-compare one v3 manifest; return its canonical digest."""

    expected = (
        parse_native_bundle_manifest(manifest)
        if isinstance(manifest, bytes)
        else normalize_native_bundle_manifest(manifest)
    )
    if enforce_host_platform:
        observed_system = host_platform.system().lower()
        machine = host_platform.machine().lower()
        machine = {"aarch64": "arm64", "amd64": "x86_64"}.get(
            machine,
            machine,
        )
        if (
            observed_system != expected["platform"]["system"]
            or machine != expected["platform"]["architecture"]
        ):
            raise _error("native_bundle_host_platform_mismatch")
        observed_version = host_platform.mac_ver()[0]
        if (
            not VERSION_RE.fullmatch(observed_version)
            or _version_tuple(observed_version)
            < _version_tuple(expected["platform"]["minimum_macos"])
        ):
            raise _error("native_bundle_host_macos_version_mismatch")
    path_classes = {
        item["path"]: {
            "ownership_class": item["ownership_class"],
            "mode_class": item["mode_class"],
        }
        for item in expected["inventory"]["directories"]
        + expected["inventory"]["files"]
    }
    rebuilt = build_native_bundle_manifest(
        bundle_root,
        bundle_id=expected["bundle_id"],
        role=expected["role"],
        platform_policy=expected["platform"],
        ownership_classes=expected["ownership_classes"],
        mode_classes=expected["mode_classes"],
        path_classes=dict(sorted(path_classes.items())),
        python_runtime=expected["python_runtime"],
        wheel_provenance=expected["wheel_provenance"],
        system_dependency_allowlist=expected["macho"][
            "system_dependency_allowlist"
        ],
    )
    if canonical_json_bytes(rebuilt) != canonical_json_bytes(expected):
        raise _error("native_bundle_manifest_filesystem_mismatch")
    if enforce_root_control and any(
        item["uid"] != 0 for item in expected["ownership_classes"]
    ):
        raise _error("native_bundle_not_root_controlled")
    return _digest(expected)


def issue_activation_receipt(*_args: Any, **_kwargs: Any) -> None:
    """Make the missing authority explicit; v3 cannot issue a receipt."""

    raise _error("native_bundle_activation_receipt_unavailable")


__all__ = [
    "ACTIVATION_RECEIPT_SCHEMA",
    "ACTIVATION_RECEIPTS_AVAILABLE",
    "NATIVE_BUNDLE_MANIFEST_SCHEMA",
    "NativeBundleError",
    "PRODUCTION_ACTIVATION",
    "build_native_bundle_manifest",
    "canonical_json_bytes",
    "issue_activation_receipt",
    "native_bundle_manifest_sha256",
    "normalize_native_bundle_manifest",
    "parse_native_bundle_manifest",
    "retained_native_bundle_manifest_bytes",
    "verify_native_bundle",
]
