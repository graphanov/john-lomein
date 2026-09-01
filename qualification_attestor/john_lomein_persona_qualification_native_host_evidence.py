#!/usr/bin/env python3
"""Dormant, descriptor-bound macOS native-host evidence.

This module measures two facts which the native-bundle manifest deliberately
does not claim:

* the bytes covered by each embedded Mach-O CodeDirectory still match every
  declared code-page hash, and
* the local macOS loader artifacts (``/usr/lib/dyld`` and the complete dyld
  shared-cache family declared by its primary cache header) have one exact,
  descriptor-measured identity.

The proof is intentionally narrower than Apple's complete code-signing
decision.  It does not authenticate a CMS signer, evaluate certificate trust,
validate notarization, interpret requirements or entitlements, reproduce AMFI,
or prove which loader/cache the kernel mapped into a running process.
``/usr/bin/codesign --verify --strict`` is recorded as a secondary negative
gate when a stable descriptor pathname is available; success never upgrades
the internal claim.

Nothing here activates production, publishes an activation receipt, installs
files, or accepts caller-authored host/version strings.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import struct
import subprocess
import sys
import unicodedata
import uuid
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Any


NATIVE_HOST_EVIDENCE_SCHEMA = (
    "john-lomein.persona-qualification-native-host-evidence.v1"
)
SIGNED_NATIVE_OBJECT_EVIDENCE_SCHEMA = (
    "john-lomein.persona-qualification-signed-native-object-evidence.v1"
)
MACOS_HOST_AUTHORITY_EVIDENCE_SCHEMA = (
    "john-lomein.persona-qualification-macos-host-authority-evidence.v1"
)

PRODUCTION_ACTIVATION = False
ACTIVATION_RECEIPTS_AVAILABLE = False
ACTIVATION_RECEIPT_SCHEMA = None

MAX_NATIVE_OBJECT_BYTES = 2 * 1024 * 1024 * 1024
MAX_SIGNATURE_BYTES = 128 * 1024 * 1024
MAX_LOAD_COMMAND_BYTES = 16 * 1024 * 1024
MAX_LOAD_COMMANDS = 4_096
MAX_SUPERBLOB_COMPONENTS = 128
MAX_CODE_SLOTS = 1_000_000
MAX_SHARED_CACHE_COMPONENTS = 128
MAX_SHARED_CACHE_COMPONENT_BYTES = 8 * 1024 * 1024 * 1024
MAX_SHARED_CACHE_TOTAL_BYTES = 16 * 1024 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+(?:\.[0-9]+)?$")
BUILD_RE = re.compile(r"^[0-9A-Z]{2,32}$")
DARWIN_RELEASE_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,254})$")
TEAM_RE = re.compile(r"^[A-Z0-9]{1,64}$")
CACHE_SUFFIX_RE = re.compile(r"^\.[A-Za-z0-9][A-Za-z0-9._-]{0,30}$")

ACTIVATION_STATE = {
    "activation_receipt_schema": None,
    "activation_receipts_available": False,
    "consumed_by_production_route": False,
    "production_activation": False,
}

LIMITATIONS = [
    "code-directory-page-hashes-prove-byte-consistency-not-signer-authority",
    "cms-certificate-chain-and-trust-are-not-parsed-or-proven",
    "requirements-and-entitlements-are-digest-bound-not-policy-interpreted",
    "notarization-stapling-and-gatekeeper-policy-are-not-proven",
    "codesign-strict-is-a-secondary-negative-gate-and-never-upgrades-the-claim",
    "codesign-secondary-path-observation-cannot-eliminate-a-rename-race",
    "static-dyld-files-do-not-prove-the-kernel-mapped-those-files-at-runtime",
    "amfi-kernel-and-library-validation-decisions-are-not-reproduced",
    "dyld-cache-map-and-atlas-sidecars-are-non-load-bearing-and-not-hashed",
    (
        "preboot-cryptexes-world-writable-container-is-accepted-only-"
        "around-the-sf-nounlink-os-mount"
    ),
    "production-activation-and-activation-receipts-remain-disabled",
]

SUPPORTED_CODE_DIRECTORY_VERSIONS = {
    0x20001,
    0x20100,
    0x20200,
    0x20300,
    0x20400,
    0x20500,
}

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
LC_UUID = 0x0000001B
LC_CODE_SIGNATURE = 0x0000001D

CPU_ARCHITECTURES = {
    0x01000007: "x86_64",
    0x0100000C: "arm64",
}
MACHO_FILE_TYPES = {
    2: "execute",
    6: "dylib",
    7: "dylinker",
    8: "bundle",
}

CSMAGIC_REQUIREMENT = 0xFADE0C00
CSMAGIC_REQUIREMENTS = 0xFADE0C01
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_BLOBWRAPPER = 0xFADE0B01
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172

CSSLOT_CODEDIRECTORY = 0
CSSLOT_REQUIREMENTS = 2
CSSLOT_ENTITLEMENTS = 5
CSSLOT_DER_ENTITLEMENTS = 7
CSSLOT_ALTERNATE_CODEDIRECTORY_FIRST = 0x1000
CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT = 0x1005
CSSLOT_SIGNATURE = 0x10000

SUPPORTED_EMBEDDED_SPECIAL_SLOTS = {
    CSSLOT_REQUIREMENTS: CSMAGIC_REQUIREMENTS,
    CSSLOT_ENTITLEMENTS: CSMAGIC_EMBEDDED_ENTITLEMENTS,
    CSSLOT_DER_ENTITLEMENTS: CSMAGIC_EMBEDDED_DER_ENTITLEMENTS,
}
MANDATORY_EMBEDDED_IF_NONZERO = {
    CSSLOT_REQUIREMENTS,
    CSSLOT_ENTITLEMENTS,
    CSSLOT_DER_ENTITLEMENTS,
}

CS_FLAG_NAMES = {
    0x00000001: "valid",
    0x00000002: "adhoc",
    0x00000004: "get-task-allow",
    0x00000008: "installer",
    0x00000010: "forced-library-validation",
    0x00000020: "invalid-allowed",
    0x00000100: "hard",
    0x00000200: "kill",
    0x00000400: "check-expiration",
    0x00000800: "restrict",
    0x00001000: "enforcement",
    0x00002000: "require-library-validation",
    0x00004000: "entitlements-validated",
    0x00008000: "nvram-unrestricted",
    0x00010000: "runtime",
    0x00020000: "linker-signed",
}
SUPPORTED_CS_FLAGS_MASK = sum(CS_FLAG_NAMES)
CS_ADHOC = 0x00000002
CS_LINKER_SIGNED = 0x00020000

HOST_COMMANDS = {
    "product_version": ("/usr/bin/sw_vers", "-productVersion"),
    "product_build": ("/usr/bin/sw_vers", "-buildVersion"),
    "darwin_release": ("/usr/sbin/sysctl", "-n", "kern.osrelease"),
    "darwin_build": ("/usr/sbin/sysctl", "-n", "kern.osversion"),
    "darwin_version": ("/usr/sbin/sysctl", "-n", "kern.version"),
    "architecture": ("/usr/bin/uname", "-m"),
}

SYSTEM_DYLD_PATH = "/usr/lib/dyld"
SHARED_CACHE_DIRECTORIES = (
    "/System/Library/dyld",
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld",
    "/private/preboot/Cryptexes/OS/System/Library/dyld",
    "/System/Cryptexes/OS/System/Library/dyld",
)
PREBOOT_CRYPTEX_CONTAINER = (
    "/System/Volumes/Preboot/Cryptexes"
)
PREBOOT_CRYPTEX_OS_MOUNT = (
    "/System/Volumes/Preboot/Cryptexes/OS"
)


class NativeHostEvidenceError(ValueError):
    """One fail-closed native-host evidence error."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _error(code: str) -> NativeHostEvidenceError:
    return NativeHostEvidenceError(code)


def _validate_canonical_value(value: Any) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > (1 << 63) - 1:
            raise _error("native_host_evidence_integer_out_of_range")
        return
    if isinstance(value, list):
        for item in value:
            _validate_canonical_value(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise _error("native_host_evidence_key_invalid")
            _validate_canonical_value(item)
        return
    raise _error("native_host_evidence_canonical_type_invalid")


def canonical_json_bytes(value: Any) -> bytes:
    """Encode the deliberately small canonical JSON value domain."""

    _validate_canonical_value(value)
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _seal(record: Mapping[str, Any]) -> dict[str, Any]:
    # The round trip also detaches the result from mutable module constants and
    # caller-owned containers before its digest is fixed.
    sealed = json.loads(canonical_json_bytes(dict(record)))
    if "evidence_sha256" in sealed:
        raise _error("native_host_evidence_digest_field_preexisting")
    sealed["evidence_sha256"] = _digest_json(sealed)
    return sealed


def verify_canonical_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    """Verify and return one self-digested evidence object."""

    if not isinstance(value, Mapping):
        raise _error("native_host_evidence_not_object")
    normalized = dict(value)
    digest = normalized.pop("evidence_sha256", None)
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise _error("native_host_evidence_digest_invalid")
    if not hmac.compare_digest(digest, _digest_json(normalized)):
        raise _error("native_host_evidence_digest_mismatch")
    normalized["evidence_sha256"] = digest
    return normalized


def canonical_evidence_bytes(value: Mapping[str, Any]) -> bytes:
    """Return one verified evidence record as canonical JSON plus newline."""

    normalized = verify_canonical_evidence(value)
    return canonical_json_bytes(normalized) + b"\n"


def _stable_stat(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _stat_evidence(info: os.stat_result) -> dict[str, int]:
    return {
        "device": info.st_dev,
        "gid": info.st_gid,
        "inode": info.st_ino,
        "mode": stat.S_IMODE(info.st_mode),
        "nlink": info.st_nlink,
        "size": info.st_size,
        "uid": info.st_uid,
    }


def _descriptor_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)


def _no_follow_flags() -> int:
    return _descriptor_flags() | getattr(os, "O_NOFOLLOW", 0)


def _directory_flags() -> int:
    return (
        _no_follow_flags()
        | getattr(os, "O_DIRECTORY", 0)
    )


def _require_readonly_regular_fd(
    fd: int,
    *,
    maximum_size: int,
    field: str,
) -> os.stat_result:
    if isinstance(fd, bool) or not isinstance(fd, int) or fd < 0:
        raise _error(f"{field}_descriptor_invalid")
    try:
        descriptor_flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        info = os.fstat(fd)
    except OSError as exc:
        raise _error(f"{field}_descriptor_unreadable") from exc
    if descriptor_flags & os.O_ACCMODE != os.O_RDONLY:
        raise _error(f"{field}_descriptor_not_readonly")
    if not stat.S_ISREG(info.st_mode):
        raise _error(f"{field}_not_regular")
    if info.st_size <= 0 or info.st_size > maximum_size:
        raise _error(f"{field}_size_invalid")
    return info


def _pread_exact(fd: int, size: int, offset: int, *, field: str) -> bytes:
    if size < 0 or offset < 0:
        raise _error(f"{field}_range_invalid")
    chunks: list[bytes] = []
    remaining = size
    cursor = offset
    try:
        while remaining:
            chunk = os.pread(fd, remaining, cursor)
            if not chunk:
                raise _error(f"{field}_truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
            cursor += len(chunk)
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    return b"".join(chunks)


def _sha256_fd_range(
    fd: int,
    size: int,
    *,
    offset: int = 0,
    field: str,
) -> str:
    if size < 0 or offset < 0:
        raise _error(f"{field}_range_invalid")
    digest = hashlib.sha256()
    cursor = offset
    remaining = size
    try:
        while remaining:
            chunk = os.pread(fd, min(READ_CHUNK_BYTES, remaining), cursor)
            if not chunk:
                raise _error(f"{field}_truncated")
            digest.update(chunk)
            cursor += len(chunk)
            remaining -= len(chunk)
    except OSError as exc:
        raise _error(f"{field}_unreadable") from exc
    return digest.hexdigest()


def _label(value: str) -> str:
    if not isinstance(value, str):
        raise _error("native_object_label_invalid")
    if (
        not value
        or len(value.encode("utf-8")) > 4096
        or unicodedata.normalize("NFC", value) != value
        or "\x00" in value
        or any(ord(character) < 0x20 for character in value)
    ):
        raise _error("native_object_label_invalid")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or str(path) != value
        or value in {".", ".."}
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise _error("native_object_label_invalid")
    return value


def _read_ascii_c_string(
    raw: bytes,
    offset: int,
    limit: int,
    *,
    field: str,
    pattern: re.Pattern[str],
) -> tuple[str, tuple[int, int]]:
    if offset < 0 or offset >= limit:
        raise _error(f"{field}_offset_invalid")
    end = raw.find(b"\x00", offset, limit)
    if end < 0:
        raise _error(f"{field}_unterminated")
    try:
        value = raw[offset:end].decode("ascii")
    except UnicodeError as exc:
        raise _error(f"{field}_encoding_invalid") from exc
    if pattern.fullmatch(value) is None:
        raise _error(f"{field}_invalid")
    return value, (offset, end + 1)


def _ranges_overlap(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def _flags_evidence(flags: int) -> tuple[list[str], bool, bool]:
    if flags & ~SUPPORTED_CS_FLAGS_MASK:
        raise _error("native_codesign_flags_unsupported")
    names = [
        name
        for bit, name in sorted(CS_FLAG_NAMES.items())
        if flags & bit
    ]
    adhoc = bool(flags & CS_ADHOC)
    linker_signed = bool(flags & CS_LINKER_SIGNED)
    if linker_signed and not adhoc:
        raise _error("native_codesign_linker_flag_semantics_unsupported")
    return names, adhoc, linker_signed


def _parse_code_directory(
    raw: bytes,
    *,
    fd: int,
    slice_base: int,
    signature_offset: int,
) -> tuple[dict[str, Any], dict[int, bytes]]:
    if len(raw) < 44:
        raise _error("native_codesign_code_directory_truncated")
    magic, declared_length = struct.unpack_from(">II", raw, 0)
    if magic != CSMAGIC_CODEDIRECTORY or declared_length != len(raw):
        raise _error("native_codesign_code_directory_header_invalid")
    (
        version,
        flags,
        hash_offset,
        identifier_offset,
        special_slot_count,
        code_slot_count,
        code_limit32,
    ) = struct.unpack_from(">7I", raw, 8)
    hash_size, hash_type, platform_identifier, page_size_log2 = (
        struct.unpack_from(">4B", raw, 36)
    )
    spare2 = struct.unpack_from(">I", raw, 40)[0]
    if version not in SUPPORTED_CODE_DIRECTORY_VERSIONS:
        raise _error("native_codesign_code_directory_version_unsupported")
    fixed_size = 44
    scatter_offset = 0
    team_offset = 0
    code_limit64 = 0
    exec_segment_base = 0
    exec_segment_limit = 0
    exec_segment_flags = 0
    runtime_version = 0
    pre_encrypt_offset = 0
    if version >= 0x20100:
        if len(raw) < 48:
            raise _error("native_codesign_code_directory_truncated")
        scatter_offset = struct.unpack_from(">I", raw, 44)[0]
        fixed_size = 48
    if version >= 0x20200:
        if len(raw) < 52:
            raise _error("native_codesign_code_directory_truncated")
        team_offset = struct.unpack_from(">I", raw, 48)[0]
        fixed_size = 52
    if version >= 0x20300:
        if len(raw) < 64:
            raise _error("native_codesign_code_directory_truncated")
        spare3, code_limit64 = struct.unpack_from(">IQ", raw, 52)
        if spare3 != 0:
            raise _error("native_codesign_code_directory_spare_invalid")
        fixed_size = 64
    if version >= 0x20400:
        if len(raw) < 88:
            raise _error("native_codesign_code_directory_truncated")
        (
            exec_segment_base,
            exec_segment_limit,
            exec_segment_flags,
        ) = struct.unpack_from(">QQQ", raw, 64)
        fixed_size = 88
    if version >= 0x20500:
        if len(raw) < 96:
            raise _error("native_codesign_code_directory_truncated")
        runtime_version, pre_encrypt_offset = struct.unpack_from(
            ">II", raw, 88
        )
        fixed_size = 96

    if spare2 != 0:
        raise _error("native_codesign_code_directory_spare_invalid")
    if scatter_offset != 0:
        raise _error("native_codesign_scatter_semantics_unsupported")
    if pre_encrypt_offset != 0:
        raise _error("native_codesign_preencrypt_semantics_unsupported")
    if code_limit64 != 0:
        # Native artifacts are capped below 2 GiB here.  A nonzero extended
        # limit therefore cannot be necessary and would introduce a second
        # coverage interpretation.
        raise _error("native_codesign_code_limit64_semantics_unsupported")
    if hash_type != 2 or hash_size != 32:
        raise _error("native_codesign_hash_algorithm_unsupported")
    if page_size_log2 not in {12, 13, 14, 15, 16}:
        raise _error("native_codesign_page_size_unsupported")
    if special_slot_count > 11:
        raise _error("native_codesign_special_slot_semantics_unsupported")
    if code_slot_count <= 0 or code_slot_count > MAX_CODE_SLOTS:
        raise _error("native_codesign_code_slot_count_invalid")
    if code_limit32 != signature_offset:
        raise _error("native_codesign_coverage_limit_mismatch")

    page_bytes = 1 << page_size_log2
    expected_slots = (code_limit32 + page_bytes - 1) // page_bytes
    if expected_slots != code_slot_count:
        raise _error("native_codesign_code_slot_count_mismatch")
    if (
        exec_segment_base > code_limit32
        or exec_segment_limit > code_limit32
        or exec_segment_base + exec_segment_limit > code_limit32
    ):
        raise _error("native_codesign_exec_segment_range_invalid")

    special_hash_start = hash_offset - special_slot_count * hash_size
    code_hash_end = hash_offset + code_slot_count * hash_size
    if (
        special_hash_start < fixed_size
        or hash_offset < special_hash_start
        or code_hash_end > len(raw)
    ):
        raise _error("native_codesign_hash_table_range_invalid")

    identifier, identifier_range = _read_ascii_c_string(
        raw,
        identifier_offset,
        special_hash_start,
        field="native_codesign_identifier",
        pattern=IDENTIFIER_RE,
    )
    if identifier_range[0] < fixed_size:
        raise _error("native_codesign_identifier_offset_invalid")
    team_identifier: str | None = None
    if team_offset:
        team_identifier, team_range = _read_ascii_c_string(
            raw,
            team_offset,
            special_hash_start,
            field="native_codesign_team_identifier",
            pattern=TEAM_RE,
        )
        if team_range[0] < fixed_size:
            raise _error("native_codesign_team_identifier_offset_invalid")
        if _ranges_overlap(identifier_range, team_range):
            raise _error("native_codesign_team_identifier_overlaps")

    flag_names, adhoc, linker_signed = _flags_evidence(flags)
    if adhoc and team_identifier is not None:
        raise _error("native_codesign_adhoc_team_semantics_unsupported")

    expected_code_hashes = raw[hash_offset:code_hash_end]
    for slot in range(code_slot_count):
        page_offset = slot * page_bytes
        page_length = min(page_bytes, code_limit32 - page_offset)
        page = _pread_exact(
            fd,
            page_length,
            slice_base + page_offset,
            field="native_codesign_code_page",
        )
        observed = hashlib.sha256(page).digest()
        expected = expected_code_hashes[
            slot * hash_size : (slot + 1) * hash_size
        ]
        if not hmac.compare_digest(observed, expected):
            raise _error("native_codesign_code_page_hash_mismatch")

    special_hashes: dict[int, bytes] = {}
    special_slot_evidence: list[dict[str, Any]] = []
    for slot in range(1, special_slot_count + 1):
        start = hash_offset - slot * hash_size
        digest = raw[start : start + hash_size]
        special_hashes[slot] = digest
        special_slot_evidence.append(
            {
                "digest": digest.hex(),
                "present": any(digest),
                "slot": slot,
            }
        )

    code_directory_sha256 = hashlib.sha256(raw).hexdigest()
    evidence = {
        "adhoc": adhoc,
        "cdhash": code_directory_sha256[:40],
        "code_directory_sha256": code_directory_sha256,
        "code_limit": code_limit32,
        "code_page_hash_table_sha256": hashlib.sha256(
            expected_code_hashes
        ).hexdigest(),
        "code_page_hashes_verified": True,
        "code_slot_count": code_slot_count,
        "exec_segment": {
            "base": exec_segment_base,
            "flags": f"0x{exec_segment_flags:016x}",
            "limit": exec_segment_limit,
        },
        "flags": f"0x{flags:08x}",
        "flag_names": flag_names,
        "hash_algorithm": "sha256",
        "hash_size": hash_size,
        "identifier": identifier,
        "linker_signed": linker_signed,
        "page_size": page_bytes,
        "platform_identifier": platform_identifier,
        "runtime_version": runtime_version,
        "special_slot_count": special_slot_count,
        "special_slots": special_slot_evidence,
        "team_identifier": team_identifier,
        "version": f"0x{version:05x}",
    }
    return evidence, special_hashes


def _require_zero_gaps(
    raw: bytes,
    occupied: list[tuple[int, int]],
    *,
    start: int,
    field: str,
) -> None:
    cursor = start
    for left, right in sorted(occupied):
        if left < cursor:
            raise _error(f"{field}_components_overlap")
        if any(raw[cursor:left]):
            raise _error(f"{field}_nonzero_gap")
        cursor = right
    if any(raw[cursor:]):
        raise _error(f"{field}_nonzero_gap")


def _parse_requirements_blob(raw: bytes) -> dict[str, Any]:
    if len(raw) < 12:
        raise _error("native_codesign_requirements_truncated")
    magic, declared_length, count = struct.unpack_from(">III", raw, 0)
    if (
        magic != CSMAGIC_REQUIREMENTS
        or declared_length != len(raw)
        or count > MAX_SUPERBLOB_COMPONENTS
        or 12 + count * 8 > len(raw)
    ):
        raise _error("native_codesign_requirements_header_invalid")
    previous_type = -1
    occupied: list[tuple[int, int]] = []
    requirement_digests: list[dict[str, Any]] = []
    for index in range(count):
        requirement_type, offset = struct.unpack_from(
            ">II", raw, 12 + index * 8
        )
        if requirement_type <= previous_type:
            raise _error("native_codesign_requirements_index_noncanonical")
        previous_type = requirement_type
        if offset < 12 + count * 8 or offset + 8 > len(raw):
            raise _error("native_codesign_requirement_offset_invalid")
        nested_magic, nested_length = struct.unpack_from(">II", raw, offset)
        if (
            nested_magic != CSMAGIC_REQUIREMENT
            or nested_length < 12
            or offset + nested_length > len(raw)
        ):
            raise _error("native_codesign_requirement_blob_invalid")
        occupied.append((offset, offset + nested_length))
        requirement_digests.append(
            {
                "sha256": hashlib.sha256(
                    raw[offset : offset + nested_length]
                ).hexdigest(),
                "type": requirement_type,
            }
        )
    _require_zero_gaps(
        raw,
        occupied,
        start=12 + count * 8,
        field="native_codesign_requirements",
    )
    return {
        "blob_sha256": hashlib.sha256(raw).hexdigest(),
        "count": count,
        "requirements": requirement_digests,
    }


def _parse_superblob(
    signature_region: bytes,
    *,
    fd: int,
    slice_base: int,
    signature_offset: int,
) -> dict[str, Any]:
    if len(signature_region) < 12:
        raise _error("native_codesign_superblob_truncated")
    magic, superblob_length, count = struct.unpack_from(
        ">III", signature_region, 0
    )
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        raise _error("native_codesign_superblob_magic_invalid")
    if (
        superblob_length < 12
        or superblob_length > len(signature_region)
        or superblob_length > MAX_SIGNATURE_BYTES
        or count <= 0
        or count > MAX_SUPERBLOB_COMPONENTS
        or 12 + count * 8 > superblob_length
    ):
        raise _error("native_codesign_superblob_header_invalid")
    if any(signature_region[superblob_length:]):
        raise _error("native_codesign_signature_padding_nonzero")
    raw = signature_region[:superblob_length]

    components: dict[int, bytes] = {}
    component_evidence: list[dict[str, Any]] = []
    occupied: list[tuple[int, int]] = []
    previous_slot = -1
    for index in range(count):
        slot, offset = struct.unpack_from(">II", raw, 12 + index * 8)
        if slot <= previous_slot:
            raise _error("native_codesign_superblob_index_noncanonical")
        previous_slot = slot
        if offset < 12 + count * 8 or offset + 8 > len(raw):
            raise _error("native_codesign_component_offset_invalid")
        component_magic, component_length = struct.unpack_from(
            ">II", raw, offset
        )
        if component_length < 8 or offset + component_length > len(raw):
            raise _error("native_codesign_component_length_invalid")
        component = raw[offset : offset + component_length]
        components[slot] = component
        occupied.append((offset, offset + component_length))
        component_evidence.append(
            {
                "length": component_length,
                "magic": f"0x{component_magic:08x}",
                "sha256": hashlib.sha256(component).hexdigest(),
                "slot": slot,
            }
        )
    _require_zero_gaps(
        raw,
        occupied,
        start=12 + count * 8,
        field="native_codesign_superblob",
    )

    if CSSLOT_CODEDIRECTORY not in components:
        raise _error("native_codesign_primary_code_directory_missing")
    code_directory_slots = [
        slot
        for slot in components
        if slot == CSSLOT_CODEDIRECTORY
        or CSSLOT_ALTERNATE_CODEDIRECTORY_FIRST
        <= slot
        < CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT
    ]
    for slot in components:
        if (
            slot not in code_directory_slots
            and slot not in SUPPORTED_EMBEDDED_SPECIAL_SLOTS
            and slot != CSSLOT_SIGNATURE
        ):
            raise _error("native_codesign_superblob_slot_unsupported")

    parsed_directories: list[dict[str, Any]] = []
    private_special_hashes: list[dict[int, bytes]] = []
    for slot in sorted(code_directory_slots):
        component = components[slot]
        if struct.unpack_from(">I", component, 0)[0] != CSMAGIC_CODEDIRECTORY:
            raise _error("native_codesign_code_directory_magic_invalid")
        parsed, special_hashes = _parse_code_directory(
            component,
            fd=fd,
            slice_base=slice_base,
            signature_offset=signature_offset,
        )
        parsed["slot"] = slot
        parsed_directories.append(parsed)
        private_special_hashes.append(special_hashes)

    identifiers = {item["identifier"] for item in parsed_directories}
    teams = {item["team_identifier"] for item in parsed_directories}
    adhoc_states = {item["adhoc"] for item in parsed_directories}
    linker_states = {item["linker_signed"] for item in parsed_directories}
    coverage_limits = {item["code_limit"] for item in parsed_directories}
    if (
        len(identifiers) != 1
        or len(teams) != 1
        or len(adhoc_states) != 1
        or len(linker_states) != 1
        or len(coverage_limits) != 1
    ):
        raise _error("native_codesign_code_directories_disagree")

    embedded_bindings: list[dict[str, Any]] = []
    requirements: dict[str, Any] | None = None
    entitlements: list[dict[str, Any]] = []
    for slot, expected_magic in SUPPORTED_EMBEDDED_SPECIAL_SLOTS.items():
        component = components.get(slot)
        if component is None:
            continue
        if struct.unpack_from(">I", component, 0)[0] != expected_magic:
            raise _error("native_codesign_special_blob_magic_invalid")
        observed_digest = hashlib.sha256(component).digest()
        for special_hashes in private_special_hashes:
            expected_digest = special_hashes.get(slot)
            if (
                expected_digest is None
                or not hmac.compare_digest(expected_digest, observed_digest)
            ):
                raise _error(
                    "native_codesign_embedded_special_hash_mismatch"
                )
        embedded_bindings.append(
            {
                "blob_sha256": observed_digest.hex(),
                "slot": slot,
                "verified_by_every_code_directory": True,
            }
        )
        if slot == CSSLOT_REQUIREMENTS:
            requirements = _parse_requirements_blob(component)
        else:
            if len(component) <= 8:
                raise _error("native_codesign_entitlements_blob_empty")
            entitlements.append(
                {
                    "blob_sha256": observed_digest.hex(),
                    "format": (
                        "xml-or-binary-plist"
                        if slot == CSSLOT_ENTITLEMENTS
                        else "der"
                    ),
                    "payload_sha256": hashlib.sha256(
                        component[8:]
                    ).hexdigest(),
                    "slot": slot,
                }
            )

    unresolved_slots: set[int] = set()
    for special_hashes in private_special_hashes:
        for slot, digest in special_hashes.items():
            if any(digest) and slot not in components:
                if slot in MANDATORY_EMBEDDED_IF_NONZERO:
                    raise _error(
                        "native_codesign_mandatory_special_blob_missing"
                    )
                unresolved_slots.add(slot)

    cms = components.get(CSSLOT_SIGNATURE)
    if cms is not None and struct.unpack_from(">I", cms, 0)[0] != (
        CSMAGIC_BLOBWRAPPER
    ):
        raise _error("native_codesign_cms_blob_magic_invalid")
    adhoc = next(iter(adhoc_states))
    if adhoc:
        if cms is not None and len(cms) != 8:
            raise _error("native_codesign_adhoc_cms_semantics_unsupported")
        signature_kind = (
            "linker-signed-ad-hoc"
            if next(iter(linker_states))
            else "ad-hoc"
        )
    else:
        if cms is None or len(cms) <= 8:
            raise _error("native_codesign_cms_blob_missing")
        signature_kind = "cms-present-authenticity-unproved"

    return {
        "all_special_slot_content_verified": not unresolved_slots,
        "blob_inventory": component_evidence,
        "code_directories": parsed_directories,
        "cms": (
            None
            if cms is None
            else {
                "authenticity_proven": False,
                "blob_sha256": hashlib.sha256(cms).hexdigest(),
                "payload_size": len(cms) - 8,
            }
        ),
        "embedded_special_bindings": embedded_bindings,
        "entitlements": entitlements,
        "identifier": next(iter(identifiers)),
        "requirements": requirements,
        "reserved_padding_sha256": hashlib.sha256(
            signature_region[superblob_length:]
        ).hexdigest(),
        "reserved_padding_size": len(signature_region) - superblob_length,
        "signature_kind": signature_kind,
        "superblob_length": superblob_length,
        "superblob_sha256": hashlib.sha256(raw).hexdigest(),
        "team_identifier": next(iter(teams)),
        "unresolved_external_special_slots": sorted(unresolved_slots),
    }


def _inspect_thin_slice(
    fd: int,
    *,
    slice_base: int,
    slice_size: int,
) -> dict[str, Any]:
    if slice_size < 32:
        raise _error("native_macho_header_truncated")
    header = _pread_exact(
        fd,
        32,
        slice_base,
        field="native_macho_header",
    )
    try:
        (
            magic,
            raw_cpu_type,
            raw_cpu_subtype,
            raw_file_type,
            command_count,
            command_bytes,
            header_flags,
            reserved,
        ) = struct.unpack("<IiiIIIII", header)
    except struct.error as exc:
        raise _error("native_macho_header_invalid") from exc
    if magic != MH_MAGIC_64:
        raise _error("native_macho_format_unsupported")
    cpu_type = raw_cpu_type & 0xFFFFFFFF
    architecture = CPU_ARCHITECTURES.get(cpu_type)
    if architecture is None:
        raise _error("native_macho_architecture_unsupported")
    file_type = MACHO_FILE_TYPES.get(raw_file_type)
    if file_type is None:
        raise _error("native_macho_file_type_unsupported")
    if (
        command_count <= 0
        or command_count > MAX_LOAD_COMMANDS
        or command_bytes <= 0
        or command_bytes > MAX_LOAD_COMMAND_BYTES
        or 32 + command_bytes > slice_size
    ):
        raise _error("native_macho_load_commands_invalid")
    commands = _pread_exact(
        fd,
        command_bytes,
        slice_base + 32,
        field="native_macho_load_commands",
    )
    cursor = 0
    code_signature: tuple[int, int] | None = None
    object_uuid: str | None = None
    for _index in range(command_count):
        if cursor + 8 > len(commands):
            raise _error("native_macho_load_command_truncated")
        command, size = struct.unpack_from("<II", commands, cursor)
        if size < 8 or size % 8 or cursor + size > len(commands):
            raise _error("native_macho_load_command_size_invalid")
        if command == LC_CODE_SIGNATURE:
            if code_signature is not None or size != 16:
                raise _error(
                    "native_macho_code_signature_command_invalid"
                )
            code_signature = struct.unpack_from(
                "<II", commands, cursor + 8
            )
        elif command == LC_UUID:
            if object_uuid is not None or size != 24:
                raise _error("native_macho_uuid_command_invalid")
            object_uuid = str(
                uuid.UUID(bytes=commands[cursor + 8 : cursor + 24])
            )
        cursor += size
    if cursor != len(commands):
        raise _error("native_macho_load_commands_size_mismatch")
    if code_signature is None:
        raise _error("native_macho_code_signature_missing")
    signature_offset, signature_size = code_signature
    if (
        signature_size < 12
        or signature_size > MAX_SIGNATURE_BYTES
        or signature_offset < 32 + command_bytes
        or signature_offset % 16
        or signature_offset + signature_size != slice_size
    ):
        raise _error("native_macho_code_signature_bounds_invalid")
    signature_region = _pread_exact(
        fd,
        signature_size,
        slice_base + signature_offset,
        field="native_macho_code_signature",
    )
    signature = _parse_superblob(
        signature_region,
        fd=fd,
        slice_base=slice_base,
        signature_offset=signature_offset,
    )
    return {
        "architecture": architecture,
        "cpu_subtype": f"0x{raw_cpu_subtype & 0xffffffff:08x}",
        "file_type": file_type,
        "header_flags": f"0x{header_flags:08x}",
        "reserved": reserved,
        "signature": {
            "data_offset": signature_offset,
            "data_size": signature_size,
            **signature,
        },
        "slice_offset": slice_base,
        "slice_sha256": _sha256_fd_range(
            fd,
            slice_size,
            offset=slice_base,
            field="native_macho_slice",
        ),
        "slice_size": slice_size,
        "uuid": object_uuid,
    }


def _fat_slices(
    fd: int,
    file_size: int,
) -> list[tuple[int, int, int, int]]:
    prefix = _pread_exact(fd, 8, 0, field="native_macho_fat_header")
    magic, count = struct.unpack(">II", prefix)
    if magic not in {FAT_MAGIC, FAT_MAGIC_64}:
        raise _error("native_macho_fat_magic_invalid")
    if count <= 0 or count > 32:
        raise _error("native_macho_fat_slice_count_invalid")
    entry_size = 20 if magic == FAT_MAGIC else 32
    table_size = 8 + count * entry_size
    if table_size > file_size:
        raise _error("native_macho_fat_table_truncated")
    table = _pread_exact(
        fd,
        table_size - 8,
        8,
        field="native_macho_fat_table",
    )
    ranges: list[tuple[int, int, int, int]] = []
    identities: set[tuple[int, int]] = set()
    for index in range(count):
        offset = index * entry_size
        if magic == FAT_MAGIC:
            cpu_type, cpu_subtype, base, size, alignment = (
                struct.unpack_from(">iiIII", table, offset)
            )
        else:
            cpu_type, cpu_subtype, base, size, alignment, reserved = (
                struct.unpack_from(">iiQQII", table, offset)
            )
            if reserved != 0:
                raise _error("native_macho_fat_reserved_invalid")
        identity = (cpu_type & 0xFFFFFFFF, cpu_subtype & 0xFFFFFFFF)
        if identity in identities:
            raise _error("native_macho_fat_architecture_duplicate")
        identities.add(identity)
        if (
            identity[0] not in CPU_ARCHITECTURES
            or size <= 0
            or base < table_size
            or base + size > file_size
            or alignment > 31
            or base % (1 << alignment)
        ):
            raise _error("native_macho_fat_slice_bounds_invalid")
        ranges.append((base, size, identity[0], identity[1]))
    ordered = sorted(ranges, key=lambda item: item[0])
    for left, right in zip(ordered, ordered[1:]):
        if left[0] + left[1] > right[0]:
            raise _error("native_macho_fat_slices_overlap")
    return ranges


def _run_subprocess(argv: tuple[str, ...]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv,
        check=False,
        capture_output=True,
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "TZ": "UTC",
        },
        timeout=60,
    )


def _fd_path(fd: int) -> str | None:
    if sys.platform != "darwin":
        return None
    try:
        raw = fcntl.fcntl(fd, 50, b"\x00" * 1024)
    except OSError:
        return None
    encoded = bytes(raw).split(b"\x00", 1)[0]
    try:
        path = encoded.decode("utf-8")
    except UnicodeError:
        return None
    if not path.startswith("/") or "\x00" in path:
        return None
    return path


def _secondary_codesign_observation(
    fd: int,
    expected: os.stat_result,
    *,
    required: bool,
) -> dict[str, Any]:
    path = _fd_path(fd)
    if path is None:
        if required:
            raise _error("native_codesign_secondary_path_unavailable")
        return {
            "claim_effect": "none-unavailable",
            "status": "unavailable",
            "tool": "/usr/bin/codesign",
        }
    verification_fd = -1
    try:
        verification_fd = os.open(path, _no_follow_flags())
        named = os.fstat(verification_fd)
    except OSError as exc:
        if required:
            raise _error("native_codesign_secondary_path_unavailable") from exc
        return {
            "claim_effect": "none-unavailable",
            "status": "unavailable",
            "tool": "/usr/bin/codesign",
        }
    finally:
        if verification_fd >= 0:
            os.close(verification_fd)
    if _stable_stat(named) != _stable_stat(expected):
        raise _error("native_codesign_secondary_path_identity_mismatch")
    try:
        completed = _run_subprocess(
            (
                "/usr/bin/codesign",
                "--verify",
                "--strict",
                "--verbose=4",
                "--",
                path,
            )
        )
    except (OSError, subprocess.SubprocessError) as exc:
        if required:
            raise _error("native_codesign_secondary_tool_unavailable") from exc
        return {
            "claim_effect": "none-unavailable",
            "status": "unavailable",
            "tool": "/usr/bin/codesign",
        }
    stdout = (
        completed.stdout.encode("utf-8")
        if isinstance(completed.stdout, str)
        else completed.stdout
    )
    stderr = (
        completed.stderr.encode("utf-8")
        if isinstance(completed.stderr, str)
        else completed.stderr
    )
    if len(stdout) + len(stderr) > 256 * 1024:
        raise _error("native_codesign_secondary_output_oversized")
    if completed.returncode != 0:
        raise _error("native_codesign_secondary_verification_failed")
    return {
        "claim_effect": "negative-gate-only",
        "output_sha256": hashlib.sha256(stdout + b"\x00" + stderr).hexdigest(),
        "status": "verified",
        "tool": "/usr/bin/codesign",
    }


def _measure_macho_fd_authoritative(
    fd: int,
    *,
    object_label: str,
    allow_fat: bool,
    required_architecture: str | None,
    require_secondary: bool,
) -> dict[str, Any]:
    label = _label(object_label)
    initial = _require_readonly_regular_fd(
        fd,
        maximum_size=MAX_NATIVE_OBJECT_BYTES,
        field="native_macho",
    )
    initial_sha256 = _sha256_fd_range(
        fd,
        initial.st_size,
        field="native_macho",
    )
    prefix = _pread_exact(fd, 4, 0, field="native_macho_magic")
    if struct.unpack("<I", prefix)[0] == MH_MAGIC_64:
        format_name = "thin-macho64"
        slice_ranges: list[tuple[int, int, int | None, int | None]] = [
            (0, initial.st_size, None, None)
        ]
    elif struct.unpack(">I", prefix)[0] in {FAT_MAGIC, FAT_MAGIC_64}:
        if not allow_fat:
            raise _error("native_macho_fat_unsupported_for_bundle")
        format_name = "universal-macho"
        slice_ranges = _fat_slices(fd, initial.st_size)
    else:
        raise _error("native_macho_format_unsupported")
    slices: list[dict[str, Any]] = []
    for base, size, declared_cpu_type, declared_cpu_subtype in slice_ranges:
        measured_slice = _inspect_thin_slice(
            fd,
            slice_base=base,
            slice_size=size,
        )
        if declared_cpu_type is not None:
            if (
                measured_slice["architecture"]
                != CPU_ARCHITECTURES[declared_cpu_type]
                or measured_slice["cpu_subtype"]
                != f"0x{declared_cpu_subtype:08x}"
            ):
                raise _error("native_macho_fat_architecture_mismatch")
        slices.append(measured_slice)
    if not allow_fat and any(
        item["file_type"] == "dylinker" for item in slices
    ):
        raise _error("native_macho_file_type_unsupported_for_bundle")
    architectures = sorted({item["architecture"] for item in slices})
    if (
        required_architecture is not None
        and required_architecture not in architectures
    ):
        raise _error("native_macho_required_architecture_missing")

    secondary = _secondary_codesign_observation(
        fd,
        initial,
        required=require_secondary,
    )
    final = os.fstat(fd)
    if _stable_stat(initial) != _stable_stat(final):
        raise _error("native_macho_changed_during_measurement")
    final_sha256 = _sha256_fd_range(
        fd,
        final.st_size,
        field="native_macho_final",
    )
    if not hmac.compare_digest(initial_sha256, final_sha256):
        raise _error("native_macho_changed_during_measurement")

    slice_evidence_sha256 = _digest_json(slices)
    return _seal(
        {
            "activation": ACTIVATION_STATE,
            "apple_codesign_semantics_proven": False,
            "artifact": {
                "descriptor_identity": _stat_evidence(initial),
                "sha256": initial_sha256,
                "size": initial.st_size,
            },
            "architectures": architectures,
            "byte_integrity_claim": (
                "every-supported-code-directory-page-hash-and-embedded-"
                "special-blob-hash-verified"
            ),
            "format": format_name,
            "limitations": LIMITATIONS,
            "object_label": label,
            "schema_version": SIGNED_NATIVE_OBJECT_EVIDENCE_SCHEMA,
            "secondary_codesign_observation": secondary,
            "slice_evidence_sha256": slice_evidence_sha256,
            "slices": slices,
            "status": "verified-static-byte-integrity",
        }
    )


def inspect_signed_macho_fd(
    fd: int,
    *,
    object_label: str,
) -> dict[str, Any]:
    """Measure one already-open thin Mach-O without activating anything."""

    if sys.platform != "darwin":
        raise _error("native_host_evidence_platform_unsupported")
    return _measure_macho_fd_authoritative(
        fd,
        object_label=object_label,
        allow_fat=False,
        required_architecture=None,
        require_secondary=False,
    )


def _run_command_line(argv: tuple[str, ...], *, field: str) -> str:
    try:
        completed = _run_subprocess(argv)
    except (OSError, subprocess.SubprocessError) as exc:
        raise _error(f"{field}_command_unavailable") from exc
    stdout = (
        completed.stdout.encode("utf-8")
        if isinstance(completed.stdout, str)
        else completed.stdout
    )
    stderr = (
        completed.stderr.encode("utf-8")
        if isinstance(completed.stderr, str)
        else completed.stderr
    )
    if completed.returncode != 0 or stderr or len(stdout) > 8192:
        raise _error(f"{field}_command_failed")
    try:
        value = stdout.decode("utf-8")
    except UnicodeError as exc:
        raise _error(f"{field}_encoding_invalid") from exc
    if (
        not value.endswith("\n")
        or "\n" in value[:-1]
        or "\x00" in value
        or any(ord(character) < 0x20 and character != "\n" for character in value)
    ):
        raise _error(f"{field}_output_invalid")
    return value[:-1]


def _measure_host_identity() -> dict[str, Any]:
    measured = {
        field: _run_command_line(command, field=f"native_host_{field}")
        for field, command in HOST_COMMANDS.items()
    }
    if VERSION_RE.fullmatch(measured["product_version"]) is None:
        raise _error("native_host_product_version_invalid")
    if BUILD_RE.fullmatch(measured["product_build"]) is None:
        raise _error("native_host_product_build_invalid")
    if DARWIN_RELEASE_RE.fullmatch(measured["darwin_release"]) is None:
        raise _error("native_host_darwin_release_invalid")
    if BUILD_RE.fullmatch(measured["darwin_build"]) is None:
        raise _error("native_host_darwin_build_invalid")
    if measured["product_build"] != measured["darwin_build"]:
        raise _error("native_host_build_identity_mismatch")
    if measured["architecture"] not in {"arm64", "x86_64"}:
        raise _error("native_host_architecture_unsupported")
    expected_prefix = (
        f"Darwin Kernel Version {measured['darwin_release']}:"
    )
    if (
        not measured["darwin_version"].startswith(expected_prefix)
        or "/RELEASE_" not in measured["darwin_version"]
    ):
        raise _error("native_host_darwin_version_inconsistent")
    identity = {
        "architecture": measured["architecture"],
        "darwin": {
            "build": measured["darwin_build"],
            "release": measured["darwin_release"],
            "version": measured["darwin_version"],
        },
        "macos": {
            "product_build_version": measured["product_build"],
            "product_version": measured["product_version"],
        },
        "measurement_source": {
            key: list(value)
            for key, value in sorted(HOST_COMMANDS.items())
        },
    }
    identity["identity_sha256"] = _digest_json(identity)
    return identity


def _open_system_file(path: str) -> int:
    pure = PurePosixPath(path)
    if (
        not pure.is_absolute()
        or str(pure) != path
        or len(pure.parts) < 3
    ):
        raise _error("native_host_system_artifact_path_invalid")
    parent_fd = _open_absolute_directory(str(pure.parent))
    try:
        fd = os.open(pure.name, _no_follow_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise _error("native_host_system_artifact_unavailable") from exc
    finally:
        os.close(parent_fd)
    try:
        info = _require_readonly_regular_fd(
            fd,
            maximum_size=MAX_NATIVE_OBJECT_BYTES,
            field="native_host_system_artifact",
        )
        if (
            info.st_uid != 0
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise _error("native_host_system_artifact_permissions_unsafe")
    except Exception:
        os.close(fd)
        raise
    return fd


def _measure_system_dyld(host_identity: Mapping[str, Any]) -> dict[str, Any]:
    fd = _open_system_file(SYSTEM_DYLD_PATH)
    try:
        measured = _measure_macho_fd_authoritative(
            fd,
            object_label="usr/lib/dyld",
            allow_fat=True,
            required_architecture=str(host_identity["architecture"]),
            require_secondary=True,
        )
    finally:
        os.close(fd)
    return {
        "artifact_path": SYSTEM_DYLD_PATH,
        "authority_policy": {
            "ancestor_walk": "descriptor-relative-no-follow",
            "artifact_owner": "uid-0",
            "group_or_world_writable": False,
        },
        "signed_artifact_evidence": measured,
    }


def _cache_header(fd: int, size: int) -> dict[str, Any]:
    if size < 416:
        raise _error("native_host_shared_cache_header_truncated")
    header = _pread_exact(
        fd,
        416,
        0,
        field="native_host_shared_cache_header",
    )
    magic_raw = header[:16].rstrip(b"\x00")
    try:
        magic = magic_raw.decode("ascii")
    except UnicodeError as exc:
        raise _error("native_host_shared_cache_magic_invalid") from exc
    if not magic.startswith("dyld_v1  ") or len(magic) < 10:
        raise _error("native_host_shared_cache_magic_invalid")
    cache_uuid = uuid.UUID(bytes=header[88:104])
    if cache_uuid.int == 0:
        raise _error("native_host_shared_cache_uuid_invalid")
    mapping_offset, mapping_count = struct.unpack_from("<II", header, 16)
    subcache_offset, subcache_count = struct.unpack_from("<II", header, 392)
    symbol_uuid = uuid.UUID(bytes=header[400:416])
    if (
        mapping_offset < 416
        or mapping_count <= 0
        or subcache_count > MAX_SHARED_CACHE_COMPONENTS
        or subcache_offset > size
    ):
        raise _error("native_host_shared_cache_header_invalid")
    return {
        "architecture_tag": magic[9:],
        "magic": magic,
        "mapping_count": mapping_count,
        "mapping_offset": mapping_offset,
        "subcache_count": subcache_count,
        "subcache_offset": subcache_offset,
        "symbol_uuid": None if symbol_uuid.int == 0 else str(symbol_uuid),
        "uuid": str(cache_uuid),
    }


def _open_cache_component(
    directory_fd: int,
    name: str,
    *,
    require_root: bool,
) -> tuple[int, os.stat_result]:
    if (
        not name
        or "/" in name
        or name in {".", ".."}
        or unicodedata.normalize("NFC", name) != name
    ):
        raise _error("native_host_shared_cache_name_invalid")
    try:
        fd = os.open(name, _no_follow_flags(), dir_fd=directory_fd)
    except OSError as exc:
        raise _error("native_host_shared_cache_component_missing") from exc
    try:
        info = _require_readonly_regular_fd(
            fd,
            maximum_size=MAX_SHARED_CACHE_COMPONENT_BYTES,
            field="native_host_shared_cache_component",
        )
        if require_root and (
            info.st_uid != 0
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise _error(
                "native_host_shared_cache_component_permissions_unsafe"
            )
    except Exception:
        os.close(fd)
        raise
    return fd, info


def _measure_cache_component(
    directory_fd: int,
    name: str,
    *,
    expected_uuid: str | None,
    require_root: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    fd, before = _open_cache_component(
        directory_fd,
        name,
        require_root=require_root,
    )
    try:
        header = _cache_header(fd, before.st_size)
        if expected_uuid is not None and header["uuid"] != expected_uuid:
            raise _error("native_host_shared_cache_component_uuid_mismatch")
        digest = _sha256_fd_range(
            fd,
            before.st_size,
            field="native_host_shared_cache_component",
        )
        after = os.fstat(fd)
        if _stable_stat(before) != _stable_stat(after):
            raise _error(
                "native_host_shared_cache_changed_during_measurement"
            )
    finally:
        os.close(fd)
    evidence = {
        "descriptor_identity": _stat_evidence(before),
        "name": name,
        "sha256": digest,
        "uuid": header["uuid"],
    }
    return evidence, header


def _measure_shared_cache_at_directory_fd(
    directory_fd: int,
    *,
    base_name: str,
    require_root: bool,
) -> dict[str, Any]:
    if (
        not base_name.startswith("dyld_shared_cache_")
        or "/" in base_name
        or len(base_name) > 128
    ):
        raise _error("native_host_shared_cache_base_name_invalid")
    primary, primary_header = _measure_cache_component(
        directory_fd,
        base_name,
        expected_uuid=None,
        require_root=require_root,
    )
    expected_architecture_tag = base_name.removeprefix(
        "dyld_shared_cache_"
    )
    if primary_header["architecture_tag"] != expected_architecture_tag:
        raise _error("native_host_shared_cache_primary_architecture_mismatch")
    primary_fd, primary_info = _open_cache_component(
        directory_fd,
        base_name,
        require_root=require_root,
    )
    try:
        count = int(primary_header["subcache_count"])
        offset = int(primary_header["subcache_offset"])
        table_size = count * 56
        if count and (
            offset < 416 or offset + table_size > primary_info.st_size
        ):
            raise _error("native_host_shared_cache_subcache_table_invalid")
        table = _pread_exact(
            primary_fd,
            table_size,
            offset,
            field="native_host_shared_cache_subcache_table",
        )
        if _stable_stat(primary_info) != _stable_stat(os.fstat(primary_fd)):
            raise _error(
                "native_host_shared_cache_changed_during_measurement"
            )
    finally:
        os.close(primary_fd)

    declared: list[tuple[str, str]] = []
    seen_suffixes: set[str] = set()
    seen_uuids: set[str] = {str(primary_header["uuid"])}
    for index in range(int(primary_header["subcache_count"])):
        cursor = index * 56
        subcache_uuid = str(uuid.UUID(bytes=table[cursor : cursor + 16]))
        suffix_raw = table[cursor + 24 : cursor + 56]
        suffix_end = suffix_raw.find(b"\x00")
        if suffix_end <= 0 or any(suffix_raw[suffix_end + 1 :]):
            raise _error("native_host_shared_cache_suffix_invalid")
        try:
            suffix = suffix_raw[:suffix_end].decode("ascii")
        except UnicodeError as exc:
            raise _error("native_host_shared_cache_suffix_invalid") from exc
        if (
            CACHE_SUFFIX_RE.fullmatch(suffix) is None
            or suffix in seen_suffixes
            or subcache_uuid in seen_uuids
            or uuid.UUID(subcache_uuid).int == 0
        ):
            raise _error("native_host_shared_cache_subcache_identity_invalid")
        seen_suffixes.add(suffix)
        seen_uuids.add(subcache_uuid)
        declared.append((suffix, subcache_uuid))

    symbol_uuid = primary_header["symbol_uuid"]
    if symbol_uuid is not None:
        if ".symbols" in seen_suffixes or symbol_uuid in seen_uuids:
            raise _error("native_host_shared_cache_symbol_identity_invalid")
        declared.append((".symbols", str(symbol_uuid)))
        seen_suffixes.add(".symbols")
        seen_uuids.add(str(symbol_uuid))

    components = [primary]
    for suffix, expected_uuid in declared:
        component, component_header = _measure_cache_component(
            directory_fd,
            base_name + suffix,
            expected_uuid=expected_uuid,
            require_root=require_root,
        )
        if component_header["architecture_tag"] != (
            primary_header["architecture_tag"]
        ):
            raise _error(
                "native_host_shared_cache_architecture_tag_mismatch"
            )
        components.append(component)

    try:
        directory_names = os.listdir(directory_fd)
    except OSError as exc:
        raise _error("native_host_shared_cache_directory_unreadable") from exc
    expected_names = {item["name"] for item in components}
    excluded_sidecars: list[str] = []
    for name in directory_names:
        if not name.startswith(base_name + ".") or name in expected_names:
            continue
        if name in {base_name + ".map", base_name + ".atlas"}:
            excluded_sidecars.append(name)
            continue
        raise _error("native_host_shared_cache_undeclared_component")

    total_bytes = sum(item["descriptor_identity"]["size"] for item in components)
    if total_bytes > MAX_SHARED_CACHE_TOTAL_BYTES:
        raise _error("native_host_shared_cache_family_oversized")
    components.sort(key=lambda item: item["name"])
    family = {
        "architecture_tag": primary_header["architecture_tag"],
        "component_count": len(components),
        "components": components,
        "excluded_non_load_bearing_sidecars": sorted(excluded_sidecars),
        "primary_uuid": primary_header["uuid"],
        "total_bytes": total_bytes,
    }
    family["content_set_sha256"] = _digest_json(components)
    family["uuid_set_sha256"] = _digest_json(
        [
            {"name": item["name"], "uuid": item["uuid"]}
            for item in components
        ]
    )
    return _seal(
        {
            "activation": ACTIVATION_STATE,
            "family": family,
            "measurement_method": (
                "apple-published-dyld-cache-header-v1-plus-"
                "descriptor-sha256-of-every-declared-component"
            ),
            "schema_version": (
                "john-lomein.persona-qualification-dyld-cache-evidence.v1"
            ),
            "status": "verified-static-cache-family-identity",
        }
    )


def _open_absolute_directory(path: str) -> int:
    pure = PurePosixPath(path)
    if not pure.is_absolute() or str(pure) != path:
        raise _error("native_host_shared_cache_directory_invalid")
    try:
        current = os.open("/", _directory_flags())
    except OSError as exc:
        raise _error("native_host_shared_cache_directory_unavailable") from exc
    try:
        traversed = ""
        for part in pure.parts[1:]:
            traversed += "/" + part
            try:
                child = os.open(
                    part,
                    _directory_flags(),
                    dir_fd=current,
                )
            except OSError as exc:
                raise _error(
                    "native_host_shared_cache_directory_unavailable"
                ) from exc
            info = os.fstat(child)
            writable = bool(
                info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            )
            permitted_cryptex_container = (
                traversed == PREBOOT_CRYPTEX_CONTAINER
                and stat.S_IMODE(info.st_mode) == 0o777
            )
            if info.st_uid != 0 or (
                writable and not permitted_cryptex_container
            ):
                os.close(child)
                raise _error(
                    "native_host_shared_cache_ancestor_permissions_unsafe"
                )
            if (
                traversed == PREBOOT_CRYPTEX_OS_MOUNT
                and not (
                    getattr(info, "st_flags", 0)
                    & getattr(stat, "SF_NOUNLINK", 0x00100000)
                )
            ):
                os.close(child)
                raise _error(
                    "native_host_shared_cache_cryptex_mount_unprotected"
                )
            os.close(current)
            current = child
        return current
    except Exception:
        os.close(current)
        raise


def _measure_shared_cache(host_identity: Mapping[str, Any]) -> dict[str, Any]:
    architecture = str(host_identity["architecture"])
    architecture_tags = (
        ("arm64e", "arm64")
        if architecture == "arm64"
        else ("x86_64",)
    )
    matches: dict[tuple[int, int, str], list[str]] = {}
    for directory in SHARED_CACHE_DIRECTORIES:
        try:
            directory_fd = _open_absolute_directory(directory)
        except NativeHostEvidenceError as exc:
            if exc.code == "native_host_shared_cache_directory_unavailable":
                continue
            raise
        try:
            directory_identity = os.fstat(directory_fd)
            for tag in architecture_tags:
                name = f"dyld_shared_cache_{tag}"
                try:
                    fd, _info = _open_cache_component(
                        directory_fd,
                        name,
                        require_root=True,
                    )
                except NativeHostEvidenceError as exc:
                    if exc.code == (
                        "native_host_shared_cache_component_missing"
                    ):
                        continue
                    raise
                else:
                    os.close(fd)
                    key = (
                        directory_identity.st_dev,
                        directory_identity.st_ino,
                        name,
                    )
                    matches.setdefault(key, []).append(directory)
        finally:
            os.close(directory_fd)
    if len(matches) != 1:
        raise _error("native_host_shared_cache_authority_ambiguous")
    (_device, _inode, base_name), aliases = next(iter(matches.items()))
    directory = aliases[0]
    directory_fd = _open_absolute_directory(directory)
    try:
        measured = _measure_shared_cache_at_directory_fd(
            directory_fd,
            base_name=base_name,
            require_root=True,
        )
    finally:
        os.close(directory_fd)
    return {
        "authority_aliases": sorted(aliases),
        "authority_policy": {
            "ancestor_walk": "descriptor-relative-no-follow",
            "component_owner": "uid-0",
            "group_or_world_writable_components": False,
            "preboot_cryptex_exception": {
                "container": PREBOOT_CRYPTEX_CONTAINER,
                "container_mode": "0777",
                "os_mount": PREBOOT_CRYPTEX_OS_MOUNT,
                "required_os_mount_flag": "SF_NOUNLINK",
            },
        },
        "base_name": base_name,
        "directory": directory,
        "evidence": measured,
    }


def measure_macos_host_authority() -> dict[str, Any]:
    """Strictly measure local, static macOS loader authority artifacts."""

    if sys.platform != "darwin":
        raise _error("native_host_evidence_platform_unsupported")
    identity = _measure_host_identity()
    system_dyld = _measure_system_dyld(identity)
    shared_cache = _measure_shared_cache(identity)
    return _seal(
        {
            "activation": ACTIVATION_STATE,
            "host_identity": identity,
            "limitations": LIMITATIONS,
            "loader_identity": {
                "dyld": system_dyld,
                "dyld_shared_cache": shared_cache,
                "runtime_mapping_proven": False,
                "static_artifact_identity_proven": True,
            },
            "schema_version": MACOS_HOST_AUTHORITY_EVIDENCE_SCHEMA,
            "status": "verified-static-macos-loader-authority",
        }
    )


def _closed_evidence(*, status: str, reason_code: str) -> dict[str, Any]:
    return _seal(
        {
            "activation": ACTIVATION_STATE,
            "authority_proven": False,
            "limitations": LIMITATIONS,
            "reason_code": reason_code,
            "schema_version": NATIVE_HOST_EVIDENCE_SCHEMA,
            "status": status,
        }
    )


def collect_native_host_evidence(
    native_object_fds: Mapping[str, int],
) -> dict[str, Any]:
    """Collect canonical dormant evidence or a canonical fail-closed result.

    Keys are root-relative logical labels only.  Values must be already-open,
    read-only descriptors for thin bundle Mach-Os.  Host identity is always
    measured locally and accepts no caller-authored version, loader, or cache
    strings.
    """

    if sys.platform != "darwin":
        return _closed_evidence(
            status="unsupported",
            reason_code="native_host_evidence_macos_only",
        )
    if not isinstance(native_object_fds, Mapping):
        return _closed_evidence(
            status="unproved",
            reason_code="native_object_descriptor_map_invalid",
        )
    try:
        labels = sorted(_label(key) for key in native_object_fds)
        if len(labels) != len(native_object_fds):
            raise _error("native_object_label_duplicate")
        if not labels:
            raise _error("native_object_descriptor_map_empty")
        host = measure_macos_host_authority()
        native_objects = [
            _measure_macho_fd_authoritative(
                native_object_fds[label],
                object_label=label,
                allow_fat=False,
                required_architecture=host["host_identity"]["architecture"],
                require_secondary=True,
            )
            for label in labels
        ]
        descriptor_identities = {
            (
                item["artifact"]["descriptor_identity"]["device"],
                item["artifact"]["descriptor_identity"]["inode"],
            )
            for item in native_objects
        }
        if len(descriptor_identities) != len(native_objects):
            raise _error("native_object_descriptor_identity_duplicate")
    except NativeHostEvidenceError as exc:
        return _closed_evidence(
            status="unproved",
            reason_code=exc.code,
        )

    return _seal(
        {
            "activation": ACTIVATION_STATE,
            "authority_proven": True,
            "digests": {
                "host_authority_evidence_sha256": host["evidence_sha256"],
                "native_objects_sha256": _digest_json(native_objects),
            },
            "host_authority": host,
            "limitations": LIMITATIONS,
            "native_objects": native_objects,
            "schema_version": NATIVE_HOST_EVIDENCE_SCHEMA,
            "status": "verified-static-native-host-evidence",
        }
    )


__all__ = [
    "ACTIVATION_RECEIPT_SCHEMA",
    "ACTIVATION_RECEIPTS_AVAILABLE",
    "ACTIVATION_STATE",
    "LIMITATIONS",
    "MACOS_HOST_AUTHORITY_EVIDENCE_SCHEMA",
    "NATIVE_HOST_EVIDENCE_SCHEMA",
    "NativeHostEvidenceError",
    "PRODUCTION_ACTIVATION",
    "SIGNED_NATIVE_OBJECT_EVIDENCE_SCHEMA",
    "canonical_evidence_bytes",
    "canonical_json_bytes",
    "collect_native_host_evidence",
    "inspect_signed_macho_fd",
    "measure_macos_host_authority",
    "verify_canonical_evidence",
]
