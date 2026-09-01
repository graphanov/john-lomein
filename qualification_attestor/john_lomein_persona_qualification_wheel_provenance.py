#!/usr/bin/env python3
"""Dormant, descriptor-bound wheel provenance closure.

This module proves a deliberately narrow statement:

* a retained local wheel archive has one exact SHA-256 digest;
* its ZIP structure, wheel metadata, and RECORD are internally coherent;
* one retained installed vendor-root descriptor contains an exact extraction
  of every archive payload, with no additional payload or directory; and
* every installed byte is bound to the wheel's RECORD (except RECORD's
  intentionally unhashed self row, whose bytes are still compared directly).

The authoritative API accepts retained directory descriptors.  It does not
accept a source URL, caller-supplied wheel digest, lockfile claim, installer
receipt, or package-index assertion.  Consequently it proves local artifact
closure, not upstream origin.

This is an engineering primitive.  It is not connected to production
activation and cannot issue an activation receipt.
"""

from __future__ import annotations

import base64
import binascii
import csv
import email.policy
import hashlib
import io
import json
import os
import re
import stat
import struct
import unicodedata
import zipfile
import zlib
from email.parser import BytesParser
from typing import Any


WHEEL_PROVENANCE_EVIDENCE_SCHEMA = (
    "john-lomein.persona-qualification-wheel-provenance-evidence.v1"
)
PRODUCTION_ACTIVATION = False
ACTIVATION_RECEIPTS_AVAILABLE = False
ACTIVATION_RECEIPT_SCHEMA = None

MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 50_000
MAX_ENTRY_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_PATH_BYTES = 4_096
MAX_PATH_DEPTH = 128
MAX_PATH_SEGMENT_BYTES = 255
MAX_METADATA_BYTES = 4 * 1024 * 1024
MAX_RECORD_BYTES = 64 * 1024 * 1024
MAX_EXTRA_FIELD_BYTES = 64 * 1024
MAX_INSTALLED_FILES = 50_000
MAX_INSTALLED_DIRECTORIES = 50_000
MAX_INSTALLED_BYTES = 2 * 1024 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024

_CENTRAL_HEADER = struct.Struct("<4s6H3I5H2I")
_LOCAL_HEADER = struct.Struct("<4s5H3I2H")
_EOCD = struct.Struct("<4s4H2IH")
_ZIP64_SENTINEL_16 = 0xFFFF
_ZIP64_SENTINEL_32 = 0xFFFFFFFF
_UTF8_FLAG = 0x0800
_ENCRYPTED_FLAG = 0x0001
_DATA_DESCRIPTOR_FLAG = 0x0008
_DEFLATE_OPTION_FLAGS = 0x0006
_FORBIDDEN_EXTRA_FIELDS = {
    0x0001,  # ZIP64: intentionally outside this bounded proof format.
    0x7075,  # Unicode path alias.
    0x9901,  # AES encryption.
}
_SUPPORTED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_WINDOWS_ABSOLUTE_RE = re.compile(r"^[A-Za-z]:")
_WHEEL_LEAF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.!+~-]{0,239}\.whl$")
_DISTRIBUTION_VALUE_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,238}[A-Za-z0-9])?$"
)
_WHEEL_COMPONENT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.]*$")
_WHEEL_VERSION_COMPONENT_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.!+]*$"
)
_BUILD_TAG_RE = re.compile(r"^[0-9][A-Za-z0-9_]*$")
_TAG_ATOM_RE = re.compile(r"^[a-z0-9_]+$")
_RECORD_SIZE_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")
_RECORD_DIGEST_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_VERSION_RE = re.compile(
    r"""
    ^
    v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?:
        [-_.]?
        (?P<pre_label>a|b|c|rc|alpha|beta|pre|preview)
        [-_.]?
        (?P<pre_number>[0-9]+)?
    )?
    (?:
        (?:
            -(?P<post_number_short>[0-9]+)
        )
        |
        (?:
            [-_.]?
            (?P<post_label>post|rev|r)
            [-_.]?
            (?P<post_number>[0-9]+)?
        )
    )?
    (?:
        [-_.]?
        (?P<dev_label>dev)
        [-_.]?
        (?P<dev_number>[0-9]+)?
    )?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    $
    """,
    re.IGNORECASE | re.VERBOSE,
)

ACTIVATION_STATE = {
    "activation_receipt_schema": None,
    "activation_receipts_available": False,
    "production_activation": False,
    "route_status": "dormant-not-consumed-by-protected-route",
}

LIMITATIONS = [
    "proves-retained-local-wheel-not-upstream-origin-or-source-url",
    "proves-exact-extraction-only-no-data-relocation-or-generated-files",
    "supports-single-disk-non-zip64-stored-or-deflated-wheel-archives-only",
    "supports-wheel-metadata-version-1.0-and-a-strict-pep440-version-subset",
    "does-not-prove-lockfile-resolution-download-transport-or-index-identity",
    "does-not-prove-installer-process-identity-or-privileged-install-transaction",
    "does-not-prove-code-signature-notarization-or-live-runtime-import",
    "does-not-activate-production-or-issue-activation-receipts",
]


class WheelProvenanceError(ValueError):
    """Stable fail-closed wheel provenance error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _error(code: str) -> WheelProvenanceError:
    return WheelProvenanceError(code)


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize generated evidence in one deterministic UTF-8 form."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _same_object(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
    )


def _require_directory_descriptor(descriptor: int, *, field: str) -> os.stat_result:
    try:
        value = os.fstat(descriptor)
    except (OSError, TypeError, ValueError) as exc:
        raise _error(f"{field}_descriptor_invalid") from exc
    if not stat.S_ISDIR(value.st_mode):
        raise _error(f"{field}_not_directory")
    return value


def _validate_wheel_leaf(value: str) -> str:
    if not isinstance(value, str):
        raise _error("wheel_filename_type_invalid")
    if value != unicodedata.normalize("NFC", value):
        raise _error("wheel_filename_not_nfc")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise _error("wheel_filename_encoding_invalid") from exc
    if not encoded or len(encoded) > MAX_PATH_SEGMENT_BYTES:
        raise _error("wheel_filename_length_invalid")
    if (
        "/" in value
        or "\\" in value
        or value in {".", ".."}
        or _CONTROL_RE.search(value)
        or not _WHEEL_LEAF_RE.fullmatch(value)
    ):
        raise _error("wheel_filename_invalid")
    return value


def _canonical_relative_path(value: str, *, field: str) -> str:
    if not isinstance(value, str):
        raise _error(f"{field}_path_type_invalid")
    if value != unicodedata.normalize("NFC", value):
        raise _error(f"{field}_path_not_nfc")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise _error(f"{field}_path_encoding_invalid") from exc
    if not encoded or len(encoded) > MAX_PATH_BYTES:
        raise _error(f"{field}_path_length_invalid")
    if (
        value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or "//" in value
        or _WINDOWS_ABSOLUTE_RE.match(value)
        or _CONTROL_RE.search(value)
    ):
        raise _error(f"{field}_path_invalid")
    parts = value.split("/")
    if len(parts) > MAX_PATH_DEPTH:
        raise _error(f"{field}_path_depth_exceeded")
    for part in parts:
        try:
            part_bytes = part.encode("utf-8", "strict")
        except UnicodeError as exc:
            raise _error(f"{field}_path_encoding_invalid") from exc
        if (
            part in {"", ".", ".."}
            or len(part_bytes) > MAX_PATH_SEGMENT_BYTES
            or _CONTROL_RE.search(part)
        ):
            raise _error(f"{field}_path_invalid")
    return value


def _canonical_segment(value: str, *, field: str) -> str:
    path = _canonical_relative_path(value, field=field)
    if "/" in path:
        raise _error(f"{field}_segment_invalid")
    return path


def _case_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


class _PreadReader(io.RawIOBase):
    """Seekable, offset-independent view over a retained regular-file fd."""

    def __init__(self, descriptor: int, size: int) -> None:
        super().__init__()
        if not hasattr(os, "pread"):
            raise _error("wheel_pread_unavailable")
        self._descriptor = descriptor
        self._size = size
        self._offset = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        self._checkClosed()
        return self._offset

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        self._checkClosed()
        if whence == os.SEEK_SET:
            target = offset
        elif whence == os.SEEK_CUR:
            target = self._offset + offset
        elif whence == os.SEEK_END:
            target = self._size + offset
        else:
            raise ValueError("invalid whence")
        if target < 0:
            raise ValueError("negative seek position")
        self._offset = target
        return target

    def read(self, size: int = -1) -> bytes:
        self._checkClosed()
        if size is None or size < 0:
            size = max(0, self._size - self._offset)
        else:
            size = min(size, max(0, self._size - self._offset))
        if size == 0:
            return b""
        try:
            value = os.pread(self._descriptor, size, self._offset)
        except OSError as exc:
            raise _error("wheel_archive_read_failed") from exc
        self._offset += len(value)
        return value

    def readinto(self, buffer: Any) -> int:
        value = self.read(len(buffer))
        buffer[: len(value)] = value
        return len(value)


def _pread_exact(descriptor: int, offset: int, size: int, *, field: str) -> bytes:
    if size < 0:
        raise _error(f"{field}_range_invalid")
    result = bytearray()
    while len(result) < size:
        try:
            chunk = os.pread(descriptor, size - len(result), offset + len(result))
        except OSError as exc:
            raise _error(f"{field}_read_failed") from exc
        if not chunk:
            raise _error(f"{field}_truncated")
        result.extend(chunk)
    return bytes(result)


def _sha256_fd(descriptor: int, size: int, *, field: str) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        amount = min(READ_CHUNK_BYTES, size - offset)
        try:
            chunk = os.pread(descriptor, amount, offset)
        except OSError as exc:
            raise _error(f"{field}_read_failed") from exc
        if not chunk:
            raise _error(f"{field}_truncated")
        digest.update(chunk)
        offset += len(chunk)
    try:
        if os.pread(descriptor, 1, size):
            raise _error(f"{field}_size_changed")
    except OSError as exc:
        raise _error(f"{field}_read_failed") from exc
    return digest.hexdigest()


def _decode_zip_name(raw: bytes, flags: int, *, field: str) -> str:
    if b"\x00" in raw:
        raise _error(f"{field}_nul_forbidden")
    try:
        if flags & _UTF8_FLAG:
            return raw.decode("utf-8", "strict")
        return raw.decode("cp437", "strict")
    except UnicodeError as exc:
        raise _error(f"{field}_encoding_invalid") from exc


def _validate_extra_fields(value: bytes, *, field: str) -> None:
    if len(value) > MAX_EXTRA_FIELD_BYTES:
        raise _error(f"{field}_too_large")
    offset = 0
    while offset < len(value):
        if len(value) - offset < 4:
            raise _error(f"{field}_malformed")
        identifier, size = struct.unpack_from("<HH", value, offset)
        offset += 4
        if size > len(value) - offset:
            raise _error(f"{field}_malformed")
        if identifier in _FORBIDDEN_EXTRA_FIELDS:
            raise _error(f"{field}_semantic_alias_forbidden")
        offset += size


def _validate_general_flags(flags: int, compression: int) -> None:
    if flags & _ENCRYPTED_FLAG:
        raise _error("wheel_zip_encrypted_entry_forbidden")
    if flags & _DATA_DESCRIPTOR_FLAG:
        raise _error("wheel_zip_data_descriptor_forbidden")
    allowed = _UTF8_FLAG
    if compression == zipfile.ZIP_DEFLATED:
        allowed |= _DEFLATE_OPTION_FLAGS
    if flags & ~allowed:
        raise _error("wheel_zip_general_flags_unsupported")


def _parse_central_directory(
    descriptor: int,
    archive_size: int,
    archive: zipfile.ZipFile,
) -> list[zipfile.ZipInfo]:
    infos = archive.infolist()
    if not infos or len(infos) > MAX_ARCHIVE_ENTRIES:
        raise _error("wheel_zip_entry_count_invalid")
    start = archive.start_dir
    if not isinstance(start, int) or start <= 0 or start >= archive_size:
        raise _error("wheel_zip_central_directory_invalid")
    cursor = start
    for info in infos:
        fixed = _pread_exact(
            descriptor,
            cursor,
            _CENTRAL_HEADER.size,
            field="wheel_zip_central_header",
        )
        (
            signature,
            version_made,
            _version_needed,
            flags,
            compression,
            _modified_time,
            _modified_date,
            crc,
            compressed_size,
            uncompressed_size,
            filename_size,
            extra_size,
            comment_size,
            disk_start,
            _internal_attributes,
            external_attributes,
            local_offset,
        ) = _CENTRAL_HEADER.unpack(fixed)
        if signature != b"PK\x01\x02":
            raise _error("wheel_zip_central_header_invalid")
        if (
            compressed_size == _ZIP64_SENTINEL_32
            or uncompressed_size == _ZIP64_SENTINEL_32
            or local_offset == _ZIP64_SENTINEL_32
            or disk_start != 0
        ):
            raise _error("wheel_zip_zip64_or_multidisk_forbidden")
        variable_size = filename_size + extra_size + comment_size
        variable = _pread_exact(
            descriptor,
            cursor + _CENTRAL_HEADER.size,
            variable_size,
            field="wheel_zip_central_header",
        )
        raw_name = variable[:filename_size]
        extra = variable[filename_size : filename_size + extra_size]
        comment = variable[filename_size + extra_size :]
        decoded_name = _decode_zip_name(
            raw_name,
            flags,
            field="wheel_zip_central_filename",
        )
        if comment or info.comment:
            raise _error("wheel_zip_entry_comment_forbidden")
        _validate_extra_fields(extra, field="wheel_zip_central_extra")
        if (
            decoded_name != info.filename
            or flags != info.flag_bits
            or compression != info.compress_type
            or crc != info.CRC
            or compressed_size != info.compress_size
            or uncompressed_size != info.file_size
            or external_attributes != info.external_attr
            or local_offset != info.header_offset
            or (version_made >> 8) != info.create_system
            or extra != info.extra
        ):
            raise _error("wheel_zip_central_directory_disagreement")
        cursor += _CENTRAL_HEADER.size + variable_size

    eocd_bytes = _pread_exact(
        descriptor,
        cursor,
        _EOCD.size,
        field="wheel_zip_eocd",
    )
    (
        signature,
        disk_number,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_size,
    ) = _EOCD.unpack(eocd_bytes)
    if signature != b"PK\x05\x06":
        raise _error("wheel_zip_eocd_invalid")
    if (
        disk_number != 0
        or central_disk != 0
        or disk_entries != len(infos)
        or total_entries != len(infos)
        or disk_entries == _ZIP64_SENTINEL_16
        or total_entries == _ZIP64_SENTINEL_16
    ):
        raise _error("wheel_zip_zip64_or_multidisk_forbidden")
    if (
        central_size != cursor - start
        or central_offset != start
        or comment_size != 0
        or cursor + _EOCD.size != archive_size
    ):
        raise _error("wheel_zip_trailing_or_hidden_data_forbidden")
    return infos


def _validate_local_headers(
    descriptor: int,
    central_start: int,
    infos: list[zipfile.ZipInfo],
) -> None:
    ordered = sorted(infos, key=lambda value: value.header_offset)
    if ordered[0].header_offset != 0:
        raise _error("wheel_zip_prefix_data_forbidden")
    expected_offset = 0
    observed_offsets: set[int] = set()
    for info in ordered:
        if info.header_offset in observed_offsets:
            raise _error("wheel_zip_overlapping_entry_forbidden")
        observed_offsets.add(info.header_offset)
        if info.header_offset != expected_offset:
            raise _error("wheel_zip_hidden_or_overlapping_data_forbidden")
        fixed = _pread_exact(
            descriptor,
            info.header_offset,
            _LOCAL_HEADER.size,
            field="wheel_zip_local_header",
        )
        (
            signature,
            _version_needed,
            flags,
            compression,
            _modified_time,
            _modified_date,
            crc,
            compressed_size,
            uncompressed_size,
            filename_size,
            extra_size,
        ) = _LOCAL_HEADER.unpack(fixed)
        if signature != b"PK\x03\x04":
            raise _error("wheel_zip_local_header_invalid")
        variable = _pread_exact(
            descriptor,
            info.header_offset + _LOCAL_HEADER.size,
            filename_size + extra_size,
            field="wheel_zip_local_header",
        )
        raw_name = variable[:filename_size]
        extra = variable[filename_size:]
        decoded_name = _decode_zip_name(
            raw_name,
            flags,
            field="wheel_zip_local_filename",
        )
        _validate_extra_fields(extra, field="wheel_zip_local_extra")
        if (
            decoded_name != info.filename
            or flags != info.flag_bits
            or compression != info.compress_type
            or crc != info.CRC
            or compressed_size != info.compress_size
            or uncompressed_size != info.file_size
        ):
            raise _error("wheel_zip_local_central_disagreement")
        expected_offset = (
            info.header_offset
            + _LOCAL_HEADER.size
            + filename_size
            + extra_size
            + info.compress_size
        )
    if expected_offset != central_start:
        raise _error("wheel_zip_hidden_or_overlapping_data_forbidden")


def _validate_zip_mode(info: zipfile.ZipInfo, *, is_directory: bool) -> int | None:
    if info.create_system not in {0, 3}:
        raise _error("wheel_zip_creator_system_unsupported")
    dos_attributes = info.external_attr & 0xFFFF
    if bool(dos_attributes & 0x10) != is_directory:
        raise _error("wheel_zip_directory_attribute_mismatch")
    if info.create_system != 3:
        return None
    unix_mode = (info.external_attr >> 16) & 0xFFFF
    object_type = stat.S_IFMT(unix_mode)
    if object_type == 0:
        return stat.S_IMODE(unix_mode)
    if is_directory and not stat.S_ISDIR(unix_mode):
        raise _error("wheel_zip_special_or_symlink_entry_forbidden")
    if not is_directory and not stat.S_ISREG(unix_mode):
        raise _error("wheel_zip_special_or_symlink_entry_forbidden")
    return stat.S_IMODE(unix_mode)


def _build_archive_tree(
    infos: list[zipfile.ZipInfo],
) -> tuple[
    dict[str, zipfile.ZipInfo],
    set[str],
    dict[str, int | None],
]:
    files: dict[str, zipfile.ZipInfo] = {}
    explicit_directories: set[str] = set()
    modes: dict[str, int | None] = {}
    raw_names: set[str] = set()
    logical_names: dict[str, tuple[str, str]] = {}
    total_uncompressed = 0

    for info in infos:
        if info.filename in raw_names:
            raise _error("wheel_zip_duplicate_entry")
        raw_names.add(info.filename)
        if info.compress_type not in _SUPPORTED_COMPRESSION:
            raise _error("wheel_zip_compression_unsupported")
        _validate_general_flags(info.flag_bits, info.compress_type)
        if (
            info.file_size < 0
            or info.compress_size < 0
            or info.file_size > MAX_ENTRY_UNCOMPRESSED_BYTES
        ):
            raise _error("wheel_zip_entry_size_exceeded")
        total_uncompressed += info.file_size
        if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise _error("wheel_zip_total_size_exceeded")
        if info.file_size and (
            info.compress_size == 0
            or info.file_size
            > max(1, info.compress_size) * MAX_COMPRESSION_RATIO
        ):
            raise _error("wheel_zip_compression_ratio_exceeded")

        is_directory = info.filename.endswith("/")
        raw_path = info.filename[:-1] if is_directory else info.filename
        path = _canonical_relative_path(raw_path, field="wheel_zip")
        mode = _validate_zip_mode(info, is_directory=is_directory)
        key = _case_key(path)
        previous = logical_names.get(key)
        if previous is not None:
            raise _error("wheel_zip_casefold_or_type_collision")
        logical_names[key] = (path, "directory" if is_directory else "file")
        modes[path] = mode
        if is_directory:
            if info.file_size != 0 or info.compress_size != 0 or info.CRC != 0:
                raise _error("wheel_zip_directory_payload_forbidden")
            explicit_directories.add(path)
        else:
            files[path] = info

    expected_directories = set(explicit_directories)
    for path in [*files, *explicit_directories]:
        parts = path.split("/")
        for index in range(1, len(parts)):
            expected_directories.add("/".join(parts[:index]))

    all_nodes: dict[str, tuple[str, str]] = {}
    for path in sorted(expected_directories):
        key = _case_key(path)
        previous = all_nodes.get(key)
        if previous is not None and previous != (path, "directory"):
            raise _error("wheel_zip_casefold_or_type_collision")
        all_nodes[key] = (path, "directory")
    for path in sorted(files):
        key = _case_key(path)
        previous = all_nodes.get(key)
        if previous is not None:
            raise _error("wheel_zip_casefold_or_type_collision")
        all_nodes[key] = (path, "file")

    return files, expected_directories, modes


def _read_archive_payloads(
    archive: zipfile.ZipFile,
    files: dict[str, zipfile.ZipInfo],
) -> tuple[dict[str, dict[str, Any]], dict[str, bytes]]:
    inventory: dict[str, dict[str, Any]] = {}
    selected: dict[str, bytes] = {}
    for path in sorted(files):
        info = files[path]
        digest = hashlib.sha256()
        captured = bytearray()
        capture_payload = (
            path.endswith(".dist-info/METADATA")
            or path.endswith(".dist-info/WHEEL")
            or path.endswith(".dist-info/RECORD")
        )
        amount = 0
        try:
            with archive.open(info, "r") as stream:
                while True:
                    chunk = stream.read(READ_CHUNK_BYTES)
                    if not chunk:
                        break
                    amount += len(chunk)
                    if amount > info.file_size:
                        raise _error("wheel_zip_payload_size_disagreement")
                    digest.update(chunk)
                    if capture_payload:
                        captured.extend(chunk)
        except WheelProvenanceError:
            raise
        except (OSError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
            raise _error("wheel_zip_payload_integrity_invalid") from exc
        if amount != info.file_size:
            raise _error("wheel_zip_payload_size_disagreement")
        inventory[path] = {
            "path": path,
            "sha256": digest.hexdigest(),
            "size": amount,
        }
        if capture_payload:
            selected[path] = bytes(captured)
    return inventory, selected


def _single_header(message: Any, name: str, *, field: str) -> str:
    values = message.get_all(name, [])
    if len(values) != 1:
        raise _error(f"{field}_{name.lower().replace('-', '_')}_invalid")
    value = str(values[0])
    if value != value.strip() or not value or _CONTROL_RE.search(value):
        raise _error(f"{field}_{name.lower().replace('-', '_')}_invalid")
    return value


def _parse_email_payload(value: bytes, *, field: str, maximum: int) -> Any:
    if not value or len(value) > maximum or b"\x00" in value:
        raise _error(f"{field}_size_or_nul_invalid")
    try:
        message = BytesParser(policy=email.policy.default).parsebytes(value)
    except (UnicodeError, ValueError) as exc:
        raise _error(f"{field}_invalid") from exc
    if message.defects:
        raise _error(f"{field}_defects_forbidden")
    return message


def _normalize_distribution(value: str) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not _DISTRIBUTION_VALUE_RE.fullmatch(value)
    ):
        raise _error("wheel_distribution_invalid")
    normalized = re.sub(r"[-_.]+", "-", value).lower()
    if not normalized:
        raise _error("wheel_distribution_invalid")
    return normalized


def _normalize_version(value: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise _error("wheel_version_invalid")
    matched = _VERSION_RE.fullmatch(value)
    if matched is None:
        raise _error("wheel_version_unsupported")
    epoch = int(matched.group("epoch") or "0")
    release = ".".join(str(int(item)) for item in matched.group("release").split("."))
    normalized = (f"{epoch}!" if epoch else "") + release

    pre_label = matched.group("pre_label")
    if pre_label:
        aliases = {
            "a": "a",
            "alpha": "a",
            "b": "b",
            "beta": "b",
            "c": "rc",
            "pre": "rc",
            "preview": "rc",
            "rc": "rc",
        }
        normalized += aliases[pre_label.lower()]
        normalized += str(int(matched.group("pre_number") or "0"))

    post_short = matched.group("post_number_short")
    post_label = matched.group("post_label")
    if post_short is not None:
        normalized += f".post{int(post_short)}"
    elif post_label is not None:
        normalized += f".post{int(matched.group('post_number') or '0')}"

    if matched.group("dev_label") is not None:
        normalized += f".dev{int(matched.group('dev_number') or '0')}"

    local = matched.group("local")
    if local:
        segments = re.split(r"[-_.]", local.lower())
        normalized_local = [
            str(int(segment)) if segment.isdigit() else segment
            for segment in segments
        ]
        normalized += "+" + ".".join(normalized_local)
    return normalized


def _parse_wheel_filename(
    filename: str,
) -> dict[str, Any]:
    stem = filename[:-4]
    components = stem.split("-")
    if len(components) not in {5, 6}:
        raise _error("wheel_filename_component_count_invalid")
    distribution_component = components[0]
    version_component = components[1]
    if not _WHEEL_COMPONENT_RE.fullmatch(distribution_component):
        raise _error("wheel_filename_distribution_invalid")
    if not _WHEEL_VERSION_COMPONENT_RE.fullmatch(version_component):
        raise _error("wheel_filename_version_invalid")
    build = None
    if len(components) == 6:
        build = components[2]
        if not _BUILD_TAG_RE.fullmatch(build):
            raise _error("wheel_filename_build_tag_invalid")
        python_component, abi_component, platform_component = components[3:]
    else:
        python_component, abi_component, platform_component = components[2:]

    groups: list[list[str]] = []
    for field, component in (
        ("python", python_component),
        ("abi", abi_component),
        ("platform", platform_component),
    ):
        atoms = component.split(".")
        if (
            not atoms
            or any(not _TAG_ATOM_RE.fullmatch(atom) for atom in atoms)
            or len(set(atoms)) != len(atoms)
        ):
            raise _error(f"wheel_filename_{field}_tag_invalid")
        groups.append(atoms)
    expanded_tags = sorted(
        f"{python_tag}-{abi_tag}-{platform_tag}"
        for python_tag in groups[0]
        for abi_tag in groups[1]
        for platform_tag in groups[2]
    )
    return {
        "build_tag": build,
        "distribution_component": distribution_component,
        "normalized_distribution": _normalize_distribution(
            distribution_component
        ),
        "normalized_version": _normalize_version(version_component),
        "tags": expanded_tags,
        "version_component": version_component,
    }


def _parse_metadata(
    value: bytes,
    *,
    filename_identity: dict[str, Any],
) -> dict[str, str]:
    message = _parse_email_payload(
        value,
        field="wheel_metadata",
        maximum=MAX_METADATA_BYTES,
    )
    metadata_version = _single_header(
        message,
        "Metadata-Version",
        field="wheel_metadata",
    )
    name = _single_header(message, "Name", field="wheel_metadata")
    version = _single_header(message, "Version", field="wheel_metadata")
    normalized_distribution = _normalize_distribution(name)
    normalized_version = _normalize_version(version)
    if normalized_distribution != filename_identity["normalized_distribution"]:
        raise _error("wheel_metadata_distribution_mismatch")
    if normalized_version != filename_identity["normalized_version"]:
        raise _error("wheel_metadata_version_mismatch")
    return {
        "metadata_version": metadata_version,
        "name": name,
        "normalized_distribution": normalized_distribution,
        "normalized_version": normalized_version,
        "version": version,
    }


def _parse_wheel_metadata(
    value: bytes,
    *,
    filename_identity: dict[str, Any],
) -> dict[str, Any]:
    message = _parse_email_payload(
        value,
        field="wheel_wheel_metadata",
        maximum=MAX_METADATA_BYTES,
    )
    wheel_version = _single_header(
        message,
        "Wheel-Version",
        field="wheel_wheel_metadata",
    )
    if wheel_version != "1.0":
        raise _error("wheel_metadata_version_unsupported")
    root_is_purelib = _single_header(
        message,
        "Root-Is-Purelib",
        field="wheel_wheel_metadata",
    )
    if root_is_purelib not in {"true", "false"}:
        raise _error("wheel_root_is_purelib_invalid")
    tags = [str(item) for item in message.get_all("Tag", [])]
    if not tags or len(set(tags)) != len(tags):
        raise _error("wheel_metadata_tags_invalid")
    for tag in tags:
        parts = tag.split("-")
        if (
            len(parts) != 3
            or any(not _TAG_ATOM_RE.fullmatch(item) for item in parts)
        ):
            raise _error("wheel_metadata_tags_invalid")
    if sorted(tags) != filename_identity["tags"]:
        raise _error("wheel_metadata_tags_mismatch")

    builds = [str(item) for item in message.get_all("Build", [])]
    expected_build = filename_identity["build_tag"]
    if expected_build is None:
        if builds:
            raise _error("wheel_metadata_build_tag_mismatch")
    elif builds != [expected_build]:
        raise _error("wheel_metadata_build_tag_mismatch")
    return {
        "root_is_purelib": root_is_purelib == "true",
        "tags": sorted(tags),
        "wheel_version": wheel_version,
    }


def _urlsafe_sha256(value: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(
        b"="
    ).decode("ascii")


def _parse_record(
    value: bytes,
    *,
    record_path: str,
    archive_inventory: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not value or len(value) > MAX_RECORD_BYTES or b"\x00" in value:
        raise _error("wheel_record_size_or_nul_invalid")
    try:
        text = value.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise _error("wheel_record_encoding_invalid") from exc
    if text.startswith("\ufeff"):
        raise _error("wheel_record_bom_forbidden")
    try:
        rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except (csv.Error, UnicodeError) as exc:
        raise _error("wheel_record_csv_invalid") from exc
    if not rows or len(rows) > MAX_ARCHIVE_ENTRIES:
        raise _error("wheel_record_row_count_invalid")

    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    case_seen: dict[str, str] = {}
    self_rows = 0
    for row in rows:
        if len(row) != 3:
            raise _error("wheel_record_row_shape_invalid")
        raw_path, encoded_hash, encoded_size = row
        path = _canonical_relative_path(raw_path, field="wheel_record")
        if path != raw_path:
            raise _error("wheel_record_path_not_canonical")
        if path in seen:
            raise _error("wheel_record_duplicate_path")
        seen.add(path)
        key = _case_key(path)
        if key in case_seen:
            raise _error("wheel_record_casefold_collision")
        case_seen[key] = path

        if path == record_path:
            self_rows += 1
            if encoded_hash or encoded_size:
                raise _error("wheel_record_self_row_must_be_unhashed")
            result.append(
                {
                    "path": path,
                    "sha256": archive_inventory[path]["sha256"],
                    "size": archive_inventory[path]["size"],
                    "self_row_unhashed": True,
                }
            )
            continue

        if not encoded_hash.startswith("sha256="):
            raise _error("wheel_record_hash_algorithm_invalid")
        digest_text = encoded_hash[len("sha256=") :]
        if (
            "=" in digest_text
            or not _RECORD_DIGEST_RE.fullmatch(digest_text)
        ):
            raise _error("wheel_record_hash_encoding_invalid")
        try:
            digest_bytes = base64.b64decode(
                digest_text + "=",
                altchars=b"-_",
                validate=True,
            )
        except (ValueError, binascii.Error) as exc:
            raise _error("wheel_record_hash_encoding_invalid") from exc
        if (
            len(digest_bytes) != hashlib.sha256().digest_size
            or base64.urlsafe_b64encode(digest_bytes)
            .rstrip(b"=")
            .decode("ascii")
            != digest_text
        ):
            raise _error("wheel_record_hash_encoding_invalid")
        if not _RECORD_SIZE_RE.fullmatch(encoded_size):
            raise _error("wheel_record_size_invalid")
        if path not in archive_inventory:
            raise _error("wheel_record_external_or_missing_path")
        size = int(encoded_size)
        expected = archive_inventory[path]
        if size != expected["size"]:
            raise _error("wheel_record_size_mismatch")
        if digest_text != _urlsafe_sha256_from_hex(expected["sha256"]):
            raise _error("wheel_record_hash_mismatch")
        result.append(
            {
                "path": path,
                "sha256": expected["sha256"],
                "size": size,
                "self_row_unhashed": False,
            }
        )

    if self_rows != 1:
        raise _error("wheel_record_self_row_invalid")
    if seen != set(archive_inventory):
        raise _error("wheel_record_archive_union_mismatch")
    return sorted(result, key=lambda item: item["path"])


def _urlsafe_sha256_from_hex(value: str) -> str:
    try:
        digest = bytes.fromhex(value)
    except ValueError as exc:
        raise _error("wheel_internal_digest_invalid") from exc
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _hash_regular_file(
    descriptor: int,
    before: os.stat_result,
    *,
    root_device: int,
) -> tuple[str, os.stat_result]:
    if not stat.S_ISREG(before.st_mode):
        raise _error("installed_special_file_forbidden")
    if before.st_dev != root_device:
        raise _error("installed_cross_device_entry_forbidden")
    if before.st_nlink != 1:
        raise _error("installed_hardlink_forbidden")
    if (
        before.st_size < 0
        or before.st_size > MAX_ENTRY_UNCOMPRESSED_BYTES
    ):
        raise _error("installed_file_size_exceeded")
    digest = hashlib.sha256()
    amount = 0
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while amount < before.st_size:
            chunk = os.read(
                descriptor,
                min(READ_CHUNK_BYTES, before.st_size - amount),
            )
            if not chunk:
                raise _error("installed_file_truncated")
            digest.update(chunk)
            amount += len(chunk)
        if os.read(descriptor, 1):
            raise _error("installed_file_size_changed")
        after = os.fstat(descriptor)
    except WheelProvenanceError:
        raise
    except OSError as exc:
        raise _error("installed_file_read_failed") from exc
    if _stat_identity(before) != _stat_identity(after):
        raise _error("installed_file_changed_during_scan")
    return digest.hexdigest(), after


def _scan_installed_root(
    root_descriptor: int,
) -> dict[str, Any]:
    root_before = _require_directory_descriptor(
        root_descriptor,
        field="installed_vendor_root",
    )
    root_device = root_before.st_dev
    files: dict[str, dict[str, Any]] = {}
    directories: dict[str, dict[str, Any]] = {}
    case_nodes: dict[str, tuple[str, str]] = {}
    total_bytes = 0
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if nofollow == 0 or directory_flag == 0:
        raise _error("installed_descriptor_flags_unavailable")

    def register(path: str, object_type: str) -> None:
        key = _case_key(path)
        if key in case_nodes:
            raise _error("installed_casefold_or_type_collision")
        case_nodes[key] = (path, object_type)

    def walk(descriptor: int, relative: str, depth: int) -> None:
        nonlocal total_bytes
        if depth > MAX_PATH_DEPTH:
            raise _error("installed_path_depth_exceeded")
        directory_before = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(directory_before.st_mode)
            or directory_before.st_dev != root_device
        ):
            raise _error("installed_directory_identity_invalid")
        try:
            names_before = sorted(os.listdir(descriptor))
        except OSError as exc:
            raise _error("installed_directory_list_failed") from exc
        if len(names_before) > MAX_INSTALLED_FILES + MAX_INSTALLED_DIRECTORIES:
            raise _error("installed_directory_entry_count_exceeded")
        for name in names_before:
            segment = _canonical_segment(name, field="installed")
            path = f"{relative}/{segment}" if relative else segment
            try:
                entry_stat = os.stat(
                    name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise _error("installed_entry_stat_failed") from exc
            if entry_stat.st_dev != root_device:
                raise _error("installed_cross_device_entry_forbidden")
            object_type = stat.S_IFMT(entry_stat.st_mode)
            if object_type == stat.S_IFDIR:
                register(path, "directory")
                if len(directories) >= MAX_INSTALLED_DIRECTORIES:
                    raise _error("installed_directory_count_exceeded")
                flags = os.O_RDONLY | directory_flag | nofollow | cloexec
                try:
                    child = os.open(name, flags, dir_fd=descriptor)
                except OSError as exc:
                    raise _error("installed_directory_open_failed") from exc
                try:
                    opened = os.fstat(child)
                    if (
                        not _same_object(entry_stat, opened)
                        or _stat_identity(entry_stat) != _stat_identity(opened)
                    ):
                        raise _error("installed_directory_replaced")
                    directories[path] = {
                        "gid": opened.st_gid,
                        "mode": stat.S_IMODE(opened.st_mode),
                        "path": path,
                        "uid": opened.st_uid,
                    }
                    walk(child, path, depth + 1)
                    child_after = os.fstat(child)
                    if _stat_identity(opened) != _stat_identity(child_after):
                        raise _error("installed_directory_changed_during_scan")
                finally:
                    os.close(child)
                try:
                    linked_after = os.stat(
                        name,
                        dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    raise _error("installed_directory_replaced") from exc
                if _stat_identity(entry_stat) != _stat_identity(linked_after):
                    raise _error("installed_directory_replaced")
            elif object_type == stat.S_IFREG:
                register(path, "file")
                if len(files) >= MAX_INSTALLED_FILES:
                    raise _error("installed_file_count_exceeded")
                flags = os.O_RDONLY | nofollow | cloexec
                try:
                    child = os.open(name, flags, dir_fd=descriptor)
                except OSError as exc:
                    raise _error("installed_file_open_failed") from exc
                try:
                    opened = os.fstat(child)
                    if (
                        not _same_object(entry_stat, opened)
                        or _stat_identity(entry_stat) != _stat_identity(opened)
                    ):
                        raise _error("installed_file_replaced")
                    digest, final_stat = _hash_regular_file(
                        child,
                        opened,
                        root_device=root_device,
                    )
                finally:
                    os.close(child)
                try:
                    linked_after = os.stat(
                        name,
                        dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    raise _error("installed_file_replaced") from exc
                if _stat_identity(final_stat) != _stat_identity(linked_after):
                    raise _error("installed_file_replaced")
                total_bytes += final_stat.st_size
                if total_bytes > MAX_INSTALLED_BYTES:
                    raise _error("installed_total_bytes_exceeded")
                files[path] = {
                    "gid": final_stat.st_gid,
                    "mode": stat.S_IMODE(final_stat.st_mode),
                    "path": path,
                    "sha256": digest,
                    "size": final_stat.st_size,
                    "uid": final_stat.st_uid,
                }
            else:
                raise _error("installed_symlink_or_special_file_forbidden")

        try:
            names_after = sorted(os.listdir(descriptor))
            directory_after = os.fstat(descriptor)
        except OSError as exc:
            raise _error("installed_directory_rescan_failed") from exc
        if names_before != names_after:
            raise _error("installed_directory_changed_during_scan")
        if _stat_identity(directory_before) != _stat_identity(directory_after):
            raise _error("installed_directory_changed_during_scan")

    walk(root_descriptor, "", 0)
    root_after = os.fstat(root_descriptor)
    if _stat_identity(root_before) != _stat_identity(root_after):
        raise _error("installed_vendor_root_changed_during_scan")

    inventory = {
        "directories": [directories[path] for path in sorted(directories)],
        "directory_count": len(directories),
        "file_count": len(files),
        "files": [files[path] for path in sorted(files)],
        "total_bytes": total_bytes,
    }
    return {
        "directory_paths": set(directories),
        "file_map": files,
        "inventory": inventory,
        "inventory_sha256": _digest_json(inventory),
    }


def _locate_dist_info(
    archive_files: dict[str, zipfile.ZipInfo],
    archive_directories: set[str],
    filename_identity: dict[str, Any],
) -> tuple[str, str, str, str]:
    candidates: set[str] = set()
    for path in [*archive_files, *archive_directories]:
        for index, part in enumerate(path.split("/")):
            if part.casefold().endswith(".dist-info"):
                if index != 0:
                    raise _error("wheel_dist_info_must_be_top_level")
                candidates.add(part)
    if len(candidates) != 1:
        raise _error("wheel_dist_info_association_invalid")
    dist_info = next(iter(candidates))
    expected = (
        f"{filename_identity['distribution_component']}-"
        f"{filename_identity['version_component']}.dist-info"
    )
    if dist_info != expected:
        raise _error("wheel_dist_info_filename_mismatch")
    metadata_path = f"{dist_info}/METADATA"
    wheel_path = f"{dist_info}/WHEEL"
    record_path = f"{dist_info}/RECORD"
    for path in (metadata_path, wheel_path, record_path):
        if path not in archive_files:
            raise _error("wheel_required_metadata_missing")
    return dist_info, metadata_path, wheel_path, record_path


def _compare_installed_union(
    *,
    archive_inventory: dict[str, dict[str, Any]],
    expected_directories: set[str],
    installed: dict[str, Any],
) -> list[dict[str, Any]]:
    installed_files = installed["file_map"]
    if set(installed_files) != set(archive_inventory):
        raise _error("installed_archive_file_union_mismatch")
    if installed["directory_paths"] != expected_directories:
        raise _error("installed_archive_directory_union_mismatch")
    mappings: list[dict[str, Any]] = []
    for path in sorted(archive_inventory):
        archived = archive_inventory[path]
        observed = installed_files[path]
        if (
            observed["size"] != archived["size"]
            or observed["sha256"] != archived["sha256"]
        ):
            raise _error("installed_archive_payload_mismatch")
        mappings.append(
            {
                "archive_sha256": archived["sha256"],
                "archive_size": archived["size"],
                "installed_sha256": observed["sha256"],
                "installed_size": observed["size"],
                "path": path,
            }
        )
    return mappings


def inspect_retained_wheel_provenance(
    *,
    wheel_directory_fd: int,
    wheel_filename: str,
    installed_vendor_root_fd: int,
) -> dict[str, Any]:
    """Prove one retained wheel-to-installed-tree exact extraction closure.

    ``wheel_directory_fd`` and ``installed_vendor_root_fd`` remain owned by
    the caller.  The wheel is opened relative to the retained directory with
    ``O_NOFOLLOW``.  No path-based fallback is provided at this authority
    boundary.
    """

    filename = _validate_wheel_leaf(wheel_filename)
    wheel_directory_before = _require_directory_descriptor(
        wheel_directory_fd,
        field="wheel_directory",
    )
    _require_directory_descriptor(
        installed_vendor_root_fd,
        field="installed_vendor_root",
    )
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    if nofollow == 0:
        raise _error("wheel_nofollow_unavailable")
    try:
        linked_before = os.stat(
            filename,
            dir_fd=wheel_directory_fd,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise _error("wheel_archive_stat_failed") from exc
    if not stat.S_ISREG(linked_before.st_mode):
        raise _error("wheel_archive_not_regular")
    if linked_before.st_nlink != 1:
        raise _error("wheel_archive_hardlink_forbidden")
    if (
        linked_before.st_size <= 0
        or linked_before.st_size > MAX_ARCHIVE_BYTES
    ):
        raise _error("wheel_archive_size_invalid")
    try:
        wheel_fd = os.open(
            filename,
            os.O_RDONLY | nofollow | cloexec,
            dir_fd=wheel_directory_fd,
        )
    except OSError as exc:
        raise _error("wheel_archive_open_failed") from exc

    try:
        opened = os.fstat(wheel_fd)
        if (
            not _same_object(linked_before, opened)
            or _stat_identity(linked_before) != _stat_identity(opened)
        ):
            raise _error("wheel_archive_replaced")
        source_sha256 = _sha256_fd(
            wheel_fd,
            opened.st_size,
            field="wheel_archive",
        )
        reader = _PreadReader(wheel_fd, opened.st_size)
        try:
            with zipfile.ZipFile(reader, "r", allowZip64=False) as archive:
                infos = _parse_central_directory(
                    wheel_fd,
                    opened.st_size,
                    archive,
                )
                _validate_local_headers(wheel_fd, archive.start_dir, infos)
                (
                    archive_files,
                    expected_directories,
                    archive_modes,
                ) = _build_archive_tree(infos)
                archive_inventory, selected = _read_archive_payloads(
                    archive,
                    archive_files,
                )
        except WheelProvenanceError:
            raise
        except (OSError, ValueError, zipfile.BadZipFile, NotImplementedError) as exc:
            raise _error("wheel_zip_invalid") from exc
        finally:
            reader.close()

        filename_identity = _parse_wheel_filename(filename)
        (
            dist_info,
            metadata_path,
            wheel_path,
            record_path,
        ) = _locate_dist_info(
            archive_files,
            expected_directories,
            filename_identity,
        )
        metadata = _parse_metadata(
            selected[metadata_path],
            filename_identity=filename_identity,
        )
        wheel_metadata = _parse_wheel_metadata(
            selected[wheel_path],
            filename_identity=filename_identity,
        )
        record_rows = _parse_record(
            selected[record_path],
            record_path=record_path,
            archive_inventory=archive_inventory,
        )

        installed = _scan_installed_root(installed_vendor_root_fd)
        mappings = _compare_installed_union(
            archive_inventory=archive_inventory,
            expected_directories=expected_directories,
            installed=installed,
        )

        archive_payload_inventory = {
            "directories": sorted(expected_directories),
            "directory_count": len(expected_directories),
            "file_count": len(archive_inventory),
            "files": [
                {
                    **archive_inventory[path],
                    "archive_mode": archive_modes[path],
                }
                for path in sorted(archive_inventory)
            ],
            "total_bytes": sum(
                item["size"] for item in archive_inventory.values()
            ),
        }
        record_evidence = {
            "path": record_path,
            "row_count": len(record_rows),
            "rows": record_rows,
            "sha256": archive_inventory[record_path]["sha256"],
        }
        evidence: dict[str, Any] = {
            "activation": ACTIVATION_STATE,
            "archive_payload_inventory": archive_payload_inventory,
            "dist_info": {
                "directory": dist_info,
                "metadata_path": metadata_path,
                "record_path": record_path,
                "wheel_path": wheel_path,
            },
            "installed_vendor_root": {
                "inventory": installed["inventory"],
                "inventory_sha256": installed["inventory_sha256"],
            },
            "limitations": LIMITATIONS,
            "mappings": mappings,
            "package": {
                **metadata,
                "build_tag": filename_identity["build_tag"],
            },
            "record": record_evidence,
            "schema_version": WHEEL_PROVENANCE_EVIDENCE_SCHEMA,
            "source_wheel": {
                "archive_sha256": source_sha256,
                "archive_size": opened.st_size,
                "entry_count": len(infos),
                "filename": filename,
                "origin_proven": False,
                "source_url_proven": False,
            },
            "wheel": wheel_metadata,
        }
        evidence["digests"] = {
            "archive_payload_inventory_sha256": _digest_json(
                archive_payload_inventory
            ),
            "installed_inventory_sha256": installed["inventory_sha256"],
            "record_evidence_sha256": _digest_json(record_evidence),
            "source_wheel_sha256": source_sha256,
        }
        evidence["evidence_sha256"] = _digest_json(evidence)

        final_sha256 = _sha256_fd(
            wheel_fd,
            opened.st_size,
            field="wheel_archive",
        )
        final_stat = os.fstat(wheel_fd)
        try:
            linked_after = os.stat(
                filename,
                dir_fd=wheel_directory_fd,
                follow_symlinks=False,
            )
            wheel_directory_after = os.fstat(wheel_directory_fd)
        except OSError as exc:
            raise _error("wheel_archive_replaced") from exc
        if (
            final_sha256 != source_sha256
            or _stat_identity(opened) != _stat_identity(final_stat)
            or _stat_identity(linked_before) != _stat_identity(linked_after)
            or _stat_identity(wheel_directory_before)
            != _stat_identity(wheel_directory_after)
        ):
            raise _error("wheel_archive_changed_during_inspection")
        return evidence
    finally:
        os.close(wheel_fd)


__all__ = [
    "ACTIVATION_RECEIPTS_AVAILABLE",
    "ACTIVATION_RECEIPT_SCHEMA",
    "ACTIVATION_STATE",
    "LIMITATIONS",
    "PRODUCTION_ACTIVATION",
    "WHEEL_PROVENANCE_EVIDENCE_SCHEMA",
    "WheelProvenanceError",
    "canonical_json_bytes",
    "inspect_retained_wheel_provenance",
]
