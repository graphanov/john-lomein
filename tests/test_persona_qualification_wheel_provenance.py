from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import stat
import struct
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_wheel_provenance as provenance,
)


WHEEL_FILENAME = "acme_widget-1.2.3-py3-none-any.whl"
DIST_INFO = "acme_widget-1.2.3.dist-info"
METADATA_PATH = f"{DIST_INFO}/METADATA"
WHEEL_PATH = f"{DIST_INFO}/WHEEL"
RECORD_PATH = f"{DIST_INFO}/RECORD"


def _record_digest(value: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(
        b"="
    ).decode("ascii")


def _record_bytes(
    payloads: list[tuple[str, bytes, int]],
    transform: Callable[[list[list[str]]], list[list[str]]] | None,
) -> bytes:
    rows = [
        [path, f"sha256={_record_digest(value)}", str(len(value))]
        for path, value, _mode in payloads
    ]
    rows.append([RECORD_PATH, "", ""])
    if transform is not None:
        rows = transform(rows)
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def _zip_info(path: str, mode: int, *, compression: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, date_time=(2025, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.compress_type = compression
    info.external_attr = mode << 16
    return info


def _patch_first_entry_flag(path: Path, flag: int) -> None:
    value = bytearray(path.read_bytes())
    local = value.find(b"PK\x03\x04")
    central = value.find(b"PK\x01\x02")
    if local < 0 or central < 0:
        raise AssertionError("fixture ZIP signatures missing")
    local_flags = struct.unpack_from("<H", value, local + 6)[0]
    central_flags = struct.unpack_from("<H", value, central + 8)[0]
    struct.pack_into("<H", value, local + 6, local_flags | flag)
    struct.pack_into("<H", value, central + 8, central_flags | flag)
    path.write_bytes(value)


class PersonaQualificationWheelProvenanceTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.wheels = self.base / "wheels"
        self.vendor = self.base / "vendor"
        self.wheels.mkdir()
        self.vendor.mkdir()

    def _build(
        self,
        *,
        filename: str = WHEEL_FILENAME,
        metadata_name: str = "Acme.Widget",
        metadata_version: str = "1.2.3",
        wheel_tags: tuple[str, ...] = ("py3-none-any",),
        extras: list[tuple[str, bytes, int]] | None = None,
        record_transform: (
            Callable[[list[list[str]]], list[list[str]]] | None
        ) = None,
        compression: int = zipfile.ZIP_STORED,
        extract: bool = True,
    ) -> Path:
        metadata = (
            "Metadata-Version: 2.4\n"
            f"Name: {metadata_name}\n"
            f"Version: {metadata_version}\n"
            "Summary: fixture\n"
            "\n"
        ).encode("utf-8")
        wheel_metadata = (
            "Wheel-Version: 1.0\n"
            "Generator: john-lomein-test\n"
            "Root-Is-Purelib: true\n"
            + "".join(f"Tag: {tag}\n" for tag in wheel_tags)
            + "\n"
        ).encode("utf-8")
        payloads: list[tuple[str, bytes, int]] = [
            ("acme_widget/__init__.py", b'VERSION = "1.2.3"\n', stat.S_IFREG | 0o644),
            (METADATA_PATH, metadata, stat.S_IFREG | 0o644),
            (WHEEL_PATH, wheel_metadata, stat.S_IFREG | 0o644),
        ]
        payloads.extend(extras or [])
        record = _record_bytes(payloads, record_transform)
        payloads.append((RECORD_PATH, record, stat.S_IFREG | 0o644))

        wheel_path = self.wheels / filename
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(
                wheel_path,
                "w",
                compression=compression,
                allowZip64=False,
            ) as archive:
                for path, value, mode in payloads:
                    archive.writestr(
                        _zip_info(path, mode, compression=compression),
                        value,
                    )
        if extract:
            for path, value, mode in payloads:
                destination = self.vendor.joinpath(*path.split("/"))
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(value)
                destination.chmod(stat.S_IMODE(mode))
        return wheel_path

    def _inspect(
        self,
        *,
        filename: str = WHEEL_FILENAME,
        **unexpected: Any,
    ) -> dict[str, Any]:
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        wheel_directory_fd = os.open(self.wheels, directory_flags)
        vendor_fd = os.open(self.vendor, directory_flags)
        try:
            return provenance.inspect_retained_wheel_provenance(
                wheel_directory_fd=wheel_directory_fd,
                wheel_filename=filename,
                installed_vendor_root_fd=vendor_fd,
                **unexpected,
            )
        finally:
            os.close(vendor_fd)
            os.close(wheel_directory_fd)

    def _assert_rejected(self, code: str) -> None:
        with self.assertRaises(provenance.WheelProvenanceError) as caught:
            self._inspect()
        self.assertEqual(caught.exception.code, code)

    def test_exact_retained_wheel_and_installed_union_are_proven(self) -> None:
        wheel_path = self._build()

        first = self._inspect()
        second = self._inspect()

        self.assertEqual(first, second)
        self.assertEqual(
            first["schema_version"],
            provenance.WHEEL_PROVENANCE_EVIDENCE_SCHEMA,
        )
        self.assertEqual(
            first["source_wheel"]["archive_sha256"],
            hashlib.sha256(wheel_path.read_bytes()).hexdigest(),
        )
        self.assertFalse(first["source_wheel"]["origin_proven"])
        self.assertFalse(first["source_wheel"]["source_url_proven"])
        self.assertEqual(first["package"]["normalized_distribution"], "acme-widget")
        self.assertEqual(first["package"]["normalized_version"], "1.2.3")
        self.assertEqual(first["wheel"]["tags"], ["py3-none-any"])
        self.assertEqual(first["record"]["row_count"], 4)
        self.assertEqual(
            {item["path"] for item in first["mappings"]},
            {
                "acme_widget/__init__.py",
                METADATA_PATH,
                WHEEL_PATH,
                RECORD_PATH,
            },
        )
        self.assertEqual(
            first["digests"]["installed_inventory_sha256"],
            first["installed_vendor_root"]["inventory_sha256"],
        )
        unsigned = dict(first)
        evidence_sha256 = unsigned.pop("evidence_sha256")
        self.assertEqual(
            evidence_sha256,
            hashlib.sha256(
                provenance.canonical_json_bytes(unsigned)
            ).hexdigest(),
        )
        self.assertFalse(first["activation"]["production_activation"])
        self.assertFalse(provenance.PRODUCTION_ACTIVATION)
        self.assertFalse(provenance.ACTIVATION_RECEIPTS_AVAILABLE)

    def test_caller_hash_and_url_claims_are_not_accepted(self) -> None:
        self._build()

        with self.assertRaises(TypeError):
            self._inspect(
                source_url="https://attacker.invalid/fake.whl",
                wheel_sha256="0" * 64,
            )

        evidence = self._inspect()
        self.assertNotIn("source_url", evidence["source_wheel"])
        self.assertNotEqual(
            evidence["source_wheel"]["archive_sha256"],
            "0" * 64,
        )

    def test_zip_paths_are_canonical_and_confined(self) -> None:
        hostile_paths = (
            "../escape.py",
            "/absolute.py",
            "C:/drive.py",
            "acme_widget\\alias.py",
            "acme_widget/../../outside.py",
        )
        for index, path in enumerate(hostile_paths):
            with self.subTest(path=path):
                case = self.base / f"case-{index}"
                case.mkdir()
                old_wheels, old_vendor = self.wheels, self.vendor
                self.wheels, self.vendor = case / "wheels", case / "vendor"
                self.wheels.mkdir()
                self.vendor.mkdir()
                try:
                    self._build(
                        extras=[(path, b"hostile", stat.S_IFREG | 0o644)],
                        extract=False,
                    )
                    self._assert_rejected("wheel_zip_path_invalid")
                finally:
                    self.wheels, self.vendor = old_wheels, old_vendor

    def test_record_parent_escape_is_rejected(self) -> None:
        def transform(rows: list[list[str]]) -> list[list[str]]:
            rows[0][0] = "../../outside.py"
            return rows

        self._build(record_transform=transform)

        self._assert_rejected("wheel_record_path_invalid")

    def test_record_requires_sha256_unpadded_hash_and_exact_size(self) -> None:
        transforms: tuple[
            tuple[str, Callable[[list[list[str]]], list[list[str]]], str],
            ...,
        ] = (
            (
                "missing hash",
                lambda rows: [[rows[0][0], "", rows[0][2]], *rows[1:]],
                "wheel_record_hash_algorithm_invalid",
            ),
            (
                "unsupported algorithm",
                lambda rows: [
                    [rows[0][0], rows[0][1].replace("sha256=", "sha512="), rows[0][2]],
                    *rows[1:],
                ],
                "wheel_record_hash_algorithm_invalid",
            ),
            (
                "padding",
                lambda rows: [
                    [rows[0][0], rows[0][1] + "=", rows[0][2]],
                    *rows[1:],
                ],
                "wheel_record_hash_encoding_invalid",
            ),
            (
                "missing size",
                lambda rows: [[rows[0][0], rows[0][1], ""], *rows[1:]],
                "wheel_record_size_invalid",
            ),
            (
                "wrong size",
                lambda rows: [[rows[0][0], rows[0][1], "999"], *rows[1:]],
                "wheel_record_size_mismatch",
            ),
        )
        for index, (label, transform, code) in enumerate(transforms):
            with self.subTest(label=label):
                case = self.base / f"record-case-{index}"
                case.mkdir()
                old_wheels, old_vendor = self.wheels, self.vendor
                self.wheels, self.vendor = case / "wheels", case / "vendor"
                self.wheels.mkdir()
                self.vendor.mkdir()
                try:
                    self._build(record_transform=transform)
                    self._assert_rejected(code)
                finally:
                    self.wheels, self.vendor = old_wheels, old_vendor

    def test_record_must_cover_archive_exactly_once(self) -> None:
        def duplicate(rows: list[list[str]]) -> list[list[str]]:
            return [rows[0], *rows]

        self._build(record_transform=duplicate)
        self._assert_rejected("wheel_record_duplicate_path")

    def test_installed_payload_bytes_and_union_must_match(self) -> None:
        self._build()
        (self.vendor / "acme_widget" / "__init__.py").write_bytes(b"tampered\n")

        self._assert_rejected("installed_archive_payload_mismatch")

    def test_unexpected_installed_payload_is_rejected(self) -> None:
        self._build()
        (self.vendor / "unexpected.py").write_text(
            "unexpected = True\n",
            encoding="utf-8",
        )

        self._assert_rejected("installed_archive_file_union_mismatch")

    def test_zip_duplicate_and_case_aliases_are_rejected(self) -> None:
        cases = (
            (
                "duplicate",
                [
                    ("acme_widget/alias.py", b"one", stat.S_IFREG | 0o644),
                    ("acme_widget/alias.py", b"two", stat.S_IFREG | 0o644),
                ],
                "wheel_zip_duplicate_entry",
            ),
            (
                "casefold",
                [
                    ("acme_widget/Alias.py", b"one", stat.S_IFREG | 0o644),
                    ("acme_widget/alias.py", b"two", stat.S_IFREG | 0o644),
                ],
                "wheel_zip_casefold_or_type_collision",
            ),
        )
        for index, (label, extras, code) in enumerate(cases):
            with self.subTest(label=label):
                case = self.base / f"alias-case-{index}"
                case.mkdir()
                old_wheels, old_vendor = self.wheels, self.vendor
                self.wheels, self.vendor = case / "wheels", case / "vendor"
                self.wheels.mkdir()
                self.vendor.mkdir()
                try:
                    self._build(extras=extras, extract=False)
                    self._assert_rejected(code)
                finally:
                    self.wheels, self.vendor = old_wheels, old_vendor

    def test_zip_symlink_and_special_modes_are_rejected(self) -> None:
        modes = (
            stat.S_IFLNK | 0o777,
            stat.S_IFIFO | 0o600,
        )
        for index, mode in enumerate(modes):
            with self.subTest(mode=oct(mode)):
                case = self.base / f"mode-case-{index}"
                case.mkdir()
                old_wheels, old_vendor = self.wheels, self.vendor
                self.wheels, self.vendor = case / "wheels", case / "vendor"
                self.wheels.mkdir()
                self.vendor.mkdir()
                try:
                    self._build(
                        extras=[("acme_widget/hostile", b"target", mode)],
                        extract=False,
                    )
                    self._assert_rejected(
                        "wheel_zip_special_or_symlink_entry_forbidden"
                    )
                finally:
                    self.wheels, self.vendor = old_wheels, old_vendor

    def test_zip_compression_ratio_is_bounded(self) -> None:
        self._build(
            extras=[
                (
                    "acme_widget/highly-compressible.bin",
                    b"\x00" * 200_000,
                    stat.S_IFREG | 0o644,
                )
            ],
            compression=zipfile.ZIP_DEFLATED,
            extract=False,
        )

        self._assert_rejected("wheel_zip_compression_ratio_exceeded")

    def test_zip_encrypted_flag_is_rejected_before_payload_read(self) -> None:
        wheel_path = self._build(extract=False)
        _patch_first_entry_flag(wheel_path, 0x0001)

        self._assert_rejected("wheel_zip_encrypted_entry_forbidden")

    def test_metadata_distribution_and_version_match_filename(self) -> None:
        cases = (
            (
                "distribution",
                {"metadata_name": "Other"},
                "wheel_metadata_distribution_mismatch",
            ),
            (
                "version",
                {"metadata_version": "9.9.9"},
                "wheel_metadata_version_mismatch",
            ),
        )
        for index, (label, arguments, code) in enumerate(cases):
            with self.subTest(label=label):
                case = self.base / f"metadata-case-{index}"
                case.mkdir()
                old_wheels, old_vendor = self.wheels, self.vendor
                self.wheels, self.vendor = case / "wheels", case / "vendor"
                self.wheels.mkdir()
                self.vendor.mkdir()
                try:
                    self._build(**arguments)
                    self._assert_rejected(code)
                finally:
                    self.wheels, self.vendor = old_wheels, old_vendor

    def test_wheel_tags_match_filename_expansion(self) -> None:
        self._build(wheel_tags=("cp313-none-any",))

        self._assert_rejected("wheel_metadata_tags_mismatch")

    def test_retained_archive_must_be_regular_unique_link(self) -> None:
        wheel_path = self._build()
        linked = self.wheels / "second-name.whl"
        os.link(wheel_path, linked)

        self._assert_rejected("wheel_archive_hardlink_forbidden")

    def test_installed_symlink_and_hardlink_are_rejected(self) -> None:
        cases = ("symlink", "hardlink")
        for index, kind in enumerate(cases):
            with self.subTest(kind=kind):
                case = self.base / f"installed-link-case-{index}"
                case.mkdir()
                old_wheels, old_vendor = self.wheels, self.vendor
                self.wheels, self.vendor = case / "wheels", case / "vendor"
                self.wheels.mkdir()
                self.vendor.mkdir()
                try:
                    self._build()
                    target = self.vendor / "acme_widget" / "__init__.py"
                    if kind == "symlink":
                        target.unlink()
                        target.symlink_to(self.vendor / METADATA_PATH)
                        code = "installed_symlink_or_special_file_forbidden"
                    else:
                        extra = self.vendor / "hardlink.py"
                        os.link(target, extra)
                        code = "installed_hardlink_forbidden"
                    self._assert_rejected(code)
                finally:
                    self.wheels, self.vendor = old_wheels, old_vendor


if __name__ == "__main__":
    unittest.main()
