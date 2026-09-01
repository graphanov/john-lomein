from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_native_host_evidence as native,
)


def _open_readonly(path: Path) -> int:
    return os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))


def _assert_error(
    test: unittest.TestCase,
    code: str,
    function: object,
    *args: object,
    **kwargs: object,
) -> None:
    with test.assertRaises(native.NativeHostEvidenceError) as raised:
        function(*args, **kwargs)  # type: ignore[operator]
    test.assertEqual(raised.exception.code, code)


def _unsigned_macho() -> bytes:
    command = struct.pack("<II", native.LC_UUID, 24) + uuid.uuid4().bytes
    header = struct.pack(
        "<IiiIIIII",
        native.MH_MAGIC_64,
        0x0100000C,
        0,
        2,
        1,
        len(command),
        0,
        0,
    )
    return header + command + b"UNSIGNED"


def _cache_header(
    *,
    cache_uuid: uuid.UUID,
    subcache_uuid: uuid.UUID | None = None,
    subcache_suffix: str = ".01",
) -> bytes:
    raw = bytearray(1024)
    raw[:16] = b"dyld_v1  arm64e\x00"
    struct.pack_into("<II", raw, 16, 552, 1)
    raw[88:104] = cache_uuid.bytes
    if subcache_uuid is not None:
        struct.pack_into("<II", raw, 392, 600, 1)
        raw[600:616] = subcache_uuid.bytes
        struct.pack_into("<Q", raw, 616, 0x100000)
        encoded = subcache_suffix.encode("ascii") + b"\x00"
        raw[624 : 624 + len(encoded)] = encoded
    return bytes(raw)


@unittest.skipUnless(
    sys.platform == "darwin"
    and Path("/usr/bin/codesign").exists()
    and shutil.which("xcrun") is not None,
    "requires the macOS compiler and codesign",
)
class PersonaQualificationGeneratedCodeSignatureTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(
            prefix="john-lomein-native-host-evidence-"
        )
        cls.root = Path(cls.temporary.name)
        source = cls.root / "main.c"
        source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        cls.executable = cls.root / "signed-demo"
        architecture = (
            "arm64"
            if subprocess.run(
                ["/usr/bin/uname", "-m"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            == "arm64"
            else "x86_64"
        )
        subprocess.run(
            [
                "xcrun",
                "clang",
                "-arch",
                architecture,
                "-o",
                str(cls.executable),
                str(source),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "/usr/bin/codesign",
                "--force",
                "--sign",
                "-",
                str(cls.executable),
            ],
            check=True,
            capture_output=True,
        )
        cls.signed_bytes = cls.executable.read_bytes()
        fd = _open_readonly(cls.executable)
        try:
            cls.evidence = native.inspect_signed_macho_fd(
                fd,
                object_label="bin/signed-demo",
            )
        finally:
            os.close(fd)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def _mutated_file(self, name: str, raw: bytes) -> Path:
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(0o755)
        return path

    def _inspect_mutated(self, path: Path) -> dict[str, object]:
        fd = _open_readonly(path)
        try:
            return native.inspect_signed_macho_fd(
                fd,
                object_label=f"mutations/{path.name}",
            )
        finally:
            os.close(fd)

    def _signature_coordinates(self) -> tuple[int, int, int, int]:
        signature = self.evidence["slices"][0]["signature"]
        signature_offset = signature["data_offset"]
        signature_size = signature["data_size"]
        raw = self.signed_bytes
        magic, length, count = struct.unpack_from(
            ">III", raw, signature_offset
        )
        self.assertEqual(magic, native.CSMAGIC_EMBEDDED_SIGNATURE)
        self.assertGreaterEqual(count, 1)
        slot, component_offset = struct.unpack_from(
            ">II", raw, signature_offset + 12
        )
        self.assertEqual(slot, native.CSSLOT_CODEDIRECTORY)
        return signature_offset, signature_size, length, component_offset

    def _component_offset(self, wanted_slot: int) -> int:
        signature_offset, _size, _length, _component = (
            self._signature_coordinates()
        )
        count = struct.unpack_from(
            ">I", self.signed_bytes, signature_offset + 8
        )[0]
        for index in range(count):
            slot, component_offset = struct.unpack_from(
                ">II",
                self.signed_bytes,
                signature_offset + 12 + index * 8,
            )
            if slot == wanted_slot:
                return component_offset
        self.fail(f"fixture lacks SuperBlob slot {wanted_slot}")

    def test_real_adhoc_signature_is_descriptor_measured_and_self_digested(
        self,
    ) -> None:
        evidence = self.evidence
        self.assertEqual(evidence["status"], "verified-static-byte-integrity")
        self.assertEqual(evidence["format"], "thin-macho64")
        self.assertEqual(
            evidence["artifact"]["sha256"],
            hashlib.sha256(self.signed_bytes).hexdigest(),
        )
        self.assertEqual(
            evidence["secondary_codesign_observation"]["status"],
            "verified",
        )
        signature = evidence["slices"][0]["signature"]
        self.assertEqual(signature["signature_kind"], "ad-hoc")
        self.assertEqual(signature["requirements"]["count"], 0)
        directory = signature["code_directories"][0]
        self.assertTrue(directory["code_page_hashes_verified"])
        self.assertTrue(directory["adhoc"])
        self.assertFalse(directory["linker_signed"])
        self.assertEqual(len(directory["cdhash"]), 40)
        self.assertEqual(len(directory["code_directory_sha256"]), 64)
        self.assertFalse(evidence["activation"]["production_activation"])
        self.assertFalse(evidence["apple_codesign_semantics_proven"])
        self.assertEqual(
            native.canonical_evidence_bytes(evidence),
            native.canonical_json_bytes(evidence) + b"\n",
        )

    def test_code_byte_tamper_is_rejected_by_page_hash(self) -> None:
        signature_offset, _size, _length, _component = (
            self._signature_coordinates()
        )
        raw = bytearray(self.signed_bytes)
        offset = min(4096, signature_offset - 1)
        raw[offset] ^= 0x01
        path = self._mutated_file("code-byte-tamper", bytes(raw))
        _assert_error(
            self,
            "native_codesign_code_page_hash_mismatch",
            self._inspect_mutated,
            path,
        )

    def test_code_directory_hash_tamper_is_rejected(self) -> None:
        signature_offset, _size, _length, component = (
            self._signature_coordinates()
        )
        raw = bytearray(self.signed_bytes)
        code_directory = signature_offset + component
        hash_offset = struct.unpack_from(">I", raw, code_directory + 16)[0]
        raw[code_directory + hash_offset] ^= 0x01
        path = self._mutated_file("signature-hash-tamper", bytes(raw))
        _assert_error(
            self,
            "native_codesign_code_page_hash_mismatch",
            self._inspect_mutated,
            path,
        )

    def test_superblob_out_of_file_length_is_rejected(self) -> None:
        signature_offset, signature_size, _length, _component = (
            self._signature_coordinates()
        )
        raw = bytearray(self.signed_bytes)
        struct.pack_into(
            ">I",
            raw,
            signature_offset + 4,
            signature_size + 1,
        )
        path = self._mutated_file("superblob-out-of-file", bytes(raw))
        _assert_error(
            self,
            "native_codesign_superblob_header_invalid",
            self._inspect_mutated,
            path,
        )

    def test_lc_code_signature_out_of_file_range_is_rejected(self) -> None:
        raw = bytearray(self.signed_bytes)
        command_count, command_bytes = struct.unpack_from("<II", raw, 16)
        cursor = 32
        found = False
        for _index in range(command_count):
            command, size = struct.unpack_from("<II", raw, cursor)
            if command == native.LC_CODE_SIGNATURE:
                struct.pack_into("<I", raw, cursor + 8, len(raw))
                found = True
                break
            cursor += size
        self.assertTrue(found)
        self.assertLessEqual(cursor, 32 + command_bytes)
        path = self._mutated_file("lc-signature-out-of-file", bytes(raw))
        _assert_error(
            self,
            "native_macho_code_signature_bounds_invalid",
            self._inspect_mutated,
            path,
        )

    def test_superblob_overlapping_components_are_rejected(self) -> None:
        signature_offset, _size, _length, _component = (
            self._signature_coordinates()
        )
        raw = bytearray(self.signed_bytes)
        count = struct.unpack_from(">I", raw, signature_offset + 8)[0]
        self.assertGreaterEqual(count, 2)
        first_offset = struct.unpack_from(
            ">I", raw, signature_offset + 16
        )[0]
        struct.pack_into(
            ">I",
            raw,
            signature_offset + 24,
            first_offset,
        )
        path = self._mutated_file("superblob-overlap", bytes(raw))
        _assert_error(
            self,
            "native_codesign_superblob_components_overlap",
            self._inspect_mutated,
            path,
        )

    def test_unsupported_code_directory_hash_and_version_are_rejected(
        self,
    ) -> None:
        signature_offset, _size, _length, component = (
            self._signature_coordinates()
        )
        code_directory = signature_offset + component
        raw = bytearray(self.signed_bytes)
        raw[code_directory + 37] = 1
        hash_path = self._mutated_file("unsupported-hash", bytes(raw))
        _assert_error(
            self,
            "native_codesign_hash_algorithm_unsupported",
            self._inspect_mutated,
            hash_path,
        )

        raw = bytearray(self.signed_bytes)
        struct.pack_into(">I", raw, code_directory + 8, 0x20600)
        version_path = self._mutated_file(
            "unsupported-version",
            bytes(raw),
        )
        _assert_error(
            self,
            "native_codesign_code_directory_version_unsupported",
            self._inspect_mutated,
            version_path,
        )

    def test_malformed_requirements_blob_is_rejected_after_digest_binding(
        self,
    ) -> None:
        signature_offset, _size, _length, code_component = (
            self._signature_coordinates()
        )
        requirement_component = self._component_offset(
            native.CSSLOT_REQUIREMENTS
        )
        raw = bytearray(self.signed_bytes)
        requirement_absolute = signature_offset + requirement_component
        requirement_length = struct.unpack_from(
            ">I", raw, requirement_absolute + 4
        )[0]
        self.assertEqual(requirement_length, 12)
        struct.pack_into(">I", raw, requirement_absolute + 8, 1)
        requirement_digest = hashlib.sha256(
            raw[
                requirement_absolute : requirement_absolute
                + requirement_length
            ]
        ).digest()
        code_directory = signature_offset + code_component
        hash_offset = struct.unpack_from(
            ">I", raw, code_directory + 16
        )[0]
        slot_two_offset = code_directory + hash_offset - 2 * 32
        raw[slot_two_offset : slot_two_offset + 32] = requirement_digest
        path = self._mutated_file("requirements-malformed", bytes(raw))
        _assert_error(
            self,
            "native_codesign_requirements_header_invalid",
            self._inspect_mutated,
            path,
        )

    def test_scatter_and_adhoc_team_semantics_are_rejected(self) -> None:
        signature_offset, _size, _length, component = (
            self._signature_coordinates()
        )
        code_directory = signature_offset + component
        raw = bytearray(self.signed_bytes)
        struct.pack_into(">I", raw, code_directory + 44, 1)
        scatter_path = self._mutated_file("scatter", bytes(raw))
        _assert_error(
            self,
            "native_codesign_scatter_semantics_unsupported",
            self._inspect_mutated,
            scatter_path,
        )

        raw = bytearray(self.signed_bytes)
        identifier_offset = struct.unpack_from(
            ">I", raw, code_directory + 20
        )[0]
        raw[
            code_directory
            + identifier_offset : code_directory
            + identifier_offset
            + 7
        ] = b"TEAMID\x00"
        struct.pack_into(
            ">I",
            raw,
            code_directory + 48,
            identifier_offset,
        )
        team_path = self._mutated_file("adhoc-team", bytes(raw))
        _assert_error(
            self,
            "native_codesign_team_identifier_overlaps",
            self._inspect_mutated,
            team_path,
        )

    def test_unsigned_macho_and_writable_descriptor_are_rejected(self) -> None:
        unsigned = self._mutated_file("unsigned-macho", _unsigned_macho())
        _assert_error(
            self,
            "native_macho_code_signature_missing",
            self._inspect_mutated,
            unsigned,
        )

        fd = os.open(self.executable, os.O_RDWR)
        try:
            _assert_error(
                self,
                "native_macho_descriptor_not_readonly",
                native.inspect_signed_macho_fd,
                fd,
                object_label="bin/writable",
            )
        finally:
            os.close(fd)

    def test_apple_universal_dyld_has_exact_signed_slice_identity(self) -> None:
        identity = native._measure_host_identity()
        evidence = native._measure_system_dyld(identity)
        artifact = evidence["signed_artifact_evidence"]
        self.assertEqual(artifact["format"], "universal-macho")
        self.assertIn(identity["architecture"], artifact["architectures"])
        self.assertTrue(
            all(
                item["file_type"] == "dylinker"
                for item in artifact["slices"]
            )
        )
        self.assertTrue(
            all(
                item["signature"]["identifier"]
                == "com.apple.darwin.ignition"
                for item in artifact["slices"]
            )
        )
        self.assertEqual(
            artifact["secondary_codesign_observation"]["status"],
            "verified",
        )

    def test_fat_header_and_slice_architecture_must_agree(self) -> None:
        raw = bytearray(Path(native.SYSTEM_DYLD_PATH).read_bytes())
        self.assertEqual(struct.unpack_from(">I", raw, 0)[0], native.FAT_MAGIC)
        struct.pack_into(">i", raw, 8, 0x0100000C)
        path = self._mutated_file("dyld-fat-header-drift", bytes(raw))
        fd = _open_readonly(path)
        try:
            _assert_error(
                self,
                "native_macho_fat_architecture_mismatch",
                native._measure_macho_fd_authoritative,
                fd,
                object_label="host/dyld-mutated",
                allow_fat=True,
                required_architecture="arm64",
                require_secondary=False,
            )
        finally:
            os.close(fd)

    def test_codesign_failure_is_a_negative_gate_not_an_upgraded_claim(
        self,
    ) -> None:
        failed = subprocess.CompletedProcess(
            args=["/usr/bin/codesign"],
            returncode=1,
            stdout=b"",
            stderr=b"invalid signature",
        )
        fd = _open_readonly(self.executable)
        try:
            with mock.patch.object(
                native,
                "_run_subprocess",
                return_value=failed,
            ):
                _assert_error(
                    self,
                    "native_codesign_secondary_verification_failed",
                    native.inspect_signed_macho_fd,
                    fd,
                    object_label="bin/secondary-failure",
                )
        finally:
            os.close(fd)


class PersonaQualificationNativeHostEvidenceTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="john-lomein-native-host-unit-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_non_macos_is_explicitly_unsupported_and_never_activates(
        self,
    ) -> None:
        with mock.patch.object(native.sys, "platform", "linux"):
            evidence = native.collect_native_host_evidence({})
        self.assertEqual(evidence["status"], "unsupported")
        self.assertEqual(
            evidence["reason_code"],
            "native_host_evidence_macos_only",
        )
        self.assertFalse(evidence["authority_proven"])
        self.assertFalse(evidence["activation"]["production_activation"])
        self.assertEqual(
            native.verify_canonical_evidence(evidence),
            evidence,
        )

    def test_self_digest_rejects_mutation(self) -> None:
        with mock.patch.object(native.sys, "platform", "linux"):
            evidence = native.collect_native_host_evidence({})
        mutated = copy.deepcopy(evidence)
        mutated["status"] = "verified-static-native-host-evidence"
        _assert_error(
            self,
            "native_host_evidence_digest_mismatch",
            native.verify_canonical_evidence,
            mutated,
        )

    def test_host_command_build_drift_fails_closed(self) -> None:
        values = {
            "native_host_product_version": "26.5.1",
            "native_host_product_build": "25F80",
            "native_host_darwin_release": "25.5.0",
            "native_host_darwin_build": "25F81",
            "native_host_darwin_version": (
                "Darwin Kernel Version 25.5.0: test/RELEASE_ARM64"
            ),
            "native_host_architecture": "arm64",
        }

        def command(_argv: tuple[str, ...], *, field: str) -> str:
            return values[field]

        with mock.patch.object(
            native,
            "_run_command_line",
            side_effect=command,
        ):
            _assert_error(
                self,
                "native_host_build_identity_mismatch",
                native._measure_host_identity,
            )

    def test_host_kernel_version_drift_fails_closed(self) -> None:
        values = {
            "native_host_product_version": "26.5.1",
            "native_host_product_build": "25F80",
            "native_host_darwin_release": "25.5.0",
            "native_host_darwin_build": "25F80",
            "native_host_darwin_version": (
                "Darwin Kernel Version 25.4.0: test/RELEASE_ARM64"
            ),
            "native_host_architecture": "arm64",
        }

        def command(_argv: tuple[str, ...], *, field: str) -> str:
            return values[field]

        with mock.patch.object(
            native,
            "_run_command_line",
            side_effect=command,
        ):
            _assert_error(
                self,
                "native_host_darwin_version_inconsistent",
                native._measure_host_identity,
            )

    def test_synthetic_shared_cache_family_binds_uuid_and_every_digest(
        self,
    ) -> None:
        primary_uuid = uuid.uuid4()
        subcache_uuid = uuid.uuid4()
        primary = _cache_header(
            cache_uuid=primary_uuid,
            subcache_uuid=subcache_uuid,
        )
        subcache = _cache_header(cache_uuid=subcache_uuid)
        base = "dyld_shared_cache_arm64e"
        (self.root / base).write_bytes(primary)
        (self.root / f"{base}.01").write_bytes(subcache)
        (self.root / f"{base}.map").write_text(
            "non-load-bearing fixture\n",
            encoding="utf-8",
        )
        directory_fd = os.open(
            self.root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            evidence = native._measure_shared_cache_at_directory_fd(
                directory_fd,
                base_name=base,
                require_root=False,
            )
        finally:
            os.close(directory_fd)
        family = evidence["family"]
        self.assertEqual(family["primary_uuid"], str(primary_uuid))
        self.assertEqual(family["component_count"], 2)
        self.assertEqual(
            [item["uuid"] for item in family["components"]],
            [str(primary_uuid), str(subcache_uuid)],
        )
        self.assertEqual(
            family["excluded_non_load_bearing_sidecars"],
            [f"{base}.map"],
        )
        self.assertEqual(
            family["content_set_sha256"],
            native._digest_json(family["components"]),
        )
        self.assertEqual(native.verify_canonical_evidence(evidence), evidence)

    def test_shared_cache_declared_uuid_drift_and_undeclared_component_fail(
        self,
    ) -> None:
        primary_uuid = uuid.uuid4()
        declared_uuid = uuid.uuid4()
        base = "dyld_shared_cache_arm64e"
        (self.root / base).write_bytes(
            _cache_header(
                cache_uuid=primary_uuid,
                subcache_uuid=declared_uuid,
            )
        )
        (self.root / f"{base}.01").write_bytes(
            _cache_header(cache_uuid=uuid.uuid4())
        )
        directory_fd = os.open(
            self.root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            _assert_error(
                self,
                "native_host_shared_cache_component_uuid_mismatch",
                native._measure_shared_cache_at_directory_fd,
                directory_fd,
                base_name=base,
                require_root=False,
            )
        finally:
            os.close(directory_fd)

        (self.root / f"{base}.01").write_bytes(
            _cache_header(cache_uuid=declared_uuid)
        )
        (self.root / f"{base}.02").write_bytes(
            _cache_header(cache_uuid=uuid.uuid4())
        )
        directory_fd = os.open(
            self.root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            _assert_error(
                self,
                "native_host_shared_cache_undeclared_component",
                native._measure_shared_cache_at_directory_fd,
                directory_fd,
                base_name=base,
                require_root=False,
            )
        finally:
            os.close(directory_fd)

    def test_fail_closed_collection_reports_only_stable_reason_code(
        self,
    ) -> None:
        with (
            mock.patch.object(native.sys, "platform", "darwin"),
            mock.patch.object(
                native,
                "measure_macos_host_authority",
                side_effect=native.NativeHostEvidenceError(
                    "native_host_build_identity_mismatch"
                ),
            ),
        ):
            evidence = native.collect_native_host_evidence(
                {"bin/demo": -1}
            )
        self.assertEqual(evidence["status"], "unproved")
        self.assertEqual(
            evidence["reason_code"],
            "native_host_build_identity_mismatch",
        )
        self.assertNotIn("host_authority", evidence)
        self.assertFalse(evidence["activation"]["production_activation"])

    def test_canonical_json_has_no_float_or_non_string_key_domain(self) -> None:
        _assert_error(
            self,
            "native_host_evidence_canonical_type_invalid",
            native.canonical_json_bytes,
            {"bad": 1.5},
        )
        _assert_error(
            self,
            "native_host_evidence_key_invalid",
            native.canonical_json_bytes,
            {1: "bad"},
        )
        encoded = native.canonical_json_bytes(
            {"activation": native.ACTIVATION_STATE}
        )
        self.assertEqual(
            json.loads(encoded),
            {"activation": native.ACTIVATION_STATE},
        )


if __name__ == "__main__":
    unittest.main()
