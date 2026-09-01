from __future__ import annotations

import copy
import ctypes
import hashlib
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_native_bundle as native,
)


LC_LOAD_DYLIB = 0x0000000C
LC_ID_DYLIB = 0x0000000D
LC_LOAD_DYLINKER = 0x0000000E
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_UUID = 0x0000001B
LC_RPATH = 0x8000001C
LC_DYLD_ENVIRONMENT = 0x00000027
LC_BUILD_VERSION = 0x00000032
LC_ID_DYLINKER = 0x0000000F


def _align_eight(value: int) -> int:
    return (value + 7) & ~7


def _packed_version(value: str) -> int:
    components = [int(item) for item in value.split(".")]
    components.extend([0] * (3 - len(components)))
    return (
        (components[0] << 16)
        | (components[1] << 8)
        | components[2]
    )


def _path_command(
    command: int,
    value: str,
    *,
    dylib: bool,
    current: str = "1.0.0",
    compatibility: str = "1.0.0",
) -> bytes:
    encoded = value.encode("utf-8") + b"\x00"
    header_size = 24 if dylib else 12
    size = _align_eight(header_size + len(encoded))
    if dylib:
        result = struct.pack(
            "<IIIIII",
            command,
            size,
            header_size,
            0,
            _packed_version(current),
            _packed_version(compatibility),
        )
    else:
        result = struct.pack("<III", command, size, header_size)
    return result + encoded + b"\x00" * (size - header_size - len(encoded))


def _build_version(minimum: str, sdk: str = "15.4.0") -> bytes:
    return struct.pack(
        "<IIIIII",
        LC_BUILD_VERSION,
        24,
        1,
        _packed_version(minimum),
        _packed_version(sdk),
        0,
    )


def _uuid_command(seed: str) -> bytes:
    return struct.pack("<II", LC_UUID, 24) + uuid.uuid5(
        uuid.NAMESPACE_URL,
        seed,
    ).bytes


def _macho(
    *,
    file_type: int,
    minimum: str,
    install_name: str | None = None,
    rpaths: tuple[str, ...] = (),
    dependencies: tuple[tuple[int, str], ...] = (),
    dynamic_linker: str | None = "/usr/lib/dyld",
    dyld_environment: str | None = None,
    extra_commands: tuple[bytes, ...] = (),
    seed: str,
) -> bytes:
    commands = [_build_version(minimum), _uuid_command(seed)]
    if file_type == 2 and dynamic_linker is not None:
        commands.append(
            _path_command(
                LC_LOAD_DYLINKER,
                dynamic_linker,
                dylib=False,
            )
        )
    if dyld_environment is not None:
        commands.append(
            _path_command(
                LC_DYLD_ENVIRONMENT,
                dyld_environment,
                dylib=False,
            )
        )
    commands.extend(extra_commands)
    if install_name is not None:
        commands.append(
            _path_command(
                LC_ID_DYLIB,
                install_name,
                dylib=True,
            )
        )
    commands.extend(
        _path_command(LC_RPATH, value, dylib=False)
        for value in rpaths
    )
    commands.extend(
        _path_command(command, value, dylib=True)
        for command, value in dependencies
    )
    command_region = b"".join(commands)
    header = struct.pack(
        "<IiiIIIII",
        0xFEEDFACF,
        0x0100000C,
        0,
        file_type,
        len(commands),
        len(command_region),
        0,
        0,
    )
    return header + command_region + b"NATIVE-FIXTURE-CONTENT\n"


class PersonaQualificationNativeBundleTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        # The native verifier intentionally rejects a bundle below a
        # group/world-writable ancestor such as Linux /tmp.  macOS gives each
        # user a private TMPDIR (and the user's home may carry a deny ACL);
        # Linux fixtures instead live below the repository working tree.
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".native-bundle-test-",
            dir=None if sys.platform == "darwin" else ROOT,
        )
        self.addCleanup(self.temporary.cleanup)
        self.bundle = Path(self.temporary.name).resolve() / "bundle"
        self.bundle.mkdir()
        self._write_fixture()
        self.schema = json.loads(
            (
                ROOT
                / "qualification_attestor"
                / "schemas"
                / "persona-qualification-native-bundle-manifest.v3.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.validator = Draft202012Validator(self.schema)

    def _write_fixture(self) -> None:
        system = "/usr/lib/libSystem.B.dylib"
        files = {
            "python/bin/python": _macho(
                file_type=2,
                minimum="13.0.0",
                dependencies=(
                    (
                        LC_LOAD_DYLIB,
                        "@executable_path/../lib/libpython3.11.dylib",
                    ),
                    (LC_LOAD_DYLIB, system),
                ),
                seed="fixture-python",
            ),
            "python/lib/libpython3.11.dylib": _macho(
                file_type=6,
                minimum="12.0.0",
                install_name="@rpath/libpython3.11.dylib",
                dependencies=((LC_LOAD_DYLIB, system),),
                seed="fixture-libpython",
            ),
            "python/lib/python3.11/os.py": b"# fixture stdlib\n",
            "app/verifier.py": b"print('fixture verifier')\n",
            "vendor/demo/__init__.py": b"VALUE = 1\n",
            "vendor/demo/_native.so": _macho(
                file_type=8,
                minimum="11.0.0",
                dependencies=((LC_LOAD_WEAK_DYLIB, system),),
                seed="fixture-extension",
            ),
            "vendor/demo-1.0.dist-info/RECORD": (
                b"demo/__init__.py,,\n"
                b"demo/_native.so,,\n"
                b"demo-1.0.dist-info/RECORD,,\n"
            ),
        }
        for relative, payload in files.items():
            path = self.bundle / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        (self.bundle / "empty").mkdir()
        self._seal_fixture()

    def _seal_fixture(self) -> None:
        for directory, directories, names in os.walk(
            self.bundle,
            topdown=False,
            followlinks=False,
        ):
            root = Path(directory)
            for name in names:
                path = root / name
                if path.is_symlink():
                    continue
                path.chmod(
                    0o555
                    if path == self.bundle / "python/bin/python"
                    else 0o444
                )
            for name in directories:
                (root / name).chmod(0o555)
            root.chmod(0o555)

    def _make_tree_writable(self) -> None:
        if not self.bundle.exists():
            return
        for directory, directories, files in os.walk(
            self.bundle,
            topdown=True,
            followlinks=False,
        ):
            root = Path(directory)
            try:
                root.chmod(0o755)
            except OSError:
                pass
            for name in directories:
                path = root / name
                if not path.is_symlink():
                    try:
                        path.chmod(0o755)
                    except OSError:
                        pass
            for name in files:
                path = root / name
                if not path.is_symlink():
                    try:
                        path.chmod(0o644)
                    except OSError:
                        pass

    def tearDown(self) -> None:
        self._make_tree_writable()

    def _sha(self, path: str) -> str:
        return hashlib.sha256((self.bundle / path).read_bytes()).hexdigest()

    def _class_contract(
        self,
    ) -> tuple[
        list[dict[str, object]],
        list[dict[str, object]],
        dict[str, dict[str, str]],
    ]:
        ownership = [
            {
                "id": "fixture-owner",
                "uid": os.getuid(),
                "gid": os.getgid(),
            }
        ]
        modes = [
            {
                "id": "directory-readonly",
                "object_type": "directory",
                "mode": 0o555,
            },
            {
                "id": "file-executable",
                "object_type": "file",
                "mode": 0o555,
            },
            {
                "id": "file-readonly",
                "object_type": "file",
                "mode": 0o444,
            },
        ]
        bindings: dict[str, dict[str, str]] = {
            ".": {
                "ownership_class": "fixture-owner",
                "mode_class": "directory-readonly",
            }
        }
        for directory, directories, files in os.walk(self.bundle):
            root = Path(directory)
            relative_root = root.relative_to(self.bundle)
            for name in directories:
                relative = (
                    relative_root / name
                    if relative_root.parts
                    else Path(name)
                ).as_posix()
                bindings[relative] = {
                    "ownership_class": "fixture-owner",
                    "mode_class": "directory-readonly",
                }
            for name in files:
                relative = (
                    relative_root / name
                    if relative_root.parts
                    else Path(name)
                ).as_posix()
                bindings[relative] = {
                    "ownership_class": "fixture-owner",
                    "mode_class": (
                        "file-executable"
                        if relative == "python/bin/python"
                        else "file-readonly"
                    ),
                }
        return ownership, modes, dict(sorted(bindings.items()))

    def _runtime(self) -> dict[str, object]:
        values = {
            "HOME": "/var/empty",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "TMPDIR": "/private/tmp/jlq-verifier",
            "TZ": "UTC",
        }
        return {
            "implementation": "cpython",
            "version": "3.11.15",
            "abi_tag": "cp311",
            "executable_path": "python/bin/python",
            "stdlib_paths": ["python/lib/python3.11"],
            "vendor_paths": ["vendor"],
            "sys_path": [".", "python/lib/python3.11", "vendor"],
            "entrypoint": {
                "role": "verifier",
                "path": "app/verifier.py",
                "sha256": self._sha("app/verifier.py"),
                "execution": "runpy.run_path",
            },
            "invocation": {
                "executable": "bundle-relative",
                "flags": ["-I", "-S", "-B"],
                "isolated": True,
                "site_import": False,
                "bytecode_write": False,
            },
            "environment": {
                "clear": True,
                "allowlist": [
                    "HOME",
                    "LANG",
                    "LC_ALL",
                    "PATH",
                    "TMPDIR",
                    "TZ",
                ],
                "values": dict(sorted(values.items())),
            },
        }

    def _wheels(self) -> list[dict[str, object]]:
        installed = [
            "vendor/demo-1.0.dist-info/RECORD",
            "vendor/demo/__init__.py",
            "vendor/demo/_native.so",
        ]
        return [
            {
                "distribution": "demo",
                "version": "1.0",
                "wheel_filename": "demo-1.0-cp311-cp311-macosx_11_0_arm64.whl",
                "wheel_sha256": "1" * 64,
                "source_url": (
                    "https://files.pythonhosted.org/packages/demo/"
                    "demo-1.0-cp311-cp311-macosx_11_0_arm64.whl"
                ),
                "wheel_tags": ["cp311-cp311-macosx_11_0_arm64"],
                "installer": "uv",
                "record_path": "vendor/demo-1.0.dist-info/RECORD",
                "record_sha256": self._sha(
                    "vendor/demo-1.0.dist-info/RECORD"
                ),
                "installed_paths": installed,
                "installed_paths_sha256": hashlib.sha256(
                    native.canonical_json_bytes(installed)
                ).hexdigest(),
            }
        ]

    def _build(
        self,
        *,
        bundle_root: Path | None = None,
        path_classes: dict[str, dict[str, str]] | None = None,
        runtime: dict[str, object] | None = None,
        wheels: list[dict[str, object]] | None = None,
        platform_policy: dict[str, object] | None = None,
    ) -> dict[str, object]:
        ownership, modes, default_bindings = self._class_contract()
        return native.build_native_bundle_manifest(
            bundle_root or self.bundle,
            role="verifier",
            platform_policy=platform_policy
            or {
                "system": "darwin",
                "architecture": "arm64",
                "binary_format": "mach-o-64-little-endian",
                "minimum_macos": "13.0.0",
            },
            ownership_classes=ownership,
            mode_classes=modes,
            path_classes=path_classes or default_bindings,
            python_runtime=runtime or self._runtime(),
            wheel_provenance=wheels if wheels is not None else self._wheels(),
            system_dependency_allowlist=[
                "/usr/lib/libSystem.B.dylib"
            ],
        )

    def assert_code(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(native.NativeBundleError) as caught:
            callable_(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def _refresh_digest(
        self,
        manifest: dict[str, object],
        field: str,
        value: object,
    ) -> None:
        manifest["digests"][field] = hashlib.sha256(
            native.canonical_json_bytes(value)
        ).hexdigest()

    def _refresh_bundle_content(self, manifest: dict[str, object]) -> None:
        content = {
            "role": manifest["role"],
            "platform": manifest["platform"],
            "filesystem_policy": manifest["filesystem_policy"],
            "ownership_classes": manifest["ownership_classes"],
            "mode_classes": manifest["mode_classes"],
            "python_runtime": manifest["python_runtime"],
            "wheel_provenance": manifest["wheel_provenance"],
            "macho": manifest["macho"],
            "inventory": manifest["inventory"],
        }
        digest = hashlib.sha256(
            native.canonical_json_bytes(content)
        ).hexdigest()
        manifest["digests"]["bundle_content_sha256"] = digest
        manifest["bundle_id"] = f"{manifest['role']}@{digest}"

    def test_build_parse_verify_schema_and_determinism(self) -> None:
        Draft202012Validator.check_schema(self.schema)
        manifest = self._build()
        errors = list(self.validator.iter_errors(manifest))
        self.assertEqual(errors, [])
        self.assertIs(native.PRODUCTION_ACTIVATION, False)
        self.assertIs(native.ACTIVATION_RECEIPTS_AVAILABLE, False)
        self.assertIsNone(native.ACTIVATION_RECEIPT_SCHEMA)
        self.assertEqual(
            manifest["activation"],
            {
                "activation_receipt_schema": None,
                "activation_receipts_available": False,
                "native_closure_status": "unproven-for-live-installation",
                "privileged_canaries": "unproven",
                "production_activation": False,
            },
        )
        self.assertEqual(
            manifest["inventory"]["directory_count"],
            len(manifest["inventory"]["directories"]),
        )
        self.assertEqual(manifest["inventory"]["directories"][0]["path"], ".")
        self.assertIn(
            "empty",
            {
                item["path"]
                for item in manifest["inventory"]["directories"]
            },
        )
        self.assertEqual(
            [item["path"] for item in manifest["macho"]["objects"]],
            [
                "python/bin/python",
                "python/lib/libpython3.11.dylib",
                "vendor/demo/_native.so",
            ],
        )
        self.assertEqual(
            {
                (
                    item["source_path"],
                    item["load_command"],
                    item["target_class"],
                    item["target_path"],
                )
                for item in manifest["macho"]["dependencies"]
            },
            {
                (
                    "python/bin/python",
                    "LC_LOAD_DYLIB",
                    "bundle",
                    "python/lib/libpython3.11.dylib",
                ),
                (
                    "python/bin/python",
                    "LC_LOAD_DYLIB",
                    "macos-system",
                    "/usr/lib/libSystem.B.dylib",
                ),
                (
                    "python/lib/libpython3.11.dylib",
                    "LC_LOAD_DYLIB",
                    "macos-system",
                    "/usr/lib/libSystem.B.dylib",
                ),
                (
                    "vendor/demo/_native.so",
                    "LC_LOAD_WEAK_DYLIB",
                    "macos-system",
                    "/usr/lib/libSystem.B.dylib",
                ),
            },
        )
        retained = native.retained_native_bundle_manifest_bytes(manifest)
        self.assertEqual(native.parse_native_bundle_manifest(retained), manifest)
        expected_digest = native.native_bundle_manifest_sha256(manifest)
        self.assertEqual(
            native.verify_native_bundle(
                self.bundle,
                retained,
                enforce_host_platform=False,
                enforce_root_control=False,
            ),
            expected_digest,
        )
        self.assertEqual(self._build(), manifest)

    def test_manifest_requires_canonical_encoding_and_exact_digests(
        self,
    ) -> None:
        manifest = self._build()
        retained = native.retained_native_bundle_manifest_bytes(manifest)
        pretty = (
            json.dumps(manifest, sort_keys=True, indent=2).encode() + b"\n"
        )
        self.assert_code(
            "native_bundle_manifest_encoding_not_canonical",
            native.parse_native_bundle_manifest,
            pretty,
        )
        self.assert_code(
            "native_bundle_manifest_duplicate_field",
            native.parse_native_bundle_manifest,
            b'{"schema_version":"x","schema_version":"y"}\n',
        )
        tampered = copy.deepcopy(manifest)
        tampered["digests"]["inventory_sha256"] = "0" * 64
        self.assert_code(
            "native_bundle_digest_mismatch",
            native.normalize_native_bundle_manifest,
            tampered,
        )
        self.assertEqual(
            hashlib.sha256(retained[:-1]).hexdigest(),
            native.native_bundle_manifest_sha256(manifest),
        )

    def test_activation_receipt_api_is_intentionally_unavailable(self) -> None:
        self.assert_code(
            "native_bundle_activation_receipt_unavailable",
            native.issue_activation_receipt,
            self._build(),
        )
        tampered = self._build()
        tampered["activation"]["production_activation"] = True
        self.assert_code(
            "native_bundle_activation_state_invalid",
            native.normalize_native_bundle_manifest,
            tampered,
        )

    def test_runtime_policy_is_exact_and_entrypoint_is_byte_bound(self) -> None:
        for change, code in (
            (
                lambda value: value["invocation"].__setitem__(
                    "flags",
                    ["-I", "-S"],
                ),
                "native_bundle_python_invocation_flags_invalid",
            ),
            (
                lambda value: value["environment"]["allowlist"].append(
                    "PYTHONPATH"
                ),
                "native_bundle_environment_allowlist_invalid",
            ),
            (
                lambda value: value["environment"]["values"].__setitem__(
                    "PYTHONHOME",
                    "/tmp",
                ),
                "native_bundle_environment_values_fields_invalid",
            ),
        ):
            with self.subTest(code=code):
                runtime = self._runtime()
                change(runtime)
                if "PYTHONPATH" in runtime["environment"]["allowlist"]:
                    runtime["environment"]["allowlist"].sort()
                self.assert_code(code, self._build, runtime=runtime)

        manifest = self._build()
        self._make_tree_writable()
        entrypoint = self.bundle / "app/verifier.py"
        entrypoint.write_bytes(b"print('replaced')\n")
        self._seal_fixture()
        self.assert_code(
            "native_bundle_python_entrypoint_mismatch",
            native.verify_native_bundle,
            self.bundle,
            manifest,
            enforce_host_platform=False,
            enforce_root_control=False,
        )

    def test_complete_inventory_rejects_unexpected_missing_and_modes(
        self,
    ) -> None:
        manifest = self._build()
        self._make_tree_writable()
        unexpected = self.bundle / "surprise.txt"
        unexpected.write_bytes(b"not declared")
        self._seal_fixture()
        self.assert_code(
            "native_bundle_unexpected_entry",
            native.verify_native_bundle,
            self.bundle,
            manifest,
            enforce_host_platform=False,
        )
        self._make_tree_writable()
        unexpected.unlink()
        missing = self.bundle / "empty"
        missing.rmdir()
        self._seal_fixture()
        self.assert_code(
            "native_bundle_declared_entry_missing",
            native.verify_native_bundle,
            self.bundle,
            manifest,
            enforce_host_platform=False,
        )

        self._make_tree_writable()
        missing.mkdir()
        self._seal_fixture()
        target = self.bundle / "app/verifier.py"
        target.chmod(0o644)
        self.assert_code(
            "native_bundle_class_binding_mismatch",
            native.verify_native_bundle,
            self.bundle,
            manifest,
            enforce_host_platform=False,
        )

    def test_symlink_hardlink_fifo_bytecode_and_cache_are_rejected(
        self,
    ) -> None:
        manifest = self._build()
        mutations = []

        def symlink() -> Path:
            path = self.bundle / "link"
            path.symlink_to("app/verifier.py")
            return path

        def hardlink() -> Path:
            path = self.bundle / "hardlink"
            os.link(self.bundle / "app/verifier.py", path)
            return path

        def fifo() -> Path:
            path = self.bundle / "pipe"
            os.mkfifo(path)
            return path

        def bytecode() -> Path:
            path = self.bundle / "leak.pyc"
            path.write_bytes(b"bytecode")
            return path

        def cache() -> Path:
            path = self.bundle / "__pycache__"
            path.mkdir()
            return path

        mutations.extend(
            [
                (symlink, "native_bundle_symlink_forbidden"),
                (hardlink, "native_bundle_file_unsafe"),
                (fifo, "native_bundle_special_file_forbidden"),
                (bytecode, "native_bundle_python_bytecode_forbidden"),
                (cache, "native_bundle_python_cache_directory_forbidden"),
            ]
        )
        for mutate, code in mutations:
            with self.subTest(code=code):
                self._make_tree_writable()
                path = mutate()
                if path.exists() and not path.is_symlink():
                    try:
                        path.chmod(0o444 if path.is_file() else 0o555)
                    except OSError:
                        pass
                self._seal_fixture()
                self.assert_code(
                    code,
                    native.verify_native_bundle,
                    self.bundle,
                    manifest,
                    enforce_host_platform=False,
                    enforce_root_control=False,
                )
                self._make_tree_writable()
                if path.is_dir() and not path.is_symlink():
                    path.rmdir()
                else:
                    path.unlink()

    def test_extended_attributes_are_rejected_descriptor_relatively(
        self,
    ) -> None:
        manifest = self._build()
        self._make_tree_writable()
        path = self.bundle / "app/verifier.py"
        name = "com.john-lomein.native-test"
        if sys.platform == "darwin":
            result = subprocess.run(
                ["/usr/bin/xattr", "-w", name, "forbidden", str(path)],
                capture_output=True,
                text=True,
            )
            if result.returncode:
                self.skipTest(
                    f"fixture filesystem cannot set xattrs: {result.stderr}"
                )
        elif sys.platform.startswith("linux"):
            name = "user.john-native-test"
            libc = ctypes.CDLL(None, use_errno=True)
            if not hasattr(libc, "setxattr"):
                self.skipTest("setxattr unavailable")
            libc.setxattr.argtypes = [
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_int,
            ]
            payload = ctypes.create_string_buffer(b"forbidden")
            if libc.setxattr(
                os.fsencode(path),
                name.encode(),
                payload,
                len(b"forbidden"),
                0,
            ):
                self.skipTest(
                    f"fixture filesystem cannot set xattrs: errno "
                    f"{ctypes.get_errno()}"
                )
        else:
            self.skipTest("xattr test unsupported on this platform")
        self._seal_fixture()
        try:
            self.assert_code(
                "native_bundle_file_extended_attributes_forbidden",
                native.verify_native_bundle,
                    self.bundle,
                    manifest,
                    enforce_host_platform=False,
                    enforce_root_control=False,
            )
        finally:
            self._make_tree_writable()
            if sys.platform == "darwin":
                subprocess.run(
                    ["/usr/bin/xattr", "-d", name, str(path)],
                    check=True,
                    capture_output=True,
                )
            else:
                libc.removexattr.argtypes = [
                    ctypes.c_char_p,
                    ctypes.c_char_p,
                ]
                libc.removexattr(os.fsencode(path), name.encode())

    @unittest.skipUnless(sys.platform == "darwin", "macOS ACL contract")
    def test_macos_acl_is_rejected_on_the_open_inode(self) -> None:
        manifest = self._build()
        self._make_tree_writable()
        path = self.bundle / "app/verifier.py"
        result = subprocess.run(
            ["/bin/chmod", "+a", "everyone allow read", str(path)],
            capture_output=True,
            text=True,
        )
        if result.returncode:
            self.skipTest(f"could not create ACL fixture: {result.stderr}")
        self._seal_fixture()
        try:
            self.assert_code(
                "native_bundle_file_acl_forbidden",
                native.verify_native_bundle,
                self.bundle,
                manifest,
                enforce_host_platform=False,
                enforce_root_control=False,
            )
        finally:
            subprocess.run(
                ["/bin/chmod", "-N", str(path)],
                capture_output=True,
            )

    def test_wheel_provenance_is_complete_and_credential_free(self) -> None:
        wheels = self._wheels()
        wheels[0]["source_url"] = (
            "https://user:secret@" + "example.test/demo.whl"
        )
        self.assert_code(
            "native_bundle_wheel_source_url_invalid",
            self._build,
            wheels=wheels,
        )

        wheels = self._wheels()
        wheels[0]["installed_paths"] = wheels[0]["installed_paths"][:-1]
        wheels[0]["installed_paths_sha256"] = hashlib.sha256(
            native.canonical_json_bytes(wheels[0]["installed_paths"])
        ).hexdigest()
        self.assert_code(
            "native_bundle_wheel_vendor_inventory_mismatch",
            self._build,
            wheels=wheels,
        )

        wheels = self._wheels()
        wheels[0]["record_sha256"] = "0" * 64
        self.assert_code(
            "native_bundle_wheel_record_digest_mismatch",
            self._build,
            wheels=wheels,
        )

    def test_macho_edges_are_reparsed_not_trusted_from_json(self) -> None:
        manifest = self._build()
        tampered = copy.deepcopy(manifest)
        edge = tampered["macho"]["dependencies"][0]
        edge["load_command"] = (
            "LC_LOAD_WEAK_DYLIB"
            if edge["load_command"] == "LC_LOAD_DYLIB"
            else "LC_LOAD_DYLIB"
        )
        tampered["macho"]["dependencies"].sort(
            key=lambda item: (
                item["source_path"],
                item["source_architecture"],
                item["load_command"],
                item["install_name"],
                item["target_class"],
                item["target_path"],
            )
        )
        self._refresh_digest(
            tampered,
            "macho_graph_sha256",
            tampered["macho"],
        )
        self._refresh_bundle_content(tampered)
        native.normalize_native_bundle_manifest(tampered)
        self.assert_code(
            "native_bundle_id_content_mismatch",
            native.verify_native_bundle,
            self.bundle,
            tampered,
            enforce_host_platform=False,
        )

        target_edge = next(
            item
            for item in manifest["macho"]["dependencies"]
            if item["target_class"] == "bundle"
        )
        self.assertEqual(
            target_edge["target_sha256"],
            self._sha("python/lib/libpython3.11.dylib"),
        )
        self.assertEqual(
            manifest["platform"]["minimum_macos"],
            max(
                item["minimum_macos"]
                for item in manifest["macho"]["objects"]
            ),
        )

    def test_inherited_rpath_cannot_shadow_source_owned_target(self) -> None:
        self._make_tree_writable()
        executable = self.bundle / "python/bin/python"
        executable.write_bytes(
            _macho(
                file_type=2,
                minimum="13.0.0",
                rpaths=("@executable_path/../lib",),
                dependencies=(
                    (LC_LOAD_DYLIB, "@rpath/libpython3.11.dylib"),
                    (LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib"),
                ),
                seed="fixture-rpath-python",
            )
        )
        extension = self.bundle / "vendor/demo/_native.so"
        extension.write_bytes(
            _macho(
                file_type=8,
                minimum="11.0.0",
                rpaths=("@loader_path/../../alternate",),
                dependencies=((LC_LOAD_WEAK_DYLIB, "/usr/lib/libSystem.B.dylib"),),
                seed="fixture-shadowing-extension",
            )
        )
        alternate = self.bundle / "alternate/libpython3.11.dylib"
        alternate.parent.mkdir()
        alternate.write_bytes(
            _macho(
                file_type=6,
                minimum="12.0.0",
                install_name="@rpath/libpython3.11.dylib",
                dependencies=((LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib"),),
                seed="fixture-shadow-libpython",
            )
        )
        self._seal_fixture()
        self.assert_code(
            "native_bundle_macho_rpath_chain_ambiguous",
            self._build,
        )

    def test_fat_or_corrupt_macho_is_not_laundered_as_native_closure(
        self,
    ) -> None:
        self._make_tree_writable()
        executable = self.bundle / "python/bin/python"
        executable.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 64)
        self._seal_fixture()
        runtime = self._runtime()
        self.assert_code(
            "native_bundle_fat_macho_unsupported",
            self._build,
            runtime=runtime,
        )

    def test_dynamic_linker_and_embedded_dyld_environment_fail_closed(
        self,
    ) -> None:
        executable = self.bundle / "python/bin/python"
        cases = (
            (
                {"dynamic_linker": "/tmp/attacker-dyld"},
                "native_bundle_macho_dylinker_not_allowed",
            ),
            (
                {"dynamic_linker": None},
                "native_bundle_macho_dylinker_missing",
            ),
            (
                {"dyld_environment": "DYLD_LIBRARY_PATH=/tmp/attacker"},
                "native_bundle_macho_dyld_environment_forbidden",
            ),
        )
        for kwargs, code in cases:
            with self.subTest(code=code):
                self._make_tree_writable()
                executable.write_bytes(
                    _macho(
                        file_type=2,
                        minimum="13.0.0",
                        dependencies=(
                            (
                                LC_LOAD_DYLIB,
                                "@executable_path/../lib/"
                                "libpython3.11.dylib",
                            ),
                            (LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib"),
                        ),
                        seed=f"fixture-{code}",
                        **kwargs,
                    )
                )
                self._seal_fixture()
                self.assert_code(code, self._build)

        self._make_tree_writable()
        executable.write_bytes(
            _macho(
                file_type=2,
                minimum="13.0.0",
                dependencies=(
                    (
                        LC_LOAD_DYLIB,
                        "@executable_path/../lib/libpython3.11.dylib",
                    ),
                    (LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib"),
                ),
                extra_commands=(
                    _path_command(
                        LC_ID_DYLINKER,
                        "/tmp/attacker-dyld",
                        dylib=False,
                    ),
                ),
                seed="fixture-unsupported-loader-command",
            )
        )
        self._seal_fixture()
        self.assert_code(
            "native_bundle_macho_loader_command_unsupported",
            self._build,
        )

    def test_platform_is_explicit_and_host_check_fails_closed(self) -> None:
        manifest = self._build()
        invalid = copy.deepcopy(manifest)
        invalid["platform"]["system"] = "linux"
        self.assert_code(
            "native_bundle_platform_system_unsupported",
            native.normalize_native_bundle_manifest,
            invalid,
        )
        with (
            mock.patch.object(
                native.host_platform,
                "system",
                return_value="Linux",
            ),
            mock.patch.object(
                native.host_platform,
                "machine",
                return_value="x86_64",
            ),
        ):
            self.assert_code(
                "native_bundle_host_platform_mismatch",
                native.verify_native_bundle,
                self.bundle,
                manifest,
            )
        with (
            mock.patch.object(
                native.host_platform,
                "system",
                return_value="Darwin",
            ),
            mock.patch.object(
                native.host_platform,
                "machine",
                return_value="arm64",
            ),
            mock.patch.object(
                native.host_platform,
                "mac_ver",
                return_value=("12.6.0", ("", "", ""), ""),
            ),
        ):
            self.assert_code(
                "native_bundle_host_macos_version_mismatch",
                native.verify_native_bundle,
                self.bundle,
                manifest,
            )

    def test_root_ancestry_and_root_control_fail_closed(self) -> None:
        manifest = self._build()
        self.assert_code(
            "native_bundle_not_root_controlled",
            native.verify_native_bundle,
            self.bundle,
            manifest,
            enforce_host_platform=False,
        )

        alias = Path(self.temporary.name).resolve() / "bundle-alias"
        alias.symlink_to(self.bundle, target_is_directory=True)
        self.assert_code(
            "native_bundle_root_path_not_canonical",
            self._build,
            bundle_root=alias,
        )
        if str(self.bundle).startswith("/private/"):
            case_alias = Path(
                str(self.bundle).replace("/private/", "/PRIVATE/", 1)
            )
            self.assert_code(
                "native_bundle_root_path_not_canonical",
                self._build,
                bundle_root=case_alias,
            )

        unsafe_parent = Path(self.temporary.name).resolve() / "unsafe-parent"
        unsafe_root = unsafe_parent / "bundle"
        unsafe_parent.mkdir()
        shutil.copytree(self.bundle, unsafe_root)
        unsafe_parent.chmod(0o777)
        try:
            self.assert_code(
                "native_bundle_root_ancestor_unsafe",
                self._build,
                bundle_root=unsafe_root,
            )
        finally:
            unsafe_parent.chmod(0o700)

    def test_classes_are_exact_readonly_owner_group_contracts(self) -> None:
        ownership, modes, bindings = self._class_contract()
        modes[0]["mode"] = 0o755
        self.assert_code(
            "native_bundle_mode_class_mutable_or_special",
            native.build_native_bundle_manifest,
            self.bundle,
            role="verifier",
            platform_policy={
                "system": "darwin",
                "architecture": "arm64",
                "binary_format": "mach-o-64-little-endian",
                "minimum_macos": "13.0.0",
            },
            ownership_classes=ownership,
            mode_classes=modes,
            path_classes=bindings,
            python_runtime=self._runtime(),
            wheel_provenance=self._wheels(),
            system_dependency_allowlist=[
                "/usr/lib/libSystem.B.dylib"
            ],
        )
        manifest = self._build()
        tampered = copy.deepcopy(manifest)
        tampered["inventory"]["files"][0]["uid"] += 1
        self.assert_code(
            "native_bundle_inventory_class_binding_mismatch",
            native.normalize_native_bundle_manifest,
            tampered,
        )

    def test_path_declaration_rejects_case_aliases_and_is_complete(
        self,
    ) -> None:
        _ownership, _modes, bindings = self._class_contract()
        bindings["APP"] = dict(bindings["app"])
        bindings = dict(sorted(bindings.items()))
        self.assert_code(
            "native_bundle_path_classes_case_collision",
            self._build,
            path_classes=bindings,
        )
        bindings = self._class_contract()[2]
        del bindings["empty"]
        self.assert_code(
            "native_bundle_unexpected_entry",
            self._build,
            path_classes=bindings,
        )

    def test_schema_rejects_extra_fields_and_activation_claims(self) -> None:
        manifest = self._build()
        extra = copy.deepcopy(manifest)
        extra["macho"]["objects"][0]["codesign_valid"] = True
        self.assertFalse(self.validator.is_valid(extra))
        activated = copy.deepcopy(manifest)
        activated["activation"]["production_activation"] = True
        self.assertFalse(self.validator.is_valid(activated))


if __name__ == "__main__":
    unittest.main()
