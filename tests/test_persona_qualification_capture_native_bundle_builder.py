from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import platform
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = (
    ROOT
    / "scripts"
    / "build-persona-qualification-capture-native-bundle.py"
)
SPEC = importlib.util.spec_from_file_location(
    "john_lomein_capture_native_bundle_builder",
    BUILDER_PATH,
)
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = builder
SPEC.loader.exec_module(builder)


def _live_bundle_runtime_supported() -> bool:
    if sys.platform != "darwin":
        return False
    trusted_python = Path(
        getattr(sys, "_base_executable", sys.executable)
    ).resolve()
    if not trusted_python.is_file():
        return False
    try:
        builder.probe_runtime(trusted_python)
    except builder.CaptureBundleBuildError:
        return False
    return True


LIVE_BUNDLE_RUNTIME_SUPPORTED = _live_bundle_runtime_supported()

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_native_bundle as native_bundle,
)


class CaptureNativeBundleBuilderTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        for child in self.root.glob("*"):
            if child.is_dir() and not child.is_symlink():
                builder._make_tree_writable(child)
            elif child.exists() and not child.is_symlink():
                try:
                    child.chmod(0o600)
                except OSError:
                    pass
        self.temporary.cleanup()

    def assert_code(self, code: str, callback, *args, **kwargs) -> None:
        with self.assertRaises(builder.CaptureBundleBuildError) as caught:
            callback(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_framework_runtime_maps_python_binary_to_bundle_libpython(self) -> None:
        runtime_root = Path(
            "/Library/Frameworks/Python.framework/Versions/3.11"
        )
        source, bundle_name = builder._runtime_library_from_probe(
            {
                "ldlibrary": "Python",
                "libdir": str(runtime_root / "lib"),
                "pythonframework": "Python",
            },
            runtime_root=runtime_root,
            major="3",
            minor="11",
        )
        self.assertEqual(source, runtime_root / "Python")
        self.assertEqual(bundle_name, "libpython3.11.dylib")

    def test_xcode_python3_framework_with_nested_libdir_is_supported(self) -> None:
        runtime_root = Path(
            "/Library/Developer/CommandLineTools/Library/Frameworks/"
            "Python3.framework/Versions/3.9"
        )
        source, bundle_name = builder._runtime_library_from_probe(
            {
                "ldlibrary": "Python3",
                "libdir": str(runtime_root / "lib" / "python3.9" / "config"),
                "pythonframework": "Python3",
            },
            runtime_root=runtime_root,
            major="3",
            minor="9",
        )
        self.assertEqual(source, runtime_root / "Python3")
        self.assertEqual(bundle_name, "libpython3.9.dylib")

    def test_framework_runtime_accepts_python3_with_libpython_ldlibrary(self) -> None:
        runtime_root = Path(
            "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/"
            "Python3.framework/Versions/3.9"
        )
        source, bundle_name = builder._runtime_library_from_probe(
            {
                "ldlibrary": "libpython3.9.dylib",
                "libdir": str(runtime_root / "lib"),
                "pythonframework": "Python3",
            },
            runtime_root=runtime_root,
            major="3",
            minor="9",
        )
        self.assertEqual(source, runtime_root / "Python3")
        self.assertEqual(bundle_name, "libpython3.9.dylib")

    def _source_stdlib(self, name: str = "stdlib") -> Path:
        source = self.root / name
        source.mkdir()
        (source / "os.py").write_text("# standard library\n", encoding="utf-8")
        (source / "lib-dynload").mkdir()
        (source / "lib-dynload" / "demo.so").write_bytes(b"not-macho\n")
        return source

    def test_contract_is_capture_only_and_explicitly_nonactivating(self) -> None:
        self.assertFalse(builder.PRODUCTION_ACTIVATION)
        self.assertFalse(builder.ACTIVATION_RECEIPT_ISSUED)
        self.assertEqual(
            builder.ARTIFACT_CLASS,
            "local-engineering-specimen",
        )
        self.assertEqual(
            builder.UPSTREAM_PROVENANCE,
            "not-attested-or-claimed",
        )
        self.assertEqual(
            builder.CAPTURE_MODULE_FILES,
            (
                "__init__.py",
                "john_lomein_persona_qualification_capture_child.py",
                "john_lomein_persona_qualification_capture_plan.py",
                "john_lomein_persona_qualification_capture_protocol.py",
                "john_lomein_persona_qualification_opaque_capture.py",
            ),
        )
        self.assertNotIn(
            "john_lomein_persona_qualification_capture_helper.py",
            builder.CAPTURE_MODULE_FILES,
        )
        self.assertNotIn(
            "john_lomein_persona_qualification_capture_adoption.py",
            builder.CAPTURE_MODULE_FILES,
        )
        self.assertEqual(
            native_bundle.NATIVE_BUNDLE_MANIFEST_SCHEMA,
            "john-lomein.persona-qualification-native-bundle-manifest.v3",
        )

    def test_stdlib_copy_omits_only_canonical_site_and_generated_cache(
        self,
    ) -> None:
        source = self._source_stdlib()
        (source / "site-packages").mkdir()
        (source / "site-packages" / "untrusted.py").write_text(
            "VALUE = 'not stdlib'\n",
            encoding="utf-8",
        )
        (source / "__pycache__").mkdir()
        (source / "__pycache__" / "os.cpython-311.pyc").write_bytes(
            b"generated"
        )
        (source / "json").mkdir()
        (source / "json" / "__init__.py").write_text(
            "# json\n",
            encoding="utf-8",
        )
        (source / "json" / "__pycache__").mkdir()
        destination = self.root / "copied"

        builder._copy_stdlib_tree(source, destination)

        self.assertEqual(
            (destination / "os.py").read_text(encoding="utf-8"),
            "# standard library\n",
        )
        self.assertTrue((destination / "lib-dynload" / "demo.so").is_file())
        self.assertTrue((destination / "json" / "__init__.py").is_file())
        self.assertFalse((destination / "site-packages").exists())
        self.assertFalse((destination / "__pycache__").exists())
        self.assertFalse((destination / "json" / "__pycache__").exists())

    def test_stdlib_rejects_ambiguous_cache_and_site_roots(self) -> None:
        cases = {
            "nested_site": (
                "capture_bundle_build_stdlib_nested_site_root_forbidden",
                lambda source: (
                    (source / "pkg").mkdir(),
                    (source / "pkg" / "site-packages").mkdir(),
                ),
            ),
            "explicit_cache": (
                "capture_bundle_build_stdlib_cache_forbidden",
                lambda source: (source / ".pytest_cache").mkdir(),
            ),
            "loose_bytecode": (
                "capture_bundle_build_stdlib_bytecode_forbidden",
                lambda source: (source / "loose.pyc").write_bytes(b"cache"),
            ),
            "metadata": (
                "capture_bundle_build_stdlib_metadata_forbidden",
                lambda source: (source / ".DS_Store").write_bytes(b"metadata"),
            ),
        }
        for index, (name, (code, prepare)) in enumerate(cases.items()):
            with self.subTest(name=name):
                source = self._source_stdlib(f"stdlib-{index}")
                prepare(source)
                self.assert_code(
                    code,
                    builder._copy_stdlib_tree,
                    source,
                    self.root / f"copied-{index}",
                )

    def test_stdlib_rejects_symlink_hardlink_and_fifo(self) -> None:
        source = self._source_stdlib("stdlib-symlink")
        (source / "link.py").symlink_to(source / "os.py")
        self.assert_code(
            "capture_bundle_build_stdlib_symlink_forbidden",
            builder._copy_stdlib_tree,
            source,
            self.root / "copied-symlink",
        )

        source = self._source_stdlib("stdlib-hardlink")
        os.link(source / "os.py", source / "alias.py")
        self.assert_code(
            "capture_bundle_build_stdlib_hardlink_forbidden",
            builder._copy_stdlib_tree,
            source,
            self.root / "copied-hardlink",
        )

        source = self._source_stdlib("stdlib-fifo")
        os.mkfifo(source / "pipe")
        self.assert_code(
            "capture_bundle_build_stdlib_special_forbidden",
            builder._copy_stdlib_tree,
            source,
            self.root / "copied-fifo",
        )

    def test_product_copy_is_the_exact_split_child_closure(self) -> None:
        product = self.root / "product"
        package = product / builder.CAPTURE_PACKAGE
        package.mkdir(parents=True)
        for index, name in enumerate(builder.CAPTURE_MODULE_FILES):
            (package / name).write_text(
                f"# module {index}\n",
                encoding="utf-8",
            )
        (package / "john_lomein_persona_qualification_attestor.py").write_text(
            "# must not cross the role boundary\n",
            encoding="utf-8",
        )
        destination = self.root / "app"

        builder._copy_capture_package(product, destination)

        self.assertEqual(
            sorted(
                path.name
                for path in (destination / builder.CAPTURE_PACKAGE).iterdir()
            ),
            sorted(builder.CAPTURE_MODULE_FILES),
        )

    def test_destination_and_external_manifest_are_fail_closed(self) -> None:
        destination = self.root / "bundle"
        destination.mkdir()
        (destination / "preexisting").write_text("no\n", encoding="utf-8")
        self.assert_code(
            "capture_bundle_build_destination_not_empty",
            builder._prepare_empty_destination,
            destination,
        )
        (destination / "preexisting").unlink()
        resolved, mode = builder._prepare_empty_destination(destination)
        self.assertEqual(resolved, destination)
        self.assertEqual(mode, stat.S_IMODE(destination.stat().st_mode))
        manifest = builder.external_manifest_path(destination)
        self.assertEqual(manifest.parent, destination.parent)
        self.assertFalse(
            os.path.commonpath([str(manifest), str(destination)])
            == str(destination)
        )

    @unittest.skipUnless(
        LIVE_BUNDLE_RUNTIME_SUPPORTED,
        "host CPython cannot produce a trusted relocated native bundle",
    )
    def test_failure_rolls_destination_back_to_empty(self) -> None:
        destination = self.root / "rollback-bundle"
        destination.mkdir()
        trusted_python = Path(
            getattr(sys, "_base_executable", sys.executable)
        ).resolve()
        with mock.patch.object(
            builder,
            "_copy_stdlib_tree",
            side_effect=builder.CaptureBundleBuildError(
                "synthetic_copy_failure"
            ),
        ):
            self.assert_code(
                "synthetic_copy_failure",
                builder.build_capture_native_bundle,
                trusted_python=trusted_python,
                product_root=ROOT,
                empty_output_destination=destination,
            )
        self.assertEqual(list(destination.iterdir()), [])
        self.assertFalse(builder.external_manifest_path(destination).exists())

    @unittest.skipUnless(
        LIVE_BUNDLE_RUNTIME_SUPPORTED,
        "host CPython cannot produce a trusted relocated native bundle",
    )
    def test_live_relocated_capture_bundle_and_v3_manifest(self) -> None:
        trusted_python = Path(
            getattr(sys, "_base_executable", sys.executable)
        ).resolve()
        if not trusted_python.is_file():
            self.skipTest("no real host CPython executable")
        destination = self.root / "live-bundle"
        destination.mkdir()

        result = builder.build_capture_native_bundle(
            trusted_python=trusted_python,
            product_root=ROOT,
            empty_output_destination=destination,
        )

        retained = result.manifest_path.read_bytes()
        self.assertEqual(
            native_bundle.parse_native_bundle_manifest(retained),
            result.manifest,
        )
        self.assertEqual(
            native_bundle.verify_native_bundle(
                destination,
                retained,
                enforce_host_platform=True,
                enforce_root_control=False,
            ),
            native_bundle.native_bundle_manifest_sha256(result.manifest),
        )
        self.assertEqual(result.manifest["role"], "capture")
        self.assertFalse(result.manifest["activation"]["production_activation"])
        self.assertFalse(
            result.manifest["activation"]["activation_receipts_available"]
        )
        self.assertEqual(
            result.report["artifact_class"],
            "local-engineering-specimen",
        )
        self.assertFalse(result.report["activation_receipt_issued"])
        self.assertFalse(result.report["production_activation"])
        self.assertEqual(
            result.report["provenance"]["upstream_provenance"],
            "not-attested-or-claimed",
        )
        self.assertEqual(
            result.report["relocation_canary"]["closure_imported"],
            list(builder.CAPTURE_IMPORTS),
        )
        self.assertTrue(result.report["relocation_canary"]["isolated"])
        self.assertTrue(
            result.report["relocation_canary"]["bytecode_disabled"]
        )
        self.assertFalse(
            result.report["relocation_canary"]["site_imported"]
        )
        self.assertEqual(
            result.report["runtime_observation"],
            {
                "abi_tag": f"cp{sys.version_info.major}{sys.version_info.minor}",
                "architecture": "arm64"
                if platform.machine().lower() in {"aarch64", "arm64"}
                else "x86_64",
                "implementation": "cpython",
                "source_executable": str(trusted_python),
                "version": (
                    f"{sys.version_info.major}.{sys.version_info.minor}."
                    f"{sys.version_info.micro}"
                ),
            },
        )

        inventory_paths = {
            item["path"] for item in result.manifest["inventory"]["files"]
        }
        packaged = {
            path
            for path in inventory_paths
            if path.startswith("app/qualification_attestor/")
        }
        self.assertEqual(
            packaged,
            {
                f"app/qualification_attestor/{name}"
                for name in builder.CAPTURE_MODULE_FILES
            },
        )
        self.assertFalse(
            any(
                "__pycache__" in path.casefold()
                or path.casefold().endswith((".pyc", ".pyo"))
                or "/site-packages/" in f"/{path.casefold()}/"
                for path in inventory_paths
            )
        )
        for item in result.manifest["inventory"]["files"]:
            path = destination / item["path"]
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(
                stat.S_IMODE(path.stat().st_mode),
                0o555
                if item["path"] == "python/bin/python"
                else 0o444,
            )
        for item in result.manifest["inventory"]["directories"]:
            path = destination if item["path"] == "." else destination / item["path"]
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o555)

        libpython_objects = [
            item
            for item in result.manifest["macho"]["objects"]
            if item["path"].startswith("python/lib/libpython")
        ]
        self.assertEqual(len(libpython_objects), 1)
        self.assertEqual(
            libpython_objects[0]["install_name"],
            f"@rpath/{Path(libpython_objects[0]['path']).name}",
        )
        transformations = result.report["transformations"]
        rewrite = [
            item
            for item in transformations
            if item["operation"]
            == "rewrite-libpython-lc-id-and-adhoc-sign"
        ]
        if rewrite:
            self.assertEqual(
                rewrite[0]["codesign_observation"],
                "adhoc-signature-verified-after-change",
            )
        self.assertEqual(
            result.report["manifest_sha256"],
            native_bundle.native_bundle_manifest_sha256(result.manifest),
        )
        self.assertEqual(
            hashlib.sha256(
                native_bundle.canonical_json_bytes(result.manifest)
            ).hexdigest(),
            result.report["manifest_sha256"],
        )


if __name__ == "__main__":
    unittest.main()
