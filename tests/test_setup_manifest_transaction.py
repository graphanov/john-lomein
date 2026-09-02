#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
READ_ENV = ROOT / "scripts" / "read-instance-env.py"
SETUP = ROOT / "setup.sh"
DEPLOY = ROOT / "scripts" / "deploy-instance.sh"
STAGE_SCRIPT = ROOT / "scripts" / "john-lomein-stage-manifest.py"
if str(STAGE_SCRIPT.parent) not in sys.path:
    sys.path.insert(0, str(STAGE_SCRIPT.parent))


def load_stage_module():
    spec = importlib.util.spec_from_file_location(
        "john_lomein_stage_manifest_test",
        STAGE_SCRIPT,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load setup manifest staging helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


stage_module = load_stage_module()
import john_lomein_service_registry as service_registry  # noqa: E402


def manifest(root: Path, slug: str) -> dict:
    return {
        "instance": {
            "slug": slug,
            "display_name": slug,
        },
        "target": {
            "repo": "owner/repository",
            "default_branch": "main",
            "local_checkout": str(root / f"{slug}-checkout"),
        },
        "runtime": {
            "activation": "owner_gated",
            "hermes_home": str(root / f"{slug}-runtime"),
            "mutation_enabled": False,
            "discord_enabled": False,
            "guide_gateway_enabled": False,
            "keep_awake_on_ac": False,
        },
        "workflows": {
            "omh_enabled": False,
            "omh_required": False,
            "omh_skills_by_role": {},
        },
        "learning": {"enabled": False},
        "open_scaffold_portfolio": {
            "enabled": False,
            "open_scaffold_instance_only": True,
            "draft_prs": True,
        },
    }


def write_manifest(path: Path, value: dict, mode: int = 0o600) -> None:
    path.write_text(
        yaml.safe_dump(value, sort_keys=False),
        encoding="utf-8",
    )
    os.chmod(path, mode)


class SetupManifestTransactionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "home"
        self.instance = self.root / "instance"
        self.bin = self.root / "bin"
        self.tmpdir = self.root / "tmp"
        for directory in (
            self.home,
            self.instance,
            self.bin,
            self.tmpdir,
        ):
            directory.mkdir(mode=0o700)
        self.source = self.instance / "instance.yaml"
        self.make_log = self.root / "make.log"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def environment(self) -> dict[str, str]:
        env = dict(os.environ)
        for key in (
            "JOHN_LOMEIN_SERVICE_LOCK_FD",
            "JOHN_LOMEIN_SETUP_MANIFEST_SOURCE",
            "JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT",
            "JOHN_LOMEIN_SETUP_MANIFEST_SHA256",
        ):
            env.pop(key, None)
        env.update(
            {
                "HOME": str(self.home),
                "TMPDIR": str(self.tmpdir),
                "PATH": f"{self.bin}:{env['PATH']}",
                "MAKE_LOG": str(self.make_log),
                "PRODUCT_ROOT": str(ROOT),
                "READ_ENV": str(READ_ENV),
            }
        )
        return env

    def install_logging_make(self, body: str = "") -> None:
        script = self.bin / "make"
        script.write_text(
            textwrap.dedent(
                f"""\
                #!/usr/bin/env bash
                set -euo pipefail
                target="${{1:-}}"
                instance=""
                for argument in "$@"; do
                  case "$argument" in
                    INSTANCE=*) instance="${{argument#INSTANCE=}}" ;;
                  esac
                done
                eval "$(uv run --frozen --project "$PRODUCT_ROOT" python \
                  "$READ_ENV" "$instance")"
                printf '%s|%s|%s|%s\\n' \
                  "$target" "$BOT_SLUG" "$JL_INSTANCE_MANIFEST" \
                  "$JL_INSTANCE_MANIFEST_INPUT" >> "$MAKE_LOG"
                {body}
                exit 0
                """
            ),
            encoding="utf-8",
        )
        script.chmod(0o700)

    def install_doctor_intercept_uv(self) -> Path:
        real_uv = shutil.which("uv")
        if real_uv is None:
            self.fail("uv is required for setup transaction tests")
        doctor_log = self.root / "doctor-argument.log"
        wrapper = self.bin / "uv"
        wrapper.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                set -euo pipefail
                for argument in "$@"; do
                  if [ "$argument" = "$PRODUCT_ROOT/scripts/doctor-instance.py" ]; then
                    printf '%s\\n' "${@: -1}" > "$DOCTOR_LOG"
                    exit 1
                  fi
                done
                exec "$REAL_UV" "$@"
                """
            ),
            encoding="utf-8",
        )
        wrapper.chmod(0o700)
        self.real_uv = real_uv
        return doctor_log

    def test_direct_deploy_enters_the_service_lifecycle_lock(self) -> None:
        uv_log = self.root / "direct-deploy-uv.log"
        uv_probe = self.bin / "uv"
        uv_probe.write_text(
            textwrap.dedent(
                """\
                #!/bin/bash
                set -euo pipefail
                printf '%s\n' "$*" > "$DEPLOY_UV_LOG"
                exit 23
                """
            ),
            encoding="utf-8",
        )
        uv_probe.chmod(0o700)
        env = self.environment()
        env["DEPLOY_UV_LOG"] = str(uv_log)

        result = subprocess.run(
            ["/bin/bash", str(DEPLOY), str(self.instance)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 23)
        invocation = uv_log.read_text(encoding="utf-8")
        self.assertIn(
            "john_lomein_service_registry.py run-locked -- bash",
            invocation,
        )
        self.assertIn(str(DEPLOY), invocation)
        self.assertIn(str(self.instance), invocation)
        self.assertNotIn("john-lomein-stage-manifest.py", invocation)

    def test_direct_deploy_reuses_an_inherited_lifecycle_lock(self) -> None:
        uv_log = self.root / "uv.log"
        uv_probe = self.bin / "uv"
        uv_probe.write_text(
            textwrap.dedent(
                """\
                #!/bin/bash
                set -euo pipefail
                if [[ " $* " == *"john_lomein_service_registry.py assert-locked"* ]]; then
                  exec "$REAL_UV" "$@"
                fi
                printf '%s\n' "$*" > "$DEPLOY_UV_LOG"
                exit 23
                """
            ),
            encoding="utf-8",
        )
        uv_probe.chmod(0o700)
        env = self.environment()
        env["DEPLOY_UV_LOG"] = str(uv_log)
        env["REAL_UV"] = shutil.which("uv") or ""

        with mock.patch.dict(os.environ, env, clear=True):
            status = service_registry.run_locked(
                ["/bin/bash", str(DEPLOY), str(self.instance)]
            )

        self.assertEqual(status, 23)
        invocation = uv_log.read_text(encoding="utf-8")
        self.assertIn("john-lomein-stage-manifest.py stage", invocation)
        self.assertNotIn("john_lomein_service_registry.py", invocation)

    def test_direct_deploy_rejects_a_fake_inherited_lock_before_staging(
        self,
    ) -> None:
        uv_log = self.root / "fake-lock-uv.log"
        uv_probe = self.bin / "uv"
        uv_probe.write_text(
            textwrap.dedent(
                """\
                #!/bin/bash
                set -euo pipefail
                printf '%s\n' "$*" > "$DEPLOY_UV_LOG"
                exit 23
                """
            ),
            encoding="utf-8",
        )
        uv_probe.chmod(0o700)
        env = self.environment()
        env["DEPLOY_UV_LOG"] = str(uv_log)
        env["JOHN_LOMEIN_SERVICE_LOCK_FD"] = "not-a-descriptor"

        result = subprocess.run(
            ["/bin/bash", str(DEPLOY), str(self.instance)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 23)
        invocation = uv_log.read_text(encoding="utf-8")
        self.assertIn(
            "john_lomein_service_registry.py assert-locked",
            invocation,
        )
        self.assertNotIn("john-lomein-stage-manifest.py", invocation)

    def test_direct_deploy_waits_for_the_confirmation_lifecycle_lock(
        self,
    ) -> None:
        uv_log = self.root / "contended-deploy-uv.log"
        uv_probe = self.bin / "uv"
        uv_probe.write_text(
            textwrap.dedent(
                """\
                #!/bin/bash
                set -euo pipefail
                if [[ " $* " == *"john_lomein_service_registry.py"* ]]; then
                  exec "$REAL_UV" "$@"
                fi
                printf '%s\n' "$*" > "$DEPLOY_UV_LOG"
                exit 23
                """
            ),
            encoding="utf-8",
        )
        uv_probe.chmod(0o700)
        env = self.environment()
        env["DEPLOY_UV_LOG"] = str(uv_log)
        env["REAL_UV"] = shutil.which("uv") or ""

        process = None
        try:
            with mock.patch.dict(os.environ, env, clear=True):
                with service_registry.lifecycle_lock():
                    process = subprocess.Popen(
                        ["/bin/bash", str(DEPLOY), str(self.instance)],
                        cwd=ROOT,
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    time.sleep(0.4)
                    self.assertIsNone(process.poll())
                    self.assertFalse(uv_log.exists())

            stdout, stderr = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 23, stdout + stderr)
            self.assertIn(
                "john-lomein-stage-manifest.py stage",
                uv_log.read_text(encoding="utf-8"),
            )
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=10)

    def test_broken_mode_preflight_reconciles_no_services(self) -> None:
        write_manifest(
            self.source,
            manifest(self.root, "broken-preflight"),
            mode=0o644,
        )
        self.install_logging_make()

        result = subprocess.run(
            ["bash", str(SETUP), str(self.instance)],
            cwd=ROOT,
            env=self.environment(),
            capture_output=True,
            text=True,
            timeout=60,
        )

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("instance manifest must have mode 0600", result.stderr)
        self.assertIn("could not be staged safely", result.stderr)
        self.assertFalse(self.make_log.exists())

    def test_all_operator_surfaces_reject_two_authoritative_manifests(
        self,
    ) -> None:
        write_manifest(self.source, manifest(self.root, "ambiguous"))
        legacy = self.instance / "bot.yaml"
        legacy.write_bytes(self.source.read_bytes())
        os.chmod(legacy, 0o600)

        with self.assertRaisesRegex(
            stage_module.SetupManifestError,
            "more than one authoritative",
        ):
            stage_module.stage(self.instance)

        read_env = subprocess.run(
            [sys.executable, str(READ_ENV), str(self.instance)],
            cwd=ROOT,
            env=self.environment(),
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(read_env.returncode, 0)
        self.assertIn(
            "more than one authoritative",
            read_env.stdout + read_env.stderr,
        )

        doctor = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "doctor-instance.py"),
                str(self.instance),
            ],
            cwd=ROOT,
            env=self.environment(),
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(doctor.returncode, 2)
        self.assertIn(
            "manifest selection or content is invalid",
            doctor.stdout + doctor.stderr,
        )

    def test_snapshot_keeps_original_service_registry_identity(self) -> None:
        write_manifest(self.source, manifest(self.root, "registry-binding"))
        binding = stage_module.stage(self.instance)
        snapshot = Path(
            binding["JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT"]
        )
        self.addCleanup(snapshot.unlink, missing_ok=True)
        with mock.patch.dict(os.environ, binding, clear=False):
            self.assertEqual(
                service_registry.canonical_manifest_path(snapshot),
                self.source,
            )
            self.assertEqual(
                service_registry.instance_key(snapshot),
                service_registry.instance_key(self.source),
            )

    def test_normal_env_loader_requires_owner_only_non_symlink_manifest(
        self,
    ) -> None:
        write_manifest(
            self.source,
            manifest(self.root, "normal-stable-read"),
            mode=0o644,
        )
        unsafe_mode = subprocess.run(
            [sys.executable, str(READ_ENV), str(self.source)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(unsafe_mode.returncode, 0)
        self.assertIn("stable read failed: unsafe", unsafe_mode.stderr)
        self.assertNotIn("BOT_SLUG=", unsafe_mode.stdout)

        self.source.chmod(0o600)
        alias = self.instance / "manifest-alias.yaml"
        alias.symlink_to(self.source)
        unsafe_link = subprocess.run(
            [sys.executable, str(READ_ENV), str(alias)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(unsafe_link.returncode, 0)
        self.assertIn("manifest path is unsafe", unsafe_link.stderr)
        self.assertNotIn("BOT_SLUG=", unsafe_link.stdout)

    def test_doctor_receives_the_same_staged_manifest_as_make_consumers(
        self,
    ) -> None:
        write_manifest(self.source, manifest(self.root, "doctor-snapshot"))
        self.install_logging_make()
        doctor_log = self.install_doctor_intercept_uv()
        env = self.environment()
        env.update(
            {
                "DOCTOR_LOG": str(doctor_log),
                "REAL_UV": self.real_uv,
            }
        )

        result = subprocess.run(
            ["bash", str(SETUP), str(self.instance)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=90,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = [
            line.split("|")
            for line in self.make_log.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(
            [row[0] for row in rows],
            [
                "uninstall-supervisor",
                "deploy",
                "smoke-all",
                "install-supervisor",
                "install-guide-gateway",
            ],
        )
        snapshot_paths = {row[3] for row in rows}
        self.assertEqual(len(snapshot_paths), 1)
        snapshot_path = snapshot_paths.pop()
        self.assertEqual(doctor_log.read_text(encoding="utf-8").strip(), snapshot_path)
        self.assertFalse(Path(snapshot_path).exists())

    def test_partial_snapshot_is_removed_when_write_and_close_fail(self) -> None:
        real_close = os.close
        destination = (
            self.instance / ".instance.yaml.john-lomein-setup-write.yaml"
        )

        def close_then_fail(descriptor: int) -> None:
            real_close(descriptor)
            raise OSError("injected close failure")

        with (
            mock.patch.object(
                stage_module.os,
                "write",
                side_effect=OSError("injected write failure"),
            ),
            mock.patch.object(
                stage_module.os,
                "close",
                side_effect=close_then_fail,
            ),
            self.assertRaisesRegex(
                stage_module.SetupManifestError,
                "snapshot write failed",
            ),
        ):
            stage_module._write_snapshot(destination, b"test manifest\n")

        self.assertEqual(
            list(self.instance.glob(".instance.yaml.john-lomein-setup-*.yaml")),
            [],
        )

    def test_partial_snapshot_is_removed_when_close_alone_fails(self) -> None:
        real_close = os.close
        destination = (
            self.instance / ".instance.yaml.john-lomein-setup-close.yaml"
        )

        def close_then_fail(descriptor: int) -> None:
            real_close(descriptor)
            raise OSError("injected close failure")

        with (
            mock.patch.object(
                stage_module.os,
                "close",
                side_effect=close_then_fail,
            ),
            self.assertRaisesRegex(
                stage_module.SetupManifestError,
                "descriptor close failed",
            ),
        ):
            stage_module._write_snapshot(destination, b"test manifest\n")

        self.assertEqual(
            list(self.instance.glob(".instance.yaml.john-lomein-setup-*.yaml")),
            [],
        )

    def test_partial_snapshot_cleanup_failure_is_explicit(self) -> None:
        write_manifest(self.source, manifest(self.root, "cleanup-failure"))
        with (
            mock.patch.object(
                stage_module.os,
                "write",
                side_effect=OSError("injected write failure"),
            ),
            mock.patch.object(
                stage_module.os,
                "unlink",
                side_effect=OSError("injected unlink failure"),
            ),
            self.assertRaisesRegex(
                stage_module.SetupManifestError,
                "snapshot write failed; partial snapshot cleanup failed",
            ),
        ):
            stage_module.stage(self.instance)

        residue = list(
            self.instance.glob(".instance.yaml.john-lomein-setup-*.yaml")
        )
        self.assertEqual(len(residue), 1)
        residue[0].unlink()

    def test_instance_directory_replacement_during_mode_tightening_is_rejected(
        self,
    ) -> None:
        write_manifest(self.source, manifest(self.root, "directory-race"))
        self.instance.chmod(0o755)
        displaced = self.root / "displaced-instance"
        real_fchmod = os.fchmod

        def tighten_then_replace(descriptor: int, mode: int) -> None:
            real_fchmod(descriptor, mode)
            self.instance.rename(displaced)
            self.instance.mkdir(mode=0o700)

        with (
            mock.patch.object(
                stage_module.os,
                "fchmod",
                side_effect=tighten_then_replace,
            ),
            self.assertRaisesRegex(
                stage_module.SetupManifestError,
                "reconciliation was ambiguous",
            ),
        ):
            stage_module.stage(self.instance)

        self.assertEqual(
            list(self.instance.glob(".instance.yaml.john-lomein-setup-*.yaml")),
            [],
        )
        self.assertEqual(
            list(displaced.glob(".instance.yaml.john-lomein-setup-*.yaml")),
            [],
        )

    def test_owner_controlled_0755_instance_directory_is_tightened(self) -> None:
        write_manifest(self.source, manifest(self.root, "mode-migration"))
        self.instance.chmod(0o755)

        binding = stage_module.stage(self.instance)
        snapshot = Path(
            binding["JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT"]
        )
        self.addCleanup(snapshot.unlink, missing_ok=True)

        self.assertEqual(self.instance.stat().st_mode & 0o777, 0o700)
        self.assertEqual(snapshot.stat().st_mode & 0o777, 0o400)

    def test_rewrite_between_projection_and_deploy_uses_one_snapshot_then_rolls_back(
        self,
    ) -> None:
        desired = manifest(self.root, "snapshot-a")
        replacement = manifest(self.root, "replacement-b")
        write_manifest(self.source, desired)
        replacement_path = self.root / "replacement.yaml"
        write_manifest(replacement_path, replacement)
        capture = self.root / "deployed-capture.yaml"
        rewrite_marker = self.root / "rewritten"
        self.install_logging_make(
            body=textwrap.dedent(
                """\
                if [ "$target" = "uninstall-supervisor" ] &&
                   [ ! -e "$REWRITE_MARKER" ]; then
                  cp "$REPLACEMENT_MANIFEST" "$ORIGINAL_MANIFEST"
                  chmod 600 "$ORIGINAL_MANIFEST"
                  : > "$REWRITE_MARKER"
                fi
                if [ "$target" = "deploy" ]; then
                  cp "$JL_INSTANCE_MANIFEST_INPUT" "$DEPLOY_CAPTURE"
                fi
                """
            )
        )
        env = self.environment()
        env.update(
            {
                "ORIGINAL_MANIFEST": str(self.source),
                "REPLACEMENT_MANIFEST": str(replacement_path),
                "REWRITE_MARKER": str(rewrite_marker),
                "DEPLOY_CAPTURE": str(capture),
            }
        )

        result = subprocess.run(
            ["bash", str(SETUP), str(self.instance)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=90,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "instance manifest changed during setup transaction",
            result.stderr,
        )
        self.assertIn(
            "no newly configured product-managed service was left running",
            result.stderr,
        )
        self.assertEqual(yaml.safe_load(self.source.read_text()), replacement)
        self.assertEqual(yaml.safe_load(capture.read_text()), desired)

        rows = [
            line.split("|")
            for line in self.make_log.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(
            [row[0] for row in rows],
            ["uninstall-supervisor", "deploy", "uninstall-supervisor"],
        )
        rollback_uninstaller = (
            ROOT / "scripts" / "uninstall-runtime-supervisor.sh"
        ).read_text(encoding="utf-8")
        self.assertIn(
            '"public_honcho=$PUBLIC_HONCHO_LABEL"',
            rollback_uninstaller,
        )
        self.assertEqual({row[1] for row in rows}, {"snapshot-a"})
        self.assertEqual({row[2] for row in rows}, {str(self.source)})
        snapshot_paths = {row[3] for row in rows}
        self.assertEqual(len(snapshot_paths), 1)
        snapshot_path = Path(snapshot_paths.pop())
        self.assertNotEqual(snapshot_path, self.source)
        self.assertFalse(snapshot_path.exists())
        self.assertEqual(snapshot_path.parent, self.instance)
        self.assertEqual(
            list(self.instance.glob(".instance.yaml.john-lomein-setup-*.yaml")),
            [],
        )
        self.assertIsNotNone(shutil.which("uv", path=env["PATH"]))


if __name__ == "__main__":
    unittest.main()
