#!/usr/bin/env python3
from __future__ import annotations

import plistlib
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
ISOLATION_SCRIPT = "john_lomein_model_isolation.py"
BROKER_ASSETS = (
    ISOLATION_SCRIPT,
    "john_lomein_provider_bootstrap.py",
    "john_lomein_provider_broker.py",
    "john_lomein_honcho_broker.py",
)


def embedded_python(source: str, marker: str) -> str:
    marker_index = source.index(marker)
    heredoc_index = source.index("<<'PY'", marker_index)
    body_start = source.index("\n", heredoc_index) + 1
    body_end = source.index("\nPY\n", body_start)
    return source[body_start:body_end] + "\n"


def shell_function(source: str, name: str) -> str:
    start = source.index(f"{name}() {{")
    end = source.index("\n}\n", start) + 3
    return source[start:end]


class GatewayEntrypointIsolationTest(unittest.TestCase):
    def render_plist(
        self,
        installer: Path,
        marker: str,
        arguments: list[str],
    ) -> dict[str, Any]:
        source = installer.read_text(encoding="utf-8")
        body = embedded_python(source, marker)
        result = subprocess.run(
            [sys.executable, "-", *arguments],
            input=body,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with Path(arguments[0]).open("rb") as handle:
            return plistlib.load(handle)

    def test_all_gateway_installers_statically_require_the_controller_and_brokers(self):
        gateway_installers: dict[str, str] = {}
        gateway_pattern = re.compile(r"['\"]gateway['\"]\s*,\s*['\"]run['\"]")
        wrapper_pattern = re.compile(
            r"john_lomein_model_isolation\.py.*?['\"]--profile['\"].*?"
            r"['\"]--['\"].*?hermes_cli\.main.*?['\"]gateway['\"]\s*,\s*"
            r"['\"]run['\"]",
            re.DOTALL,
        )
        for path in sorted(SCRIPTS.glob("*.sh")):
            source = path.read_text(encoding="utf-8")
            if gateway_pattern.search(source):
                gateway_installers[path.name] = source

        self.assertEqual(
            set(gateway_installers),
            {"install-guide-gateway.sh", "install-runtime-supervisor.sh"},
        )
        for name, source in gateway_installers.items():
            with self.subTest(installer=name):
                self.assertRegex(source, wrapper_pattern)
                for asset in BROKER_ASSETS:
                    self.assertIn(asset, source)

        doctor = (SCRIPTS / "doctor-instance.py").read_text(encoding="utf-8")
        scheduler_check = doctor[
            doctor.index("scheduler_label=") : doctor.index("keep_label=")
        ]
        self.assertIn("require_isolation=True", scheduler_check)

    def test_generated_gateway_plists_wrap_hermes_and_pin_isolation_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = root / "runtime"
            logs = runtime / "logs"
            real_home = root / "real-home"
            authority = real_home / ".hermes"
            python = sys.executable
            provider = "openai-codex"
            fallback = "openai-codex"

            cases = (
                (
                    SCRIPTS / "install-runtime-supervisor.sh",
                    '"${PRODUCT_PYTHON[@]}" - "$plist"',
                    "ai.hermes.john-lomein-fixture-scheduler",
                    "john-lomein-maintainer",
                    root / "scheduler.plist",
                    [
                        str(root / "scheduler.plist"),
                        "ai.hermes.john-lomein-fixture-scheduler",
                        python,
                        "john-lomein-maintainer",
                        str(runtime),
                        str(runtime / "managed-policy" / "john-lomein-maintainer"),
                        str(root / "venv"),
                        str(logs / "scheduler.launchd.log"),
                        str(logs / "scheduler.launchd.error.log"),
                        str(real_home),
                        str(authority),
                        str(runtime / "locks" / "gateway"),
                        str(
                            runtime
                            / "profiles"
                            / "john-lomein-maintainer"
                            / "home"
                            / ".config"
                            / "gh"
                        ),
                        "required",
                        provider,
                        fallback,
                    ],
                ),
                (
                    SCRIPTS / "install-guide-gateway.sh",
                    '"${PRODUCT_PYTHON[@]}" - "$PLIST"',
                    "ai.hermes.gateway-john-lomein-fixture-guide",
                    "john-lomein-guide",
                    root / "guide.plist",
                    [
                        str(root / "guide.plist"),
                        "ai.hermes.gateway-john-lomein-fixture-guide",
                        python,
                        "john-lomein-guide",
                        str(runtime),
                        str(runtime / "managed-policy" / "john-lomein-guide"),
                        str(root / "venv"),
                        str(real_home),
                        str(authority),
                        str(runtime / "locks" / "gateway"),
                        "owner/repository",
                        "owner",
                        "a" * 64,
                        "1001",
                        "1002",
                        "required",
                        provider,
                        fallback,
                    ],
                ),
            )

            for installer, marker, label, profile, plist_path, arguments in cases:
                with self.subTest(installer=installer.name):
                    plist = self.render_plist(installer, marker, arguments)
                    direct = [
                        python,
                        "-I",
                        "-m",
                        "hermes_cli.main",
                        "gateway",
                        "run",
                        "--replace",
                    ]
                    self.assertEqual(
                        plist["ProgramArguments"],
                        [
                            python,
                            str(runtime / "scripts" / ISOLATION_SCRIPT),
                            "--profile",
                            profile,
                            "--",
                            *direct,
                        ],
                    )
                    environment = plist["EnvironmentVariables"]
                    self.assertEqual(environment["BOT_HERMES_HOME"], str(runtime))
                    self.assertEqual(
                        environment["BOT_MODEL_MEMORY_ISOLATION"],
                        "required",
                    )
                    self.assertEqual(
                        environment["BOT_STEWARD_PRIVATE_ROOT"],
                        str(runtime / "private" / "learning-steward"),
                    )
                    self.assertEqual(
                        environment["BOT_STEWARD_PROJECTION_ROOT"],
                        str(runtime / "state" / "learning"),
                    )
                    self.assertEqual(
                        environment["HERMES_HONCHO_HOST"],
                        f"hermes_{profile}",
                    )
                    self.assertEqual(plist["Label"], label)
                    self.assertEqual(plist_path, Path(arguments[0]))

    def test_gateway_asset_guard_fails_closed_when_honcho_broker_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            scripts = runtime / "scripts"
            scripts.mkdir(parents=True)
            for asset in BROKER_ASSETS[:-1]:
                (scripts / asset).write_text("# fixture\n", encoding="utf-8")

            for installer_name in (
                "install-guide-gateway.sh",
                "install-runtime-supervisor.sh",
            ):
                with self.subTest(installer=installer_name):
                    source = (SCRIPTS / installer_name).read_text(encoding="utf-8")
                    guard = shell_function(source, "require_isolated_gateway_assets")
                    result = subprocess.run(
                        [
                            "bash",
                            "-c",
                            (
                                "set -Eeuo pipefail\n"
                                f"{guard}\n"
                                'require_isolated_gateway_assets "$1"\n'
                            ),
                            "gateway-asset-test",
                            str(runtime),
                        ],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("john_lomein_honcho_broker.py", result.stderr)


if __name__ == "__main__":
    unittest.main()
