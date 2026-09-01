#!/usr/bin/env python3
from __future__ import annotations

import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import john_lomein_service_registry as registry


class ServiceRegistryTest(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        launch_agents = root / "Library" / "LaunchAgents"
        launch_agents.mkdir(parents=True)
        manifest_a = root / "instance-a" / "instance.yaml"
        manifest_b = root / "instance-b" / "instance.yaml"
        manifest_a.parent.mkdir()
        manifest_b.parent.mkdir()
        manifest_a.write_text("instance:\n  slug: alpha\n", encoding="utf-8")
        manifest_b.write_text("instance:\n  slug: beta\n", encoding="utf-8")
        runtime_a = root / "runtime-a"
        runtime_b = root / "runtime-b"
        runtime_a.mkdir()
        runtime_b.mkdir()
        env = mock.patch.dict(
            os.environ,
            {
                "HOME": str(root),
            },
        )
        env.start()
        no_launchctl = mock.patch.object(
            registry.shutil,
            "which",
            return_value=None,
        )
        no_launchctl.start()
        self.addCleanup(no_launchctl.stop)
        self.addCleanup(env.stop)
        self.addCleanup(temporary.cleanup)
        return manifest_a, manifest_b, runtime_a, runtime_b, launch_agents

    @staticmethod
    def write_plist(
        path: Path,
        label: str,
        runtime_home: Path,
        *,
        isolated: bool = True,
    ) -> None:
        profile: str | None = None
        if label.startswith("ai.hermes.gateway-john-lomein-"):
            profile = "john-lomein-guide"
            arguments = [
                "/usr/bin/python3",
                "-m",
                "hermes_cli.main",
                "--profile",
                profile,
                "gateway",
                "run",
                "--replace",
            ]
            working_directory = runtime_home / "profiles" / profile
        elif label.endswith("-scheduler"):
            profile = "john-lomein-maintainer"
            arguments = [
                "/usr/bin/python3",
                "-m",
                "hermes_cli.main",
                "--profile",
                profile,
                "gateway",
                "run",
                "--replace",
            ]
            working_directory = runtime_home / "profiles" / profile
        else:
            arguments = [
                str(
                    runtime_home
                    / "scripts"
                    / "john-lomein-keepawake.sh"
                )
            ]
            working_directory = runtime_home
        if isolated and (
            label.startswith("ai.hermes.gateway-john-lomein-")
            or label.endswith("-scheduler")
        ):
            assert profile is not None
            arguments = [
                "/usr/bin/python3",
                str(
                    runtime_home
                    / "scripts"
                    / "john_lomein_model_isolation.py"
                ),
                "--profile",
                profile,
                "--",
                *arguments,
            ]
        with path.open("wb") as handle:
            plistlib.dump(
                {
                    "Label": label,
                    "ProgramArguments": arguments,
                    "WorkingDirectory": str(working_directory),
                    "EnvironmentVariables": {
                        "HERMES_HOME": str(runtime_home),
                        "JOHN_LOMEIN_INSTANCE_HERMES_HOME": str(runtime_home),
                    },
                },
                handle,
            )

    @staticmethod
    def launchctl_output(
        label: str,
        runtime_home: Path,
        *,
        isolated: bool = True,
    ) -> str:
        if label.startswith("ai.hermes.gateway-john-lomein-"):
            profile = "john-lomein-guide"
        else:
            profile = "john-lomein-maintainer"
        arguments = [
            "/usr/bin/python3",
            "-m",
            "hermes_cli.main",
            "--profile",
            profile,
            "gateway",
            "run",
            "--replace",
        ]
        if isolated:
            arguments = [
                "/usr/bin/python3",
                str(
                    runtime_home
                    / "scripts"
                    / "john_lomein_model_isolation.py"
                ),
                "--profile",
                profile,
                "--",
                *arguments,
            ]
        lines = [
            "program = /usr/bin/python3",
            "arguments = {",
            *(f"\t{argument}" for argument in arguments),
            "}",
            f"working directory = {runtime_home / 'profiles' / profile}",
            "environment = {",
            f"\tHERMES_HOME => {runtime_home}",
            f"\tJOHN_LOMEIN_INSTANCE_HERMES_HOME => {runtime_home}",
            "}",
        ]
        return "\n".join(lines)

    def test_slug_migration_stops_recorded_and_desired_labels(self):
        manifest, _, runtime, _, launch_agents = self.fixture()
        old = "ai.hermes.john-lomein-old-scheduler"
        new = "ai.hermes.john-lomein-new-scheduler"
        self.write_plist(
            launch_agents / f"{old}.plist",
            old,
            runtime,
        )
        registry.record_services(manifest, runtime, {"scheduler": old})
        (launch_agents / f"{old}.plist").unlink()

        result = registry.stop_services(
            manifest,
            runtime,
            {"scheduler": new},
        )

        self.assertEqual(result["stopped"], [new, old])
        self.assertIsNone(registry.read_registry(manifest))

    def test_pre_registry_old_slug_plist_is_discovered_by_runtime(self):
        manifest, _, runtime, _, launch_agents = self.fixture()
        old = "ai.hermes.john-lomein-old-scheduler"
        new = "ai.hermes.john-lomein-new-scheduler"
        old_plist = launch_agents / f"{old}.plist"
        self.write_plist(old_plist, old, runtime)

        def fake_run(cmd, **_kwargs):
            if cmd[1] == "print":
                return SimpleNamespace(
                    returncode=1,
                    stdout="",
                    stderr="Could not find service",
                )
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch.object(
            registry.shutil,
            "which",
            return_value="/usr/bin/launchctl",
        ), mock.patch.object(registry.subprocess, "run", side_effect=fake_run):
            result = registry.stop_services(
                manifest,
                runtime,
                {"scheduler": new},
            )

        self.assertEqual(result["stopped"], [new, old])
        self.assertFalse(old_plist.exists())

    def test_two_instances_cannot_own_the_same_label(self):
        (
            manifest_a,
            manifest_b,
            runtime_a,
            runtime_b,
            launch_agents,
        ) = self.fixture()
        label = "ai.hermes.john-lomein-shared-scheduler"
        self.write_plist(
            launch_agents / f"{label}.plist",
            label,
            runtime_a,
        )
        registry.record_services(manifest_a, runtime_a, {"scheduler": label})

        with self.assertRaisesRegex(
            registry.ServiceRegistryError,
            "launchd label collision",
        ):
            registry.record_services(
                manifest_b,
                runtime_b,
                {"scheduler": label},
            )

    def test_all_stop_candidates_are_preflighted_before_any_removal(self):
        (
            manifest_a,
            manifest_b,
            runtime_a,
            runtime_b,
            launch_agents,
        ) = self.fixture()
        old = "ai.hermes.john-lomein-alpha-scheduler"
        foreign = "ai.hermes.john-lomein-beta-scheduler"
        self.write_plist(
            launch_agents / f"{old}.plist",
            old,
            runtime_a,
        )
        registry.record_services(manifest_a, runtime_a, {"scheduler": old})
        self.write_plist(
            launch_agents / f"{foreign}.plist",
            foreign,
            runtime_b,
        )
        registry.record_services(manifest_b, runtime_b, {"scheduler": foreign})
        (launch_agents / f"{old}.plist").unlink()
        (launch_agents / f"{foreign}.plist").unlink()

        with mock.patch.object(registry, "_stop_label") as stop_label:
            with self.assertRaisesRegex(
                registry.ServiceRegistryError,
                "refusing to stop foreign",
            ):
                registry.stop_services(
                    manifest_a,
                    runtime_a,
                    {"scheduler": foreign},
                )
        stop_label.assert_not_called()
        self.assertEqual(
            registry.read_registry(manifest_a)["labels"]["scheduler"],
            old,
        )

    def test_unregistered_foreign_plist_is_not_stopped_or_deleted(self):
        manifest_a, _, runtime_a, runtime_b, launch_agents = self.fixture()
        label = "ai.hermes.john-lomein-shared-scheduler"
        plist = launch_agents / f"{label}.plist"
        self.write_plist(plist, label, runtime_b)

        with self.assertRaisesRegex(
            registry.ServiceRegistryError,
            "belongs to another runtime",
        ):
            registry.stop_services(
                manifest_a,
                runtime_a,
                {"scheduler": label},
            )
        self.assertTrue(plist.exists())

    def test_registered_plist_symlink_is_never_followed_or_removed(self):
        manifest, _, runtime, runtime_b, launch_agents = self.fixture()
        label = "ai.hermes.john-lomein-alpha-scheduler"
        registered = launch_agents / f"{label}.plist"
        self.write_plist(registered, label, runtime)
        registry.record_services(manifest, runtime, {"scheduler": label})
        foreign = launch_agents / "foreign.plist"
        self.write_plist(foreign, label, runtime_b)
        registered.unlink()
        registered.symlink_to(foreign)

        with self.assertRaisesRegex(
            registry.ServiceRegistryError,
            "plist is a symlink",
        ):
            registry.stop_services(
                manifest,
                runtime,
                {"scheduler": label},
            )

        self.assertTrue(registered.is_symlink())
        self.assertTrue(foreign.exists())

    def test_registered_plist_identity_must_match_registry(self):
        manifest, _, runtime, runtime_b, launch_agents = self.fixture()
        label = "ai.hermes.john-lomein-alpha-scheduler"
        plist = launch_agents / f"{label}.plist"
        self.write_plist(plist, label, runtime)
        registry.record_services(manifest, runtime, {"scheduler": label})
        self.write_plist(plist, label, runtime_b)

        with self.assertRaisesRegex(
            registry.ServiceRegistryError,
            "runtime does not match registered ownership",
        ):
            registry.stop_services(
                manifest,
                runtime,
                {"scheduler": label},
            )

        self.assertTrue(plist.exists())

    def test_bootout_success_is_not_trusted_until_print_confirms_absence(self):
        manifest, _, runtime, _, launch_agents = self.fixture()
        label = "ai.hermes.john-lomein-alpha-scheduler"
        plist = launch_agents / f"{label}.plist"
        self.write_plist(plist, label, runtime)

        def fake_run(cmd, **_kwargs):
            if cmd[1] == "print":
                return SimpleNamespace(
                    returncode=0,
                    stdout=self.launchctl_output(label, runtime),
                    stderr="",
                )
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch.object(
            registry.shutil,
            "which",
            return_value="/usr/bin/launchctl",
        ), mock.patch.object(
            registry.subprocess,
            "run",
            side_effect=fake_run,
        ), mock.patch.object(registry.time, "sleep"):
            with self.assertRaisesRegex(
                registry.ServiceRegistryError,
                "remains loaded after bootout",
            ):
                registry.stop_services(
                    manifest,
                    runtime,
                    {"scheduler": label},
                )
        self.assertTrue(plist.exists())

    def test_bootout_waits_for_transient_sigtermed_service_to_disappear(self):
        manifest, _, runtime, _, launch_agents = self.fixture()
        label = "ai.hermes.john-lomein-alpha-scheduler"
        plist = launch_agents / f"{label}.plist"
        self.write_plist(plist, label, runtime)
        print_calls = 0

        def fake_run(cmd, **_kwargs):
            nonlocal print_calls
            if cmd[1] == "print":
                print_calls += 1
                if print_calls <= 8:
                    return SimpleNamespace(
                        returncode=0,
                        stdout=self.launchctl_output(label, runtime),
                        stderr="",
                    )
                return SimpleNamespace(
                    returncode=1,
                    stdout="",
                    stderr="Could not find service",
                )
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch.object(
            registry.shutil,
            "which",
            return_value="/usr/bin/launchctl",
        ), mock.patch.object(
            registry.subprocess,
            "run",
            side_effect=fake_run,
        ), mock.patch.object(registry.time, "sleep") as sleep:
            registry.stop_services(
                manifest,
                runtime,
                {"scheduler": label},
            )

        self.assertGreaterEqual(sleep.call_count, 5)
        self.assertFalse(plist.exists())

    def test_runtime_home_change_requires_full_service_reconciliation(self):
        manifest, _, runtime_a, runtime_b, launch_agents = self.fixture()
        guide = "ai.hermes.gateway-john-lomein-alpha-guide"
        scheduler = "ai.hermes.john-lomein-alpha-scheduler"
        self.write_plist(
            launch_agents / f"{guide}.plist",
            guide,
            runtime_a,
        )
        registry.record_services(manifest, runtime_a, {"guide": guide})
        self.write_plist(
            launch_agents / f"{scheduler}.plist",
            scheduler,
            runtime_b,
        )

        with self.assertRaisesRegex(
            registry.ServiceRegistryError,
            "runtime home changed",
        ):
            registry.record_services(
                manifest,
                runtime_b,
                {"scheduler": scheduler},
            )

    def test_adoption_cannot_merge_services_from_two_runtime_homes(self):
        manifest, _, runtime_a, runtime_b, launch_agents = self.fixture()
        guide = "ai.hermes.gateway-john-lomein-alpha-guide"
        scheduler = "ai.hermes.john-lomein-alpha-scheduler"
        self.write_plist(
            launch_agents / f"{guide}.plist",
            guide,
            runtime_a,
        )
        registry.record_services(manifest, runtime_a, {"guide": guide})
        self.write_plist(
            launch_agents / f"{scheduler}.plist",
            scheduler,
            runtime_b,
        )

        with self.assertRaisesRegex(
            registry.ServiceRegistryError,
            "different runtime",
        ):
            registry.adopt_services(manifest, runtime_b)

        entry = registry.read_registry(manifest)
        self.assertEqual(entry["runtime_home"], str(runtime_a.resolve()))
        self.assertEqual(entry["labels"], {"guide": guide})

    def test_unregistered_other_runtime_requires_explicit_adoption(self):
        manifest, _, runtime_a, runtime_b, launch_agents = self.fixture()
        legacy = "ai.hermes.john-lomein-legacy-scheduler"
        desired = "ai.hermes.john-lomein-alpha-scheduler"
        self.write_plist(
            launch_agents / f"{legacy}.plist",
            legacy,
            runtime_b,
        )

        with self.assertRaisesRegex(
            registry.ServiceRegistryError,
            "requires explicit adoption",
        ):
            registry.record_services(
                manifest,
                runtime_a,
                {"scheduler": desired},
            )

    def test_status_reports_registered_slug_drift(self):
        manifest, _, runtime, _, launch_agents = self.fixture()
        old = "ai.hermes.gateway-john-lomein-old-guide"
        new = "ai.hermes.gateway-john-lomein-new-guide"
        self.write_plist(
            launch_agents / f"{old}.plist",
            old,
            runtime,
        )
        registry.record_services(manifest, runtime, {"guide": old})

        status = registry.registry_status(
            manifest,
            runtime,
            {"guide": new},
        )

        self.assertIn(
            "registry_labels_do_not_match_expected",
            status["issues"],
        )

    def test_record_refuses_runtime_rewrite_without_matching_service_identity(
        self,
    ):
        manifest, _, runtime_a, runtime_b, launch_agents = self.fixture()
        label = "ai.hermes.john-lomein-alpha-scheduler"
        self.write_plist(
            launch_agents / f"{label}.plist",
            label,
            runtime_a,
        )
        registry.record_services(manifest, runtime_a, {"scheduler": label})

        with self.assertRaisesRegex(
            registry.ServiceRegistryError,
            "does not consistently match runtime",
        ):
            registry.record_services(
                manifest,
                runtime_b,
                {"scheduler": label},
            )

        self.assertEqual(
            registry.read_registry(manifest)["runtime_home"],
            str(runtime_a.resolve()),
        )

    def test_record_refuses_to_orphan_previous_same_kind_label(self):
        manifest, _, runtime, _, launch_agents = self.fixture()
        old = "ai.hermes.john-lomein-old-scheduler"
        new = "ai.hermes.john-lomein-new-scheduler"
        self.write_plist(
            launch_agents / f"{old}.plist",
            old,
            runtime,
        )
        registry.record_services(manifest, runtime, {"scheduler": old})
        self.write_plist(
            launch_agents / f"{new}.plist",
            new,
            runtime,
        )

        with self.assertRaisesRegex(
            registry.ServiceRegistryError,
            "previous service still exists",
        ):
            registry.record_services(
                manifest,
                runtime,
                {"scheduler": new},
            )

        self.assertEqual(
            registry.read_registry(manifest)["labels"],
            {"scheduler": old},
        )

    def test_status_reports_missing_and_wrong_runtime_service_identity(self):
        manifest, _, runtime_a, runtime_b, launch_agents = self.fixture()
        label = "ai.hermes.john-lomein-alpha-scheduler"
        plist = launch_agents / f"{label}.plist"
        self.write_plist(plist, label, runtime_a)
        registry.record_services(manifest, runtime_a, {"scheduler": label})
        self.write_plist(plist, label, runtime_b)

        status = registry.registry_status(
            manifest,
            runtime_a,
            {"scheduler": label},
        )

        self.assertIn("expected_runtime_services_missing", status["issues"])
        self.assertIn("service_identity_mismatch", status["issues"])
        self.assertEqual(status["missing"], [label])
        self.assertEqual(status["identity_mismatches"], [label])
        self.assertEqual(status["discovered"], [])

    def test_unwrapped_scheduler_gateway_is_rejected(self):
        manifest, _, runtime, _, launch_agents = self.fixture()
        label = "ai.hermes.john-lomein-alpha-scheduler"
        plist = launch_agents / f"{label}.plist"
        self.write_plist(plist, label, runtime, isolated=False)

        self.assertNotEqual(registry._plist_identity(plist)[2], "")
        with self.assertRaises(registry.ServiceRegistryError):
            registry.record_services(
                manifest,
                runtime,
                {"scheduler": label},
            )

    def test_plist_command_contract_is_bound_to_registered_identity(self):
        manifest, _, runtime, _, launch_agents = self.fixture()
        label = "ai.hermes.john-lomein-alpha-scheduler"
        plist = launch_agents / f"{label}.plist"
        self.write_plist(plist, label, runtime)
        registry.record_services(manifest, runtime, {"scheduler": label})
        with plist.open("wb") as handle:
            plistlib.dump(
                {
                    "Label": label,
                    "ProgramArguments": [
                        "/bin/sh",
                        "-c",
                        "echo unrelated",
                    ],
                    "WorkingDirectory": str(
                        runtime / "profiles" / "john-lomein-maintainer"
                    ),
                    "EnvironmentVariables": {
                        "HERMES_HOME": str(runtime),
                        "JOHN_LOMEIN_INSTANCE_HERMES_HOME": str(runtime),
                    },
                },
                handle,
            )

        status = registry.registry_status(
            manifest,
            runtime,
            {"scheduler": label},
        )
        self.assertIn("service_identity_mismatch", status["issues"])
        self.assertIn("runtime_service_identity_conflict", status["issues"])
        with self.assertRaisesRegex(
            registry.ServiceRegistryError,
            "does not consistently match runtime",
        ):
            registry.record_services(
                manifest,
                runtime,
                {"scheduler": label},
            )

    def test_wrapped_guide_command_is_bound_to_deployed_isolation_entrypoint(self):
        manifest, _, runtime, _, launch_agents = self.fixture()
        label = "ai.hermes.gateway-john-lomein-alpha-guide"
        profile = "john-lomein-guide"
        wrapper = runtime / "scripts" / "john_lomein_model_isolation.py"
        plist = launch_agents / f"{label}.plist"
        arguments = [
            "/usr/bin/python3",
            str(wrapper),
            "--profile",
            profile,
            "--",
            "/usr/bin/python3",
            "-I",
            "-m",
            "hermes_cli.main",
            "--profile",
            profile,
            "gateway",
            "run",
            "--replace",
        ]
        with plist.open("wb") as handle:
            plistlib.dump(
                {
                    "Label": label,
                    "ProgramArguments": arguments,
                    "WorkingDirectory": str(runtime / "profiles" / profile),
                    "EnvironmentVariables": {
                        "HERMES_HOME": str(runtime),
                        "JOHN_LOMEIN_INSTANCE_HERMES_HOME": str(runtime),
                    },
                },
                handle,
            )

        registry.record_services(manifest, runtime, {"guide": label})
        status = registry.registry_status(
            manifest,
            runtime,
            {"guide": label},
        )
        self.assertNotIn("service_identity_mismatch", status["issues"])

        arguments[1] = str(runtime / "scripts" / "untrusted-wrapper.py")
        with plist.open("wb") as handle:
            plistlib.dump(
                {
                    "Label": label,
                    "ProgramArguments": arguments,
                    "WorkingDirectory": str(runtime / "profiles" / profile),
                    "EnvironmentVariables": {
                        "HERMES_HOME": str(runtime),
                        "JOHN_LOMEIN_INSTANCE_HERMES_HOME": str(runtime),
                    },
                },
                handle,
            )
        status = registry.registry_status(
            manifest,
            runtime,
            {"guide": label},
        )
        self.assertIn("service_identity_mismatch", status["issues"])

    def test_loaded_no_plist_adoption_rejects_unrelated_command(self):
        manifest, _, runtime, _, _ = self.fixture()
        label = "ai.hermes.john-lomein-alpha-scheduler"
        output = "\n".join(
            [
                "program = /bin/sh",
                "arguments = {",
                "\t/bin/sh",
                "\t-c",
                "\techo unrelated",
                "}",
                "working directory = "
                f"{runtime / 'profiles' / 'john-lomein-maintainer'}",
                "environment = {",
                f"\tJOHN_LOMEIN_INSTANCE_HERMES_HOME => {runtime}",
                "}",
            ]
        )

        def fake_run(cmd, **_kwargs):
            if cmd[1] == "list":
                return SimpleNamespace(
                    returncode=0,
                    stdout=f"- 0 {label}",
                    stderr="",
                )
            if cmd[1] == "print":
                return SimpleNamespace(
                    returncode=0,
                    stdout=output,
                    stderr="",
                )
            raise AssertionError(f"unexpected launchctl command: {cmd}")

        with mock.patch.object(
            registry.shutil,
            "which",
            return_value="/usr/bin/launchctl",
        ), mock.patch.object(registry.subprocess, "run", side_effect=fake_run):
            status = registry.registry_status(manifest, runtime, {})
            self.assertIn(
                "runtime_service_identity_conflict",
                status["issues"],
            )
            with self.assertRaisesRegex(
                registry.ServiceRegistryError,
                "contradictory plist/loaded identity",
            ):
                registry.adopt_services(manifest, runtime)

        self.assertIsNone(registry.read_registry(manifest))

    def test_plist_and_live_interpreter_identity_must_match_exactly(self):
        manifest, _, runtime, _, launch_agents = self.fixture()
        label = "ai.hermes.john-lomein-alpha-scheduler"
        plist = launch_agents / f"{label}.plist"
        self.write_plist(plist, label, runtime)
        registry.record_services(manifest, runtime, {"scheduler": label})
        alternate_python = runtime.parent / "python-backdoor"
        alternate_python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        alternate_python.chmod(0o755)
        fake_hermes = runtime.parent / "hermes"
        fake_hermes.write_text(
            f"#!{alternate_python}\n",
            encoding="utf-8",
        )
        live_output = self.launchctl_output(label, runtime).replace(
            "/usr/bin/python3",
            str(alternate_python),
        )

        def fake_which(command):
            return {
                "launchctl": "/usr/bin/launchctl",
                "hermes": str(fake_hermes),
                "python3": "/usr/bin/python3",
            }.get(command)

        def fake_run(cmd, **_kwargs):
            if cmd[1] == "list":
                return SimpleNamespace(
                    returncode=0,
                    stdout=f"- 0 {label}",
                    stderr="",
                )
            if cmd[1] == "print":
                return SimpleNamespace(
                    returncode=0,
                    stdout=live_output,
                    stderr="",
                )
            raise AssertionError(f"unexpected launchctl command: {cmd}")

        with mock.patch.object(
            registry.shutil,
            "which",
            side_effect=fake_which,
        ), mock.patch.object(registry.subprocess, "run", side_effect=fake_run):
            status = registry.registry_status(
                manifest,
                runtime,
                {"scheduler": label},
            )
            self.assertIn("service_identity_mismatch", status["issues"])
            self.assertIn(
                "runtime_service_identity_conflict",
                status["issues"],
            )
            with self.assertRaisesRegex(
                registry.ServiceRegistryError,
                "does not consistently match runtime",
            ):
                registry.record_services(
                    manifest,
                    runtime,
                    {"scheduler": label},
                )
            with self.assertRaisesRegex(
                registry.ServiceRegistryError,
                "does not match registered ownership",
            ):
                registry.stop_services(
                    manifest,
                    runtime,
                    {"scheduler": label},
                )

        self.assertTrue(plist.exists())

    def test_conflicting_runtime_environment_markers_are_rejected(self):
        manifest, _, runtime_a, runtime_b, launch_agents = self.fixture()
        label = "ai.hermes.john-lomein-alpha-scheduler"
        plist = launch_agents / f"{label}.plist"
        self.write_plist(plist, label, runtime_a)
        registry.record_services(manifest, runtime_a, {"scheduler": label})
        with plist.open("rb") as handle:
            data = plistlib.load(handle)
        data["EnvironmentVariables"]["HERMES_HOME"] = str(runtime_b)
        with plist.open("wb") as handle:
            plistlib.dump(data, handle)

        status = registry.registry_status(
            manifest,
            runtime_a,
            {"scheduler": label},
        )
        self.assertIn("expected_runtime_services_missing", status["issues"])
        self.assertIn("service_identity_mismatch", status["issues"])
        with self.assertRaisesRegex(
            registry.ServiceRegistryError,
            "does not consistently match runtime",
        ):
            registry.record_services(
                manifest,
                runtime_a,
                {"scheduler": label},
            )

        live_output = self.launchctl_output(label, runtime_a).replace(
            f"\tHERMES_HOME => {runtime_a}",
            f"\tHERMES_HOME => {runtime_b}",
        )
        self.assertEqual(
            registry._runtime_home_from_launchctl_output(live_output),
            "",
        )

    def test_adoption_rejects_conflicting_plist_and_loaded_runtime(self):
        manifest, _, runtime_a, runtime_b, launch_agents = self.fixture()
        label = "ai.hermes.john-lomein-alpha-scheduler"
        self.write_plist(
            launch_agents / f"{label}.plist",
            label,
            runtime_a,
        )

        def fake_run(cmd, **_kwargs):
            if cmd[1] == "list":
                return SimpleNamespace(
                    returncode=0,
                    stdout=f"- 0 {label}",
                    stderr="",
                )
            if cmd[1] == "print":
                return SimpleNamespace(
                    returncode=0,
                    stdout=self.launchctl_output(label, runtime_b),
                    stderr="",
                )
            raise AssertionError(f"unexpected launchctl command: {cmd}")

        with mock.patch.object(
            registry.shutil,
            "which",
            return_value="/usr/bin/launchctl",
        ), mock.patch.object(registry.subprocess, "run", side_effect=fake_run):
            status = registry.registry_status(manifest, runtime_a, {})
            self.assertIn(
                "runtime_service_identity_conflict",
                status["issues"],
            )
            self.assertEqual(status["conflicting"], [label])
            with self.assertRaisesRegex(
                registry.ServiceRegistryError,
                "contradictory plist/loaded identity",
            ):
                registry.adopt_services(manifest, runtime_a)

        self.assertIsNone(registry.read_registry(manifest))

    def test_launchctl_permission_error_is_not_proof_of_absence(self):
        manifest, _, runtime, _, launch_agents = self.fixture()
        label = "ai.hermes.john-lomein-alpha-scheduler"
        plist = launch_agents / f"{label}.plist"
        self.write_plist(plist, label, runtime)
        registry.record_services(manifest, runtime, {"scheduler": label})

        def fake_run(cmd, **_kwargs):
            if cmd[1] == "list":
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if cmd[1] == "print":
                return SimpleNamespace(
                    returncode=1,
                    stdout="",
                    stderr="Operation not permitted",
                )
            if cmd[1] == "bootout":
                return SimpleNamespace(
                    returncode=1,
                    stdout="",
                    stderr="Operation not permitted",
                )
            raise AssertionError(f"unexpected launchctl command: {cmd}")

        with mock.patch.object(
            registry.shutil,
            "which",
            return_value="/usr/bin/launchctl",
        ), mock.patch.object(registry.subprocess, "run", side_effect=fake_run):
            with self.assertRaisesRegex(
                registry.ServiceRegistryError,
                "could not inspect service",
            ):
                registry.stop_services(
                    manifest,
                    runtime,
                    {"scheduler": label},
                )

        self.assertTrue(plist.exists())
        self.assertEqual(
            registry.read_registry(manifest)["labels"],
            {"scheduler": label},
        )

    def test_loaded_legacy_service_without_plist_is_reported_adopted_and_stopped(
        self,
    ):
        manifest, _, runtime, _, _ = self.fixture()
        old = "ai.hermes.john-lomein-old-scheduler"
        new = "ai.hermes.john-lomein-new-scheduler"
        loaded = {old}

        def fake_run(cmd, **_kwargs):
            operation = cmd[1]
            if operation == "list":
                rows = ["PID Status Label"]
                rows.extend(f"- 0 {label}" for label in sorted(loaded))
                return SimpleNamespace(
                    returncode=0,
                    stdout="\n".join(rows),
                    stderr="",
                )
            if operation == "print":
                label = cmd[2].rsplit("/", 1)[-1]
                if label in loaded:
                    return SimpleNamespace(
                        returncode=0,
                        stdout=self.launchctl_output(
                            label,
                            runtime,
                            isolated=False,
                        ),
                        stderr="",
                    )
                return SimpleNamespace(
                    returncode=1,
                    stdout="",
                    stderr="Could not find service",
                )
            if operation == "bootout":
                loaded.discard(cmd[2].rsplit("/", 1)[-1])
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            raise AssertionError(f"unexpected launchctl command: {cmd}")

        with mock.patch.object(
            registry.shutil,
            "which",
            return_value="/usr/bin/launchctl",
        ), mock.patch.object(registry.subprocess, "run", side_effect=fake_run):
            status = registry.registry_status(
                manifest,
                runtime,
                {"scheduler": new},
            )
            self.assertEqual(status["unexpected"], [old])

            adoption = registry.adopt_services(manifest, runtime)
            self.assertEqual(adoption["adopted"], {"scheduler": old})

            stopped = registry.stop_services(
                manifest,
                runtime,
                {"scheduler": new},
            )

        self.assertEqual(stopped["stopped"], [new, old])
        self.assertFalse(loaded)
        self.assertIsNone(registry.read_registry(manifest))

    def test_service_specific_environment_cannot_split_product_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(
                os.environ,
                {
                    "HOME": tmp,
                    "JOHN_LOMEIN_SERVICE_TEST_MODE": "1",
                    "JOHN_LOMEIN_SERVICE_REGISTRY_DIR": "/tmp/foreign-registry",
                    "JOHN_LOMEIN_LAUNCH_AGENTS_DIR": "/tmp/foreign-agents",
                },
            ):
                self.assertEqual(
                    registry.registry_root(),
                    Path(tmp).resolve()
                    / ".john-lomein"
                    / "service-registry",
                )
                self.assertEqual(
                    registry.launch_agents_root(),
                    Path(tmp).resolve() / "Library" / "LaunchAgents",
                )

    def test_run_locked_serializes_complete_lifecycle_commands(self):
        manifest, _, runtime, _, _ = self.fixture()
        del manifest, runtime
        log = Path(tempfile.mkdtemp()) / "events.log"
        self.addCleanup(lambda: log.parent.exists() and shutil.rmtree(log.parent))
        worker = (
            "import pathlib,sys,time;"
            "p=pathlib.Path(sys.argv[1]);"
            "name=sys.argv[2];"
            "p.open('a').write(name+'-start\\n');"
            "time.sleep(0.25);"
            "p.open('a').write(name+'-end\\n')"
        )
        helper = SCRIPTS / "john_lomein_service_registry.py"
        command = lambda name: [
            sys.executable,
            str(helper),
            "run-locked",
            "--",
            sys.executable,
            "-c",
            worker,
            str(log),
            name,
        ]
        env = dict(os.environ)
        first = subprocess.Popen(command("first"), env=env)
        second = subprocess.Popen(command("second"), env=env)
        self.assertEqual(first.wait(timeout=10), 0)
        self.assertEqual(second.wait(timeout=10), 0)
        lines = log.read_text(encoding="utf-8").splitlines()
        self.assertIn(
            lines,
            [
                ["first-start", "first-end", "second-start", "second-end"],
                ["second-start", "second-end", "first-start", "first-end"],
            ],
        )

    def test_assert_inherited_lock_rejects_invalid_closed_and_wrong_fds(self):
        self.fixture()
        root = registry.registry_root()
        root.mkdir(parents=True, exist_ok=True)
        lock_path = root / ".lifecycle.lock"
        lock_path.touch(mode=0o600)
        wrong_path = root / "wrong.lock"
        wrong_path.touch(mode=0o600)
        wrong_fd = os.open(wrong_path, os.O_RDWR)
        closed_fd = os.open(wrong_path, os.O_RDWR)
        os.close(closed_fd)
        self.addCleanup(os.close, wrong_fd)

        for value in ("not-a-descriptor", str(closed_fd), str(wrong_fd)):
            with self.subTest(value=value), mock.patch.dict(
                os.environ,
                {"JOHN_LOMEIN_SERVICE_LOCK_FD": value},
                clear=False,
            ):
                with self.assertRaisesRegex(
                    registry.ServiceRegistryError,
                    "invalid or not locked",
                ):
                    registry.assert_inherited_lock()

    def test_assert_inherited_lock_accepts_the_held_registry_fd(self):
        self.fixture()
        with mock.patch.dict(
            os.environ,
            {"JOHN_LOMEIN_SERVICE_LOCK_FD": ""},
            clear=False,
        ):
            with registry.lifecycle_lock() as descriptor:
                with mock.patch.dict(
                    os.environ,
                    {
                        "JOHN_LOMEIN_SERVICE_LOCK_FD": str(descriptor),
                    },
                    clear=False,
                ):
                    registry.assert_inherited_lock()


if __name__ == "__main__":
    unittest.main()
