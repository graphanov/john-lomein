#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from john_lomein_manifest_contract import (  # noqa: E402
    model_memory_isolation_mode,
)
from john_lomein_honcho_broker import (  # noqa: E402
    HonchoBinding,
    create_server as create_honcho_server,
)
from john_lomein_model_isolation import (  # noqa: E402
    IsolationError,
    darwin_policy,
    honcho_broker_socket_path,
    isolated_command,
    isolated_environment,
    provider_broker_socket_path,
    run_isolation_canary,
)


class ModelMemoryIsolationTest(unittest.TestCase):
    def fixture(self, root: Path) -> dict[str, str]:
        home = root / "hermes"
        owner_home = root / "owner"
        owner_home.mkdir(parents=True, exist_ok=True)
        checkout = root / "checkout"
        for path in (
            home / "scripts",
            home / "managed-policy",
            home / "managed-policy" / "john-lomein-guide",
            home / "plugins",
            home / "private",
            home / "private" / "owner-overrides",
            home / "private" / "owner-overrides" / "inbox",
            home / "private" / "review-receipts",
            home / "private" / "honcho-deletion-tombstones",
            home / "private" / "honcho-backups",
            home / "private" / "release-bundles",
            home / "private" / "learning-steward",
            home / "private" / "learning-steward" / "learning",
            home / "private" / "learning-steward" / "mnemosyne",
            home / "private" / "learning-steward" / "mnemosyne" / "data",
            home / "state" / "learning",
            home / "state" / "continuity",
            home / "state" / "honcho",
            home / "services" / "public-honcho",
            home / "logs",
            home / "logs" / "public-honcho",
            home / "work",
            home / "profiles" / "john-lomein-guide" / "home",
            home / "profiles" / "john-lomein-guide" / "home" / ".config" / "gh",
            home / "profiles" / "john-lomein-guide" / "logs",
            home / "profiles" / "john-lomein-guide" / "skills",
            home / "profiles" / "john-lomein-guide" / "memories",
            home / "profiles" / "john-lomein-guide" / "plugins",
            home / "profiles" / "john-lomein-guide" / "scripts",
            home / "profiles" / "john-lomein-guide" / "hooks",
            home / "profiles" / "john-lomein-guide" / "bin",
            home / "profiles" / "john-lomein-guide" / "skins",
            checkout,
        ):
            path.mkdir(parents=True, exist_ok=True)
            os.chmod(path, 0o700)
        (home / "scripts" / "john_lomein_model_isolation.py").write_text(
            "# deployed fixture\n",
            encoding="utf-8",
        )
        for name in (
            "john_lomein_provider_broker.py",
            "john_lomein_provider_bootstrap.py",
            "john_lomein_honcho_broker.py",
        ):
            (home / "scripts" / name).write_text(
                "# deployed fixture\n",
                encoding="utf-8",
            )
        for name in ("instance.yaml", "auth.json", "config.yaml", ".env"):
            (home / name).write_text("{}\n", encoding="utf-8")
        profile = home / "profiles" / "john-lomein-guide"
        (profile / "home" / ".config" / "gh" / "hosts.yml").write_text("token: hidden\n", encoding="utf-8")
        for name in (
            "SOUL.md",
            "config.yaml",
            "distribution.yaml",
            "honcho.json",
            ".env",
            "auth.json",
            "profile.yaml",
            ".no-bundled-skills",
        ):
            (profile / name).write_text("fixture\n", encoding="utf-8")
        (profile / "honcho.json").write_text(
            json.dumps(
                {
                    "baseUrl": "http://127.0.0.1:8000",
                    "hosts": {
                        "hermes": {
                            "workspace": "selected-workspace",
                            "saveMessages": True,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        (profile / "config.yaml").write_text("{}\n", encoding="utf-8")
        shutil.copytree(
            home / "scripts",
            profile / "scripts",
            dirs_exist_ok=True,
        )
        for plugin_name in (
            "john-lomein-continuity",
            "john-lomein-release-approval",
            "john-lomein-guide-lifecycle",
        ):
            runtime_plugin = home / "plugins" / plugin_name
            runtime_plugin.mkdir()
            os.chmod(runtime_plugin, 0o700)
            plugin_file = runtime_plugin / "__init__.py"
            plugin_file.write_text(
                "# product plugin fixture\n",
                encoding="utf-8",
            )
            os.chmod(plugin_file, 0o600)
            (
                profile / "plugins" / plugin_name
            ).symlink_to(runtime_plugin, target_is_directory=True)
        return {
            "PATH": os.environ.get("PATH", ""),
            "BOT_HERMES_HOME": str(home),
            "HERMES_HOME": str(home),
            "HERMES_REAL_HOME": str(owner_home),
            "BOT_LOCAL": str(checkout),
            "BOT_MODEL_MEMORY_ISOLATION": "required",
            "BOT_STEWARD_PRIVATE_ROOT": str(
                home / "private" / "learning-steward"
            ),
            "BOT_STEWARD_PROJECTION_ROOT": str(home / "state" / "learning"),
            "HERMES_MANAGED_DIR": str(
                home / "managed-policy" / "john-lomein-guide"
            ),
        }

    @staticmethod
    def bind_profile_plugin(env: dict[str, str], name: str) -> Path:
        home = Path(env["BOT_HERMES_HOME"])
        runtime_plugin = home / "plugins" / name
        binding = (
            home
            / "profiles"
            / "john-lomein-guide"
            / "plugins"
            / name
        )
        if binding.exists() or binding.is_symlink():
            binding.unlink()
        binding.symlink_to(runtime_plugin, target_is_directory=True)
        return binding

    def test_manifest_requires_boundary_when_learning_is_enabled(self):
        self.assertEqual(model_memory_isolation_mode({}), "required")
        with self.assertRaisesRegex(
            ValueError,
            "learning-enabled instances require",
        ):
            model_memory_isolation_mode(
                {
                    "learning": {
                        "enabled": True,
                        "model_memory_isolation": "disabled",
                    }
                }
            )
        self.assertEqual(
            model_memory_isolation_mode(
                {
                    "learning": {
                        "enabled": False,
                        "model_memory_isolation": "disabled",
                    }
                }
            ),
            "disabled",
        )

    def test_darwin_policy_hides_private_root_and_seals_deployment_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            policy = darwin_policy(env)
            home = Path(env["BOT_HERMES_HOME"])
            private = Path(env["BOT_STEWARD_PRIVATE_ROOT"]).resolve()
            self.assertIn(
                f'(deny file-read* file-write* (subpath "{private}"))',
                policy,
            )
            owner_overrides = (home / "private" / "owner-overrides").resolve()
            self.assertIn(
                f'(deny file-read* file-write* (subpath "{owner_overrides}"))',
                policy,
            )
            review_receipts = (home / "private" / "review-receipts").resolve()
            self.assertIn(
                f'(deny file-read* file-write* (subpath "{review_receipts}"))',
                policy,
            )
            hidden = (
                home / "state" / "honcho",
                home / "private" / "honcho-deletion-tombstones",
                home / "private" / "honcho-backups",
                home / "services" / "public-honcho",
                home / "logs" / "public-honcho",
            )
            for root in hidden:
                self.assertIn(
                    f'(deny file-read* file-write* (subpath "{root.resolve()}"))',
                    policy,
                )
            self.assertIn(
                f'(deny file-write* (subpath "{(home / "scripts").resolve()}"))',
                policy,
            )
            self.assertIn(
                f'(deny file-write* (subpath "{(home / "state" / "continuity").resolve()}"))',
                policy,
            )
            self.assertIn(
                f'(deny file-write* (literal "{(home / "profiles" / "john-lomein-guide" / "SOUL.md").resolve()}"))',
                policy,
            )

    def test_active_profile_is_the_only_profile_scoped_write_grant(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            home = Path(env["BOT_HERMES_HOME"])
            guide = home / "profiles" / "john-lomein-guide"
            policy = darwin_policy(
                env,
                profile="john-lomein-guide",
            )

            self.assertIn(
                f'  (subpath "{guide.resolve()}")',
                policy,
            )
            self.assertNotIn(
                f'  (subpath "{home / "profiles" / "john-lomein-maintainer"}")',
                policy,
            )
            for relative, matcher in (
                ("config.yaml", "literal"),
                ("distribution.yaml", "literal"),
                ("honcho.json", "literal"),
                ("auth.json", "literal"),
                ("SOUL.md", "literal"),
                ("skills", "subpath"),
                ("plugins", "subpath"),
                ("hooks", "subpath"),
                ("bin", "subpath"),
            ):
                self.assertIn(
                    "(deny file-write* "
                    f'({matcher} "{guide / relative}"))',
                    policy,
                )

    def test_refresh_authority_and_fallback_stores_are_hidden_from_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = self.fixture(root)
            authority = root / "owner" / ".hermes"
            authority.mkdir(parents=True)
            (authority / "auth.json").write_text(
                '{"refresh_token":"never model-readable"}\n',
                encoding="utf-8",
            )
            env.update(
                {
                    "HERMES_REAL_HOME": str(authority.parent),
                    "JOHN_LOMEIN_AUTH_AUTHORITY_HOME": str(authority),
                    "BOT_MODEL_PROVIDER": "zai",
                    "BOT_FALLBACK_PROVIDER": "openai-codex",
                }
            )
            home = Path(env["BOT_HERMES_HOME"])
            guide_auth = (
                home / "profiles" / "john-lomein-guide" / "auth.json"
            )
            policy = darwin_policy(
                env,
                profile="john-lomein-guide",
            )

            self.assertIn(
                "(deny file-read* file-write* "
                f'(literal "{(authority / "auth.json").resolve()}"))',
                policy,
            )
            self.assertIn(
                "(deny file-read* file-write* "
                f'(literal "{(home / "auth.json").resolve()}"))',
                policy,
            )
            self.assertIn(
                "(deny file-read* file-write* "
                f'(literal "{guide_auth.resolve()}"))',
                policy,
            )
            guide_gh = home / "profiles" / "john-lomein-guide" / "home" / ".config" / "gh"
            self.assertIn(f'(subpath "{guide_gh.resolve()}"))', policy)

            def which(name: str, *, path: str = "") -> str | None:
                return "/usr/bin/true" if name == "bwrap" else None

            command = isolated_command(
                env,
                ["/usr/bin/true"],
                system="Linux",
                which=which,
                profile="john-lomein-guide",
            )
            self.assertIn(
                ["--ro-bind", "/dev/null", str(authority / "auth.json")],
                [
                    command[index : index + 3]
                    for index in range(len(command) - 2)
                ],
            )
            self.assertIn(
                ["--ro-bind", "/dev/null", str(home / "auth.json")],
                [
                    command[index : index + 3]
                    for index in range(len(command) - 2)
                ],
            )
            self.assertIn(
                ["--ro-bind", "/dev/null", str(guide_auth)],
                [
                    command[index : index + 3]
                    for index in range(len(command) - 2)
                ],
            )

    def test_auth_authority_cannot_be_redirected_by_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = self.fixture(root)
            real_home = root / "owner"
            authority = real_home / ".hermes"
            authority.mkdir(parents=True)
            (authority / "auth.json").write_text("{}\n", encoding="utf-8")
            redirected = root / "redirected-auth"
            redirected.mkdir()
            env.update(
                {
                    "HERMES_REAL_HOME": str(real_home),
                    "JOHN_LOMEIN_AUTH_AUTHORITY_HOME": str(redirected),
                    "BOT_MODEL_PROVIDER": "openai-codex",
                }
            )
            with self.assertRaisesRegex(
                IsolationError,
                "auth_authority_path_mismatch",
            ):
                darwin_policy(env, profile="john-lomein-guide")

    def test_active_profile_scope_pins_inner_home_and_rejects_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            guide = (
                Path(env["BOT_HERMES_HOME"])
                / "profiles"
                / "john-lomein-guide"
            )
            env["HERMES_HONCHO_HOST"]="attacker"
            child = isolated_environment(
                env,
                profile="john-lomein-guide",
            )
            self.assertEqual(child["HERMES_HOME"], str(guide))
            self.assertEqual(child["HERMES_HONCHO_HOST"], "hermes")
            self.assertEqual(
                child["BOT_HERMES_HOME"],
                env["BOT_HERMES_HOME"],
            )

            with self.assertRaisesRegex(
                IsolationError,
                "unknown_active_profile",
            ):
                isolated_command(
                    env,
                    ["/usr/bin/true"],
                    profile="../../other",
                )

            wrong = dict(env)
            wrong["HERMES_MANAGED_DIR"] = str(
                Path(env["BOT_HERMES_HOME"])
                / "managed-policy"
                / "john-lomein-maintainer"
            )
            with self.assertRaisesRegex(
                IsolationError,
                "active_profile_policy_mismatch",
            ):
                isolated_environment(
                    wrong,
                    profile="john-lomein-guide",
                )

    def test_linux_boundary_masks_private_state_and_rebinds_only_runtime_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))

            def which(name: str, *, path: str = "") -> str | None:
                return "/usr/bin/true" if name == "bwrap" else None

            command = isolated_command(
                env,
                ["/usr/bin/true"],
                system="Linux",
                which=which,
            )
            private = env["BOT_STEWARD_PRIVATE_ROOT"]
            projection = env["BOT_STEWARD_PROJECTION_ROOT"]
            self.assertEqual(command[0], "/usr/bin/true")
            self.assertIn("--unshare-all", command)
            self.assertNotIn("--share-net", command)
            self.assertIn("--tmpfs", command)
            run_index = command.index("/run")
            self.assertEqual(command[run_index - 1], "--tmpfs")
            private_learning = str(Path(private) / "learning")
            self.assertIn(private_learning, command)
            self.assertEqual(command[command.index(private_learning) - 1], "--tmpfs")
            owner_overrides = str(Path(env["BOT_HERMES_HOME"]) / "private" / "owner-overrides")
            owner_index = command.index(owner_overrides)
            self.assertEqual(command[owner_index - 1], "--tmpfs")
            review_receipts = str(Path(env["BOT_HERMES_HOME"]) / "private" / "review-receipts")
            review_index = command.index(review_receipts)
            self.assertEqual(command[review_index - 1], "--tmpfs")
            home = Path(env["BOT_HERMES_HOME"])
            for root in (
                home / "state" / "honcho",
                home / "private" / "honcho-deletion-tombstones",
                home / "private" / "honcho-backups",
                home / "services" / "public-honcho",
                home / "logs" / "public-honcho",
            ):
                index = command.index(str(root))
                self.assertEqual(command[index - 1], "--tmpfs")
            projection_index = command.index(projection)
            self.assertEqual(command[projection_index - 1], "--ro-bind")
            self.assertIn(env["BOT_LOCAL"], command)

    def test_linux_active_profile_bind_precedes_protected_read_only_binds(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))

            def which(name: str, *, path: str = "") -> str | None:
                return "/usr/bin/true" if name == "bwrap" else None

            command = isolated_command(
                env,
                ["/usr/bin/true"],
                system="Linux",
                which=which,
                profile="john-lomein-guide",
            )
            profile = (
                Path(env["BOT_HERMES_HOME"])
                / "profiles"
                / "john-lomein-guide"
            )
            writable = [
                index
                for index in range(len(command) - 2)
                if command[index : index + 3]
                == ["--bind", str(profile), str(profile)]
            ]
            self.assertEqual(len(writable), 1)
            for protected in (
                profile / "config.yaml",
                profile / "distribution.yaml",
                profile / "honcho.json",
                profile / "auth.json",
                profile / "skills",
                profile / "plugins",
            ):
                read_only = [
                    index
                    for index in range(len(command) - 2)
                    if command[index : index + 3]
                    == ["--ro-bind", str(protected), str(protected)]
                ]
                self.assertEqual(len(read_only), 1, protected)
                self.assertGreater(read_only[0], writable[0], protected)

    def test_required_mode_has_no_best_effort_backend_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            with self.assertRaisesRegex(
                IsolationError,
                "bubblewrap_unavailable",
            ):
                isolated_command(
                    env,
                    ["/usr/bin/true"],
                    system="Linux",
                    which=lambda _name, **_kwargs: None,
                )

    def test_private_hardlink_alias_fails_before_backend_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = self.fixture(root)
            private = (
                Path(env["BOT_STEWARD_PRIVATE_ROOT"])
                / "mnemosyne"
                / "data"
                / "record"
            )
            private.write_text("index\n", encoding="utf-8")
            os.chmod(private, 0o600)
            os.link(private, root / "outside-alias")
            with self.assertRaisesRegex(
                IsolationError,
                "model_isolation_private_file_unsafe",
            ):
                isolated_command(env, ["/usr/bin/true"])

    def test_protected_script_hardlink_alias_fails_before_backend_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            protected = (
                Path(env["BOT_HERMES_HOME"])
                / "scripts"
                / "john_lomein_model_isolation.py"
            )
            os.link(
                protected,
                Path(env["BOT_LOCAL"]) / "protected-script-alias",
            )
            with self.assertRaisesRegex(
                IsolationError,
                "model_isolation_scripts_file_unsafe",
            ):
                isolated_command(env, ["/usr/bin/true"])

    def test_exact_product_profile_plugin_binding_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))

            command = isolated_command(
                env,
                ["/usr/bin/true"],
                system="Linux",
                which=lambda name, **_kwargs: (
                    "/usr/bin/true" if name == "bwrap" else None
                ),
            )

            self.assertEqual(command[0], "/usr/bin/true")

    def test_redirected_product_profile_plugin_binding_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            home = Path(env["BOT_HERMES_HOME"])
            redirected = home / "plugins" / "redirected"
            redirected.mkdir()
            binding = (
                home
                / "profiles"
                / "john-lomein-guide"
                / "plugins"
                / "john-lomein-continuity"
            )
            binding.unlink()
            binding.symlink_to(redirected, target_is_directory=True)

            with self.assertRaisesRegex(
                IsolationError,
                "model_isolation_profile_0_plugins_binding_unsafe",
            ):
                isolated_command(env, ["/usr/bin/true"])

    def test_unexpected_profile_plugin_entry_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            plugins = (
                Path(env["BOT_HERMES_HOME"])
                / "profiles"
                / "john-lomein-guide"
                / "plugins"
            )
            (plugins / "not-a-product-hook").mkdir()

            with self.assertRaisesRegex(
                IsolationError,
                "model_isolation_profile_0_plugins_bindings_incomplete",
            ):
                isolated_command(env, ["/usr/bin/true"])

    def test_missing_required_profile_plugin_binding_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            home = Path(env["BOT_HERMES_HOME"])
            (
                home
                / "profiles"
                / "john-lomein-guide"
                / "plugins"
                / "john-lomein-continuity"
            ).unlink()

            with self.assertRaisesRegex(
                IsolationError,
                "model_isolation_profile_0_plugins_bindings_incomplete",
            ):
                isolated_command(env, ["/usr/bin/true"])

    def test_missing_guide_release_approval_binding_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            home = Path(env["BOT_HERMES_HOME"])
            (
                home
                / "profiles"
                / "john-lomein-guide"
                / "plugins"
                / "john-lomein-release-approval"
            ).unlink()

            with self.assertRaisesRegex(
                IsolationError,
                "model_isolation_profile_0_plugins_bindings_incomplete",
            ):
                isolated_command(env, ["/usr/bin/true"])

    def test_missing_guide_lifecycle_binding_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            home = Path(env["BOT_HERMES_HOME"])
            (
                home
                / "profiles"
                / "john-lomein-guide"
                / "plugins"
                / "john-lomein-guide-lifecycle"
            ).unlink()

            with self.assertRaisesRegex(
                IsolationError,
                "model_isolation_profile_0_plugins_bindings_incomplete",
            ):
                isolated_command(env, ["/usr/bin/true"])

    def test_release_approval_binding_on_non_guide_profile_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            home = Path(env["BOT_HERMES_HOME"])
            profile = home / "profiles" / "john-lomein-maintainer"
            for path in (
                profile,
                profile / "home",
                profile / "logs",
                profile / "skills",
                profile / "memories",
                profile / "plugins",
                profile / "scripts",
                home / "managed-policy" / "john-lomein-maintainer",
            ):
                path.mkdir(exist_ok=True)
                os.chmod(path, 0o700)
            for name in (
                "SOUL.md",
                "config.yaml",
                "distribution.yaml",
                "honcho.json",
                ".env",
                "auth.json",
                "profile.yaml",
                ".no-bundled-skills",
            ):
                (profile / name).write_text("fixture\n", encoding="utf-8")
            shutil.copytree(
                home / "scripts",
                profile / "scripts",
                dirs_exist_ok=True,
            )
            for plugin_name in (
                "john-lomein-continuity",
                "john-lomein-release-approval",
                "john-lomein-guide-lifecycle",
            ):
                (profile / "plugins" / plugin_name).symlink_to(
                    home / "plugins" / plugin_name,
                    target_is_directory=True,
                )

            with self.assertRaisesRegex(
                IsolationError,
                "bindings_incomplete",
            ):
                isolated_command(env, ["/usr/bin/true"])

    def test_intermediate_alias_profile_plugin_binding_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            home = Path(env["BOT_HERMES_HOME"])
            binding = (
                home
                / "profiles"
                / "john-lomein-guide"
                / "plugins"
                / "john-lomein-continuity"
            )
            intermediate = home / "plugins" / "continuity-alias"
            intermediate.symlink_to(
                home / "plugins" / "john-lomein-continuity",
                target_is_directory=True,
            )
            binding.unlink()
            binding.symlink_to(intermediate, target_is_directory=True)

            with self.assertRaisesRegex(
                IsolationError,
                "binding_unsafe",
            ):
                isolated_command(env, ["/usr/bin/true"])

    def test_regular_directory_profile_plugin_binding_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            home = Path(env["BOT_HERMES_HOME"])
            binding = (
                home
                / "profiles"
                / "john-lomein-guide"
                / "plugins"
                / "john-lomein-continuity"
            )
            binding.unlink()
            binding.mkdir()

            with self.assertRaisesRegex(
                IsolationError,
                "binding_unsafe",
            ):
                isolated_command(env, ["/usr/bin/true"])

    def test_writable_runtime_plugin_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            home = Path(env["BOT_HERMES_HOME"])
            os.chmod(home / "plugins", 0o777)

            with self.assertRaisesRegex(
                IsolationError,
                "runtime_plugins_directory_unsafe",
            ):
                isolated_command(env, ["/usr/bin/true"])

    def test_nested_symlink_in_runtime_product_plugin_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            home = Path(env["BOT_HERMES_HOME"])
            (
                home
                / "plugins"
                / "john-lomein-continuity"
                / "redirect"
            ).symlink_to(home / "config.yaml")

            with self.assertRaisesRegex(
                IsolationError,
                "runtime_plugin_john_lomein_continuity_symlink",
            ):
                isolated_command(env, ["/usr/bin/true"])

    def test_disabled_memoryless_instance_is_an_explicit_passthrough(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            env["BOT_MODEL_MEMORY_ISOLATION"] = "disabled"
            self.assertEqual(
                isolated_command(env, ["/usr/bin/true"]),
                ["/usr/bin/true"],
            )

    def test_model_environment_never_receives_index_pointer(self):
        env = {
            "MNEMOSYNE_DATA_DIR": "/private/index",
            "JOHN_LOMEIN_STEWARD_PRIVATE_ROOT": "/private/steward",
            "BOT_STEWARD_PRIVATE_ROOT": "/private/steward",
            "BOT_STEWARD_PROJECTION_ROOT": "/private/projection",
            "PATH": "/usr/bin",
            "BOT_MODEL_MEMORY_ISOLATION": "disabled",
            "GH_TOKEN": "secret",
            "SSH_AUTH_SOCK": "/tmp/agent.sock",
            "AWS_ACCESS_KEY_ID": "secret",
            "OPENAI_API_KEY": "provider-secret",
            "ANTHROPIC_API_KEY": "provider-secret",
            "HERMES_CODEX_BASE_URL": "https://attacker.invalid",
            "CODEX_HOME": "/private/codex",
            "DATABASE_URL": "postgresql://private",
            "PGHOST": "/private/postgres.sock",
            "HONCHO_API_KEY": "real-honcho-secret",
            "HONCHO_BASE_URL": "https://attacker.invalid",
            "HONCHO_WORKSPACE_ID": "other-workspace",
            "REDIS_URL": "redis://user:password@127.0.0.1:6379/0",
        }
        child = isolated_environment(env)
        self.assertNotIn("MNEMOSYNE_DATA_DIR", child)
        self.assertNotIn("JOHN_LOMEIN_STEWARD_PRIVATE_ROOT", child)
        self.assertNotIn("BOT_STEWARD_PRIVATE_ROOT", child)
        self.assertNotIn("BOT_STEWARD_PROJECTION_ROOT", child)
        self.assertNotIn("GH_TOKEN", child)
        self.assertNotIn("SSH_AUTH_SOCK", child)
        self.assertNotIn("AWS_ACCESS_KEY_ID", child)
        self.assertNotIn("OPENAI_API_KEY", child)
        self.assertNotIn("ANTHROPIC_API_KEY", child)
        self.assertNotIn("HERMES_CODEX_BASE_URL", child)
        self.assertNotIn("CODEX_HOME", child)
        self.assertNotIn("DATABASE_URL", child)
        self.assertNotIn("PGHOST", child)
        self.assertNotIn("HONCHO_API_KEY", child)
        self.assertNotIn("HONCHO_BASE_URL", child)
        self.assertNotIn("HONCHO_WORKSPACE_ID", child)
        self.assertNotIn("REDIS_URL", child)
        self.assertEqual(child["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(child["JOHN_LOMEIN_MODEL_ISOLATED"], "1")

    def test_darwin_network_policy_allows_only_sealed_broker_sockets(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            broker_socket = provider_broker_socket_path()
            honcho_socket = honcho_broker_socket_path(broker_socket)
            policy = darwin_policy(
                env,
                profile="john-lomein-guide",
                provider_socket=broker_socket,
                honcho_socket=honcho_socket,
            )

            self.assertIn("(deny network*)", policy)
            self.assertIn("(deny process-info*)", policy)
            self.assertIn("(allow process-info* (target self))", policy)
            self.assertIn("(deny mach-task-name)", policy)
            self.assertIn(
                "(allow network-outbound "
                f'(literal "{broker_socket.resolve(strict=False)}"))',
                policy,
            )
            self.assertIn(
                "(allow network-outbound "
                f'(literal "{honcho_socket.resolve(strict=False)}"))',
                policy,
            )
            self.assertNotIn("(allow network-outbound (remote tcp))", policy)

    def test_provider_socket_path_fits_platform_limit_with_long_runtime_home(self):
        path = provider_broker_socket_path()
        self.assertLessEqual(len(os.fsencode(path)), 100)
        self.assertEqual(path.name, "broker.sock")
        self.assertEqual(len(path.parent.name), 24)
        honcho = honcho_broker_socket_path(path)
        self.assertEqual(honcho.parent, path.parent)
        self.assertEqual(honcho.name, "honcho.sock")
        self.assertLessEqual(len(os.fsencode(honcho)), 100)

    def test_openai_codex_hermes_command_is_controller_broker_wrapped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = self.fixture(root)
            authority = root / "owner" / ".hermes"
            authority.mkdir(mode=0o700)
            (authority / "auth.json").write_text("{}\n", encoding="utf-8")
            env.update(
                {
                    "BOT_MODEL_PROVIDER": "openai-codex",
                    "JOHN_LOMEIN_AUTH_AUTHORITY_HOME": str(authority),
                }
            )
            bin_dir = root / "venv" / "bin"
            bin_dir.mkdir(parents=True)
            hermes = bin_dir / "hermes"
            hermes.write_text(
                "#!/usr/bin/python3\nprint('fixture')\n",
                encoding="utf-8",
            )
            hermes.chmod(0o755)

            command = isolated_command(
                env,
                [str(hermes), "chat", "-q", "hello"],
                system="Darwin",
                which=lambda name, **_kwargs: (
                    "/usr/bin/sandbox-exec" if name == "sandbox-exec" else None
                ),
                profile="john-lomein-guide",
            )

            self.assertEqual(command[0:2], [sys.executable, "-I"])
            self.assertIn("john_lomein_provider_broker.py", command[2])
            self.assertIn("--socket", command)
            self.assertIn("--honcho-socket", command)
            sandbox_index = command.index("/usr/bin/sandbox-exec")
            policy = command[sandbox_index + 2]
            self.assertIn("(deny network*)", policy)
            self.assertIn("jl-pb-", policy)
            self.assertIn("honcho.sock", policy)
            self.assertTrue(
                any(
                    Path(item).name == "john_lomein_provider_bootstrap.py"
                    for item in command
                )
            )
            self.assertNotIn(str(authority / "auth.json"), command[sandbox_index + 3 :])

    @unittest.skipUnless(
        platform.system() == "Darwin" and shutil.which("sandbox-exec"),
        "real Seatbelt backend is only available on macOS",
    )
    def test_real_backend_denies_private_reads_descendant_reads_and_policy_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            ok, detail = run_isolation_canary(env, python=sys.executable)
            self.assertTrue(ok, detail)
            self.assertEqual(detail, "seatbelt")

    @unittest.skipUnless(
        platform.system() == "Darwin" and shutil.which("sandbox-exec"),
        "real Seatbelt backend is only available on macOS",
    )
    def test_real_backend_honcho_proxy_and_network_denial_canary(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            home = Path(env["BOT_HERMES_HOME"])
            broker_socket = provider_broker_socket_path()
            honcho_socket = honcho_broker_socket_path(broker_socket)
            broker_socket.parent.parent.mkdir(mode=0o700, exist_ok=True)
            os.chmod(broker_socket.parent.parent, 0o700)
            broker_socket.parent.mkdir(mode=0o700)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(broker_socket))
            os.chmod(broker_socket, 0o600)
            listener.listen(1)
            backend_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            backend_listener.bind(("127.0.0.1", 0))
            backend_listener.listen(1)
            backend_port = backend_listener.getsockname()[1]
            honcho_capability = "real-backend-honcho-capability"
            honcho_server = create_honcho_server(
                honcho_socket,
                binding=HonchoBinding(
                    host="127.0.0.1",
                    port=backend_port,
                    workspace="selected-workspace",
                    save_messages=True,
                    profile="john-lomein-guide",
                ),
                capability=honcho_capability,
            )
            honcho_thread = threading.Thread(
                target=honcho_server.serve_forever,
                daemon=True,
            )
            honcho_thread.start()
            postgres_socket = broker_socket.parent.parent / "postgres.sock"
            postgres_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            postgres_listener.bind(str(postgres_socket))
            postgres_listener.listen(1)
            tcp_listeners = []
            for _label in ("honcho", "postgres", "redis", "https"):
                endpoint = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                endpoint.bind(("127.0.0.1", 0))
                endpoint.listen(1)
                tcp_listeners.append(endpoint)
            ports = [endpoint.getsockname()[1] for endpoint in tcp_listeners]

            def serve() -> None:
                connection, _ = listener.accept()
                with connection:
                    if connection.recv(16) == b"provider-canary":
                        connection.sendall(b"trusted-path-ok")

            server = threading.Thread(target=serve, daemon=True)
            server.start()

            def serve_backend() -> None:
                connection, _ = backend_listener.accept()
                with connection:
                    request = b""
                    while b"\r\n\r\n" not in request:
                        request += connection.recv(65536)
                    self.assertIn(
                        b"GET /v3/workspaces/selected-workspace/queue/status",
                        request,
                    )
                    body = b'{"selected_workspace":true}'
                    connection.sendall(
                        b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n"
                        + f"Content-Length: {len(body)}\r\n\r\n".encode()
                        + body
                    )

            backend_thread = threading.Thread(
                target=serve_backend,
                daemon=True,
            )
            backend_thread.start()
            probe = (
                "from pathlib import Path\n"
                "import os,socket,subprocess,sys\n"
                f"broker={str(broker_socket)!r}\n"
                f"honcho={str(honcho_socket)!r}\n"
                f"honcho_capability={honcho_capability!r}\n"
                f"postgres_socket={str(postgres_socket)!r}\n"
                f"ports={ports!r}\n"
                f"auth=Path({str(home / 'profiles' / 'john-lomein-guide' / 'auth.json')!r})\n"
                "def uds_http(path,target,capability):\n"
                " s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect(path)\n"
                " s.sendall(f'GET {target} HTTP/1.1\\r\\nAuthorization: Bearer {capability}\\r\\n\\r\\n'.encode())\n"
                " response=b''\n"
                " while True:\n"
                "  chunk=s.recv(65536)\n"
                "  if not chunk: break\n"
                "  response+=chunk\n"
                " return response\n"
                "uds=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
                "uds.connect(broker); uds.sendall(b'provider-canary')\n"
                "provider_ok=uds.recv(32)==b'trusted-path-ok'\n"
                "selected=uds_http(honcho,'/v3/workspaces/selected-workspace/queue/status',honcho_capability)\n"
                "selected_ok=b' 200 ' in selected and b'selected_workspace' in selected\n"
                "other=uds_http(honcho,'/v3/workspaces/other-workspace/queue/status',honcho_capability)\n"
                "other_denied=b' 403 ' in other\n"
                "tcp_denied=True\n"
                "for port in ports:\n"
                " try: socket.create_connection(('127.0.0.1',port),timeout=.2); tcp_denied=False\n"
                " except OSError: pass\n"
                "fixed_denied=True\n"
                "for endpoint in [('127.0.0.1',8000),('127.0.0.1',5432),('127.0.0.1',6379),('1.1.1.1',443)]:\n"
                " try: socket.create_connection(endpoint,timeout=.2); fixed_denied=False\n"
                " except OSError: pass\n"
                "try:\n"
                " pg=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);pg.connect(postgres_socket); postgres_denied=False\n"
                "except OSError: postgres_denied=True\n"
                "try:\n"
                " auth.read_bytes(); auth_denied=False\n"
                "except OSError: auth_denied=True\n"
                "try:\n"
                " parent_info=subprocess.run(['/bin/ps','-p',str(os.getppid()),'-o','command='],capture_output=True)\n"
                " parent_hidden=parent_info.returncode!=0 or not parent_info.stdout.strip()\n"
                "except OSError: parent_hidden=True\n"
                "checks={'provider':provider_ok,'selected':selected_ok,'other':other_denied,'tcp':tcp_denied,'fixed':fixed_denied,'postgres_socket':postgres_denied,'auth':auth_denied,'parent':parent_hidden}\n"
                "if not all(checks.values()): print(checks)\n"
                "raise SystemExit(0 if all(checks.values()) else 9)\n"
            )
            command = isolated_command(
                env,
                [sys.executable, "-I", "-c", probe],
                profile="john-lomein-guide",
                provider_socket=broker_socket,
                honcho_socket=honcho_socket,
            )
            result = subprocess.run(
                command,
                env=isolated_environment(env, profile="john-lomein-guide"),
                capture_output=True,
                text=True,
                timeout=20,
            )
            listener.close()
            honcho_server.shutdown()
            honcho_server.server_close()
            backend_listener.close()
            postgres_listener.close()
            postgres_socket.unlink(missing_ok=True)
            for endpoint in tcp_listeners:
                endpoint.close()
            server.join(timeout=2)
            honcho_thread.join(timeout=2)
            backend_thread.join(timeout=2)
            broker_socket.unlink(missing_ok=True)
            honcho_socket.unlink(missing_ok=True)
            broker_socket.parent.rmdir()
            try:
                broker_socket.parent.parent.rmdir()
            except OSError:
                pass
            self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(
        platform.system() == "Linux" and shutil.which("bwrap"),
        "real bubblewrap backend is only available on Linux",
    )
    def test_real_bubblewrap_allows_broker_uds_but_denies_network_and_auth(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            home = Path(env["BOT_HERMES_HOME"])
            broker_socket = provider_broker_socket_path()
            broker_socket.parent.parent.mkdir(mode=0o700, exist_ok=True)
            os.chmod(broker_socket.parent.parent, 0o700)
            broker_socket.parent.mkdir(mode=0o700)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(broker_socket))
            os.chmod(broker_socket, 0o600)
            listener.listen(1)
            # Keep this socket in a bind-mounted runtime path. A hidden /tmp
            # socket would prove only mount masking, not AF_UNIX isolation.
            postgres_socket = home / "work" / ".s.PGSQL.5432"
            postgres_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            postgres_listener.bind(str(postgres_socket))
            postgres_listener.listen(1)
            tcp_listeners = []
            for _label in ("honcho", "postgres", "egress"):
                endpoint = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                endpoint.bind(("127.0.0.1", 0))
                endpoint.listen(1)
                tcp_listeners.append(endpoint)
            ports = [endpoint.getsockname()[1] for endpoint in tcp_listeners]

            def serve() -> None:
                connection, _ = listener.accept()
                with connection:
                    if connection.recv(16) == b"provider-canary":
                        connection.sendall(b"trusted-path-ok")

            server = threading.Thread(target=serve, daemon=True)
            server.start()
            probe = (
                "from pathlib import Path\n"
                "import socket\n"
                f"broker={str(broker_socket)!r}\n"
                f"postgres_socket={str(postgres_socket)!r}\n"
                f"ports={ports!r}\n"
                f"auth=Path({str(home / 'profiles' / 'john-lomein-guide' / 'auth.json')!r})\n"
                "uds=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
                "uds.connect(broker); uds.sendall(b'provider-canary')\n"
                "provider_ok=uds.recv(32)==b'trusted-path-ok'\n"
                "network_denied=True\n"
                "for port in ports:\n"
                " try: socket.create_connection(('127.0.0.1',port),timeout=.2); network_denied=False\n"
                " except OSError: pass\n"
                "try:\n"
                " pg=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);pg.connect(postgres_socket); postgres_denied=False\n"
                "except OSError: postgres_denied=True\n"
                "try:\n"
                " auth.read_bytes(); auth_denied=False\n"
                "except OSError: auth_denied=True\n"
                "raise SystemExit(0 if provider_ok and network_denied and postgres_denied and auth_denied else 9)\n"
            )
            command = isolated_command(
                env,
                [sys.executable, "-I", "-c", probe],
                profile="john-lomein-guide",
                provider_socket=broker_socket,
            )
            result = subprocess.run(
                command,
                env=isolated_environment(env, profile="john-lomein-guide"),
                capture_output=True,
                text=True,
                timeout=20,
            )
            listener.close()
            server.join(timeout=2)
            postgres_listener.close()
            postgres_socket.unlink(missing_ok=True)
            for endpoint in tcp_listeners:
                endpoint.close()
            broker_socket.unlink(missing_ok=True)
            broker_socket.parent.rmdir()
            try:
                broker_socket.parent.parent.rmdir()
            except OSError:
                pass
            self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(
        platform.system() == "Darwin" and shutil.which("sandbox-exec"),
        "real Seatbelt backend is only available on macOS",
    )
    def test_seatbelt_executes_sealed_polyglot_hermes_python_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = self.fixture(root)
            bin_dir = root / "venv" / "bin"
            bin_dir.mkdir(parents=True)
            hermes = bin_dir / "hermes"
            hermes.write_text(
                "#!/bin/sh\n"
                "'''exec' \"$(dirname -- \"$(realpath -- \"$0\")\")\"/"
                "'python3' \"$0\" \"$@\"\n"
                "' '''\n"
                "print('sealed-hermes-runtime-ok')\n",
                encoding="utf-8",
            )
            hermes.chmod(0o755)
            (bin_dir / "python3").symlink_to(
                Path("/usr/bin/python3").resolve(strict=True)
            )

            command = isolated_command(
                env,
                [str(hermes)],
                profile="john-lomein-guide",
            )
            result = subprocess.run(
                command,
                env=isolated_environment(env, profile="john-lomein-guide"),
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "sealed-hermes-runtime-ok")

    @unittest.skipUnless(
        platform.system() == "Darwin"
        and shutil.which("sandbox-exec")
        and shutil.which("hermes"),
        "real Hermes/Seatbelt provider canary requires a local Hermes runtime",
    )
    def test_real_hermes_openai_client_uses_uds_broker_under_seatbelt(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            env = self.fixture(Path(tmp))
            home = Path(env["BOT_HERMES_HOME"])
            broker_socket = provider_broker_socket_path()
            honcho_socket = honcho_broker_socket_path(broker_socket)
            broker_socket.parent.parent.mkdir(mode=0o700, exist_ok=True)
            os.chmod(broker_socket.parent.parent, 0o700)
            broker_socket.parent.mkdir(mode=0o700)
            capability = "synthetic-session-capability"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(broker_socket))
            os.chmod(broker_socket, 0o600)
            listener.listen(1)
            honcho_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            honcho_listener.bind(str(honcho_socket))
            os.chmod(honcho_socket, 0o600)
            honcho_listener.listen(1)
            observed = []
            honcho_observed = []

            def serve() -> None:
                connection, _ = listener.accept()
                with connection:
                    request = b""
                    while b"\r\n\r\n" not in request:
                        request += connection.recv(65536)
                    observed.append(request)
                    body = b'{"object":"list","data":[]}'
                    connection.sendall(
                        b"HTTP/1.0 200 OK\r\n"
                        b"Content-Type: application/json\r\n"
                        + f"Content-Length: {len(body)}\r\n\r\n".encode()
                        + body
                    )

            server = threading.Thread(target=serve, daemon=True)
            server.start()

            def serve_honcho() -> None:
                connection, _ = honcho_listener.accept()
                with connection:
                    request = b""
                    while b"\r\n\r\n" not in request:
                        request += connection.recv(65536)
                    honcho_observed.append(request)
                    body = b'{"selected_workspace":true}'
                    connection.sendall(
                        b"HTTP/1.0 200 OK\r\n"
                        b"Content-Type: application/json\r\n"
                        + f"Content-Length: {len(body)}\r\n\r\n".encode()
                        + body
                    )

            honcho_server = threading.Thread(target=serve_honcho, daemon=True)
            honcho_server.start()
            hermes_bin = Path(shutil.which("hermes") or "")
            hermes_python = hermes_bin.parent / "python3"
            self.assertTrue(hermes_python.is_file() or hermes_python.is_symlink())
            bootstrap = ROOT / "scripts" / "john_lomein_provider_bootstrap.py"
            probe = (
                "import importlib.util,sys\n"
                f"spec=importlib.util.spec_from_file_location('jl_bootstrap',{str(bootstrap)!r})\n"
                "module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)\n"
                "assert 'plugins.memory.honcho.client' not in sys.modules\n"
                "module.install_broker_boundary()\n"
                "assert 'plugins.memory.honcho.client' not in sys.modules\n"
                "from hermes_cli.runtime_provider import resolve_runtime_provider\n"
                "runtime=resolve_runtime_provider(requested='openai-codex')\n"
                "assert runtime['base_url']=='http://localhost'\n"
                "import agent.agent_runtime_helpers as helpers\n"
                "class Agent:\n"
                " provider='openai-codex'\n"
                " model='gpt-test'\n"
                " def _build_keepalive_http_client(self,*a,**k): raise AssertionError('must use UDS client')\n"
                " def _client_log_context(self): return 'provider-canary'\n"
                "agent=Agent()\n"
                "client=helpers.create_openai_client(agent,{'api_key':'must-not-leave','base_url':'https://attacker.invalid'},reason='canary',shared=False)\n"
                "assert list(client.models.list().data)==[]\n"
                "client.close()\n"
                "import agent.auxiliary_client as auxiliary\n"
                "aux_client,aux_model=auxiliary.resolve_provider_client('openai-codex',model='gpt-test')\n"
                "assert aux_client is not None and aux_model=='gpt-test'\n"
                "from plugins.memory.honcho.client import HonchoClientConfig,get_honcho_client\n"
                "honcho_config=HonchoClientConfig.from_global_config()\n"
                "honcho_client=get_honcho_client(honcho_config)\n"
                "assert honcho_client.workspace_id=='selected-workspace'\n"
                "payload=honcho_client._http.get('/v3/workspaces/selected-workspace/queue/status')\n"
                "assert payload=={'selected_workspace':True}\n"
            )
            honcho_capability = "synthetic-honcho-capability"
            env.update(
                {
                    "JOHN_LOMEIN_PROVIDER_BROKER_SOCKET": str(broker_socket),
                    "JOHN_LOMEIN_PROVIDER_BROKER_CAPABILITY": capability,
                    "JOHN_LOMEIN_HONCHO_BROKER_SOCKET": str(honcho_socket),
                    "JOHN_LOMEIN_HONCHO_BROKER_CAPABILITY": honcho_capability,
                    "JOHN_LOMEIN_HONCHO_BROKER_WORKSPACE": "selected-workspace",
                }
            )
            command = isolated_command(
                env,
                [str(hermes_python), "-I", "-c", probe],
                profile="john-lomein-guide",
                provider_socket=broker_socket,
                honcho_socket=honcho_socket,
            )
            result = subprocess.run(
                command,
                env=isolated_environment(env, profile="john-lomein-guide"),
                capture_output=True,
                text=True,
                timeout=30,
            )
            listener.close()
            honcho_listener.close()
            server.join(timeout=3)
            honcho_server.join(timeout=3)
            broker_socket.unlink(missing_ok=True)
            honcho_socket.unlink(missing_ok=True)
            broker_socket.parent.rmdir()
            try:
                broker_socket.parent.parent.rmdir()
            except OSError:
                pass
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(observed), 1)
            request = observed[0]
            self.assertIn(b"GET /models HTTP/1.1", request)
            self.assertIn(f"Authorization: Bearer {capability}".encode(), request)
            self.assertNotIn(b"must-not-leave", request)
            self.assertEqual(len(honcho_observed), 1)
            honcho_request = honcho_observed[0]
            self.assertIn(
                b"GET /v3/workspaces/selected-workspace/queue/status HTTP/1.1",
                honcho_request,
            )
            self.assertIn(
                f"Authorization: Bearer {honcho_capability}".encode(),
                honcho_request,
            )
            self.assertNotIn(b"must-not-leave", honcho_request)

    @unittest.skipUnless(
        platform.system() == "Darwin" and shutil.which("sandbox-exec"),
        "real Seatbelt backend is only available on macOS",
    )
    def test_symlink_from_writable_checkout_cannot_alias_private_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            private = (
                Path(env["BOT_STEWARD_PRIVATE_ROOT"])
                / "mnemosyne"
                / "data"
                / "secret"
            )
            private.write_text("private-index\n", encoding="utf-8")
            os.chmod(private, 0o600)
            alias = Path(env["BOT_LOCAL"]) / "memory-alias"
            alias.symlink_to(private)
            with self.assertRaisesRegex(
                IsolationError,
                "model_isolation_private_alias",
            ):
                isolated_command(env, [sys.executable, "-c", "pass"])

    @unittest.skipUnless(
        platform.system() == "Darwin" and shutil.which("sandbox-exec"),
        "real Seatbelt backend is only available on macOS",
    )
    def test_public_guide_scope_cannot_read_private_role_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            projection = (
                Path(env["BOT_STEWARD_PROJECTION_ROOT"])
                / "current-operating-brief.md"
            )
            projection.write_text("private-role continuity\n", encoding="utf-8")
            probe = (
                "from pathlib import Path\n"
                f"p=Path({str(projection)!r})\n"
                "try:\n"
                " p.read_bytes()\n"
                "except OSError:\n"
                " raise SystemExit(0)\n"
                "raise SystemExit(9)\n"
            )
            command = isolated_command(
                env,
                [sys.executable, "-c", probe],
                allow_projection=False,
            )
            result = subprocess.run(
                command,
                env=isolated_environment(env),
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(
        platform.system() == "Darwin" and shutil.which("sandbox-exec"),
        "real Seatbelt backend is only available on macOS",
    )
    def test_same_uid_model_process_cannot_write_continuity_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            target = (
                Path(env["BOT_HERMES_HOME"])
                / "state"
                / "continuity"
                / "forged-entry"
            )
            probe = (
                "from pathlib import Path\n"
                f"p=Path({str(target)!r})\n"
                "try:\n"
                " p.write_text('forged owner preference', encoding='utf-8')\n"
                "except OSError:\n"
                " raise SystemExit(0)\n"
                "raise SystemExit(9)\n"
            )
            command = isolated_command(
                env,
                [sys.executable, "-c", probe],
            )
            result = subprocess.run(
                command,
                env=isolated_environment(env),
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(target.exists())

    @unittest.skipUnless(
        platform.system() == "Darwin" and shutil.which("sandbox-exec"),
        "real Seatbelt backend is only available on macOS",
    )
    def test_active_profile_runtime_writes_cannot_replace_control_surfaces(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            profile = (
                Path(env["BOT_HERMES_HOME"])
                / "profiles"
                / "john-lomein-guide"
            )
            config = profile / "config.yaml"
            config.write_text("control-sentinel\n", encoding="utf-8")
            skill = profile / "skills" / "fixture" / "SKILL.md"
            skill.parent.mkdir()
            skill.write_text("skill-sentinel\n", encoding="utf-8")
            runtime = profile / "gateway_state.json"
            probe = (
                "from pathlib import Path\n"
                f"profile=Path({str(profile)!r})\n"
                "config=profile/'config.yaml'\n"
                "skills=profile/'skills'\n"
                "scripts=profile/'scripts'\n"
                "def denied(operation):\n"
                " try:\n"
                "  operation()\n"
                " except OSError:\n"
                "  return True\n"
                " return False\n"
                "runtime=profile/'gateway_state.json'\n"
                "runtime.write_text('runtime-ok')\n"
                "replacement=profile/'runtime-replacement'\n"
                "replacement.write_text('replacement')\n"
                "checks=[\n"
                " denied(lambda: config.write_text('forged')),\n"
                " denied(lambda: config.unlink()),\n"
                " denied(lambda: config.rename(profile/'config.moved')),\n"
                " denied(lambda: replacement.replace(config)),\n"
                " denied(lambda: (skills/'forged').write_text('forged')),\n"
                " denied(lambda: scripts.rename(profile/'scripts.moved')),\n"
                "]\n"
                "raise SystemExit(0 if all(checks) else 9)\n"
            )
            command = isolated_command(
                env,
                [sys.executable, "-I", "-c", probe],
                profile="john-lomein-guide",
            )
            result = subprocess.run(
                command,
                env=isolated_environment(
                    env,
                    profile="john-lomein-guide",
                ),
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(config.read_text(encoding="utf-8"), "control-sentinel\n")
            self.assertEqual(skill.read_text(encoding="utf-8"), "skill-sentinel\n")
            self.assertEqual(runtime.read_text(encoding="utf-8"), "runtime-ok")
            self.assertTrue((profile / "scripts").is_dir())

    @unittest.skipUnless(
        platform.system() == "Darwin" and shutil.which("sandbox-exec"),
        "real Seatbelt backend is only available on macOS",
    )
    def test_post_launch_symlink_still_cannot_alias_private_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            private = (
                Path(env["BOT_STEWARD_PRIVATE_ROOT"])
                / "mnemosyne"
                / "data"
                / "secret"
            )
            private.write_text("private-index\n", encoding="utf-8")
            os.chmod(private, 0o600)
            alias = Path(env["BOT_LOCAL"]) / "post-launch-memory-alias"
            probe = (
                "from pathlib import Path\n"
                f"target=Path({str(private)!r})\n"
                f"alias=Path({str(alias)!r})\n"
                "alias.symlink_to(target)\n"
                "try:\n"
                " alias.read_bytes()\n"
                "except OSError:\n"
                " raise SystemExit(0)\n"
                "raise SystemExit(9)\n"
            )
            command = isolated_command(
                env,
                [sys.executable, "-c", probe],
            )
            result = subprocess.run(
                command,
                env=isolated_environment(env),
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(alias.exists())
            self.assertTrue(alias.is_symlink())

    @unittest.skipUnless(
        platform.system() == "Darwin" and shutil.which("sandbox-exec"),
        "real Seatbelt backend is only available on macOS",
    )
    def test_model_boundary_preserves_inherited_stdout_and_stderr(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture(Path(tmp))
            command = isolated_command(
                env,
                [
                    sys.executable,
                    "-c",
                    "import sys; print('sandbox-stdout'); "
                    "sys.stderr.write('sandbox-stderr\\n')",
                ],
            )
            result = subprocess.run(
                command,
                env=isolated_environment(env),
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "sandbox-stdout")
            self.assertEqual(result.stderr.strip(), "sandbox-stderr")


if __name__ == "__main__":
    unittest.main()
