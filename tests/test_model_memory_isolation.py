#!/usr/bin/env python3
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from john_lomein_manifest_contract import (  # noqa: E402
    model_memory_isolation_mode,
)
from john_lomein_model_isolation import (  # noqa: E402
    IsolationError,
    darwin_policy,
    isolated_command,
    isolated_environment,
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
            home / "private" / "release-bundles",
            home / "private" / "learning-steward",
            home / "private" / "learning-steward" / "learning",
            home / "private" / "learning-steward" / "mnemosyne",
            home / "private" / "learning-steward" / "mnemosyne" / "data",
            home / "state" / "learning",
            home / "state" / "continuity",
            home / "logs",
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
        shutil.copytree(
            home / "scripts",
            profile / "scripts",
            dirs_exist_ok=True,
        )
        for plugin_name in (
            "john-lomein-continuity",
            "john-lomein-release-approval",
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
            self.assertNotIn(
                "(deny file-read* file-write* "
                f'(literal "{(home / "auth.json").resolve()}"))',
                policy,
            )
            self.assertNotIn(
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
            self.assertNotIn(
                ["--ro-bind", "/dev/null", str(home / "auth.json")],
                [
                    command[index : index + 3]
                    for index in range(len(command) - 2)
                ],
            )
            self.assertNotIn(
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
            self.assertIn("--share-net", command)
            self.assertIn("--tmpfs", command)
            private_learning = str(Path(private) / "learning")
            self.assertIn(private_learning, command)
            self.assertEqual(command[command.index(private_learning) - 1], "--tmpfs")
            owner_overrides = str(Path(env["BOT_HERMES_HOME"]) / "private" / "owner-overrides")
            owner_index = command.index(owner_overrides)
            self.assertEqual(command[owner_index - 1], "--tmpfs")
            review_receipts = str(Path(env["BOT_HERMES_HOME"]) / "private" / "review-receipts")
            review_index = command.index(review_receipts)
            self.assertEqual(command[review_index - 1], "--tmpfs")
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
        }
        child = isolated_environment(env)
        self.assertNotIn("MNEMOSYNE_DATA_DIR", child)
        self.assertNotIn("JOHN_LOMEIN_STEWARD_PRIVATE_ROOT", child)
        self.assertNotIn("BOT_STEWARD_PRIVATE_ROOT", child)
        self.assertNotIn("BOT_STEWARD_PROJECTION_ROOT", child)
        self.assertNotIn("GH_TOKEN", child)
        self.assertNotIn("SSH_AUTH_SOCK", child)
        self.assertNotIn("AWS_ACCESS_KEY_ID", child)
        self.assertEqual(child["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(child["JOHN_LOMEIN_MODEL_ISOLATED"], "1")

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
