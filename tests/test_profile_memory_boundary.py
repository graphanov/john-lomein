#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from john_lomein_memory_contract import (  # noqa: E402
    CONTINUITY_PLUGIN,
    DISABLED_AGENT_MEMORY_TOOLSETS,
    NO_MCP_SENTINEL,
    OPERATIONAL_ROLES,
    agent_memory_boundary_errors,
    agent_memory_managed_policy,
    agent_memory_managed_policy_errors,
    apply_agent_memory_boundary,
    allowed_profile_plugins,
)


def load_doctor():
    spec = importlib.util.spec_from_file_location(
        "doctor_instance_memory_test",
        SCRIPTS / "doctor-instance.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load doctor-instance.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


doctor = load_doctor()


class ProfileMemoryContractTest(unittest.TestCase):
    def test_apply_boundary_removes_stale_provider_and_preserves_unrelated_config(self):
        for role in sorted(OPERATIONAL_ROLES):
            with self.subTest(role=role):
                config = {
                    "agent": {
                        "max_turns": 123,
                        "disabled_toolsets": ["context_engine"],
                    },
                    "memory": {
                        "memory_enabled": True,
                        "user_profile_enabled": True,
                        "provider": "mnemosyne",
                        "mnemosyne": {"profile_isolation": True},
                    },
                    "plugins": {
                        "enabled": ["mnemosyne", "kept-plugin"],
                        "disabled": ["old-disabled"],
                    },
                    "known_plugin_toolsets": {
                        "cli": ["memory", "plugin-private"],
                    },
                    "mcp_servers": {
                        "mnemosyne": {
                            "command": "/safe/local/memory-server",
                            "enabled": True,
                        }
                    },
                    "platform_toolsets": {
                        "cli": ["web", "mnemosyne"],
                        "discord": ["web", "skills", "todo", "mnemosyne"],
                    },
                    "model": {"provider": "fixture"},
                }

                apply_agent_memory_boundary(config, role)

                self.assertEqual(
                    config["memory"],
                    {
                        "memory_enabled": False,
                        "user_profile_enabled": False,
                        "provider": "honcho",
                        "write_approval": True,
                        "nudge_interval": 0,
                        "flush_min_turns": 0,
                    },
                )
                self.assertEqual(config["agent"]["max_turns"], 123)
                self.assertTrue(
                    DISABLED_AGENT_MEMORY_TOOLSETS
                    <= set(config["agent"]["disabled_toolsets"])
                )
                self.assertNotIn("mnemosyne", config["plugins"]["enabled"])
                self.assertIn("mnemosyne", config["plugins"]["disabled"])
                self.assertNotIn("kept-plugin", config["plugins"]["enabled"])
                self.assertIn(
                    CONTINUITY_PLUGIN,
                    config["plugins"]["enabled"],
                )
                self.assertNotIn(
                    CONTINUITY_PLUGIN,
                    config["plugins"]["disabled"],
                )
                self.assertEqual(
                    config["plugins"]["enabled"],
                    allowed_profile_plugins(role),
                )
                self.assertNotIn("known_plugin_toolsets", config)
                self.assertEqual(config["curator"]["enabled"], False)
                self.assertEqual(config["mcp_servers"], {})
                self.assertIn(
                    NO_MCP_SENTINEL,
                    config["platform_toolsets"]["cli"],
                )
                self.assertNotIn(
                    "mnemosyne",
                    config["platform_toolsets"]["cli"],
                )
                if role == "guide":
                    self.assertIn(
                        NO_MCP_SENTINEL,
                        config["platform_toolsets"]["discord"],
                    )
                self.assertEqual(config["model"], {"provider": "fixture"})
                self.assertEqual(agent_memory_boundary_errors(config, role), [])

    def test_validator_rejects_each_agent_memory_reactivation_surface(self):
        safe: dict = {}
        apply_agent_memory_boundary(safe, "guide")
        mutations = {
            "memory_enabled": lambda cfg: cfg["memory"].update(
                {"memory_enabled": True}
            ),
            "user_profile_enabled": lambda cfg: cfg["memory"].update(
                {"user_profile_enabled": True}
            ),
            "provider": lambda cfg: cfg["memory"].update(
                {"provider": "mnemosyne"}
            ),
            "provider_subtree": lambda cfg: cfg["memory"].update(
                {"mnemosyne": {"profile_isolation": True}}
            ),
            "memory_toolset": lambda cfg: cfg["agent"].update(
                {
                    "disabled_toolsets": [
                        name
                        for name in cfg["agent"]["disabled_toolsets"]
                        if name != "memory"
                    ]
                }
            ),
            "session_toolset": lambda cfg: cfg["agent"].update(
                {
                    "disabled_toolsets": [
                        name
                        for name in cfg["agent"]["disabled_toolsets"]
                        if name != "session_search"
                    ]
                }
            ),
            "plugin_enabled": lambda cfg: cfg["plugins"]["enabled"].append(
                "mnemosyne"
            ),
            "plugin_not_disabled": lambda cfg: cfg["plugins"].update(
                {"disabled": []}
            ),
            "unexpected_plugin": lambda cfg: cfg["plugins"]["enabled"].append(
                "recall-by-another-name"
            ),
            "mcp_server": lambda cfg: cfg["mcp_servers"].update(
                {
                    "mnemosyne": {
                        "command": "/safe/local/memory-server",
                        "enabled": True,
                    }
                }
            ),
            "mcp_passthrough": lambda cfg: cfg["platform_toolsets"][
                "discord"
            ].append("mnemosyne"),
            "persisted_known_plugin_toolsets": lambda cfg: cfg.update(
                {"known_plugin_toolsets": {"cli": ["spotify"]}}
            ),
            "curator_reenabled": lambda cfg: cfg["curator"].update(
                {"enabled": True}
            ),
            "missing_cli_no_mcp": lambda cfg: cfg["platform_toolsets"].update(
                {
                    "cli": [
                        name
                        for name in cfg["platform_toolsets"]["cli"]
                        if name != NO_MCP_SENTINEL
                    ]
                }
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                candidate = yaml.safe_load(yaml.safe_dump(safe))
                mutate(candidate)
                self.assertTrue(
                    agent_memory_boundary_errors(candidate, "guide"),
                    candidate,
                )

    def test_doctor_fails_unsafe_exact_config_and_unproven_tool_disables(self):
        with tempfile.TemporaryDirectory() as tmp:
            pdir = Path(tmp) / "profile"
            pdir.mkdir()
            unsafe = {
                "memory": {
                    "memory_enabled": True,
                    "user_profile_enabled": False,
                    "provider": "mnemosyne",
                    "write_approval": True,
                    "nudge_interval": 0,
                    "flush_min_turns": 0,
                },
                "agent": {"disabled_toolsets": []},
                "plugins": {"enabled": ["mnemosyne"], "disabled": []},
                "mcp_servers": {
                    "mnemosyne": {
                        "command": "/safe/local/memory-server",
                        "enabled": True,
                    }
                },
                "platform_toolsets": {
                    "cli": ["web", "mnemosyne"],
                    "discord": ["web", "mnemosyne"],
                },
            }
            doctor.FAIL.clear()
            doctor.WARN.clear()

            output = io.StringIO()
            with redirect_stdout(output):
                self.assertFalse(
                    doctor.check_profile_memory_boundary(
                        "guide",
                        "john-lomein-guide",
                        unsafe,
                        pdir,
                    )
                )
                self.assertFalse(
                    doctor.check_model_memory_toolsets(
                        "john-lomein-guide",
                        {"session_search"},
                    )
                )
            failures = "\n".join(doctor.FAIL)
            self.assertIn("memory.memory_enabled must be exactly false", failures)
            self.assertIn("memory.provider must be exactly honcho", failures)
            self.assertIn(
                "model-facing memory/session toolsets exposed or unproven",
                failures,
            )
            self.assertIn(
                "mcp_servers must be empty",
                failures,
            )

    def test_managed_overlay_is_probed_as_effective_config_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            managed = root / "managed-policy" / "john-lomein-guide"
            managed.mkdir(parents=True)
            policy = agent_memory_managed_policy("guide")
            (managed / "config.yaml").write_text(
                yaml.safe_dump(policy, sort_keys=False),
                encoding="utf-8",
            )
            self.assertEqual(
                agent_memory_managed_policy_errors(policy, "guide"),
                [],
            )
            hostile = yaml.safe_load(yaml.safe_dump(policy))
            hostile["memory"]["memory_enabled"] = True
            self.assertTrue(
                agent_memory_managed_policy_errors(hostile, "guide")
            )

            effective_values = {
                "memory": {
                    **policy["memory"],
                    "memory_enabled": True,
                    "provider": "honcho",
                    "memory_char_limit": 7000,
                    "user_char_limit": 7000,
                },
                "agent.disabled_toolsets": policy["agent"][
                    "disabled_toolsets"
                ],
                "plugins": policy["plugins"],
                "mcp_servers": None,
                "platform_toolsets": policy["platform_toolsets"],
            }
            seen_envs: list[dict[str, str]] = []

            def fake_run(cmd, **kwargs):
                key = cmd[-2]
                seen_envs.append(dict(kwargs["env"]))
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    json.dumps(effective_values[key]),
                    "",
                )

            with mock.patch.object(
                doctor.subprocess,
                "run",
                side_effect=fake_run,
            ):
                effective = doctor.load_effective_profile_config(
                    "john-lomein-guide",
                    root,
                    managed,
                    runtime_python=sys.executable,
                )
            self.assertTrue(seen_envs)
            self.assertTrue(
                all(
                    env["HERMES_MANAGED_DIR"] == str(managed)
                    and "MNEMOSYNE_DATA_DIR" not in env
                    for env in seen_envs
                )
            )
            doctor.FAIL.clear()
            with redirect_stdout(io.StringIO()):
                self.assertFalse(
                    doctor.check_effective_profile_memory_boundary(
                        "guide",
                        "john-lomein-guide",
                        effective,
                    )
                )
            self.assertIn(
                "memory.memory_enabled must be exactly false",
                "\n".join(doctor.FAIL),
            )

    def test_effective_config_probe_ambiguity_is_an_error(self):
        with mock.patch.object(
            doctor.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                ["hermes"],
                0,
                "not-json",
                "",
            ),
        ):
            with self.assertRaisesRegex(ValueError, "non-JSON"):
                doctor.load_effective_profile_config(
                    "john-lomein-guide",
                    Path("/runtime"),
                    Path("/runtime/managed-policy/john-lomein-guide"),
                    runtime_python=sys.executable,
                )

    def test_doctor_loads_only_a_regular_exact_deployed_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            safe: dict = {}
            apply_agent_memory_boundary(safe, "guide")
            real = root / "real.yaml"
            real.write_text(yaml.safe_dump(safe), encoding="utf-8")
            exact = root / "config.yaml"
            exact.write_text(yaml.safe_dump(safe), encoding="utf-8")
            self.assertEqual(doctor.load_exact_profile_config(exact), safe)

            redirected = root / "redirected.yaml"
            redirected.symlink_to(real)
            with self.assertRaisesRegex(ValueError, "must not be a symlink"):
                doctor.load_exact_profile_config(redirected)

            invalid = root / "invalid.yaml"
            invalid.write_text("- not\n- a\n- mapping\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "root must be a mapping"):
                doctor.load_exact_profile_config(invalid)

            hardlink = root / "hardlink.yaml"
            os.link(real, hardlink)
            with self.assertRaisesRegex(ValueError, "exactly one link"):
                doctor.load_exact_profile_config(hardlink)


if __name__ == "__main__":
    unittest.main()
