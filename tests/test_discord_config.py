#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "scripts" / "apply-guide-discord-config.py"
ASSERTION_PATH = ROOT / "scripts" / "john-lomein-trust-assertion.py"
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from john_lomein_memory_contract import (  # noqa: E402
    CONTINUITY_PLUGIN,
    NO_MCP_SENTINEL,
    agent_memory_managed_policy,
)


def write_guide_managed_policy(hermes: Path) -> None:
    policy_dir = hermes / "managed-policy" / "john-lomein-guide"
    policy_dir.mkdir(parents=True)
    (policy_dir / "config.yaml").write_text(
        yaml.safe_dump(
            agent_memory_managed_policy("guide"),
            sort_keys=False,
        ),
        encoding="utf-8",
    )


class DiscordConfigTrustTierTest(unittest.TestCase):
    def test_apply_config_renders_trust_tiers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes = root / "hermes"
            profile = hermes / "profiles" / "john-lomein-guide"
            profile.mkdir(parents=True)
            write_guide_managed_policy(hermes)
            (profile / "config.yaml").write_text(
                textwrap.dedent(
                    """
                    discord: {}
                    memory:
                      memory_enabled: true
                      user_profile_enabled: true
                      provider: mnemosyne
                    agent:
                      disabled_toolsets: []
                    plugins:
                      enabled: [mnemosyne]
                      disabled: []
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            instance = root / "instance.yaml"
            instance.write_text(
                textwrap.dedent(
                    f"""
                    instance:
                      slug: test
                    runtime:
                      hermes_home: {hermes}
                    profiles:
                      guide: john-lomein-guide
                    discord:
                      allowed_channels:
                      - public-channel
                      owner_user_ids:
                      - owner-user
                      trusted_collaborator_user_ids:
                      - collaborator-user
                      untrusted_example_channels:
                      - examples-channel
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run([sys.executable, str(CONFIG_PATH), str(root)], capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            cfg = yaml.safe_load((profile / "config.yaml").read_text(encoding="utf-8"))
            trust = cfg["discord"]["john_lomein_trust_tiers"]
            self.assertEqual(trust["owner_user_ids"], ["owner-user"])
            self.assertEqual(trust["trusted_collaborator_user_ids"], ["collaborator-user"])
            self.assertEqual(trust["public_guide_channels"], ["public-channel"])
            self.assertEqual(trust["untrusted_example_channels"], ["examples-channel"])
            self.assertTrue(trust["owner_commands_require_exact_identity"])
            self.assertTrue(trust["signed_trust_assertions_required"])
            self.assertEqual(trust["trust_assertion_env"], "JOHN_LOMEIN_TRUST_ASSERTION")
            self.assertEqual(trust["trust_assertion_issuer"], "external_gateway_only")
            self.assertFalse(trust["public_input_may_route_readiness_or_approve_release"])
            self.assertIs(cfg["memory"]["memory_enabled"], False)
            self.assertIs(cfg["memory"]["user_profile_enabled"], False)
            self.assertEqual(cfg["memory"]["provider"], "honcho")
            self.assertIn("memory", cfg["agent"]["disabled_toolsets"])
            self.assertIn("session_search", cfg["agent"]["disabled_toolsets"])
            self.assertNotIn("mnemosyne", cfg["plugins"]["enabled"])
            self.assertIn("mnemosyne", cfg["plugins"]["disabled"])
            self.assertIn(CONTINUITY_PLUGIN, cfg["plugins"]["enabled"])
            self.assertNotIn(CONTINUITY_PLUGIN, cfg["plugins"]["disabled"])
            self.assertEqual(cfg["mcp_servers"], {})
            self.assertIn(
                NO_MCP_SENTINEL,
                cfg["platform_toolsets"]["discord"],
            )

    def test_apply_config_rejects_redirected_guide_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes = root / "hermes"
            profile = hermes / "profiles" / "john-lomein-guide"
            profile.mkdir(parents=True)
            write_guide_managed_policy(hermes)
            redirected = root / "redirected.yaml"
            redirected.write_text("discord: {}\n", encoding="utf-8")
            (profile / "config.yaml").symlink_to(redirected)
            instance = root / "instance.yaml"
            instance.write_text(
                textwrap.dedent(
                    f"""
                    instance:
                      slug: test
                    runtime:
                      hermes_home: {hermes}
                    profiles:
                      guide: john-lomein-guide
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                [sys.executable, str(CONFIG_PATH), str(root)],
                capture_output=True,
                text=True,
                timeout=30,
            )

            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("redirected guide config", proc.stderr + proc.stdout)
            self.assertEqual(
                redirected.read_text(encoding="utf-8"),
                "discord: {}\n",
            )

    def test_apply_config_rejects_hostile_managed_overlay(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes = root / "hermes"
            profile = hermes / "profiles" / "john-lomein-guide"
            profile.mkdir(parents=True)
            (profile / "config.yaml").write_text(
                "discord: {}\n",
                encoding="utf-8",
            )
            write_guide_managed_policy(hermes)
            managed = (
                hermes
                / "managed-policy"
                / "john-lomein-guide"
                / "config.yaml"
            )
            hostile = yaml.safe_load(managed.read_text(encoding="utf-8"))
            hostile["memory"]["memory_enabled"] = True
            managed.write_text(
                yaml.safe_dump(hostile, sort_keys=False),
                encoding="utf-8",
            )
            instance = root / "instance.yaml"
            instance.write_text(
                textwrap.dedent(
                    f"""
                    instance:
                      slug: test
                    runtime:
                      hermes_home: {hermes}
                    profiles:
                      guide: john-lomein-guide
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                [sys.executable, str(CONFIG_PATH), str(root)],
                capture_output=True,
                text=True,
                timeout=30,
            )

            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("managed policy drift", proc.stderr + proc.stdout)

    def test_trust_assertion_verifier_init_is_verification_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "hermes"
            env = {"HERMES_HOME": str(home), "BOT_HERMES_HOME": str(home)}
            init = subprocess.run([sys.executable, str(ASSERTION_PATH), "init-verifier"], env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(init.returncode, 0, init.stderr + init.stdout)
            data = yaml.safe_load(init.stdout)
            self.assertTrue(data["ok"])
            self.assertFalse(data["public_key_present"])
            self.assertEqual(data["signing"], "external_gateway_only")
            proc = subprocess.run([sys.executable, str(ASSERTION_PATH), "route", "--repo", "owner/repo", "--issue", "28", "--route", "pr"], env=env, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
