from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from john_lomein_honcho_contract import (  # noqa: E402
    honcho_settings,
    profile_honcho_config,
    profile_honcho_errors,
    probe_honcho_health,
    write_profile_honcho_config,
)


class HonchoContractTest(unittest.TestCase):
    def manifest(self) -> dict:
        return {
            "authority": {"owner_approvers": ["owner-id"]},
            "runtime": {"hermes_home": "/tmp/john-lomein-honcho-contract/runtime"},
            "memory": {
                "provider": "honcho",
                "honcho": {
                    "workspace": "workspace",
                    "owner_peer": "Owner",
                    "guide_save_messages": True,
                    "timeout": 120,
                },
            },
        }

    def test_workspace_defaults_to_instance_slug(self):
        manifest=self.manifest()
        manifest["memory"]["honcho"].pop("workspace")
        self.assertEqual(honcho_settings(manifest,instance_slug="alpha")["workspace"],"john-lomein-alpha")

    def test_guide_maps_owner_and_isolates_other_gateway_users(self):
        data = profile_honcho_config(
            self.manifest(), instance_slug="repo", role="guide", profile="john-guide"
        )
        host = data["hosts"]["hermes_john-guide"]
        self.assertEqual(data["hosts"]["hermes"], host)
        self.assertFalse(host["pinUserPeer"])
        self.assertEqual(host["userPeerAliases"], {"owner-id": "Owner"})
        self.assertEqual(host["runtimePeerPrefix"], "discord_")
        self.assertTrue(host["saveMessages"])
        self.assertEqual(host["recallMode"], "context")
        self.assertFalse(host["observation"]["ai"]["observeMe"])

    def test_discord_owner_ids_override_authority_fallback(self):
        manifest = self.manifest()
        manifest["discord"] = {"owner_user_ids": ["discord-owner"]}
        data = profile_honcho_config(
            manifest, instance_slug="repo", role="guide", profile="john-guide"
        )
        host = data["hosts"]["hermes_john-guide"]
        self.assertEqual(data["hosts"]["hermes"], host)
        self.assertEqual(host["userPeerAliases"], {"discord-owner": "Owner"})

    def test_workers_read_context_without_saving_scheduler_prompts(self):
        data = profile_honcho_config(
            self.manifest(), instance_slug="repo", role="maintainer", profile="john-maintainer"
        )
        host = data["hosts"]["hermes_john-maintainer"]
        self.assertEqual(data["hosts"]["hermes"], host)
        self.assertTrue(host["pinUserPeer"])
        self.assertFalse(host["saveMessages"])
        self.assertEqual(host["recallMode"], "context")

    def test_writer_is_private_and_exactly_verifiable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_profile_honcho_config(
                self.manifest(),
                instance_slug="repo",
                role="forge",
                profile="john-forge",
                profile_home=tmp,
            )
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                profile_honcho_errors(
                    data,
                    instance_slug="repo",
                    role="forge",
                    profile="john-forge",
                    manifest=self.manifest(),
                ),
                [],
            )

    def test_writer_rejects_symlink_and_hardlink_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = root / "profile"
            profile.mkdir()
            outside = root / "outside.json"
            outside.write_text("{}\n", encoding="utf-8")
            target = profile / "honcho.json"
            target.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "unsafe existing Honcho config"):
                write_profile_honcho_config(
                    self.manifest(), instance_slug="repo", role="guide",
                    profile="john-guide", profile_home=profile,
                )
            target.unlink()
            os.link(outside, target)
            with self.assertRaisesRegex(ValueError, "unsafe existing Honcho config"):
                write_profile_honcho_config(
                    self.manifest(), instance_slug="repo", role="guide",
                    profile="john-guide", profile_home=profile,
                )

    def test_health_probe_requires_reachable_success_status(self):
        connection=mock.MagicMock()
        connection.getresponse.return_value.status=204
        with mock.patch('john_lomein_honcho_contract.HTTPConnection',return_value=connection):
            probe_honcho_health('http://127.0.0.1:8000')
        connection.request.side_effect=OSError('down')
        with mock.patch('john_lomein_honcho_contract.HTTPConnection',return_value=connection):
            with self.assertRaisesRegex(RuntimeError,'health probe failed'):
                probe_honcho_health('http://127.0.0.1:8000')
        connection.request.side_effect=None
        connection.getresponse.return_value.status=302
        with mock.patch('john_lomein_honcho_contract.HTTPConnection',return_value=connection):
            with self.assertRaisesRegex(RuntimeError,'HTTP 302'):
                probe_honcho_health('http://127.0.0.1:8000')
        with self.assertRaisesRegex(RuntimeError,'non-positive port'):
            probe_honcho_health('http://127.0.0.1:0')

    def test_invalid_provider_url_and_timeout_fail_closed(self):
        for replacement in (
            {"provider": "builtin"},
            {"provider": False},
            {"provider": "honcho", "honcho": {"base_url": False}},
            {"provider": "honcho", "honcho": {"workspace": 0}},
            {"provider": "honcho", "honcho": {"base_url": "file:///tmp/x"}},
            {"provider": "honcho", "honcho": {"base_url": "https://example.invalid"}},
            {"provider": "honcho", "honcho": {"base_url": "http://127.0.0.1:notaport"}},
            {"provider": "honcho", "honcho": {"base_url": "http://127.0.0.1:0"}},
            {"provider": "honcho", "honcho": {"timeout": None}},
            {"provider": "honcho", "honcho": {"timeout": "120"}},
            {"provider": "honcho", "honcho": {"timeout": 0}},
            {"provider": "honcho", "honcho": {"guide_save_messages": "false"}},
        ):
            manifest = self.manifest()
            manifest["memory"] = replacement
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                honcho_settings(manifest, instance_slug="repo")


    def test_present_sections_must_be_mappings(self):
        manifests=({"memory": []},{"memory":{"provider":"honcho","honcho":[]}})
        for manifest in manifests:
            with self.subTest(manifest=manifest), self.assertRaisesRegex(ValueError,'YAML mapping'):
                honcho_settings(manifest,instance_slug='repo')

    def test_deploy_and_doctor_enforce_profile_honcho_contract(self):
        root = Path(__file__).resolve().parents[1]
        deploy = (root / "scripts" / "deploy-instance.sh").read_text(encoding="utf-8")
        doctor = (root / "scripts" / "doctor-instance.py").read_text(encoding="utf-8")
        self.assertIn("write_profile_honcho_config(", deploy)
        self.assertNotIn("probe_honcho_health(settings", deploy)
        self.assertIn("public-service-install", deploy)
        self.assertIn("unset HERMES_HONCHO_HOST", deploy)
        self.assertIn("john_lomein_honcho_contract.py", deploy)
        self.assertIn("profile_honcho_errors(", doctor)
        self.assertIn("local Honcho contract is exact", doctor)
        self.assertIn("dedicated public Honcho provider is reachable", doctor)


if __name__ == "__main__":
    unittest.main()
