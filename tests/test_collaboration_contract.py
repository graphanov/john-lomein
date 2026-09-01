#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


class CollaborationContractTest(unittest.TestCase):
    def test_absent_policy_is_disabled_and_advisory_only(self):
        from john_lomein_collaboration_contract import collaboration_policy

        policy = collaboration_policy({})
        self.assertEqual(policy["schema_version"], "john-lomein.collaboration.v1")
        self.assertEqual(policy["mode"], "disabled")
        self.assertEqual(policy["authority"], "advisory_only")
        self.assertFalse(policy["bot_chat_protocol_enabled"])
        self.assertFalse(policy["peer_messaging_enabled"])
        self.assertEqual(policy["allowed_routes"], {})
        self.assertEqual(policy["peer_targets"], [])

    def test_prepared_policy_can_describe_routes_but_cannot_enable_transport(self):
        from john_lomein_collaboration_contract import collaboration_policy

        policy = collaboration_policy(
            {
                "collaboration": {
                    "schema_version": "john-lomein.collaboration.v1",
                    "mode": "prepared",
                    "authority": "advisory_only",
                    "bot_chat_protocol_enabled": False,
                    "peer_messaging_enabled": False,
                    "max_message_chars": 4000,
                    "allowed_routes": {
                        "guide": ["forge"],
                        "forge": ["overwatch", "maintainer"],
                        "overwatch": ["forge"],
                    },
                    "peer_targets": [],
                }
            }
        )
        self.assertEqual(policy["mode"], "prepared")
        self.assertEqual(policy["allowed_routes"]["forge"], ["maintainer", "overwatch"])
        self.assertFalse(policy["bot_chat_protocol_enabled"])

    def test_transport_activation_unknown_fields_and_authority_escalation_fail_closed(self):
        from john_lomein_collaboration_contract import collaboration_policy

        invalid_sections = (
            {"bot_chat_protocol_enabled": True},
            {"peer_messaging_enabled": True},
            {"authority": "owner_ready"},
            {"mode": "active"},
            {"unexpected": True},
            {"allowed_routes": {"guide": ["unknown-role"]}},
            {"peer_targets": ["peer with spaces"]},
        )
        for section in invalid_sections:
            with self.subTest(section=section), self.assertRaisesRegex(
                ValueError,
                "collaboration",
            ):
                collaboration_policy({"collaboration": section})

    def test_doctor_and_deploy_own_the_collaboration_boundary(self):
        doctor = (ROOT / "scripts" / "doctor-instance.py").read_text(encoding="utf-8")
        deploy = (ROOT / "scripts" / "deploy-instance.sh").read_text(encoding="utf-8")
        for text in (doctor, deploy):
            self.assertIn("john_lomein_collaboration_contract", text)
            self.assertIn("bot_mode_protocol", text)
            self.assertIn("john-lomein-collaboration-policy.json", text)
        assessment = ROOT / "docs" / "productization" / "hermes-v0.21-collaboration-assessment.md"
        self.assertTrue(assessment.is_file())
        self.assertIn("transport is not authority", assessment.read_text(encoding="utf-8"))

    def test_advisory_message_is_digest_bound_and_route_checked(self):
        from john_lomein_collaboration_contract import (
            collaboration_policy,
            normalize_role_message,
        )

        policy = collaboration_policy(
            {
                "collaboration": {
                    "schema_version": "john-lomein.collaboration.v1",
                    "mode": "prepared",
                    "authority": "advisory_only",
                    "bot_chat_protocol_enabled": False,
                    "peer_messaging_enabled": False,
                    "max_message_chars": 4000,
                    "allowed_routes": {"forge": ["overwatch"]},
                    "peer_targets": [],
                }
            }
        )
        message = normalize_role_message(
            {
                "schema_version": "john-lomein.role-message.v1",
                "sender_role": "forge",
                "recipient_role": "overwatch",
                "purpose": "design_consultation",
                "correlation_id": "issue-42",
                "body": "Review the proposed acceptance criteria for ambiguity.",
                "authority": "advisory_only",
            },
            policy=policy,
        )
        self.assertRegex(message["message_id"], r"^jlrm-[0-9a-f]{24}$")
        self.assertEqual(message["authority"], "advisory_only")
        self.assertFalse(message["may_mark_ready"])
        self.assertFalse(message["may_merge"])
        self.assertFalse(message["may_publish"])

        with self.assertRaisesRegex(ValueError, "route"):
            normalize_role_message(
                {
                    **message,
                    "sender_role": "guide",
                    "recipient_role": "overwatch",
                },
                policy=policy,
            )

    def test_message_rejects_private_paths_secrets_and_claimed_authority(self):
        from john_lomein_collaboration_contract import (
            collaboration_policy,
            normalize_role_message,
        )

        policy = collaboration_policy(
            {
                "collaboration": {
                    "mode": "prepared",
                    "allowed_routes": {"forge": ["overwatch"]},
                }
            }
        )
        base = {
            "schema_version": "john-lomein.role-message.v1",
            "sender_role": "forge",
            "recipient_role": "overwatch",
            "purpose": "design_consultation",
            "correlation_id": "issue-42",
            "body": "Review this design.",
            "authority": "advisory_only",
        }
        invalid = (
            {**base, "body": "/" + "Users/operator/private"},
            {**base, "body": "token " + "sk-" + "a" * 24},
            {**base, "authority": "owner_ready"},
            {**base, "may_merge": True},
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_role_message(value, policy=policy)


if __name__ == "__main__":
    unittest.main()
