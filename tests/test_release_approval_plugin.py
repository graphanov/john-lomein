#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = (
    ROOT
    / "runtime_plugins"
    / "john-lomein-release-approval"
    / "__init__.py"
)
SPEC = importlib.util.spec_from_file_location(
    "john_lomein_release_approval_plugin_test", PLUGIN
)
assert SPEC and SPEC.loader
plugin = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = plugin
SPEC.loader.exec_module(plugin)

BUNDLE_ID = "jlb-" + "a" * 24
BUNDLE_DIGEST = "sha256:" + "b" * 64
PACKET_ID = "jlrp-" + "c" * 24
APPROVAL = (
    f"APPROVE JOHN-LOMEIN BUNDLE {BUNDLE_ID} DIGEST {BUNDLE_DIGEST}: "
    "squash-merge the listed PR with the protected release broker; "
    "DO NOT publish. Post-merge repository verification and any "
    "publication require separate gates."
)


def session_getter(values):
    def get(name, default=""):
        if name == "HERMES_SESSION_USER_ID":
            raise AssertionError("actor identity must never be requested")
        return values.get(name, default)

    return get


def helper_result(*, outcome="succeeded"):
    reason = {
        "succeeded": "release_merged",
        "rejected": "policy_rejected",
        "partial": "partial_merge",
        "indeterminate": "indeterminate_readback",
    }[outcome]
    return {
        "schema_version": plugin.RESULT_SCHEMA,
        "instance_slug": "widget-production",
        "bundle_id": BUNDLE_ID,
        "bundle_digest": BUNDLE_DIGEST,
        "record_id": "jlros-" + "d" * 24,
        "event_id": "jlroe-" + "e" * 24,
        "packet_id": PACKET_ID,
        "packet_locator": (
            f"state/protected-releases/outbox/{PACKET_ID}.json"
        ),
        "submission": {
            "schema_version": "john-lomein.release-submit-result.v1",
            "packet_id": PACKET_ID,
            "bundle_id": BUNDLE_ID,
            "outcome": outcome,
            "reason_code": reason,
            "receipt_locator": (
                "state/protected-releases/receipts/jlrrc-"
                + "f" * 24
                + ".json"
            ),
        },
    }


class ReleaseApprovalPluginTest(unittest.TestCase):
    def setUp(self):
        self.values = {
            "HERMES_SESSION_PROFILE": plugin.GUIDE_PROFILE,
            "HERMES_SESSION_PLATFORM": "discord",
            "HERMES_SESSION_CHAT_ID": "123456789" + "012345678",
            "HERMES_SESSION_MESSAGE_ID": "223456789" + "012345678",
        }

    def test_nonapproval_is_noop(self):
        calls = []
        result = plugin.process_exact_release_approval(
            user_message="hello",
            platform="discord",
            session_getter=session_getter(self.values),
            runner=lambda *args, **kwargs: calls.append((args, kwargs)),
        )
        self.assertIsNone(result)
        self.assertEqual(calls, [])

    def test_wrong_platform_or_missing_ids_fail_closed_without_invocation(self):
        cases = [
            (self.values, "cli"),
            ({**self.values, "HERMES_SESSION_PLATFORM": "cli"}, "discord"),
            ({**self.values, "HERMES_SESSION_CHAT_ID": ""}, "discord"),
            ({**self.values, "HERMES_SESSION_MESSAGE_ID": ""}, "discord"),
            (
                {
                    **self.values,
                    "HERMES_SESSION_MESSAGE_ID": self.values[
                        "HERMES_SESSION_CHAT_ID"
                    ],
                },
                "discord",
            ),
        ]
        for values, platform_name in cases:
            calls = []
            with self.subTest(values=values, platform=platform_name):
                result = plugin.process_exact_release_approval(
                    user_message=APPROVAL,
                    platform=platform_name,
                    session_getter=session_getter(values),
                    runner=lambda *args, **kwargs: calls.append(
                        (args, kwargs)
                    ),
                )
                self.assertIn("blocked", result["context"])
                self.assertEqual(calls, [])

    def test_unconfigured_channel_helper_refusal_is_specific(self):
        diagnostic = (
            "john-lomein current release approval blocked: current Discord "
            "channel is not configured for protected release approvals\n"
        ).encode()
        result = plugin.process_exact_release_approval(
            user_message=APPROVAL,
            platform="discord",
            session_getter=session_getter(self.values),
            runner=lambda command, env: subprocess.CompletedProcess(
                command, 2, b"", diagnostic
            ),
        )
        self.assertIn("not configured", result["context"])

    def test_exact_guide_message_invokes_fixed_helper_once_without_actor(self):
        calls = []
        raw = json.dumps(
            helper_result(), sort_keys=True, separators=(",", ":")
        ).encode()

        def runner(command, *, env):
            calls.append((command, env))
            return subprocess.CompletedProcess(command, 0, raw, b"")

        result = plugin.process_exact_release_approval(
            user_message=APPROVAL,
            platform="discord",
            session_getter=session_getter(
                {**self.values, "HERMES_SESSION_USER_ID": "spoofed"}
            ),
            runner=runner,
        )
        self.assertEqual(len(calls), 1)
        command, env = calls[0]
        self.assertEqual(
            command[1:],
            [
                str(ROOT / "scripts" / "john-lomein-release-approve.py"),
                "approve",
                "--approval",
                APPROVAL,
            ],
        )
        self.assertEqual(
            set(env),
            {
                "PATH",
                "LANG",
                "HERMES_SESSION_PLATFORM",
                "HERMES_SESSION_CHAT_ID",
                "HERMES_SESSION_MESSAGE_ID",
            },
        )
        self.assertNotIn("USER", " ".join(env))
        self.assertIn("Outcome: succeeded.", result["context"])
        self.assertIn("proves only the protected merge", result["context"])

    def test_all_signed_terminal_outcomes_are_injected_with_exact_exit_code(self):
        exits = {
            "succeeded": 0,
            "rejected": 3,
            "partial": 4,
            "indeterminate": 5,
        }
        for outcome, code in exits.items():
            raw = json.dumps(
                helper_result(outcome=outcome),
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            with self.subTest(outcome=outcome):
                result = plugin.process_exact_release_approval(
                    user_message=APPROVAL,
                    platform="discord",
                    session_getter=session_getter(self.values),
                    runner=lambda command, env, raw=raw, code=code: (
                        subprocess.CompletedProcess(command, code, raw, b"")
                    ),
                )
                self.assertIn(f"Outcome: {outcome}.", result["context"])

    def test_ambiguous_submission_never_retries(self):
        calls = []

        def runner(command, *, env):
            calls.append((command, env))
            return subprocess.CompletedProcess(command, 6, b"", b"ambiguous")

        result = plugin.process_exact_release_approval(
            user_message=APPROVAL,
            platform="discord",
            session_getter=session_getter(self.values),
            runner=runner,
        )
        self.assertEqual(len(calls), 1)
        self.assertIn("Do not retry automatically", result["context"])

    @unittest.skipUnless(
        shutil.which("hermes"),
        "Hermes CLI is required for real profile plugin discovery",
    )
    def test_real_hermes_discovers_guide_profile_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "runtime"
            canonical = (
                runtime / "plugins" / plugin.PLUGIN_NAME
            )
            canonical.parent.mkdir(parents=True)
            shutil.copytree(PLUGIN.parent, canonical)
            guide = runtime / "profiles" / plugin.GUIDE_PROFILE
            guide_plugins = guide / "plugins"
            guide_plugins.mkdir(parents=True)
            (guide_plugins / plugin.PLUGIN_NAME).symlink_to(
                canonical, target_is_directory=True
            )
            (guide / "config.yaml").write_text(
                yaml.safe_dump(
                    {
                        "plugins": {
                            "enabled": [plugin.PLUGIN_NAME],
                            "disabled": [],
                        }
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            env = dict(os.environ)
            env["HERMES_HOME"] = str(guide)
            proc = subprocess.run(
                [
                    shutil.which("hermes") or "hermes",
                    "plugins",
                    "list",
                    "--enabled",
                    "--user",
                    "--json",
                ],
                capture_output=True,
                text=True,
                timeout=60,
                env=env,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertIn(plugin.PLUGIN_NAME, json.dumps(data))


if __name__ == "__main__":
    unittest.main()
