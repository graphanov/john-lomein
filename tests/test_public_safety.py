#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from john_lomein_public_safety import (
    PublicSafetyError,
    assert_public_safe_text,
    sanitize_public_text,
)


class PublicSafetyTest(unittest.TestCase):
    def test_validator_accepts_public_urls_and_relative_repo_paths(self):
        text = (
            "Evidence: https://github.com/owner/repo/issues/12\n"
            "Changed scripts/example.py; compare active / backlog."
        )
        self.assertEqual(
            assert_public_safe_text(text, field="test"),
            text,
        )

    def test_validator_rejects_secrets_private_paths_and_controls(self):
        synthetic_token = (
            "ghp" + "_" + "abcdefghijklmnopqrstuvwxyz123456"
        )
        private_root = "/" + "Users/operator"
        unsafe = (
            f"GH_TOKEN={synthetic_token}",
            (
                f"See {private_root}/.john-lomein/instances/"
                "private/state.json"
            ),
            "bad\x00text",
        )
        for text in unsafe:
            with self.subTest(text=text):
                with self.assertRaises(PublicSafetyError):
                    assert_public_safe_text(text, field="test")

    def test_sanitizer_redacts_before_truncating(self):
        private_root = "/" + "Users/operator"
        synthetic_token = (
            "ghp" + "_" + "abcdefghijklmnopqrstuvwxyz123456"
        )
        text = (
            f"failure at {private_root}/private/repo "
            f"GH_TOKEN={synthetic_token} "
            + ("x" * 200)
        )
        safe = sanitize_public_text(text, limit=96)
        self.assertNotIn(private_root, safe)
        self.assertNotIn("ghp_", safe)
        self.assertIn("[REDACTED]", safe)
        self.assertLessEqual(len(safe), 96)

    def test_notification_boundary_reads_body_from_stdin_and_redacts(self):
        script = SCRIPTS / "john-lomein-overwatch-post.sh"
        private_root = "/" + "Users/operator"
        synthetic_token = (
            "ghp" + "_" + "abcdefghijklmnopqrstuvwxyz123456"
        )
        proc = subprocess.run(
            ["bash", str(script), "TEST_ALERT"],
            input=(
                f"failed in {private_root}/private/repo "
                f"with GH_TOKEN={synthetic_token}"
            ),
            capture_output=True,
            text=True,
            env={
                "PATH": (
                    "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:"
                    "/usr/sbin:/sbin"
                ),
                "BOT_DISCORD_ENABLED": "0",
                "BOT_DISPLAY_NAME": "john-lomein-test",
            },
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn(private_root, proc.stdout)
        self.assertNotIn("ghp_", proc.stdout)
        self.assertIn("[REDACTED]", proc.stdout)


if __name__ == "__main__":
    unittest.main()
