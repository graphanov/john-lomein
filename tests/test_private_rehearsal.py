#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PrivateRehearsalTest(unittest.TestCase):
    def test_offline_rehearsal_proves_owner_gate_and_exact_head(self):
        script = ROOT / "scripts" / "john-lomein-private-rehearsal.py"
        self.assertTrue(script.is_file(), f"missing rehearsal script: {script}")
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "receipt.json"
            result = subprocess.run(
                [
                    "uv",
                    "run",
                    "--frozen",
                    "python",
                    str(script),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=120,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(receipt["schema_version"], "john-lomein.private-rehearsal.v1")
        self.assertEqual(receipt["status"], "PASSED")
        self.assertEqual(receipt["guide"]["stage"], "EXHAUSTED")
        self.assertFalse(receipt["guide"]["questioning_permitted"])
        self.assertTrue(receipt["proposal"]["proposal_id"].startswith("jl-proposal-"))
        self.assertTrue(receipt["owner_readiness"]["proven"])
        self.assertEqual(receipt["owner_readiness"]["actor"], "repo-owner")
        self.assertEqual(
            receipt["verdict_parser"]["ambiguous"],
            {"status": "BLOCKED", "valid": False},
        )
        self.assertEqual(
            receipt["verdict_parser"]["final"],
            {"status": "SHIP", "valid": True},
        )
        head = receipt["merge_ready"]["head_sha"]
        self.assertEqual(len(head), 40)
        self.assertIn(head, receipt["merge_ready"]["report"])
        self.assertEqual(receipt["merge_ready"]["pr_count"], 1)
        self.assertTrue(receipt["merge_ready"]["quorum_passed"])
        self.assertTrue(receipt["merge_ready"]["quorum_sha256"].startswith("sha256:"))
        self.assertTrue(receipt["merge_ready"]["owner_manual_merge_required"])
        self.assertFalse(receipt["side_effects"]["github_mutated"])
        self.assertFalse(receipt["side_effects"]["runtime_activated"])
        self.assertFalse(receipt["side_effects"]["merge_executed"])


if __name__ == "__main__":
    unittest.main()
