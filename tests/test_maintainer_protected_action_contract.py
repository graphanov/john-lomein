#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class MaintainerProtectedActionContractTest(unittest.TestCase):
    def test_maintainer_routes_protected_github_updates_to_broker_packets(self):
        skill = (
            ROOT / "skills" / "john-lomein-maintainer" / "SKILL.md"
        ).read_text(encoding="utf-8")
        soul = (
            ROOT / "profiles" / "john-lomein-maintainer" / "SOUL.md"
        ).read_text(encoding="utf-8")
        prompt = (
            ROOT / "scripts" / "john-lomein-maintainer-prompt.txt"
        ).read_text(encoding="utf-8")

        for name, text in {
            "skill": skill,
            "soul": soul,
            "prompt": prompt,
        }.items():
            lowered = text.lower()
            self.assertIn("protected", lowered, name)
            self.assertIn("broker", lowered, name)
            self.assertIn("top-level", lowered, name)
            self.assertIn("receipt", lowered, name)

        for text in (skill, prompt):
            lowered = text.lower()
            self.assertIn("resolve_review_thread", text)
            self.assertIn("mark_pr_ready", text)
            self.assertIn("john-lomein-protected-submit.py", text)
            self.assertIn("--receipt-output", text)
            self.assertIn("signature-verified", lowered)
            self.assertIn("do not run `gh pr ready`", lowered)
            self.assertNotIn(
                "post compact evidence and resolve the thread",
                text,
            )
            self.assertNotIn(
                "mark it ready for review (`gh pr ready`)",
                text,
            )
        self.assertIn("--verify-receipt", skill)

    def test_operator_docs_do_not_claim_current_protected_mutations(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        operations = (ROOT / "OPERATIONS.md").read_text(encoding="utf-8")
        standard = (
            ROOT
            / "docs"
            / "productization"
            / "maintainer-appliance-10-10-standard.md"
        ).read_text(encoding="utf-8")
        runbook = (
            ROOT
            / "docs"
            / "productization"
            / "new-maintainer-appliance-runbook.md"
        ).read_text(encoding="utf-8")

        self.assertNotIn(
            "promotes verified bot-created draft PRs to ready-for-review",
            readme,
        )
        self.assertNotIn(
            "post evidence and resolve the stale/false-positive thread",
            operations,
        )
        self.assertNotIn(
            "| Resolve review thread | allowed",
            standard,
        )
        self.assertIn(
            "prepares exact protected-action packets and submits them once",
            readme,
        )
        self.assertIn("current runtime cannot perform it", standard)
        self.assertIn("rejects draft promotion", runbook)
        self.assertIn("direct `--merge` and `--publish` fail closed", operations)


if __name__ == "__main__":
    unittest.main()
