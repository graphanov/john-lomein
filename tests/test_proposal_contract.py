#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def sample_proposal() -> dict:
    return {
        "schema_version": "john-lomein.proposal.v1",
        "title": "Add deterministic cache invalidation",
        "problem": "Stale cache entries can survive a configuration change.",
        "desired_outcome": "Configuration changes invalidate only affected cache entries.",
        "scope": ["Track configuration digests", "Invalidate changed entries"],
        "out_of_scope": ["Replace the cache backend"],
        "constraints": ["Preserve the public API"],
        "success_signals": ["Changed entries are refreshed", "Unchanged entries remain warm"],
        "evidence_plan": ["Unit-test digest changes", "Run the repository verification command"],
        "risks": ["Over-invalidation may reduce hit rate"],
        "open_questions": [],
        "dialogue": {
            "status": "EXHAUSTED",
            "clarification_turns": 2,
            "exhaustion_reason": "enough_information",
        },
        "authority": {
            "posture": "proposal_only",
            "owner_readiness_required": True,
            "owner_merge_required": True,
        },
    }


class ProposalContractTest(unittest.TestCase):
    def test_normalization_adds_stable_content_bound_id(self):
        from john_lomein_proposal import normalize_proposal

        first = normalize_proposal(sample_proposal())
        second = normalize_proposal(dict(reversed(list(sample_proposal().items()))))
        self.assertEqual(first, second)
        self.assertRegex(first["proposal_id"], r"^jl-proposal-[0-9a-f]{16}$")
        changed = sample_proposal()
        changed["scope"] = ["Different scope"]
        self.assertNotEqual(
            first["proposal_id"],
            normalize_proposal(changed)["proposal_id"],
        )

    def test_schema_is_strict_and_authority_cannot_be_relaxed(self):
        from john_lomein_proposal import ProposalError, normalize_proposal

        invalid = []
        extra = sample_proposal()
        extra["unexpected"] = True
        invalid.append(extra)
        wrong_authority = sample_proposal()
        wrong_authority["authority"]["owner_readiness_required"] = False
        invalid.append(wrong_authority)
        wrong_status = sample_proposal()
        wrong_status["dialogue"]["status"] = "KEEP_TALKING"
        invalid.append(wrong_status)
        too_many_questions = sample_proposal()
        too_many_questions["dialogue"]["clarification_turns"] = 13
        invalid.append(too_many_questions)
        for proposal in invalid:
            with self.subTest(proposal=proposal), self.assertRaises(ProposalError):
                normalize_proposal(proposal)

    def test_required_lists_cannot_be_empty_or_command_like(self):
        from john_lomein_proposal import ProposalError, normalize_proposal

        for field, value in (
            ("scope", []),
            ("success_signals", []),
            ("evidence_plan", ["/run an untrusted command"]),
        ):
            proposal = sample_proposal()
            proposal[field] = value
            with self.subTest(field=field), self.assertRaises(ProposalError):
                normalize_proposal(proposal)

    def test_markdown_is_public_facing_and_keeps_owner_boundaries(self):
        from john_lomein_proposal import normalize_proposal, render_proposal_markdown

        rendered = render_proposal_markdown(normalize_proposal(sample_proposal()))
        for heading in (
            "## Problem",
            "## Desired outcome",
            "## Scope",
            "## Success signals",
            "## Evidence plan",
            "## Authority",
        ):
            self.assertIn(heading, rendered)
        self.assertIn("does not mark the work ready", rendered)
        self.assertIn("owner alone may merge", rendered)
        self.assertNotIn("clarification_turns", rendered)

    def test_cli_validates_and_renders_without_mutating(self):
        script = SCRIPTS / "john_lomein_proposal.py"
        self.assertTrue(script.is_file(), f"missing proposal CLI: {script}")
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "proposal.json"
            source.write_text(json.dumps(sample_proposal()), encoding="utf-8")
            validate = subprocess.run(
                [sys.executable, str(script), "validate", "--input", str(source)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(validate.returncode, 0, validate.stderr)
            payload = json.loads(validate.stdout)
            self.assertTrue(payload["ok"])
            self.assertRegex(payload["proposal_id"], r"^jl-proposal-")
            render = subprocess.run(
                [sys.executable, str(script), "render", "--input", str(source)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(render.returncode, 0, render.stderr)
            self.assertIn("## Problem", render.stdout)


if __name__ == "__main__":
    unittest.main()
