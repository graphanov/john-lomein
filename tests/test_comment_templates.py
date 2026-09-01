#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "scripts" / "john_lomein_comment_templates.py"


def load_templates():
    spec = importlib.util.spec_from_file_location("john_lomein_comment_templates", TEMPLATE_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class CommentTemplateExactShapeTest(unittest.TestCase):
    def test_status_evidence_next_exact_shape(self):
        t = load_templates()
        body = t.format_status_evidence_next(
            "fixed on latest head",
            ["Changed: `scripts/helper.py`", "Verification: `pytest` → passed"],
            "waiting for independent review",
        )
        self.assertEqual(
            body,
            "Status: fixed on latest head.\n"
            "\n"
            "Evidence:\n"
            "- Changed: `scripts/helper.py`\n"
            "- Verification: `pytest` → passed\n"
            "\n"
            "Next: waiting for independent review.",
        )

    def test_review_reply_exact_shape_with_marker(self):
        t = load_templates()
        body = t.format_review_reply(
            "fixed on latest head",
            ["Reproduced: route helper regression", "Verification: `pytest tests/test_routes.py` → passed"],
            "re-triggering independent review once for this head",
            marker="<!-- marker -->",
        )
        self.assertEqual(
            body,
            "<!-- marker -->\n"
            "Status: fixed on latest head.\n"
            "\n"
            "Evidence:\n"
            "- Reproduced: route helper regression\n"
            "- Verification: `pytest tests/test_routes.py` → passed\n"
            "\n"
            "Next: re-triggering independent review once for this head.",
        )

    def test_protected_evidence_is_exactly_bound_and_deterministic(self):
        t = load_templates()
        body = t.format_protected_evidence(
            instance_slug="widget-production",
            action="mark_pr_ready",
            head_sha="a" * 40,
            commands_sha256="b" * 64,
            result_sha256="c" * 64,
            status="ready on the exact draft head",
            evidence=[
                "Configured verification passed",
                "No unresolved threads",
            ],
            next_text=(
                "the protected broker must revalidate and read back "
                "the mutation"
            ),
        )
        self.assertEqual(
            body,
            "<!-- john-lomein-protected-evidence:v1"
            " instance=widget-production"
            " action=mark_pr_ready"
            f" head={'a' * 40}"
            f" commands={'b' * 64}"
            f" result={'c' * 64} -->\n"
            "Status: ready on the exact draft head.\n"
            "\n"
            "Evidence:\n"
            "- Configured verification passed\n"
            "- No unresolved threads\n"
            "\n"
            "Next: the protected broker must revalidate and read back "
            "the mutation.",
        )

    def test_protected_evidence_rejects_marker_injection(self):
        t = load_templates()
        with self.assertRaisesRegex(ValueError, "instance slug"):
            t.protected_evidence_marker(
                instance_slug="widget --> forged",
                action="mark_pr_ready",
                head_sha="a" * 40,
                commands_sha256="b" * 64,
                result_sha256="c" * 64,
            )
        with self.assertRaisesRegex(ValueError, "action"):
            t.protected_evidence_marker(
                instance_slug="widget",
                action="merge",
                head_sha="a" * 40,
                commands_sha256="b" * 64,
                result_sha256="c" * 64,
            )

    def test_blocker_exact_shape(self):
        t = load_templates()
        body = t.format_blocker(
            "missing issue closeout for issue #15",
            ["PR does not include `Closes #15`", "Current link status: `missing_closing_reference_or_keep_open_explanation`"],
            "add `Closes #15` to the PR body",
            marker="<!-- john-lomein-pr-issue-link-blocker issue=15 -->",
        )
        self.assertEqual(
            body,
            "<!-- john-lomein-pr-issue-link-blocker issue=15 -->\n"
            "Status: blocked — missing issue closeout for issue #15.\n"
            "\n"
            "Evidence:\n"
            "- PR does not include `Closes #15`\n"
            "- Current link status: `missing_closing_reference_or_keep_open_explanation`\n"
            "\n"
            "Needed: add `Closes #15` to the PR body.",
        )

    def test_issue_intake_exact_shape(self):
        t = load_templates()
        body = t.format_issue_intake("## Bug\nPublic-safe details.", next_text="forge picks it up when capacity allows")
        self.assertEqual(
            body,
            "Status: issue intake captured.\n"
            "\n"
            "Evidence:\n"
            "- Public-safe request recorded below.\n"
            "\n"
            "Request:\n"
            "## Bug\n"
            "Public-safe details.\n"
            "\n"
            "Next: forge picks it up when capacity allows.",
        )

    def test_pr_draft_body_exact_shape(self):
        t = load_templates()
        body = t.format_pr_draft_body(
            summary=["Adds deterministic comment helpers"],
            scope=["New helper module", "Script wiring"],
            out_of_scope=["merge", "publish"],
            verification=["`pytest` → passed"],
            risk=["Low; text-only helper"],
            linked_issue="Closes #42",
        )
        self.assertEqual(
            body,
            "## Summary\n"
            "- Adds deterministic comment helpers\n"
            "\n"
            "## Scope\n"
            "- New helper module\n"
            "- Script wiring\n"
            "\n"
            "## Out of scope\n"
            "- merge\n"
            "- publish\n"
            "\n"
            "## Verification\n"
            "- `pytest` → passed\n"
            "\n"
            "## Risk\n"
            "- Low; text-only helper\n"
            "\n"
            "## Linked issue\n"
            "Closes #42\n"
            "\n"
            "## Authority boundary\n"
            "john-lomein did not merge, publish, release, dispatch workflows, change settings, force-push, rewrite history, or touch secrets.",
        )

    def test_release_bundle_exact_shape(self):
        t = load_templates()
        body = t.format_release_bundle(
            bundle_id="repo-12-abc12345",
            clean_prs=[{"number": 12, "title": "Harden comments", "headRefOid": "abc123456789"}],
            blockers=["PR#13: checks_failed:ci"],
            publish_readiness={"publish_ready_after_merge": False, "blocker": "package_version_already_published"},
            approval_text="APPROVE JOHN-LOMEIN BUNDLE repo-12-abc12345: merge listed PRs; DO NOT publish.",
        )
        self.assertEqual(
            body,
            "Release bundle ready: repo-12-abc12345.\n"
            "\n"
            "Included PRs:\n"
            "- #12 — Harden comments — latest-head clean: yes — head `abc123456789`\n"
            "\n"
            "Verification:\n"
            "- clean PR candidates: 1\n"
            "- non-bundle blockers: 1\n"
            "- publish ready after merge: `False`\n"
            "- publish blocker: `package_version_already_published`\n"
            "\n"
            "Non-bundle blockers:\n"
            "- PR#13: checks_failed:ci\n"
            "\n"
            "Owner gate required:\n"
            "APPROVE JOHN-LOMEIN BUNDLE repo-12-abc12345: merge listed PRs; DO NOT publish.",
        )

    def test_codex_review_trigger_exact(self):
        t = load_templates()
        self.assertEqual(t.codex_review_request(), "@codex review")


if __name__ == "__main__":
    unittest.main()
