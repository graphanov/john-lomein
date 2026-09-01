#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
QUEUE_PATH = ROOT / "scripts" / "john-lomein-queue-health.py"


def review_policy_json(*, enabled: bool = False) -> str:
    source = {
        "schema_version": "john-lomein.review-quorum-policy.v1",
        "enabled": enabled,
        "required_roles": ["maintainer", "overwatch"],
        "require_tests": True,
        "require_codex": True,
        "minimum_human_reviews": 1,
        "human_reviewer_logins": ["RepoOwner"] if enabled else [],
    }
    canonical = json.dumps(source, sort_keys=True, separators=(",", ":")).encode()
    source["policy_sha256"] = "sha256:" + hashlib.sha256(canonical).hexdigest()
    return json.dumps(source, sort_keys=True, separators=(",", ":"))


def load_queue_health() -> Any:
    spec = importlib.util.spec_from_file_location("john_lomein_queue_health", QUEUE_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return cast(Any, mod)


def install_queue_env() -> Path:
    home = Path(os.environ.get("BOT_HERMES_HOME") or os.environ.get("HERMES_HOME") or (Path(tempfile.mkdtemp()) / "hermes"))
    scripts = home / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    vals = {
        "BOT_REPO": os.environ.get("BOT_REPO", "owner/repo"),
        "BOT_SLUG": os.environ.get("BOT_SLUG", "test"),
        "BOT_MUTATION_ENABLED": os.environ.get("BOT_MUTATION_ENABLED", "1"),
        "BOT_HERMES_HOME": str(home),
        "HERMES_HOME": str(home),
        "BOT_REVIEW_QUORUM_POLICY_JSON": os.environ.get(
            "BOT_REVIEW_QUORUM_POLICY_JSON",
            review_policy_json(),
        ),
    }
    for key in ["BOT_LOCAL", "BOT_DEFAULT_BRANCH", "BOT_READINESS_LABELS", "BOT_TRIAGE_NEEDED_LABEL", "BOT_OSC_PORTFOLIO_BRANCH_PREFIX"]:
        if os.environ.get(key):
            vals[key] = os.environ[key]
    (scripts / "john-lomein-instance.env").write_text("".join(f"{k}='{v}'\n" for k, v in vals.items()), encoding="utf-8")
    os.environ.update({"BOT_HERMES_HOME": str(home), "HERMES_HOME": str(home)})
    return home


class QueueHealthCoverageTest(unittest.TestCase):
    def test_load_env_refuses_forged_instance_env_selector(self):
        queue = load_queue_health()
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "hermes"
            expected = home / "scripts" / "john-lomein-instance.env"
            expected.parent.mkdir(parents=True, exist_ok=True)
            expected.write_text("BOT_REPO='owner/repo'\nBOT_OWNER_APPROVERS='real-owner'\n", encoding="utf-8")
            forged = Path(tmp) / "forged.env"
            forged.write_text("BOT_REPO='evil/repo'\nBOT_OWNER_APPROVERS='attacker'\n", encoding="utf-8")
            old_env = os.environ.copy()
            os.environ.clear()
            os.environ.update({"HERMES_HOME": str(home), "JOHN_LOMEIN_INSTANCE_ENV": str(forged)})
            try:
                with self.assertRaises(RuntimeError):
                    queue.load_env()
            finally:
                os.environ.clear()
                os.environ.update(old_env)

    def test_parse_env_file_does_not_seed_authority_from_caller_env(self):
        queue = load_queue_health()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "john-lomein-instance.env"
            path.write_text("BOT_REPO='owner/repo'\n", encoding="utf-8")
            old_env = os.environ.copy()
            os.environ["BOT_OWNER_APPROVERS"] = "attacker"
            try:
                vals = queue.parse_env_file(path)
            finally:
                os.environ.clear()
                os.environ.update(old_env)
            self.assertEqual(vals.get("BOT_REPO"), "owner/repo")
            self.assertNotIn("BOT_OWNER_APPROVERS", vals)

    def test_command_env_ignores_caller_auth_and_config(self):
        queue = load_queue_health()
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "hermes"
            gh_config = home / "profiles" / "john-lomein-maintainer" / "home" / ".config" / "gh"
            gh_config.mkdir(parents=True)
            old_env = os.environ.copy()
            os.environ.clear()
            os.environ.update({"BOT_HERMES_HOME": str(home), "GH_CONFIG_DIR": "/tmp/evil-gh", "GH_TOKEN": "evil", "PATH": "/tmp/evil-bin"})
            try:
                env = queue.command_env()
            finally:
                os.environ.clear()
                os.environ.update(old_env)
            self.assertEqual(env.get("GH_CONFIG_DIR"), str(gh_config))
            self.assertNotIn("GH_TOKEN", env)
            self.assertNotIn("/tmp/evil-bin", env.get("PATH", ""))

    def test_review_thread_summary_paginates_and_uses_latest_comment(self):
        queue = load_queue_health()
        calls: list[list[str]] = []

        def fake_gh_json(cmd, *, timeout=45):
            calls.append(cmd)
            if "cursor=page-2" in " ".join(cmd):
                return {
                    "data": {
                        "repository": {
                            "pullRequest": {
                                "reviewThreads": {
                                    "nodes": [
                                        {
                                            "id": "thread-101",
                                            "isResolved": False,
                                            "isOutdated": False,
                                            "path": "src/live.py",
                                            "line": 12,
                                            "originalLine": 11,
                                            "comments": {
                                                "nodes": [
                                                    {
                                                        "author": {
                                                            "login": "reviewer"
                                                        },
                                                        "body": "Latest unresolved observation",
                                                        "url": "https://example/thread-101",
                                                        "createdAt": "2026-07-16T00:00:00Z",
                                                    }
                                                ]
                                            },
                                        }
                                    ],
                                    "pageInfo": {
                                        "hasNextPage": False,
                                        "endCursor": None,
                                    },
                                }
                            }
                        }
                    }
                }
            return {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "nodes": [
                                    {
                                        "id": f"thread-{index}",
                                        "isResolved": True,
                                        "isOutdated": False,
                                        "comments": {"nodes": []},
                                    }
                                    for index in range(100)
                                ],
                                "pageInfo": {
                                    "hasNextPage": True,
                                    "endCursor": "page-2",
                                },
                            }
                        }
                    }
                }
            }

        old = queue.gh_json
        queue.gh_json = fake_gh_json
        try:
            result = queue.review_thread_summary("owner/repo", 42)
        finally:
            queue.gh_json = old
        self.assertEqual(result["total"], 101)
        self.assertEqual(result["unresolved"], 1)
        self.assertEqual(result["unresolved_current"], 1)
        self.assertEqual(
            result["samples"],
            [
                {
                    "path": "src/live.py",
                    "line": 12,
                    "author": "reviewer",
                    "url": "https://example/thread-101",
                    "body": "Latest unresolved observation",
                }
            ],
        )
        self.assertEqual(len(calls), 2)

    def test_review_thread_summary_fails_closed_on_cursor_loop(self):
        queue = load_queue_health()
        old = queue.gh_json
        queue.gh_json = lambda *args, **kwargs: {
            "data": {
                "repository": {
                    "pullRequest": {
                        "reviewThreads": {
                            "nodes": [],
                            "pageInfo": {
                                "hasNextPage": True,
                                "endCursor": "same-cursor",
                            },
                        }
                    }
                }
            }
        }
        try:
            with self.assertRaisesRegex(
                RuntimeError,
                "review_threads_pagination_cursor_invalid",
            ):
                queue.review_thread_summary("owner/repo", 42)
        finally:
            queue.gh_json = old

    def test_ready_issue_is_covered_by_open_pr_branch_or_body(self):
        queue = load_queue_health()
        issue = {"number": 35, "title": "lazyglm uninstall leaves AGENTS.md"}
        prs = [
            {
                "number": 36,
                "title": "fix(uninstall): clean up artifacts",
                "headRefName": "forge/issue-35-lazyglm-uninstall-leaves-agents-stale-gitignore-entry",
                "body": "Closes #35",
            }
        ]
        self.assertTrue(queue.issue_is_covered_by_pr(issue, prs))

    def test_unrelated_ready_issue_is_not_covered(self):
        queue = load_queue_health()
        issue = {"number": 35, "title": "lazyglm uninstall leaves AGENTS.md"}
        prs = [
            {
                "number": 36,
                "title": "fix(other): different issue",
                "headRefName": "forge/issue-12-other",
                "body": "Closes #12",
            }
        ]
        self.assertFalse(queue.issue_is_covered_by_pr(issue, prs))

    def test_receipt_reconciliation_drops_closed_issue(self):
        queue = load_queue_health()
        summaries = [
            {
                "run_id": "issue-15-cycle-1",
                "event": {"kind": "github_issue", "id": "issue#15"},
                "classification": "repair_due",
                "branch": "forge/issue-15",
                "head_sha": "a" * 12,
            }
        ]

        reconciled = queue.reconcile_receipt_summaries(
            summaries,
            open_issue_numbers=set(),
            open_pr_details=[],
            codex_pending_prs=[],
        )

        self.assertEqual(reconciled, [])

    def test_receipt_reconciliation_drops_stale_codex_state_after_owner_gate(self):
        queue = load_queue_health()
        summary = {
            "run_id": "issue-10-cycle-1",
            "event": {"kind": "github_issue", "id": "issue#10"},
            "classification": "codex_pending",
            "branch": "forge/issue-10",
            "head_sha": "abcdef123456",
        }
        live_pr = {
            "number": 12,
            "headRefName": "forge/issue-10",
            "headRefOid": "abcdef1234567890" + "0" * 24,
            "body": "Closes #10",
        }

        reconciled = queue.reconcile_receipt_summaries(
            [summary],
            open_issue_numbers={10},
            open_pr_details=[live_pr],
            codex_pending_prs=[],
        )

        self.assertEqual(reconciled, [])

    def test_receipt_reconciliation_keeps_only_exact_live_codex_head(self):
        queue = load_queue_health()
        current = {
            "run_id": "issue-10-cycle-2",
            "event": {"kind": "github_issue", "id": "issue#10"},
            "classification": "codex_pending",
            "branch": "forge/issue-10",
            "head_sha": "abcdef123456",
        }
        stale = dict(current, run_id="issue-10-cycle-1", head_sha="111111111111")
        live_pr = {
            "number": 12,
            "headRefName": "forge/issue-10",
            "headRefOid": "abcdef1234567890" + "0" * 24,
            "body": "Closes #10",
        }

        reconciled = queue.reconcile_receipt_summaries(
            [stale, current],
            open_issue_numbers={10},
            open_pr_details=[live_pr],
            codex_pending_prs=[12],
        )

        self.assertEqual(reconciled, [current])

    def test_receipt_reconciliation_drops_repair_state_owned_by_live_pr(self):
        queue = load_queue_health()
        summary = {
            "run_id": "issue-10-cycle-1",
            "event": {"kind": "github_issue", "id": "issue#10"},
            "classification": "repair_due",
            "branch": "forge/issue-10",
            "head_sha": "abcdef123456",
        }
        live_pr = {
            "number": 12,
            "headRefName": "forge/issue-10",
            "headRefOid": "abcdef1234567890" + "0" * 24,
            "body": "Closes #10",
        }

        reconciled = queue.reconcile_receipt_summaries(
            [summary],
            open_issue_numbers={10},
            open_pr_details=[live_pr],
            codex_pending_prs=[],
        )

        self.assertEqual(reconciled, [])

    def test_current_formal_codex_review_with_suggestions_is_not_clean_when_threads_are_clear(self):
        queue = load_queue_health()

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "issues/37/comments" in joined:
                return [{"user": {"login": "repo-owner"}, "body": "@Codex Review", "created_at": "2026-06-25T23:23:05Z"}]
            if "pulls/37/reviews" in joined:
                return [
                    {
                        "user": {"login": "chatgpt-codex-connector[bot]"},
                        "body": "### Codex Review\nDIDN'T FIND ANY MAJOR ISSUES.\n\nHere are some Automated Review Suggestions.\n\n**Reviewed commit:** `abcdef1234567890000000000000000000000000`",
                        "commit_id": "abcdef1234567890" + "0" * 24,
                        "submitted_at": "2026-06-25T23:24:00Z",
                    }
                ]
            return []

        old = queue.gh_json
        queue.gh_json = fake_gh_json
        try:
            status = queue.codex_review_status("owner/repo", 37, "abcdef1234567890" + "0" * 24)
        finally:
            queue.gh_json = old
        self.assertFalse(status["clean_current"])
        self.assertFalse(status["pending_trigger"])
        self.assertEqual(status["status"], "current_head_not_clean head=abcdef1234")

    def test_newer_suggestion_review_revokes_older_clean_queue_evidence(self):
        queue = load_queue_health()

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "issues/37/comments" in joined:
                return []
            if "pulls/37/reviews" in joined:
                return [
                    {
                        "user": {"login": "chatgpt-codex-connector[bot]"},
                        "body": "Didn't find any major issues.\n\nReviewed commit:** `abcdef1234567890000000000000000000000000`",
                        "commit_id": "abcdef1234567890" + "0" * 24,
                        "submitted_at": "2026-06-25T23:24:00Z",
                    },
                    {
                        "user": {"login": "chatgpt-codex-connector[bot]"},
                        "body": "### Codex Review\nDIDN'T FIND ANY MAJOR ISSUES.\n\nHere are some Automated Review Suggestions.\n\n**Reviewed commit:** `abcdef1234567890000000000000000000000000`",
                        "commit_id": "abcdef1234567890" + "0" * 24,
                        "submitted_at": "2026-06-25T23:25:00Z",
                    },
                ]
            return []

        old = queue.gh_json
        queue.gh_json = fake_gh_json
        try:
            status = queue.codex_review_status("owner/repo", 37, "abcdef1234567890" + "0" * 24)
        finally:
            queue.gh_json = old
        self.assertFalse(status["clean_current"])
        self.assertEqual(status["status"], "current_head_not_clean head=abcdef1234")

    def test_lookup_failure_blocks_codex_clean_queue_evidence(self):
        queue = load_queue_health()

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "issues/37/comments" in joined:
                return [
                    {
                        "user": {"login": "chatgpt-codex-connector[bot]"},
                        "body": "Didn't find any major issues.\n\nReviewed commit:** `abcdef1234567890000000000000000000000000`",
                        "created_at": "2026-06-25T23:24:00Z",
                    }
                ]
            if "pulls/37/reviews" in joined:
                raise RuntimeError("reviews down")
            return []

        old = queue.gh_json
        queue.gh_json = fake_gh_json
        try:
            status = queue.codex_review_status("owner/repo", 37, "abcdef1234567890" + "0" * 24)
        finally:
            queue.gh_json = old
        self.assertFalse(status["clean_current"])
        self.assertFalse(status["pending_trigger"])
        self.assertIn("lookup_failed", status["status"])

    def test_codex_login_uses_exact_trusted_identities(self):
        queue = load_queue_health()
        self.assertTrue(queue.codex_login("chatgpt-codex-connector"))
        self.assertTrue(queue.codex_login("chatgpt-codex-connector[bot]"))
        self.assertFalse(queue.codex_login("chatgpt-codex-connector-evil"))

    def test_prefixed_non_codex_login_does_not_count_as_clean(self):
        queue = load_queue_health()

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "issues/37/comments" in joined:
                return [
                    {
                        "user": {"login": "chatgpt-codex-connector-evil"},
                        "body": "Didn't find any major issues.\n\nReviewed commit:** `abcdef1234567890000000000000000000000000`",
                        "created_at": "2026-06-25T23:24:00Z",
                    }
                ]
            if "pulls/37/reviews" in joined:
                return []
            return []

        old = queue.gh_json
        queue.gh_json = fake_gh_json
        try:
            status = queue.codex_review_status("owner/repo", 37, "abcdef1234567890" + "0" * 24)
        finally:
            queue.gh_json = old
        self.assertFalse(status["clean_current"])
        self.assertEqual(status["status"], "missing_current head=abcdef1234")

    def test_stale_formal_codex_review_does_not_count_as_clean(self):
        queue = load_queue_health()

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "issues/37/comments" in joined:
                return []
            if "pulls/37/reviews" in joined:
                return [
                    {
                        "user": {"login": "chatgpt-codex-connector[bot]"},
                        "body": "### Codex Review\n**Reviewed commit:** `aaaaaa1111`",
                        "commit_id": "aaaaaa1111111111" + "0" * 24,
                        "submitted_at": "2026-06-25T23:24:00Z",
                    }
                ]
            return []

        old = queue.gh_json
        queue.gh_json = fake_gh_json
        try:
            status = queue.codex_review_status("owner/repo", 37, "bbbbbb2222222222" + "0" * 24)
        finally:
            queue.gh_json = old
        self.assertFalse(status["clean_current"])
        self.assertIn("stale_or_missing_current", status["status"])

    def test_clean_owner_gated_pr_is_owner_action_notification(self):
        queue = load_queue_health()
        head = "abcdef1234567890" + "0" * 24
        queue.load_role_review_receipts = lambda *args, **kwargs: []
        queue.evaluate_review_quorum = lambda **kwargs: {"merge_ready": True, "reasons": [], "quorum_sha256": "sha256:" + "q" * 64, "policy_sha256": "sha256:" + "p" * 64}

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "api graphql" in joined:
                return {"data": {"repository": {"pullRequest": {"reviewThreads": {"nodes": [], "pageInfo": {"hasNextPage": False, "endCursor": None}}}}}}
            if "pr list" in joined:
                return [{"number": 12}]
            if "pr view" in joined:
                return {
                    "number": 12,
                    "title": "Harden release lane",
                    "url": "https://example/pr/12",
                    "headRefName": "forge/issue-10",
                    "headRefOid": head,
                    "isDraft": False,
                    "mergeable": "MERGEABLE",
                    "mergeStateStatus": "CLEAN",
                    "reviewDecision": None,
                    "statusCheckRollup": [{"name": "ci", "status": "COMPLETED", "conclusion": "SUCCESS"}],
                    "latestReviews": [],
                    "updatedAt": "2026-06-29T00:00:00Z",
                    "body": "Closes #10",
                }
            if "issues/12/comments" in joined:
                return [
                    {
                        "user": {"login": "chatgpt-codex-connector[bot]"},
                        "body": "Didn't find any major issues.\n\nReviewed commit:** `abcdef1234567890000000000000000000000000`",
                        "created_at": "2026-06-29T00:01:00Z",
                    }
                ]
            if "pulls/12/reviews" in joined:
                return [{"id": 91, "state": "APPROVED", "commit_id": head, "submitted_at": "2026-06-29T00:02:00Z", "user": {"login": "RepoOwner"}}]
            if "issue list" in joined:
                return []
            return []

        old_gh_json = queue.gh_json
        old_argv = sys.argv[:]
        old_env = os.environ.copy()
        queue.gh_json = fake_gh_json
        sys.argv = ["john-lomein-queue-health.py", "--json"]
        os.environ.clear()
        os.environ.update({"BOT_REPO": "owner/repo", "BOT_SLUG": "test", "BOT_MUTATION_ENABLED": "1"})
        install_queue_env()
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                code = queue.main()
        finally:
            queue.gh_json = old_gh_json
            sys.argv = old_argv
            os.environ.clear()
            os.environ.update(old_env)
        self.assertEqual(code, 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["clean_candidates"], [12])
        self.assertEqual(data["merge_ready_evidence"][0]["head_sha"], head)
        self.assertEqual(data["merge_ready_evidence"][0]["pr"], 12)
        self.assertEqual(data["blockers"], 0)
        self.assertEqual(data["action_board"]["owner_action"]["clean_owner_gated_prs"], [12])
        self.assertEqual(data["factory_loops"]["owner_gate"], [{"id": 12, "kind": "pr"}])
        self.assertFalse(data["factory_loops"]["clean_idle"])
        self.assertTrue(data["notification"]["should_notify"])
        self.assertEqual(data["notification"]["classes"], ["owner_action"])

    def test_live_owner_gate_replaces_persisted_codex_pending_receipt(self):
        queue = load_queue_health()
        queue.load_role_review_receipts = lambda *args, **kwargs: []
        queue.evaluate_review_quorum = lambda **kwargs: {"merge_ready": True, "reasons": [], "quorum_sha256": "sha256:" + "q" * 64, "policy_sha256": "sha256:" + "p" * 64}

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "api graphql" in joined:
                return {"data": {"repository": {"pullRequest": {"reviewThreads": {"nodes": [], "pageInfo": {"hasNextPage": False, "endCursor": None}}}}}}
            if "pr list" in joined:
                return [{"number": 12}]
            if "pr view" in joined:
                return {
                    "number": 12,
                    "title": "Harden release lane",
                    "url": "https://example/pr/12",
                    "headRefName": "forge/issue-10",
                    "headRefOid": "abcdef1234567890" + "0" * 24,
                    "isDraft": False,
                    "mergeable": "MERGEABLE",
                    "mergeStateStatus": "CLEAN",
                    "reviewDecision": None,
                    "statusCheckRollup": [{"name": "ci", "status": "COMPLETED", "conclusion": "SUCCESS"}],
                    "latestReviews": [],
                    "updatedAt": "2026-06-29T00:00:00Z",
                    "body": "Closes #10",
                }
            if "issues/12/comments" in joined:
                return [
                    {
                        "user": {"login": "chatgpt-codex-connector[bot]"},
                        "body": "Didn't find any major issues.\n\nReviewed commit:** `abcdef1234567890000000000000000000000000`",
                        "created_at": "2026-06-29T00:01:00Z",
                    }
                ]
            if "pulls/12/reviews" in joined:
                return []
            if "issue list" in joined:
                return [
                    {
                        "number": 10,
                        "title": "Harden release lane",
                        "labels": [],
                        "updatedAt": "2026-06-29T00:00:00Z",
                        "body": "Discussion tracked by the open implementation PR.",
                    }
                ]
            return []

        old_gh_json = queue.gh_json
        old_argv = sys.argv[:]
        old_env = os.environ.copy()
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "hermes"
            os.environ.clear()
            os.environ.update(
                {
                    "BOT_REPO": "owner/repo",
                    "BOT_SLUG": "test",
                    "BOT_MUTATION_ENABLED": "1",
                    "BOT_HERMES_HOME": str(home),
                }
            )
            install_queue_env()
            receipt_dir = home / "state" / "forge-cycles" / "issue-10-cycle-1"
            receipt_dir.mkdir(parents=True)
            (receipt_dir / "factory-receipt.json").write_text(
                json.dumps(
                    {
                        "schema_version": "john-lomein.factory-receipt.v1",
                        "run_id": "issue-10-cycle-1",
                        "event": {"kind": "github_issue", "id": "issue#10"},
                        "loop": "forge",
                        "phase": "codex_handoff",
                        "classification": "codex_pending",
                        "evidence": {"branch": "forge/issue-10", "head_sha": "abcdef1234567890" + "0" * 24},
                        "verifier": {"verdict": "passed", "missing": []},
                        "next_action": {"class": "codex_pending", "action": "await_codex_review"},
                    }
                ),
                encoding="utf-8",
            )
            queue.gh_json = fake_gh_json
            sys.argv = ["john-lomein-queue-health.py", "--json"]
            try:
                out = io.StringIO()
                with redirect_stdout(out):
                    code = queue.main()
            finally:
                queue.gh_json = old_gh_json
                sys.argv = old_argv
                os.environ.clear()
                os.environ.update(old_env)

        self.assertEqual(code, 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["action_board"]["owner_action"]["clean_owner_gated_prs"], [12])
        self.assertEqual(data["factory_receipts"], [])
        self.assertEqual(data["factory_loops"]["codex_pending"], [])
        self.assertEqual(data["factory_loops"]["owner_gate"], [{"id": 12, "kind": "pr"}])
        self.assertEqual(data["notification"]["classes"], ["owner_action"])

    def test_codex_pending_pr_is_not_owner_action_notification(self):
        queue = load_queue_health()

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "api graphql" in joined:
                return {"data": {"repository": {"pullRequest": {"reviewThreads": {"nodes": [], "pageInfo": {"hasNextPage": False, "endCursor": None}}}}}}
            if "pr list" in joined:
                return [{"number": 13}]
            if "pr view" in joined:
                return {
                    "number": 13,
                    "title": "Wait for Codex",
                    "url": "https://example/pr/13",
                    "headRefName": "forge/issue-11",
                    "headRefOid": "bbbbbb1234567890" + "0" * 24,
                    "isDraft": False,
                    "mergeable": "MERGEABLE",
                    "mergeStateStatus": "CLEAN",
                    "reviewDecision": None,
                    "statusCheckRollup": [],
                    "latestReviews": [],
                    "updatedAt": "2026-06-29T00:00:00Z",
                    "body": "Closes #11",
                }
            if "issues/13/comments" in joined:
                return [{"user": {"login": "maintainer"}, "body": "@CODEX REVIEW", "created_at": "2026-06-29T00:02:00Z"}]
            if "pulls/13/reviews" in joined:
                return []
            if "issue list" in joined:
                return []
            return []

        old_gh_json = queue.gh_json
        old_argv = sys.argv[:]
        old_env = os.environ.copy()
        queue.gh_json = fake_gh_json
        sys.argv = ["john-lomein-queue-health.py", "--json"]
        os.environ.clear()
        os.environ.update({"BOT_REPO": "owner/repo", "BOT_SLUG": "test", "BOT_MUTATION_ENABLED": "1"})
        install_queue_env()
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                code = queue.main()
        finally:
            queue.gh_json = old_gh_json
            sys.argv = old_argv
            os.environ.clear()
            os.environ.update(old_env)
        self.assertEqual(code, 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["codex_pending_prs"], [13])
        self.assertEqual(data["action_board"]["codex_pending"]["prs"], [13])
        self.assertEqual(data["action_board"]["owner_action"], {})
        self.assertEqual(data["factory_loops"]["codex_pending"], [{"id": 13, "kind": "pr"}])
        self.assertEqual(data["factory_loops"]["owner_gate"], [])
        self.assertFalse(data["factory_loops"]["clean_idle"])
        self.assertFalse(data["notification"]["should_notify"])

    def test_portfolio_draft_pr_is_owner_gated_not_maintainer_work(self):
        queue = load_queue_health()

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "api graphql" in joined:
                return {"data": {"repository": {"pullRequest": {"reviewThreads": {"nodes": [], "pageInfo": {"hasNextPage": False, "endCursor": None}}}}}}
            if "pr list" in joined:
                return [{"number": 251}]
            if "pr view" in joined:
                return {
                    "number": 251,
                    "title": "docs(osc): add portfolio follow-up",
                    "url": "https://example/pr/251",
                    "headRefName": "portfolio/active-open-questions-d2a918602b",
                    "headRefOid": "abcdef1234567890" + "0" * 24,
                    "isDraft": True,
                    "mergeable": "MERGEABLE",
                    "mergeStateStatus": "CLEAN",
                    "reviewDecision": None,
                    "statusCheckRollup": [],
                    "latestReviews": [],
                    "updatedAt": "2026-07-07T00:00:00Z",
                    "body": "<!-- john-lomein-osc-gap: active-open-questions-d2a918602b -->",
                }
            if "issue list" in joined:
                return []
            raise AssertionError(f"unexpected gh call: {joined}")

        old_gh_json = queue.gh_json
        old_argv = sys.argv[:]
        old_env = os.environ.copy()
        queue.gh_json = fake_gh_json
        sys.argv = ["john-lomein-queue-health.py", "--json"]
        os.environ.clear()
        os.environ.update({
            "BOT_REPO": "owner/repo",
            "BOT_SLUG": "test",
            "BOT_MUTATION_ENABLED": "1",
            "BOT_OSC_PORTFOLIO_BRANCH_PREFIX": "portfolio/",
        })
        install_queue_env()
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                code = queue.main()
        finally:
            queue.gh_json = old_gh_json
            sys.argv = old_argv
            os.environ.clear()
            os.environ.update(old_env)
        self.assertEqual(code, 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["drafts"], [])
        self.assertEqual(data["codex_awaiting_prs"], [])
        self.assertEqual(data["portfolio_owner_gated_prs"], [251])
        self.assertEqual(data["action_board"]["owner_action"]["portfolio_owner_gated_prs"], [251])
        self.assertNotIn("draft_prs_needing_promotion_or_review", data["action_board"]["automation_blocker"])

    def test_ignored_open_issue_is_noise_not_notification(self):
        queue = load_queue_health()

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "pr list" in joined:
                return []
            if "issue list" in joined:
                return [
                    {
                        "number": 99,
                        "title": "Loose discussion",
                        "labels": [],
                        "updatedAt": "2026-06-29T00:00:00Z",
                        "body": "General discussion without an acceptance criteria section or readiness label.",
                    }
                ]
            return []

        old_gh_json = queue.gh_json
        old_argv = sys.argv[:]
        old_env = os.environ.copy()
        queue.gh_json = fake_gh_json
        sys.argv = ["john-lomein-queue-health.py", "--json"]
        os.environ.clear()
        os.environ.update({"BOT_REPO": "owner/repo", "BOT_SLUG": "test", "BOT_MUTATION_ENABLED": "1"})
        install_queue_env()
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                code = queue.main()
        finally:
            queue.gh_json = old_gh_json
            sys.argv = old_argv
            os.environ.clear()
            os.environ.update(old_env)
        self.assertEqual(code, 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["ignored_open_issues"], [99])
        self.assertEqual(data["action_board"]["ignored_noise"]["open_issues"], [99])
        self.assertEqual(data["blockers"], 0)
        self.assertEqual(data["details"], ["ok"])
        self.assertFalse(data["notification"]["should_notify"])
        self.assertEqual(data["factory_loops"]["ignored_noise"], [{"id": 99, "kind": "open_issue"}])
        self.assertTrue(data["factory_loops"]["clean_idle"])

    def test_queue_health_projects_persisted_roadmap_candidates_without_new_github_calls(self):
        queue = load_queue_health()

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "pr list" in joined or "issue list" in joined:
                return []
            raise AssertionError(f"unexpected GitHub call: {cmd}")

        old_gh_json = queue.gh_json
        old_argv = sys.argv[:]
        old_env = os.environ.copy()
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "hermes"
            os.environ.clear()
            os.environ.update({"BOT_REPO": "owner/repo", "BOT_SLUG": "test", "BOT_MUTATION_ENABLED": "1", "BOT_HERMES_HOME": str(home)})
            install_queue_env()
            receipt_path = home / "state/factory/portfolio-receipt.json"
            receipt_path.parent.mkdir(parents=True)
            receipt_path.write_text(
                json.dumps(
                    {
                        "schema_version": "john-lomein.factory-receipt.v1",
                        "run_id": "portfolio-test",
                        "event": {"kind": "roadmap_scan", "id": "osc-portfolio"},
                        "loop": "roadmap_portfolio",
                        "phase": "candidates_proposed",
                        "classification": "roadmap_candidate",
                        "evidence": {
                            "roadmap_candidates": [
                                {"gap_id": "folded-backlog-abc", "kind": "folded_backlog_unreconciled", "title": "Reconcile folded backlog", "confidence": "medium", "source_paths": [".osc/plans/backlog/164.md"]}
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            queue.gh_json = fake_gh_json
            sys.argv = ["john-lomein-queue-health.py", "--json"]
            try:
                out = io.StringIO()
                with redirect_stdout(out):
                    code = queue.main()
            finally:
                queue.gh_json = old_gh_json
                sys.argv = old_argv
                os.environ.clear()
                os.environ.update(old_env)

        self.assertEqual(code, 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["factory_loops"]["roadmap_candidates"][0]["gap_id"], "folded-backlog-abc")
        self.assertTrue(data["factory_loops"]["clean_idle"])

    def test_queue_health_projects_portfolio_mutation_lifecycle_receipts(self):
        queue = load_queue_health()

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "pr list" in joined or "issue list" in joined:
                return []
            raise AssertionError(f"unexpected GitHub call: {cmd}")

        cases = [
            ("mutation_pending", "in_progress", "in_progress"),
            ("applying", "in_progress", "in_progress"),
            ("blocked_partial", "repair_due", "repair_due"),
        ]
        for phase, classification, expected_bucket in cases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as tmp:
                old_gh_json = queue.gh_json
                old_argv = sys.argv[:]
                old_env = os.environ.copy()
                home = Path(tmp) / "hermes"
                os.environ.clear()
                os.environ.update({"BOT_REPO": "owner/repo", "BOT_SLUG": "test", "BOT_MUTATION_ENABLED": "1", "BOT_HERMES_HOME": str(home)})
                install_queue_env()
                receipt_path = home / "state/factory/portfolio-receipt.json"
                receipt_path.parent.mkdir(parents=True)
                receipt_path.write_text(
                    json.dumps(
                        {
                            "schema_version": "john-lomein.factory-receipt.v1",
                            "run_id": "portfolio-test",
                            "event": {"kind": "roadmap_scan", "id": "osc-portfolio"},
                            "loop": "roadmap_portfolio",
                            "phase": phase,
                            "classification": classification,
                            "evidence": {"roadmap_candidates": []},
                            "verifier": {"verdict": "pending" if classification == "in_progress" else "blocked", "missing": []},
                            "next_action": {"class": "automation", "action": "continue_or_repair_portfolio"},
                        }
                    ),
                    encoding="utf-8",
                )
                queue.gh_json = fake_gh_json
                sys.argv = ["john-lomein-queue-health.py", "--json"]
                try:
                    out = io.StringIO()
                    with redirect_stdout(out):
                        code = queue.main()
                finally:
                    queue.gh_json = old_gh_json
                    sys.argv = old_argv
                    os.environ.clear()
                    os.environ.update(old_env)

                self.assertEqual(code, 0)
                data = json.loads(out.getvalue())
                self.assertEqual(len(data["factory_loops"][expected_bucket]), 1)
                self.assertEqual(data["factory_loops"][expected_bucket][0]["event"]["id"], "osc-portfolio")
                self.assertFalse(data["factory_loops"]["clean_idle"])

    def test_unlabeled_acceptance_criteria_issue_is_reported_in_json_health(self):
        queue = load_queue_health()

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "pr list" in joined:
                return []
            if "issue list" in joined:
                return [
                    {
                        "number": 231,
                        "title": "Automate product repair",
                        "labels": [],
                        "updatedAt": "2026-06-26T00:00:00Z",
                        "body": "Status: proposed\n\nAcceptance criteria\n- Add deterministic automation\n- Add tests\n",
                    }
                ]
            return []

        old_gh_json = queue.gh_json
        old_argv = sys.argv[:]
        old_env = os.environ.copy()
        queue.gh_json = fake_gh_json
        sys.argv = ["john-lomein-queue-health.py", "--json"]
        os.environ.clear()
        os.environ.update({"BOT_REPO": "owner/repo", "BOT_SLUG": "test", "BOT_MUTATION_ENABLED": "1"})
        install_queue_env()
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                code = queue.main()
        finally:
            queue.gh_json = old_gh_json
            sys.argv = old_argv
            os.environ.clear()
            os.environ.update(old_env)
        self.assertEqual(code, 1)
        data = json.loads(out.getvalue())
        self.assertEqual(data["ready_issues"], [])
        self.assertEqual(data["blockers"], 1)
        self.assertEqual(data["untriaged_actionable_issues"], [231])
        self.assertEqual(data["action_board"]["owner_action"]["triage_actionable"]["untriaged_actionable_issues"], [231])
        self.assertTrue(data["notification"]["should_notify"])
        self.assertIn("untriaged_actionable_issues=[231]", " | ".join(data["details"]))

    def test_ready_issue_with_open_dependency_is_not_reported_ready(self):
        queue = load_queue_health()

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "pr list" in joined:
                return []
            if "issue list" in joined:
                return [
                    {
                        "number": 28,
                        "title": "Phase 1 build pipeline",
                        "labels": [{"name": "ready-for-implementation"}],
                        "updatedAt": "2026-06-26T00:00:00Z",
                        "body": "tracking issue still open",
                    },
                    {
                        "number": 50,
                        "title": "Phase 2 conversion",
                        "labels": [{"name": "ready-for-implementation"}],
                        "updatedAt": "2026-06-26T00:05:00Z",
                        "body": "## Depends on\n- #28 must land first\n\n## Acceptance criteria\n- Convert modules\n",
                    },
                ]
            return []

        old_gh_json = queue.gh_json
        old_argv = sys.argv[:]
        old_env = os.environ.copy()
        queue.gh_json = fake_gh_json
        sys.argv = ["john-lomein-queue-health.py", "--json"]
        os.environ.clear()
        os.environ.update({"BOT_REPO": "owner/repo", "BOT_SLUG": "test", "BOT_MUTATION_ENABLED": "1"})
        install_queue_env()
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                code = queue.main()
        finally:
            queue.gh_json = old_gh_json
            sys.argv = old_argv
            os.environ.clear()
            os.environ.update(old_env)
        self.assertEqual(code, 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["ready_issues"], [28])
        self.assertEqual(data["dependency_blocked_issues"], [{"depends_on": [28], "issue": 50}])
        self.assertEqual(data["satisfied_dependency_issues"], [])
        self.assertEqual(data["blockers"], 0)

    def test_open_dependency_satisfied_by_merged_pr_unblocks_followup_issue(self):
        queue = load_queue_health()

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "pr list" in joined and "--state merged" in joined:
                return [
                    {
                        "number": 55,
                        "title": "build(ts): add Phase 1 TypeScript build pipeline",
                        "headRefName": "forge/issue-28-ts-build-pipeline-phase1",
                        "body": "Refs #28",
                        "mergedAt": "2026-06-28T20:19:50Z",
                        "url": "https://example/pr/55",
                    }
                ]
            if "pr list" in joined:
                return []
            if "issue list" in joined:
                return [
                    {
                        "number": 28,
                        "title": "Phase 1 build pipeline",
                        "labels": [{"name": "enhancement"}],
                        "updatedAt": "2026-06-28T20:37:49Z",
                        "body": "Phase 1 tracking issue still open after PR #55 merged.",
                    },
                    {
                        "number": 50,
                        "title": "Phase 2 conversion",
                        "labels": [{"name": "ready-for-implementation"}],
                        "updatedAt": "2026-06-28T20:20:20Z",
                        "body": "## Depends on\n- #28 must land first\n\n## Acceptance criteria\n- Convert modules\n",
                    },
                ]
            return []

        old_gh_json = queue.gh_json
        old_argv = sys.argv[:]
        old_env = os.environ.copy()
        queue.gh_json = fake_gh_json
        sys.argv = ["john-lomein-queue-health.py", "--json"]
        os.environ.clear()
        os.environ.update({"BOT_REPO": "owner/repo", "BOT_SLUG": "test", "BOT_MUTATION_ENABLED": "1"})
        install_queue_env()
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                code = queue.main()
        finally:
            queue.gh_json = old_gh_json
            sys.argv = old_argv
            os.environ.clear()
            os.environ.update(old_env)
        self.assertEqual(code, 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["ready_issues"], [50])
        self.assertEqual(data["dependency_blocked_issues"], [])
        self.assertEqual(data["satisfied_dependency_issues"], [{"issue": 50, "satisfied_by": [{"issue": 28, "prs": [55]}]}])
        self.assertEqual(data["ignored_open_issues"], [28])
        self.assertEqual(data["action_board"]["ignored_noise"]["open_issues"], [28])
        self.assertFalse(data["notification"]["should_notify"])

    def test_dirty_default_checkout_is_reported_as_blocker(self):
        queue = load_queue_health()

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "pr list" in joined or "issue list" in joined:
                return []
            return []

        def fake_run(cmd, *, timeout=45, cwd=None):
            if cmd[:3] == ["git", "status", "--short"]:
                return 0, "## main...origin/main\n M scripts/example.py", ""
            return 0, "", ""

        old_gh_json = queue.gh_json
        old_run = queue.run
        old_argv = sys.argv[:]
        old_env = os.environ.copy()
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / "repo"
            (local / ".git").mkdir(parents=True)
            queue.gh_json = fake_gh_json
            queue.run = fake_run
            sys.argv = ["john-lomein-queue-health.py", "--json"]
            os.environ.clear()
            os.environ.update(
                {
                    "BOT_REPO": "owner/repo",
                    "BOT_SLUG": "test",
                    "BOT_MUTATION_ENABLED": "1",
                    "BOT_LOCAL": str(local),
                    "BOT_DEFAULT_BRANCH": "main",
                    "BOT_HERMES_HOME": str(Path(tmp) / "hermes"),
                }
            )
            install_queue_env()
            try:
                out = io.StringIO()
                with redirect_stdout(out):
                    code = queue.main()
            finally:
                queue.gh_json = old_gh_json
                queue.run = old_run
                sys.argv = old_argv
                os.environ.clear()
                os.environ.update(old_env)
        self.assertEqual(code, 1)
        data = json.loads(out.getvalue())
        self.assertEqual(data["blockers"], 1)
        self.assertIn("managed_checkout_dirty_default_branch", " | ".join(data["details"]))
        self.assertIn("do_not_reset_or_delete", " | ".join(data["details"]))

    def test_dirty_prefix_branch_is_not_reported_as_default_branch(self):
        queue = load_queue_health()

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "pr list" in joined or "issue list" in joined:
                return []
            return []

        def fake_run(cmd, *, timeout=45, cwd=None):
            if cmd[:3] == ["git", "status", "--short"]:
                return 0, "## main-fix...origin/main-fix\n M scripts/example.py", ""
            return 0, "", ""

        old_gh_json = queue.gh_json
        old_run = queue.run
        old_argv = sys.argv[:]
        old_env = os.environ.copy()
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / "repo"
            (local / ".git").mkdir(parents=True)
            queue.gh_json = fake_gh_json
            queue.run = fake_run
            sys.argv = ["john-lomein-queue-health.py", "--json"]
            os.environ.clear()
            os.environ.update(
                {
                    "BOT_REPO": "owner/repo",
                    "BOT_SLUG": "test",
                    "BOT_MUTATION_ENABLED": "1",
                    "BOT_LOCAL": str(local),
                    "BOT_DEFAULT_BRANCH": "main",
                    "BOT_HERMES_HOME": str(Path(tmp) / "hermes"),
                }
            )
            install_queue_env()
            try:
                out = io.StringIO()
                with redirect_stdout(out):
                    code = queue.main()
            finally:
                queue.gh_json = old_gh_json
                queue.run = old_run
                sys.argv = old_argv
                os.environ.clear()
                os.environ.update(old_env)
        self.assertEqual(code, 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["blockers"], 0)
        self.assertEqual(data["details"], ["ok"])

    def test_recent_blocked_forge_cycle_is_reported_as_blocker(self):
        queue = load_queue_health()

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "pr list" in joined:
                return []
            if "issue list" in joined:
                return [
                    {
                        "number": 77,
                        "title": "Ready implementation",
                        "labels": [{"name": "ready-for-implementation"}],
                        "updatedAt": "2026-06-29T00:00:00Z",
                        "body": "Acceptance criteria\n- Produce a draft PR\n",
                    }
                ]
            return []

        old_gh_json = queue.gh_json
        old_argv = sys.argv[:]
        old_env = os.environ.copy()
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "hermes"
            cycle = home / "state" / "forge-cycles" / "issue-77-20260629T000000Z"
            cycle.mkdir(parents=True)
            (cycle / "blocked.json").write_text(
                json.dumps(
                    {
                        "schema_version": "john_lomein_forge_blocked_cycle/v1",
                        "stage": "implementation",
                        "issue": 77,
                        "branch": "forge/issue-77-ready",
                        "status": "BLOCKED",
                        "reasons": ["no_open_pr_for_branch"],
                    }
                ),
                encoding="utf-8",
            )
            setattr(queue, "gh_json", fake_gh_json)
            sys.argv = ["john-lomein-queue-health.py", "--json"]
            os.environ.clear()
            os.environ.update({"BOT_REPO": "owner/repo", "BOT_SLUG": "test", "BOT_MUTATION_ENABLED": "1", "BOT_HERMES_HOME": str(home)})
            install_queue_env()
            try:
                out = io.StringIO()
                with redirect_stdout(out):
                    code = queue.main()
            finally:
                setattr(queue, "gh_json", old_gh_json)
                sys.argv = old_argv
                os.environ.clear()
                os.environ.update(old_env)
        self.assertEqual(code, 1)
        data = json.loads(out.getvalue())
        self.assertEqual(data["ready_issues"], [77])
        self.assertEqual(data["blockers"], 1)
        self.assertEqual(len(data["blocked_forge_cycles"]), 1)
        self.assertIn("blocked_forge_cycle issue=77", data["blocked_forge_cycles"][0])
        self.assertNotEqual(data["details"], ["ok"])

    def test_newer_complete_forge_cycle_suppresses_older_blocked_cycle(self):
        queue = load_queue_health()

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "pr list" in joined:
                return []
            if "issue list" in joined:
                return [
                    {
                        "number": 77,
                        "title": "Ready implementation",
                        "labels": [{"name": "ready-for-implementation"}],
                        "updatedAt": "2026-06-29T00:00:00Z",
                        "body": "Acceptance criteria\n- Produce a draft PR\n",
                    }
                ]
            return []

        old_gh_json = getattr(queue, "gh_json")
        old_argv = sys.argv[:]
        old_env = os.environ.copy()
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "hermes"
            old_cycle = home / "state" / "forge-cycles" / "issue-77-old-blocked"
            new_cycle = home / "state" / "forge-cycles" / "issue-77-new-complete"
            old_cycle.mkdir(parents=True)
            new_cycle.mkdir(parents=True)
            (old_cycle / "blocked.json").write_text(
                json.dumps(
                    {
                        "schema_version": "john_lomein_forge_blocked_cycle/v1",
                        "stage": "implementation",
                        "issue": 77,
                        "branch": "forge/issue-77-ready",
                        "status": "BLOCKED",
                        "reasons": ["no_open_pr_for_branch"],
                    }
                ),
                encoding="utf-8",
            )
            (new_cycle / "summary.json").write_text(
                json.dumps({"issue": 77, "branch": "forge/issue-77-ready", "implement_status": "COMPLETE"}),
                encoding="utf-8",
            )
            (new_cycle / "factory-receipt.json").write_text(
                json.dumps(
                    {
                        "schema_version": "john-lomein.factory-receipt.v1",
                        "run_id": "issue-77-new-complete",
                        "event": {"kind": "github_issue", "id": "issue#77"},
                        "loop": "forge",
                        "phase": "complete",
                        "classification": "codex_pending",
                        "evidence": {"branch": "forge/issue-77-ready", "verifier_provenance": "live_verifier_commands", "commands_executed": True},
                        "done_authority": "john-lomein-verifier",
                        "verifier": {
                            "verdict": "passed",
                            "missing": [],
                            "checks": [
                                {"name": name, "passed": True}
                                for name in [
                                    "process_exit_zero",
                                    "executor_did_not_report_blocked",
                                    "open_pr_exact_branch",
                                    "draft_pr",
                                    "issue_link_present",
                                    "pr_head_present",
                                    "isolated_worktree",
                                    "worktree_exact_branch",
                                    "worktree_head_present",
                                    "worktree_head_stable",
                                    "worktree_clean",
                                    "pr_head_matches_worktree",
                                    "changed_files_present",
                                    "diff_check_passed",
                                    "configured_test_present",
                                    "configured_test_passed",
                                    "verifier_sandbox_enforced",
                                    "live_verifier_evidence",
                                    "codex_review_handoff_recorded",
                                ]
                            ],
                        },
                        "next_action": {"class": "codex_pending", "action": "await_independent_codex_review"},
                    }
                ),
                encoding="utf-8",
            )
            now = time.time()
            os.utime(old_cycle, (now - 10, now - 10))
            os.utime(new_cycle, (now, now))
            setattr(queue, "gh_json", fake_gh_json)
            sys.argv = ["john-lomein-queue-health.py", "--json"]
            os.environ.clear()
            os.environ.update({"BOT_REPO": "owner/repo", "BOT_SLUG": "test", "BOT_MUTATION_ENABLED": "1", "BOT_HERMES_HOME": str(home)})
            install_queue_env()
            try:
                out = io.StringIO()
                with redirect_stdout(out):
                    code = queue.main()
            finally:
                setattr(queue, "gh_json", old_gh_json)
                sys.argv = old_argv
                os.environ.clear()
                os.environ.update(old_env)
        self.assertEqual(code, 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["ready_issues"], [77])
        self.assertEqual(data["blocked_forge_cycles"], [])
        self.assertEqual(data["details"], ["ok"])

    def test_bare_legacy_complete_cycle_is_not_verifier_owned_completion(self):
        queue = load_queue_health()
        with tempfile.TemporaryDirectory() as tmp:
            cycle = Path(tmp) / "issue-77-legacy-complete"
            cycle.mkdir()
            (cycle / "summary.json").write_text(
                json.dumps({"issue": 77, "branch": "forge/issue-77-ready", "implement_status": "COMPLETE"}),
                encoding="utf-8",
            )
            (cycle / "factory-receipt.json").write_text(
                json.dumps(
                    {
                        "schema_version": "john-lomein.factory-receipt.v1",
                        "done_authority": "john-lomein-verifier",
                        "verifier": {"verdict": "passed", "missing": [], "checks": []},
                    }
                ),
                encoding="utf-8",
            )

            issue, alert, state = queue.blocked_cycle_state_from_dir(cycle, {77})

            self.assertEqual(issue, 77)
            self.assertEqual(state, "blocked")
            self.assertIn("legacy_complete_without_verifier", alert)

    def test_blocked_forge_cycle_for_ready_issue_covered_by_pr_is_not_reported(self):
        queue = load_queue_health()

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "api graphql" in joined:
                return {"data": {"repository": {"pullRequest": {"reviewThreads": {"nodes": [], "pageInfo": {"hasNextPage": False, "endCursor": None}}}}}}
            if "pr list" in joined:
                return [{"number": 88}]
            if "pr view" in joined:
                return {
                    "number": 88,
                    "title": "Implement ready issue",
                    "headRefName": "forge/issue-77-ready",
                    "headRefOid": "abcdef1234567890" + "0" * 24,
                    "isDraft": True,
                    "mergeable": "UNKNOWN",
                    "mergeStateStatus": "UNKNOWN",
                    "statusCheckRollup": [],
                    "latestReviews": [],
                    "body": "Closes #77",
                }
            if "issue list" in joined:
                return [
                    {
                        "number": 77,
                        "title": "Ready implementation",
                        "labels": [{"name": "ready-for-implementation"}],
                        "updatedAt": "2026-06-29T00:00:00Z",
                        "body": "Acceptance criteria\n- Produce a draft PR\n",
                    }
                ]
            return []

        old_gh_json = getattr(queue, "gh_json")
        old_argv = sys.argv[:]
        old_env = os.environ.copy()
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "hermes"
            cycle = home / "state" / "forge-cycles" / "issue-77-20260629T000000Z"
            cycle.mkdir(parents=True)
            (cycle / "blocked.json").write_text(
                json.dumps(
                    {
                        "schema_version": "john_lomein_forge_blocked_cycle/v1",
                        "stage": "implementation",
                        "issue": 77,
                        "branch": "forge/issue-77-ready",
                        "status": "BLOCKED",
                        "reasons": ["no_open_pr_for_branch"],
                    }
                ),
                encoding="utf-8",
            )
            setattr(queue, "gh_json", fake_gh_json)
            sys.argv = ["john-lomein-queue-health.py", "--json"]
            os.environ.clear()
            os.environ.update({"BOT_REPO": "owner/repo", "BOT_SLUG": "test", "BOT_MUTATION_ENABLED": "1", "BOT_HERMES_HOME": str(home)})
            install_queue_env()
            try:
                out = io.StringIO()
                with redirect_stdout(out):
                    code = queue.main()
            finally:
                setattr(queue, "gh_json", old_gh_json)
                sys.argv = old_argv
                os.environ.clear()
                os.environ.update(old_env)
        self.assertEqual(code, 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["covered_ready_issues"], [77])
        self.assertEqual(data["blocked_forge_cycles"], [])
        self.assertEqual(data["details"], ["ok"])

    def test_blocked_forge_cycle_for_closed_or_absent_issue_is_not_reported(self):
        queue = load_queue_health()

        def fake_gh_json(cmd, *, timeout=45):
            joined = " ".join(cmd)
            if "pr list" in joined or "issue list" in joined:
                return []
            return []

        old_gh_json = queue.gh_json
        old_argv = sys.argv[:]
        old_env = os.environ.copy()
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "hermes"
            cycle = home / "state" / "forge-cycles" / "issue-77-20260629T000000Z"
            cycle.mkdir(parents=True)
            (cycle / "blocked.json").write_text(
                json.dumps(
                    {
                        "schema_version": "john_lomein_forge_blocked_cycle/v1",
                        "stage": "implementation",
                        "issue": 77,
                        "branch": "forge/issue-77-ready",
                        "status": "BLOCKED",
                        "reasons": ["no_open_pr_for_branch"],
                    }
                ),
                encoding="utf-8",
            )
            setattr(queue, "gh_json", fake_gh_json)
            sys.argv = ["john-lomein-queue-health.py", "--json"]
            os.environ.clear()
            os.environ.update({"BOT_REPO": "owner/repo", "BOT_SLUG": "test", "BOT_MUTATION_ENABLED": "1", "BOT_HERMES_HOME": str(home)})
            install_queue_env()
            try:
                out = io.StringIO()
                with redirect_stdout(out):
                    code = queue.main()
            finally:
                setattr(queue, "gh_json", old_gh_json)
                sys.argv = old_argv
                os.environ.clear()
                os.environ.update(old_env)
        self.assertEqual(code, 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["blocked_forge_cycles"], [])
        self.assertEqual(data["details"], ["ok"])


if __name__ == "__main__":
    unittest.main()
