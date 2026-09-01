#!/usr/bin/env python3
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_broker import john_lomein_release_broker_actions as actions
from tests.test_release_broker_protocol import (
    release_bundle,
    release_config,
)


HEAD = "b" * 40
BASE = "a" * 40
POTENTIAL_MERGE = "f" * 40
EXPECTED_TREE = "e" * 40
CODEX = "chatgpt-codex-connector[bot]"


def marker(verdict: str = "clean", head: str = HEAD) -> str:
    return (
        "<!-- john-lomein-release-review:v1 "
        f"head={head} verdict={verdict} -->"
    )


def policy() -> dict:
    return release_config(Path("/private/tmp/jl-release-test"))["instance"][
        "policy"
    ]


def snapshot() -> dict:
    return {
        "repository": "acme/widget",
        "repository_id": 987654,
        "repository_policy": {
            "is_archived": False,
            "is_disabled": False,
            "squash_merge_allowed": True,
        },
        "pr": {
            "id": "PR_17",
            "number": 17,
            "url": "https://github.com/acme/widget/pull/17",
            "state": "OPEN",
            "is_draft": False,
            "merged": False,
            "merged_at": None,
            "head_oid": HEAD,
            "base_branch": "main",
            "base_oid": BASE,
            "author_login": "john-lomein[bot]",
            "same_repository_head": True,
            "changed_files": 2,
            "mergeable": "MERGEABLE",
            "merge_state_status": "CLEAN",
            "review_decision": "APPROVED",
            "merge_commit_oid": None,
            "potential_merge_commit_oid": POTENTIAL_MERGE,
            "potential_merge_tree_oid": EXPECTED_TREE,
            "potential_merge_parent_oids": [BASE, HEAD],
            "auto_merge_requested": False,
            "merge_queue_entry_present": False,
            "merged_by_login": None,
        },
        "default_branch": {
            "name": "main",
            "qualified_name": "refs/heads/main",
            "commit": {
                "oid": BASE,
                "tree_oid": "c" * 40,
                "parent_oids": ["d" * 40],
                "committed_at": "2026-07-16T11:00:00Z",
                "author": {
                    "name": "A",
                    "email": "synthetic-author",
                    "date": "2026-07-16T11:00:00Z",
                    "github_login": "maintainer",
                },
                "committer": {
                    "name": "C",
                    "email": "synthetic-committer",
                    "date": "2026-07-16T11:00:00Z",
                    "github_login": "maintainer",
                },
            },
        },
        "files": [
            {
                "path": "src/widget.py",
                "additions": 4,
                "deletions": 1,
                "change_type": "MODIFIED",
            },
            {
                "path": "tests/test_widget.py",
                "additions": 8,
                "deletions": 0,
                "change_type": "ADDED",
            },
        ],
        "checks": [
            {
                "name": "CI / test",
                "status": "COMPLETED",
                "conclusion": "SUCCESS",
                "details_url": "https://github.com/acme/widget/actions/runs/1",
                "producer_app_id": 15368,
                "producer_slug": "github-actions",
            }
        ],
        "statuses": [],
        "review_threads": [],
        "issue_comments": [
            {
                "id": "IC_1",
                "database_id": 1,
                "url": (
                    "https://github.com/acme/widget/pull/17"
                    "#issuecomment-1"
                ),
                "body": marker(),
                "created_at": "2026-07-16T11:40:00Z",
                "updated_at": "2026-07-16T11:40:00Z",
                "author_login": CODEX,
            }
        ],
        "reviews": [],
        "unresolved_thread_count": 0,
        "unresolved_current_thread_count": 0,
        "exact_head_evidence": [],
        "minimum_rate_limit_remaining": 4500,
    }


class ReleaseBrokerActionsTest(unittest.TestCase):
    def test_exact_live_snapshot_produces_digest_bound_preflight(self):
        bundle = release_bundle()
        result = actions.validate_preflight(snapshot(), bundle, policy())
        self.assertEqual(result.pr_number, 17)
        self.assertEqual(result.head_sha, HEAD)
        self.assertEqual(result.expected_base_sha, BASE)
        self.assertEqual(
            result.expected_merge_tree_sha, EXPECTED_TREE
        )
        self.assertEqual(
            result.evidence["expected_merge_tree_sha"], EXPECTED_TREE
        )
        self.assertTrue(result.precondition_digest.startswith("sha256:"))
        self.assertEqual(result.codex_evidence.verdict, "clean")
        changed = snapshot()
        changed["minimum_rate_limit_remaining"] = 4499
        self.assertNotEqual(
            actions.validate_preflight(
                changed, bundle, policy()
            ).precondition_digest,
            result.precondition_digest,
        )

    def test_signed_expected_merge_tree_and_topology_fail_closed(self):
        cases = [
            (
                "tree",
                lambda value: value["pr"].update(
                    {"potential_merge_tree_oid": "9" * 40}
                ),
                "signed authority",
            ),
            (
                "parents",
                lambda value: value["pr"].update(
                    {"potential_merge_parent_oids": [HEAD, BASE]}
                ),
                "exact base and head",
            ),
        ]
        for label, mutate, message in cases:
            live = snapshot()
            mutate(live)
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    actions.ReleaseActionError, message
                ):
                    actions.validate_preflight(
                        live, release_bundle(), policy()
                    )

    def test_pr_repo_base_head_author_and_path_drift_fail_closed(self):
        cases = [
            ("repository", lambda value: value.update(
                {"repository_id": 1}
            )),
            ("head", lambda value: value["pr"].update(
                {"head_oid": "f" * 40}
            )),
            ("base", lambda value: value["default_branch"]["commit"].update(
                {"oid": "f" * 40}
            )),
            ("author", lambda value: value["pr"].update(
                {"author_login": "attacker"}
            )),
            ("path", lambda value: value["files"][0].update(
                {"path": "secrets.txt"}
            )),
        ]
        for label, mutate in cases:
            live = snapshot()
            mutate(live)
            with self.subTest(label=label):
                with self.assertRaises(actions.ReleaseActionError):
                    actions.validate_preflight(
                        live, release_bundle(), policy()
                    )

    def test_open_draft_same_repo_mergeability_and_competing_merge_fail(self):
        cases = [
            ("closed", {"state": "CLOSED"}),
            ("draft", {"is_draft": True}),
            ("fork", {"same_repository_head": False}),
            ("unknown", {"mergeable": "UNKNOWN"}),
            ("blocked", {"merge_state_status": "BLOCKED"}),
            ("auto", {"auto_merge_requested": True}),
            ("queue", {"merge_queue_entry_present": True}),
        ]
        for label, mutation in cases:
            live = snapshot()
            live["pr"].update(mutation)
            with self.subTest(label=label):
                with self.assertRaises(actions.ReleaseActionError):
                    actions.validate_preflight(
                        live, release_bundle(), policy()
                    )

    def test_repository_state_and_all_unresolved_threads_are_blocking(self):
        for field in ("is_archived", "is_disabled"):
            live = snapshot()
            live["repository_policy"][field] = True
            with self.subTest(field=field):
                with self.assertRaises(actions.ReleaseActionError):
                    actions.validate_preflight(
                        live, release_bundle(), policy()
                    )
        live = snapshot()
        live["repository_policy"]["squash_merge_allowed"] = False
        with self.assertRaisesRegex(
            actions.ReleaseActionError, "squash"
        ):
            actions.validate_preflight(
                live, release_bundle(), policy()
            )
        live = snapshot()
        live["unresolved_thread_count"] = 1
        live["unresolved_current_thread_count"] = 0
        with self.assertRaisesRegex(
            actions.ReleaseActionError, "unresolved"
        ):
            actions.validate_preflight(
                live, release_bundle(), policy()
            )

    def test_required_check_is_bound_to_numeric_app_identity_and_slug(self):
        for mutation in (
            {"producer_app_id": 999},
            {"producer_slug": "lookalike-actions"},
            {"status": "IN_PROGRESS", "conclusion": None},
            {"status": "COMPLETED", "conclusion": "FAILURE"},
        ):
            live = snapshot()
            live["checks"][0].update(mutation)
            with self.subTest(mutation=mutation):
                with self.assertRaises(actions.ReleaseActionError):
                    actions.validate_preflight(
                        live, release_bundle(), policy()
                    )

    def test_unconfigured_pending_or_failing_context_is_rejected(self):
        for extra in (
            {
                "name": "surprise",
                "status": "COMPLETED",
                "conclusion": "FAILURE",
                "producer_app_id": 1,
                "producer_slug": "other",
            },
            {
                "name": "surprise",
                "status": "IN_PROGRESS",
                "conclusion": None,
                "producer_app_id": 1,
                "producer_slug": "other",
            },
        ):
            live = snapshot()
            live["checks"].append(extra)
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(
                    actions.ReleaseActionError, "observed"
                ):
                    actions.validate_preflight(
                        live, release_bundle(), policy()
                    )

    def test_latest_trusted_structured_codex_verdict_controls_release(self):
        live = snapshot()
        live["issue_comments"].append(
            {
                "id": "IC_2",
                "url": "https://github.com/acme/widget/pull/17#issuecomment-2",
                "body": marker("changes_requested"),
                "created_at": "2026-07-16T11:50:00Z",
                "updated_at": "2026-07-16T11:50:00Z",
                "author_login": CODEX,
            }
        )
        with self.assertRaisesRegex(
            actions.ReleaseActionError, "adverse"
        ):
            actions.validate_preflight(
                live, release_bundle(), policy()
            )

        untrusted = snapshot()
        untrusted["issue_comments"][0]["author_login"] = "attacker"
        with self.assertRaisesRegex(
            actions.ReleaseActionError, "no trusted"
        ):
            actions.validate_preflight(
                untrusted, release_bundle(), policy()
            )
        abbreviated = snapshot()
        abbreviated["issue_comments"][0]["body"] = marker(
            head=HEAD[:12]
        )
        with self.assertRaisesRegex(
            actions.ReleaseActionError, "no trusted"
        ):
            actions.validate_preflight(
                abbreviated, release_bundle(), policy()
            )

    def test_current_codex_review_format_requires_github_full_head_binding(self):
        live = snapshot()
        live["issue_comments"] = []
        live["reviews"] = [
            {
                "id": "PRR_1",
                "url": "https://github.com/acme/widget/pull/17#pullrequestreview-1",
                "body": "Didn't find any major issues.",
                "state": "COMMENTED",
                "submitted_at": "2026-07-16T11:45:00Z",
                "author_login": CODEX,
                "commit_oid": HEAD,
            }
        ]
        result = actions.validate_preflight(
            live, release_bundle(), policy()
        )
        self.assertEqual(result.codex_evidence.verdict, "clean")

        live["reviews"][0]["commit_oid"] = HEAD[:12]
        with self.assertRaisesRegex(
            actions.ReleaseActionError, "no trusted"
        ):
            actions.validate_preflight(
                live, release_bundle(), policy()
            )
        live["reviews"][0]["commit_oid"] = HEAD
        live["reviews"][0]["body"] += (
            "\nHere are some automated review suggestions."
        )
        with self.assertRaisesRegex(
            actions.ReleaseActionError, "adverse"
        ):
            actions.validate_preflight(
                live, release_bundle(), policy()
            )

    def test_immediate_base_fence_detects_last_millisecond_advance(self):
        branch = snapshot()["default_branch"]
        actions.validate_immediate_base_fence(
            branch,
            expected_branch="main",
            expected_base_sha=BASE,
        )
        branch["commit"]["oid"] = "f" * 40
        with self.assertRaisesRegex(
            actions.ReleaseActionError, "changed immediately"
        ):
            actions.validate_immediate_base_fence(
                branch,
                expected_branch="main",
                expected_base_sha=BASE,
            )


if __name__ == "__main__":
    unittest.main()
