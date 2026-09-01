#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_broker import john_lomein_release_broker_protocol as broker_protocol

BUNDLER_PATH = ROOT / "scripts" / "john-lomein-release-bundler.py"
OWNER_ACTIONS_PATH = ROOT / "scripts" / "john_lomein_owner_actions.py"

SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40
SHA_D = "d" * 40
CODEX_HEAD = "abcdef1234567890abcdef1234567890abcdef12"
CREATED = "2026-07-16T10:00:00Z"
EXPIRES = "2026-07-16T11:00:00Z"
V5_ROOT_FIELDS = {
    "schema_version",
    "bundle_id",
    "bundle_digest",
    "instance_slug",
    "repository",
    "created_at",
    "expires_at",
    "initial_base_sha",
    "merge_method",
    "publish",
    "train_attestation_digest",
    "actions",
    "ordered_prs",
}
V5_PR_FIELDS = {
    "position",
    "number",
    "url",
    "head_sha",
    "expected_merge_tree_sha",
    "base_branch",
    "author_login",
    "changed_paths",
    "changed_paths_digest",
    "changed_path_count",
    "risk_class",
    "review_quorum_sha256",
    "review_quorum_policy_sha256",
}


def load_bundler():
    spec = importlib.util.spec_from_file_location(
        "john_lomein_release_bundler",
        BUNDLER_PATH,
    )
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return cast(Any, mod)


def load_owner_actions():
    spec = importlib.util.spec_from_file_location(
        "john_lomein_owner_actions_v5_test",
        OWNER_ACTIONS_PATH,
    )
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return cast(Any, mod)


def make_env(home: Path | str = "/tmp/john-lomein-test-hermes") -> dict[str, str]:
    policy = {
        "schema_version": "john-lomein.review-quorum-policy.v1",
        "enabled": False,
        "required_roles": ["maintainer", "overwatch"],
        "require_tests": True,
        "require_codex": True,
        "minimum_human_reviews": 1,
        "human_reviewer_logins": [],
    }
    raw = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    policy["policy_sha256"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    return {
        "BOT_REPO": "owner/repo",
        "BOT_REPO_ID": "123456",
        "BOT_DEFAULT_BRANCH": "main",
        "BOT_HERMES_HOME": str(home),
        "HERMES_HOME": str(home),
        "BOT_SLUG": "repo",
        "BOT_REVIEW_QUORUM_POLICY_JSON": json.dumps(
            policy, sort_keys=True, separators=(",", ":")
        ),
    }


def clean_pr(
    number: int,
    *,
    head: str = SHA_A,
    paths: list[str] | None = None,
    author: str = "maintainer",
    expected_merge_tree_sha: str = SHA_D,
) -> dict[str, Any]:
    return {
        "number": number,
        "title": f"Ready PR {number}",
        "url": f"https://github.com/owner/repo/pull/{number}",
        "headRefOid": head,
        "expected_merge_tree_sha": expected_merge_tree_sha,
        "baseRefName": "main",
        "baseRefOid": SHA_B,
        "author": {"login": author},
        "changed_paths": list(paths or ["src/a.py"]),
        "review_quorum": {
            "head_sha": head,
            "policy_sha256": "sha256:" + "b" * 64,
            "quorum_sha256": "sha256:" + "c" * 64,
        },
    }


class ReleaseBundlerReviewGateTest(unittest.TestCase):
    def test_load_env_refuses_forged_instance_env_selector(self):
        bundler = load_bundler()
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "hermes"
            expected = home / "scripts" / "john-lomein-instance.env"
            expected.parent.mkdir(parents=True, exist_ok=True)
            expected.write_text(
                "BOT_REPO='owner/repo'\nBOT_OWNER_APPROVERS='real-owner'\n",
                encoding="utf-8",
            )
            forged = Path(tmp) / "forged.env"
            forged.write_text(
                "BOT_REPO='evil/repo'\nBOT_OWNER_APPROVERS='attacker'\n",
                encoding="utf-8",
            )
            old_env = os.environ.copy()
            os.environ.clear()
            os.environ.update(
                {
                    "HERMES_HOME": str(home),
                    "JOHN_LOMEIN_INSTANCE_ENV": str(forged),
                }
            )
            try:
                with self.assertRaises(RuntimeError):
                    bundler.load_env()
            finally:
                os.environ.clear()
                os.environ.update(old_env)

    def test_parse_env_does_not_seed_authority_from_caller_env(self):
        bundler = load_bundler()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "john-lomein-instance.env"
            path.write_text("BOT_REPO='owner/repo'\n", encoding="utf-8")
            old_env = os.environ.copy()
            os.environ["BOT_OWNER_APPROVERS"] = "attacker"
            try:
                vals = bundler.parse_env(path)
            finally:
                os.environ.clear()
                os.environ.update(old_env)
            self.assertEqual(vals.get("BOT_REPO"), "owner/repo")
            self.assertNotIn("BOT_OWNER_APPROVERS", vals)

    def test_gh_env_ignores_caller_auth_and_config(self):
        bundler = load_bundler()
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "hermes"
            gh_config = (
                home
                / "profiles"
                / "john-lomein-maintainer"
                / "home"
                / ".config"
                / "gh"
            )
            gh_config.mkdir(parents=True)
            old_env = os.environ.copy()
            os.environ.clear()
            os.environ.update(
                {
                    "GH_CONFIG_DIR": "/tmp/evil-gh",
                    "GH_TOKEN": "evil",
                    "PATH": "/tmp/evil-bin",
                }
            )
            try:
                env = bundler.gh_env(
                    {
                        "BOT_HERMES_HOME": str(home),
                        "BOT_MAINTAINER_PROFILE": "john-lomein-maintainer",
                    }
                )
            finally:
                os.environ.clear()
                os.environ.update(old_env)
            self.assertEqual(env.get("GH_CONFIG_DIR"), str(gh_config))
            self.assertNotIn("GH_TOKEN", env)
            self.assertNotIn("/tmp/evil-bin", env.get("PATH", ""))

    def run_candidate_case(
        self,
        pr_number: int,
        comments: list[dict],
        reviews: list[dict],
        *,
        review_decision: str | None = None,
        fail_lookup: str = "",
    ):
        bundler = load_bundler()

        def fake_gh_json(cmd, *, env=None, timeout=60):
            joined = " ".join(cmd)
            if "ReleaseBundlerPotentialMerge" in joined:
                return {
                    "data": {
                        "repository": {
                            "databaseId": 123456,
                            "nameWithOwner": "owner/repo",
                            "pullRequest": {
                                "number": pr_number,
                                "headRefOid": CODEX_HEAD,
                                "baseRefOid": SHA_B,
                                "mergeable": "MERGEABLE",
                                "potentialMergeCommit": {
                                    "oid": SHA_C,
                                    "tree": {"oid": SHA_D},
                                    "parents": {
                                        "totalCount": 2,
                                        "nodes": [
                                            {"oid": SHA_B},
                                            {"oid": CODEX_HEAD},
                                        ],
                                        "pageInfo": {
                                            "hasNextPage": False,
                                            "endCursor": None,
                                        },
                                    },
                                },
                            }
                        }
                    }
                }
            if "pullRequests(" in joined:
                return {
                    "data": {
                        "repository": {
                            "pullRequests": {
                                "nodes": [{"number": pr_number}],
                                "pageInfo": {
                                    "hasNextPage": False,
                                    "endCursor": None,
                                },
                            }
                        }
                    }
                }
            if "pr view" in joined:
                return {
                    "number": pr_number,
                    "title": "Release-ready slice",
                    "url": f"https://github.com/owner/repo/pull/{pr_number}",
                    "author": {"login": "maintainer"},
                    "headRefName": "forge/issue-1",
                    "headRefOid": CODEX_HEAD,
                    "baseRefName": "main",
                    "baseRefOid": SHA_B,
                    "isDraft": False,
                    "mergeable": "MERGEABLE",
                    "mergeStateStatus": "CLEAN",
                    "reviewDecision": review_decision,
                    "statusCheckRollup": [
                        {
                            "name": "ci",
                            "status": "COMPLETED",
                            "conclusion": "SUCCESS",
                        }
                    ],
                    "latestReviews": [],
                }
            if f"pulls/{pr_number}/files?" in joined:
                return [{"filename": "src/a.py"}]
            if "reviewThreads" in joined:
                return {
                    "data": {
                        "repository": {
                            "pullRequest": {
                                "reviewThreads": {
                                    "nodes": [],
                                    "pageInfo": {
                                        "hasNextPage": False,
                                        "endCursor": None,
                                    },
                                }
                            }
                        }
                    }
                }
            if f"issues/{pr_number}/comments" in joined:
                if fail_lookup == "comments":
                    raise RuntimeError("comments down")
                return comments
            if f"pulls/{pr_number}/reviews" in joined:
                if fail_lookup == "reviews":
                    raise RuntimeError("reviews down")
                return reviews
            raise AssertionError(f"unexpected gh call: {joined}")

        old = bundler.gh_json
        bundler.gh_json = fake_gh_json
        bundler.load_role_review_receipts = lambda *args, **kwargs: []
        bundler.evaluate_review_quorum = lambda **kwargs: {
            "merge_ready": True,
            "reasons": [],
            "quorum_sha256": "sha256:" + "q" * 64,
            "policy_sha256": "sha256:" + "p" * 64,
        }
        try:
            return bundler.clean_candidates(make_env())
        finally:
            bundler.gh_json = old

    def test_pending_codex_review_is_not_release_clean(self):
        clean, blockers = self.run_candidate_case(
            13,
            [
                {
                    "user": {"login": "maintainer"},
                    "body": "@Codex Review",
                    "created_at": "2026-06-29T00:02:00Z",
                }
            ],
            [],
        )
        self.assertEqual(clean, [])
        self.assertTrue(
            any("PR#13: codex_pending_trigger" in blocker for blocker in blockers)
        )

    def test_missing_current_codex_review_is_not_release_clean(self):
        clean, blockers = self.run_candidate_case(14, [], [])
        self.assertEqual(clean, [])
        self.assertTrue(
            any(
                "PR#14: codex_missing_current head=abcdef1234" in blocker
                for blocker in blockers
            )
        )

    def test_human_approval_does_not_replace_current_codex_evidence(self):
        clean, blockers = self.run_candidate_case(
            18,
            [],
            [],
            review_decision="APPROVED",
        )
        self.assertEqual(clean, [])
        self.assertTrue(
            any("PR#18: codex_missing_current" in blocker for blocker in blockers)
        )

    def test_current_clean_codex_comment_is_release_clean(self):
        clean, blockers = self.run_candidate_case(
            15,
            [
                {
                    "user": {"login": "chatgpt-codex-connector[bot]"},
                    "body": (
                        "Didn't find any major issues.\n\n"
                        "Reviewed commit:** `abcdef1234567890abcdef1234567890abcdef12`"
                    ),
                    "created_at": "2026-06-29T00:03:00Z",
                }
            ],
            [],
        )
        self.assertEqual([pr["number"] for pr in clean], [15])
        self.assertEqual(clean[0]["changed_paths"], ["src/a.py"])
        self.assertEqual(clean[0]["expected_merge_tree_sha"], SHA_D)
        self.assertEqual(blockers, [])

    def test_lookup_failure_is_not_release_clean(self):
        clean, blockers = self.run_candidate_case(
            20,
            [
                {
                    "user": {"login": "chatgpt-codex-connector[bot]"},
                    "body": (
                        "Didn't find any major issues.\n\n"
                        "Reviewed commit:** `abcdef1234567890abcdef1234567890abcdef12`"
                    ),
                    "created_at": "2026-06-29T00:03:00Z",
                }
            ],
            [],
            fail_lookup="reviews",
        )
        self.assertEqual(clean, [])
        self.assertTrue(
            any("PR#20: codex_lookup_failed" in blocker for blocker in blockers)
        )

    def test_newer_suggestion_review_revokes_older_clean_evidence(self):
        clean, blockers = self.run_candidate_case(
            19,
            [],
            [
                {
                    "user": {"login": "chatgpt-codex-connector[bot]"},
                    "body": (
                        "Didn't find any major issues.\n\n"
                        "Reviewed commit:** `abcdef1234567890abcdef1234567890abcdef12`"
                    ),
                    "commit_id": CODEX_HEAD,
                    "submitted_at": "2026-06-29T00:04:00Z",
                },
                {
                    "user": {"login": "chatgpt-codex-connector[bot]"},
                    "body": (
                        "### Codex Review\nDidn't find any major issues.\n\n"
                        "Here are some automated review suggestions.\n\n"
                        "**Reviewed commit:** `abcdef1234567890abcdef1234567890abcdef12`"
                    ),
                    "commit_id": CODEX_HEAD,
                    "submitted_at": "2026-06-29T00:05:00Z",
                },
            ],
        )
        self.assertEqual(clean, [])
        self.assertTrue(
            any(
                "PR#19: codex_current_head_not_clean" in blocker
                for blocker in blockers
            )
        )

    def test_open_pr_listing_is_fully_paginated_and_order_preserved(self):
        bundler = load_bundler()
        calls: list[list[str]] = []

        def fake_gh_json(cmd, *, env=None, timeout=60):
            calls.append(cmd)
            if any("cursor=page-2" == value for value in cmd):
                return {
                    "data": {
                        "repository": {
                            "pullRequests": {
                                "nodes": [{"number": 3}, {"number": 1}],
                                "pageInfo": {
                                    "hasNextPage": False,
                                    "endCursor": None,
                                },
                            }
                        }
                    }
                }
            return {
                "data": {
                    "repository": {
                        "pullRequests": {
                            "nodes": [{"number": 9}, {"number": 4}],
                            "pageInfo": {
                                "hasNextPage": True,
                                "endCursor": "page-2",
                            },
                        }
                    }
                }
            }

        old = bundler.gh_json
        bundler.gh_json = fake_gh_json
        try:
            numbers = bundler.open_pull_request_numbers(
                "owner/repo",
                make_env(),
            )
        finally:
            bundler.gh_json = old
        self.assertEqual(numbers, [9, 4, 3, 1])
        self.assertEqual(len(calls), 2)

    def test_open_pr_pagination_fails_closed_on_cursor_loop(self):
        bundler = load_bundler()

        def fake_gh_json(cmd, *, env=None, timeout=60):
            return {
                "data": {
                    "repository": {
                        "pullRequests": {
                            "nodes": [],
                            "pageInfo": {
                                "hasNextPage": True,
                                "endCursor": "same",
                            },
                        }
                    }
                }
            }

        old = bundler.gh_json
        bundler.gh_json = fake_gh_json
        try:
            with self.assertRaisesRegex(
                RuntimeError,
                "open_prs_pagination_cursor_invalid",
            ):
                bundler.open_pull_request_numbers(
                    "owner/repo",
                    make_env(),
                )
        finally:
            bundler.gh_json = old

    def test_review_threads_are_fully_paginated(self):
        bundler = load_bundler()
        calls: list[list[str]] = []

        def fake_gh_json(cmd, *, env=None, timeout=60):
            calls.append(cmd)
            if any("cursor=page-2" == value for value in cmd):
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

        old = bundler.gh_json
        bundler.gh_json = fake_gh_json
        try:
            result = bundler.unresolved_threads(
                "owner/repo",
                42,
                make_env(),
            )
        finally:
            bundler.gh_json = old
        self.assertEqual(
            result,
            {"total": 101, "unresolved": 1, "unresolved_current": 1},
        )
        self.assertEqual(len(calls), 2)

    def test_pr_files_are_fully_paginated_and_canonicalized(self):
        bundler = load_bundler()
        calls: list[list[str]] = []

        def fake_gh_json(cmd, *, env=None, timeout=60):
            calls.append(cmd)
            joined = " ".join(cmd)
            if "&page=1" in joined:
                return [
                    {"filename": f"src/z{index:03}.py"}
                    for index in range(100)
                ]
            return [{"filename": "README.md"}]

        old = bundler.gh_json
        bundler.gh_json = fake_gh_json
        try:
            paths = bundler.pull_request_changed_paths(
                "owner/repo",
                9,
                make_env(),
            )
        finally:
            bundler.gh_json = old
        self.assertEqual(len(paths), 101)
        self.assertEqual(paths[0], "README.md")
        self.assertEqual(len(calls), 2)

    def test_potential_merge_tree_requires_exact_repository_and_parents(self):
        bundler = load_bundler()
        env = make_env()

        def response(
            *,
            repository: str = "owner/repo",
            parents: list[str] | None = None,
            tree: str = SHA_D,
        ) -> dict[str, Any]:
            return {
                "data": {
                    "repository": {
                        "databaseId": 123456,
                        "nameWithOwner": repository,
                        "pullRequest": {
                            "number": 9,
                            "headRefOid": SHA_A,
                            "baseRefOid": SHA_B,
                            "mergeable": "MERGEABLE",
                            "potentialMergeCommit": {
                                "oid": SHA_C,
                                "tree": {"oid": tree},
                                "parents": {
                                    "totalCount": 2,
                                    "nodes": [
                                        {"oid": oid}
                                        for oid in (
                                            parents
                                            if parents is not None
                                            else [SHA_B, SHA_A]
                                        )
                                    ],
                                    "pageInfo": {
                                        "hasNextPage": False,
                                        "endCursor": None,
                                    },
                                },
                            },
                        },
                    }
                }
            }

        old = bundler.gh_json
        try:
            bundler.gh_json = lambda *_args, **_kwargs: response()
            self.assertEqual(
                bundler.pull_request_expected_merge_tree(
                    "owner/repo", 9, env
                ),
                SHA_D,
            )
            for label, value, message in (
                (
                    "repository",
                    response(repository="other/repo"),
                    "identity_invalid",
                ),
                (
                    "parent-order",
                    response(parents=[SHA_A, SHA_B]),
                    "tree_invalid",
                ),
                (
                    "missing-tree",
                    response(tree=""),
                    "tree_invalid",
                ),
            ):
                with self.subTest(label=label):
                    bundler.gh_json = (
                        lambda *_args, result=value, **_kwargs: result
                    )
                    with self.assertRaisesRegex(RuntimeError, message):
                        bundler.pull_request_expected_merge_tree(
                            "owner/repo", 9, env
                        )
        finally:
            bundler.gh_json = old


class ReleaseBundleV5ContractTest(unittest.TestCase):
    def write_fixture(
        self,
        bundler,
        root: Path,
        prs: list[dict],
        *,
        blockers: list[str] | None = None,
        signal: bool = False,
        target: str = SHA_D,
        slug: str = "repo",
    ) -> tuple[str, dict, Path, Path, list[tuple[str, str]]]:
        env = make_env(root / "hermes")
        env["BOT_LOCAL"] = str(root / "repo")
        env["BOT_SLUG"] = slug
        Path(env["BOT_LOCAL"]).mkdir(parents=True, exist_ok=True)
        posts: list[tuple[str, str]] = []
        old_readiness = bundler.publish_readiness
        old_window = bundler.release_bundle_window
        old_post = bundler.post
        bundler.publish_readiness = lambda _env: {
            "publish_ready_after_merge": False,
            "blocker": "publish_requires_protected_broker",
        }
        bundler.release_bundle_window = lambda _env: (CREATED, EXPIRES)
        bundler.post = lambda _env, label, body: posts.append((label, body))
        try:
            bundle_id = bundler.write_bundle(
                env,
                prs,
                list(blockers or []),
                signal,
                target_base_oid=target,
            )
        finally:
            bundler.publish_readiness = old_readiness
            bundler.release_bundle_window = old_window
            bundler.post = old_post
        bundle_root = Path(env["BOT_HERMES_HOME"]) / "private" / "release-bundles"
        json_path = bundle_root / f"{bundle_id}.json"
        markdown_path = (
            bundle_root / f"{bundle_id}.md"
            if bundle_id
            else bundle_root / "release-status.md"
        )
        bundle = (
            json.loads(json_path.read_text(encoding="utf-8"))
            if bundle_id
            else {}
        )
        return (
            bundle_id,
            bundle,
            json_path,
            markdown_path,
            posts,
        )

    def test_emits_strict_v5_schema_and_private_atomic_artifacts(self):
        bundler = load_bundler()
        with tempfile.TemporaryDirectory() as tmp:
            bundle_id, bundle, json_path, markdown_path, _posts = (
                self.write_fixture(
                    bundler,
                    Path(tmp),
                    [
                        clean_pr(
                            22,
                            head=SHA_C,
                            paths=["src/z.py", "src/a.py"],
                            author="alice",
                        ),
                        clean_pr(
                            11,
                            head=SHA_A,
                            paths=[
                                ".github/workflows/release.yml",
                                "README.md",
                            ],
                            author="release-bot[bot]",
                        ),
                    ],
                )
            )
            json_mode = stat.S_IMODE(json_path.stat().st_mode)
            markdown_mode = stat.S_IMODE(markdown_path.stat().st_mode)
        self.assertEqual(set(bundle), V5_ROOT_FIELDS)
        self.assertEqual(
            bundle["schema_version"],
            "john-lomein.release-bundle.v6",
        )
        self.assertEqual(bundle["instance_slug"], "repo")
        self.assertEqual(
            bundle["repository"],
            {
                "full_name": "owner/repo",
                "id": 123456,
                "default_branch": "main",
            },
        )
        self.assertEqual(bundle["initial_base_sha"], SHA_D)
        self.assertEqual(bundle["merge_method"], "squash")
        self.assertIs(bundle["publish"], False)
        self.assertIsNone(bundle["train_attestation_digest"])
        self.assertEqual(
            bundle["actions"],
            {"merge": True, "publish": False},
        )
        self.assertEqual(
            [item["number"] for item in bundle["ordered_prs"]],
            [22, 11],
        )
        self.assertEqual(
            [item["position"] for item in bundle["ordered_prs"]],
            [0, 1],
        )
        self.assertTrue(
            all(set(item) == V5_PR_FIELDS for item in bundle["ordered_prs"])
        )
        self.assertEqual(
            bundle["ordered_prs"][0]["changed_paths"],
            ["src/a.py", "src/z.py"],
        )
        self.assertEqual(
            bundle["ordered_prs"][0]["changed_path_count"],
            2,
        )
        self.assertRegex(
            bundle["ordered_prs"][0]["changed_paths_digest"],
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertEqual(bundle["ordered_prs"][0]["risk_class"], "medium")
        self.assertEqual(bundle["ordered_prs"][1]["risk_class"], "critical")
        self.assertRegex(bundle["bundle_digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(
            bundle_id,
            "jlb-" + bundle["bundle_digest"].removeprefix("sha256:")[:24],
        )
        self.assertEqual(
            bundler.release_bundle_digest(bundle),
            bundle["bundle_digest"],
        )
        self.assertEqual(
            broker_protocol.normalize_release_bundle(bundle),
            bundle,
        )
        self.assertEqual(json_mode, 0o600)
        self.assertEqual(markdown_mode, 0o600)

    def test_order_is_authoritative_and_never_sorted_for_digest(self):
        bundler = load_bundler()
        first_order = bundler.ordered_pr_contract(
            [clean_pr(9, head=SHA_A), clean_pr(2, head=SHA_B)],
            repository_full_name="owner/repo",
            default_branch="main",
        )
        second_order = bundler.ordered_pr_contract(
            [clean_pr(2, head=SHA_B), clean_pr(9, head=SHA_A)],
            repository_full_name="owner/repo",
            default_branch="main",
        )

        def authority(ordered_prs):
            return {
                "schema_version": "john-lomein.release-bundle.v6",
                "instance_slug": "repo",
                "repository": {
                    "full_name": "owner/repo",
                    "id": 123456,
                    "default_branch": "main",
                },
                "created_at": CREATED,
                "expires_at": EXPIRES,
                "initial_base_sha": SHA_D,
                "merge_method": "squash",
                "publish": False,
                "train_attestation_digest": None,
                "actions": {"merge": True, "publish": False},
                "ordered_prs": ordered_prs,
            }

        self.assertEqual([item["number"] for item in first_order], [9, 2])
        self.assertEqual([item["number"] for item in second_order], [2, 9])
        self.assertNotEqual(
            bundler.release_bundle_v5_content_digest(authority(first_order)),
            bundler.release_bundle_v5_content_digest(authority(second_order)),
        )

    def test_tampering_and_unknown_schema_fields_fail_closed(self):
        bundler = load_bundler()
        with tempfile.TemporaryDirectory() as tmp:
            _bundle_id, bundle, _json_path, _markdown_path, _posts = (
                self.write_fixture(
                    bundler,
                    Path(tmp),
                    [
                        clean_pr(9, head=SHA_A),
                        clean_pr(2, head=SHA_B),
                    ],
                )
            )
        original_digest = bundle["bundle_digest"]

        changed_head = copy.deepcopy(bundle)
        changed_head["ordered_prs"][0]["head_sha"] = SHA_C
        self.assertNotEqual(
            bundler.release_bundle_digest(changed_head),
            original_digest,
        )

        changed_tree = copy.deepcopy(bundle)
        changed_tree["ordered_prs"][0][
            "expected_merge_tree_sha"
        ] = SHA_C
        self.assertNotEqual(
            bundler.release_bundle_digest(changed_tree),
            original_digest,
        )

        changed_order = copy.deepcopy(bundle)
        changed_order["ordered_prs"].reverse()
        for position, item in enumerate(changed_order["ordered_prs"]):
            item["position"] = position
        self.assertNotEqual(
            bundler.release_bundle_digest(changed_order),
            original_digest,
        )

        stale_path_digest = copy.deepcopy(bundle)
        stale_path_digest["ordered_prs"][0]["changed_paths"].append("src/z.py")
        stale_path_digest["ordered_prs"][0]["changed_paths"].sort()
        stale_path_digest["ordered_prs"][0]["changed_path_count"] += 1
        with self.assertRaisesRegex(
            ValueError,
            "changed_paths_digest_invalid",
        ):
            bundler.release_bundle_digest(stale_path_digest)

        unknown = copy.deepcopy(bundle)
        unknown["surprise"] = True
        with self.assertRaisesRegex(ValueError, "root_fields_invalid"):
            bundler.release_bundle_digest(unknown)

        wrong_schema = copy.deepcopy(bundle)
        wrong_schema["schema_version"] = "john-lomein.release-bundle.v7"
        with self.assertRaisesRegex(ValueError, "schema_unsupported"):
            bundler.release_bundle_digest(wrong_schema)

    def test_atomic_write_failure_preserves_previous_file(self):
        bundler = load_bundler()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "bundle.json"
            path.write_text("old", encoding="utf-8")
            path.chmod(0o600)
            old_replace = bundler.os.replace

            def fail_replace(_source, _destination):
                raise OSError("simulated replace failure")

            bundler.os.replace = fail_replace
            try:
                with self.assertRaisesRegex(
                    OSError,
                    "simulated replace failure",
                ):
                    bundler.atomic_write_private(path, "new")
            finally:
                bundler.os.replace = old_replace
            self.assertEqual(path.read_text(encoding="utf-8"), "old")
            self.assertEqual(
                list(root.glob(f".{path.name}.*.tmp")),
                [],
            )

    def test_repository_id_is_fetched_when_not_deployed(self):
        bundler = load_bundler()
        env = make_env()
        env.pop("BOT_REPO_ID")
        calls: list[list[str]] = []

        def fake_gh_json(cmd, *, env=None, timeout=60):
            calls.append(cmd)
            return {
                "id": 987654,
                "full_name": "owner/repo",
                "default_branch": "main",
            }

        old = bundler.gh_json
        bundler.gh_json = fake_gh_json
        try:
            identity = bundler.repository_identity(env)
        finally:
            bundler.gh_json = old
        self.assertEqual(identity["id"], 987654)
        self.assertEqual(len(calls), 1)

    def test_same_authority_produces_stable_digest_derived_id(self):
        bundler = load_bundler()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, first_bundle, *_ = self.write_fixture(
                bundler,
                root,
                [clean_pr(12, head=SHA_A)],
            )
            second, second_bundle, *_ = self.write_fixture(
                bundler,
                root,
                [clean_pr(12, head=SHA_A)],
            )
        self.assertEqual(first, second)
        self.assertEqual(
            first_bundle["bundle_digest"],
            second_bundle["bundle_digest"],
        )

    def test_target_branch_advance_creates_distinct_bundle(self):
        bundler = load_bundler()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, *_ = self.write_fixture(
                bundler,
                root,
                [clean_pr(12, head=SHA_A)],
                target=SHA_C,
            )
            second, *_ = self.write_fixture(
                bundler,
                root,
                [clean_pr(12, head=SHA_A)],
                target=SHA_D,
            )
        self.assertNotEqual(first, second)

    def test_notification_fingerprint_changes_do_not_change_authority_bundle(self):
        bundler = load_bundler()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, *_rest, first_posts = self.write_fixture(
                bundler,
                root,
                [clean_pr(12, head=SHA_A)],
                blockers=[],
                signal=True,
            )
            second, *_rest, second_posts = self.write_fixture(
                bundler,
                root,
                [clean_pr(12, head=SHA_A)],
                blockers=["PR#13: codex_pending_trigger"],
                signal=True,
            )
        self.assertEqual(first, second)
        self.assertEqual(
            [label for label, _body in first_posts + second_posts],
            ["RELEASE_GATE", "RELEASE_GATE"],
        )

    def test_identical_empty_blocker_bundle_does_not_repost(self):
        bundler = load_bundler()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, *_rest, first_posts = self.write_fixture(
                bundler,
                root,
                [],
                blockers=["PR#13: codex_pending_trigger"],
                signal=True,
            )
            second, *_rest, second_posts = self.write_fixture(
                bundler,
                root,
                [],
                blockers=["PR#13: codex_pending_trigger"],
                signal=True,
            )
            status_path = (
                root
                / "hermes"
                / "private"
                / "release-bundles"
                / "release-status.md"
            )
            status_exists = status_path.is_file()
            authorization_json = list(
                status_path.parent.glob("jlb-*.json")
            )
        self.assertEqual(first, second)
        self.assertEqual(first, "")
        self.assertTrue(status_exists)
        self.assertEqual(authorization_json, [])
        self.assertEqual(
            [label for label, _body in first_posts + second_posts],
            ["RELEASE_GATE"],
        )

    def test_unsafe_instance_slug_fails_before_writing(self):
        bundler = load_bundler()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(ValueError, "instance_invalid"):
                self.write_fixture(
                    bundler,
                    root,
                    [clean_pr(1)],
                    slug="../escape",
                )
            self.assertFalse((root / "escape.json").exists())

    def test_missing_author_and_invalid_ttl_fail_closed(self):
        bundler = load_bundler()
        pr = clean_pr(1)
        pr["author"] = None
        with self.assertRaisesRegex(RuntimeError, "pr_author_invalid"):
            bundler.ordered_pr_contract(
                [pr],
                repository_full_name="owner/repo",
                default_branch="main",
            )
        with self.assertRaisesRegex(RuntimeError, "ttl_invalid"):
            bundler.release_bundle_window(
                {"BOT_RELEASE_BUNDLE_TTL_SECONDS": "one hour"}
            )

    def test_legacy_v4_digest_remains_available(self):
        owner_actions = load_owner_actions()
        bundle = {
            "bundle_id": "repo-12-abc",
            "repo": "owner/repo",
            "clean_prs": [
                {
                    "number": 12,
                    "headRefOid": "abc",
                    "baseRefName": "main",
                    "baseRefOid": "base-abc",
                    "targetBaseOid": "target-abc",
                    "files": [{"path": "src/a.py"}],
                }
            ],
            "blockers": [],
            "approved_actions": {"merge": True, "publish": False},
            "publish_request": {"npm_tag": "latest"},
            "publish_readiness": {
                "package_name": "pkg",
                "package_version": "1.0.0",
                "publish_ready_after_merge": True,
                "blocker": "",
            },
            "allowed_after_gate": ["merge listed PRs"],
            "forbidden_without_gate": ["publish"],
        }
        digest = owner_actions.release_bundle_digest(bundle)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        explicit = dict(bundle)
        explicit["schema_version"] = "john-lomein.release-bundle.v4"
        self.assertEqual(
            owner_actions.release_bundle_digest(explicit),
            digest,
        )


class ReleaseBundleActionBoardTest(unittest.TestCase):
    def test_mixed_clean_and_blocked_bundle_notifies_both_classes(self):
        owner_actions = load_owner_actions()
        board = owner_actions.release_bundle_action_board(
            bundle_id="jlb-0123456789abcdef01234567",
            clean_prs=[{"number": 12}],
            blockers=["PR#13: codex_pending_trigger"],
        )
        meta = owner_actions.notification_meta(
            source="release-bundler",
            instance="repo",
            repo="owner/repo",
            action_board=board,
        )
        self.assertEqual(
            board["owner_action"]["release_bundles"],
            [
                {
                    "bundle_id": "jlb-0123456789abcdef01234567",
                    "clean_prs": [12],
                }
            ],
        )
        self.assertEqual(
            board["automation_blocker"]["release_blockers"],
            ["PR#13: codex_pending_trigger"],
        )
        self.assertTrue(meta["should_notify"])
        self.assertEqual(
            meta["classes"],
            ["owner_action", "automation_blocker"],
        )


if __name__ == "__main__":
    unittest.main()
