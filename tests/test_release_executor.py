#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
EXECUTOR_PATH = ROOT / "scripts" / "john-lomein-release-executor.py"
VALID_PUBLISH_WORKFLOW = """\
name: Publish npm
on:
  workflow_dispatch:
    inputs:
      expected-sha:
        required: true
      expected-version:
        required: true
      npm-tag:
        required: true
env:
  JOHN_LOMEIN_PUBLISH_CONTRACT: john-lomein-publish/v1
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Verify approved commit
        env:
          EXPECTED_SHA: ${{ inputs.expected-sha }}
          ACTUAL_SHA: ${{ github.sha }}
          EXPECTED_VERSION: ${{ inputs.expected-version }}
        run: |
          test "$ACTUAL_SHA" = "$EXPECTED_SHA"
          ACTUAL_VERSION="$(node -p "require('./package.json').version")"
          test "$ACTUAL_VERSION" = "$EXPECTED_VERSION"
      - name: Publish
        env:
          NPM_TAG: ${{ inputs.npm-tag }}
        run: npm publish --provenance --tag "$NPM_TAG"
"""


def load_executor():
    spec = importlib.util.spec_from_file_location("john_lomein_release_executor", EXECUTOR_PATH)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return cast(Any, mod)


class ReleaseExecutorBundleSelectionTest(unittest.TestCase):
    def test_runtime_source_contains_no_direct_merge_or_publish_command(self):
        source = EXECUTOR_PATH.read_text(encoding="utf-8")
        self.assertNotIn('["gh", "pr", "merge"', source)
        self.assertNotIn('"workflow", "run"', source)

    def make_env(self, tmp: str) -> dict[str, str]:
        H = Path(tmp) / "hermes"
        (H / "private" / "release-bundles").mkdir(parents=True)
        local = Path(tmp) / "repo"
        local.mkdir()
        return {
            "BOT_HERMES_HOME": str(H),
            "HERMES_HOME": str(H),
            "BOT_LOCAL": str(local),
            "BOT_REPO": "owner/repo",
            "BOT_MISSION_COMPLETE": "1",
        }

    def write_bundle(self, env: dict[str, str], bundle_id: str, clean_prs: list[dict] | None = None) -> Path:
        root = Path(env["BOT_HERMES_HOME"]) / "private" / "release-bundles"
        path = root / f"{bundle_id}.json"
        path.write_text(json.dumps({"bundle_id": bundle_id, "repo": env["BOT_REPO"], "clean_prs": clean_prs or []}), encoding="utf-8")
        return path

    def trust_assertion(self, env: dict[str, str], *, bundle_id: str, approval_text: str, actor: str = "owner-user", tier: str = "owner", bundle_digest: str = "") -> str:
        key_root = Path(env["BOT_HERMES_HOME"]) / "state" / "gateway"
        key_root.mkdir(parents=True, exist_ok=True)
        private = key_root / "test-private.pem"
        public = key_root / "trust-assertion.public.pem"
        if not private.exists():
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)], check=True, capture_output=True, text=True, timeout=30)
            subprocess.run(["openssl", "rsa", "-pubout", "-in", str(private), "-out", str(public)], check=True, capture_output=True, text=True, timeout=30)
            public.chmod(0o444)
        env["BOT_TRUST_PUBLIC_KEY_SHA256"] = hashlib.sha256(public.read_bytes()).hexdigest()
        payload = {
            "purpose": "release_approval",
            "tier": tier,
            "actor": actor,
            "bundle_id": bundle_id,
            "approval_hash": hashlib.sha256(" ".join(approval_text.strip().split()).encode("utf-8")).hexdigest(),
            "nonce": f"test-nonce-{time.time_ns()}",
            "iat": time.time(),
        }
        if bundle_digest:
            payload["bundle_digest"] = bundle_digest
        with tempfile.TemporaryDirectory() as sig_tmp:
            body_path = Path(sig_tmp) / "payload.json"
            sig_path = Path(sig_tmp) / "payload.sig"
            body_path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")
            subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private), "-out", str(sig_path), str(body_path)], check=True, capture_output=True, text=True, timeout=30)
            signature = base64.b64encode(sig_path.read_bytes()).decode("ascii")
        return json.dumps({"payload": payload, "signature": signature}, separators=(",", ":"))

    def test_default_loads_freshest_generated_bundle_not_stale_last_signaled(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            root = Path(env["BOT_HERMES_HOME"]) / "private" / "release-bundles"
            stale = self.write_bundle(env, "repo-99-old", [{"number": 99, "headRefOid": "old"}])
            time.sleep(0.01)
            fresh = self.write_bundle(env, "repo-empty-new", [])
            (root / ".last-signaled").write_text("repo-99-old", encoding="utf-8")
            bundle_id, data, path = executor.load_bundle(env, None)
            self.assertEqual(bundle_id, "repo-empty-new")
            self.assertEqual(path, fresh)
            self.assertNotEqual(path, stale)

    def test_approval_text_selects_exact_bundle_without_bundle_arg(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            wanted = self.write_bundle(env, "repo-1-good", [{"number": 1, "headRefOid": "abc"}])
            time.sleep(0.01)
            self.write_bundle(env, "repo-empty-new", [])
            bundle_id, data, path = executor.load_bundle(env, None, approval="APPROVE JOHN-LOMEIN BUNDLE repo-1-good: merge listed PRs")
            self.assertEqual(bundle_id, "repo-1-good")
            self.assertEqual(path, wanted)

    def test_bundle_id_from_approval_cannot_traverse_bundle_directory(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            with self.assertRaises(ValueError):
                executor.load_bundle(env, None, approval="APPROVE JOHN-LOMEIN BUNDLE ../outside: merge listed PRs")

    def test_empty_bundle_is_not_a_dry_run_blocker(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            ready, blockers = executor.verify_bundle(env, {"repo": env["BOT_REPO"], "clean_prs": []})
            self.assertEqual(ready, [])
            self.assertEqual(blockers, [])

    def test_review_thread_gate_paginates_beyond_first_page(self):
        executor = load_executor()
        calls: list[list[str]] = []

        def fake_gh_json(cmd, *, env=None, timeout=120):
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

        old = executor.gh_json
        executor.gh_json = fake_gh_json
        try:
            result = executor.unresolved_threads(
                "owner/repo", 42, {"PATH": "/usr/bin"}
            )
        finally:
            executor.gh_json = old
        self.assertEqual(
            result,
            {"total": 101, "unresolved": 1, "unresolved_current": 1},
        )
        self.assertEqual(len(calls), 2)

    def test_review_thread_gate_fails_closed_on_invalid_page_info(self):
        executor = load_executor()
        old = executor.gh_json
        executor.gh_json = lambda *args, **kwargs: {
            "data": {
                "repository": {
                    "pullRequest": {
                        "reviewThreads": {
                            "nodes": [],
                            "pageInfo": {"hasNextPage": "false"},
                        }
                    }
                }
            }
        }
        try:
            with self.assertRaisesRegex(
                RuntimeError,
                "review_threads_graphql_response_invalid",
            ):
                executor.unresolved_threads(
                    "owner/repo", 42, {"PATH": "/usr/bin"}
                )
        finally:
            executor.gh_json = old

    def test_publish_requires_merge_flag_for_exact_bundle_resume(self):
        executor = load_executor()
        self.assertEqual(
            executor.requested_action_blockers(merge=False, publish=True),
            ["publish_requires_merge"],
        )
        self.assertEqual(
            executor.requested_action_blockers(merge=True, publish=True),
            ["publish_requires_protected_broker"],
        )
        self.assertEqual(
            executor.requested_action_blockers(merge=True, publish=False),
            ["merge_requires_protected_broker"],
        )
        self.assertEqual(executor.requested_action_blockers(merge=False, publish=False), [])

    def test_publish_request_binds_the_approved_npm_tag(self):
        executor = load_executor()
        bundle = {"publish_request": {"npm_tag": "latest"}}
        self.assertEqual(executor.publish_request_blockers(bundle, publish=True, npm_tag="latest"), [])
        self.assertEqual(
            executor.publish_request_blockers(bundle, publish=True, npm_tag="next"),
            ["publish_npm_tag_mismatch approved=latest requested=next"],
        )
        self.assertEqual(
            executor.publish_request_blockers({"publish_request": "latest"}, publish=True, npm_tag="latest"),
            ["bundle_publish_npm_tag_missing_or_invalid"],
        )
        self.assertEqual(executor.publish_request_blockers(bundle, publish=False, npm_tag="next"), [])

    def test_publish_workflow_contract_requires_sha_guard_and_bound_tag(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "publish-npm.yml"
            path.write_text(VALID_PUBLISH_WORKFLOW, encoding="utf-8")
            valid = executor.publish_workflow_contract(path)
            self.assertTrue(valid["publish_contract_valid"])
            self.assertFalse(valid["blocker"])

            path.write_text(VALID_PUBLISH_WORKFLOW.replace('test "$ACTUAL_SHA" = "$EXPECTED_SHA"', "echo unchecked"), encoding="utf-8")
            self.assertIn("sha_guard_missing", executor.publish_workflow_contract(path)["blocker"])

            path.write_text(VALID_PUBLISH_WORKFLOW.replace('NPM_TAG: ${{ inputs.npm-tag }}', "NPM_TAG: latest"), encoding="utf-8")
            self.assertIn("npm_tag_unbound", executor.publish_workflow_contract(path)["blocker"])

            path.write_text(VALID_PUBLISH_WORKFLOW.replace("      - name: Publish", "      - name: Publish\n        if: always()"), encoding="utf-8")
            self.assertIn("publish_condition_forbidden", executor.publish_workflow_contract(path)["blocker"])

    def test_dispatch_publish_has_no_callable_runtime_mutation_path(self):
        executor = load_executor()
        with self.assertRaisesRegex(
            RuntimeError,
            "publish_requires_protected_broker",
        ):
            executor.dispatch_publish(
                {"BOT_REPO": "owner/repo"},
                "latest",
                "a" * 40,
            )

    def test_release_verification_rejects_dirty_checkout_before_or_after_tests(self):
        executor = load_executor()
        env = {"BOT_LOCAL": "/tmp/repo", "BOT_TEST_CMD": "make test"}
        executor.git_admin_path = lambda _path: Path("/tmp/repo/.git")
        executor.run_verifier_command = lambda *args, **kwargs: (0, " M package.json", "")
        code, _, error = executor.run_release_verification(env)
        self.assertEqual(code, 1)
        self.assertEqual(error, "release_checkout_dirty_before_verification")

        status_calls = {"count": 0}

        def fake_run(cmd, **kwargs):
            if " status " in cmd:
                status_calls["count"] += 1
                return (0, "", "") if status_calls["count"] == 1 else (0, "?? generated.txt", "")
            return 0, "", ""

        executor.run_verifier_command = fake_run
        code, _, error = executor.run_release_verification(env)
        self.assertEqual(code, 1)
        self.assertEqual(error, "release_checkout_dirty_after_verification")

    def test_release_verifier_environment_contains_no_parent_credentials(self):
        executor = load_executor()
        old = os.environ.copy()
        os.environ.update(
            {
                "GH_TOKEN": "secret",
                "GITHUB_TOKEN": "secret",
                "JOHN_LOMEIN_TRUST_ASSERTION": "signed-secret",
                "GH_CONFIG_DIR": "/tmp/credentialed-gh",
            }
        )
        try:
            with tempfile.TemporaryDirectory() as tmp:
                verifier = executor.verifier_process_env(Path(tmp))
        finally:
            os.environ.clear()
            os.environ.update(old)
        self.assertNotIn("GH_TOKEN", verifier)
        self.assertNotIn("GITHUB_TOKEN", verifier)
        self.assertNotIn("JOHN_LOMEIN_TRUST_ASSERTION", verifier)
        self.assertNotIn("GH_CONFIG_DIR", verifier)
        self.assertEqual(verifier["NPM_CONFIG_USERCONFIG"], "/dev/null")

    @unittest.skipUnless(sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").is_file(), "macOS sandbox required")
    def test_release_verifier_sandbox_denies_user_files_network_and_git_admin_writes(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            worktree = root / "repo"
            git_admin = worktree / ".git"
            verifier_home = root / "verifier-home"
            worktree.mkdir()
            git_admin.mkdir()
            (git_admin / "config").write_text("", encoding="utf-8")
            private = root / "private-token"
            private.write_text("secret", encoding="utf-8")
            outside_write = root / "outside-write"
            old = os.environ.copy()
            os.environ["GH_TOKEN"] = "parent-secret"
            try:
                code, out, err = executor.run_verifier_command(
                    (
                        'test -z "${GH_TOKEN:-}" || exit 40; '
                        f"if cat {private} >/dev/null 2>&1; then exit 41; fi; "
                        f"if printf leaked > {outside_write} 2>/dev/null; then exit 42; fi; "
                        "if printf changed > .git/config 2>/dev/null; then exit 43; fi; "
                        "if /usr/bin/nc -z 127.0.0.1 1 >/dev/null 2>&1; then exit 44; fi; "
                        "printf sandbox-ok"
                    ),
                    cwd=worktree,
                    verifier_home=verifier_home,
                    git_admin=git_admin,
                    timeout=30,
                )
            finally:
                os.environ.clear()
                os.environ.update(old)
            self.assertEqual(code, 0, err)
            self.assertEqual(out, "sandbox-ok")
            self.assertFalse(outside_write.exists())
            self.assertEqual((git_admin / "config").read_text(encoding="utf-8"), "")

    def test_publish_without_merge_is_rejected_before_loading_runtime(self):
        executor = load_executor()
        executor.load_env = lambda: self.fail("invalid action sequence must not load runtime or consume an assertion")
        out = StringIO()
        with redirect_stdout(out):
            code = executor.main(["john-lomein-release-executor.py", "--publish", "--dry-run"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out.getvalue())["blockers"], ["publish_requires_merge"])

    def test_publish_with_merge_is_blocked_until_protected_broker_exists(self):
        executor = load_executor()
        executor.load_env = lambda: self.fail("blocked publish must not load runtime or consume an assertion")
        out = StringIO()
        with redirect_stdout(out):
            code = executor.main(["john-lomein-release-executor.py", "--merge", "--publish"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out.getvalue())["blockers"], ["publish_requires_protected_broker"])

    def test_merge_is_blocked_before_loading_runtime_until_broker_exists(self):
        executor = load_executor()
        executor.load_env = lambda: self.fail("blocked merge must not load runtime or consume an assertion")
        out = StringIO()
        with redirect_stdout(out):
            code = executor.main(["john-lomein-release-executor.py", "--merge"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out.getvalue())["blockers"], ["merge_requires_protected_broker"])

    def test_allow_merged_rejects_bundle_head_mismatch(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp) | {"BOT_DEFAULT_BRANCH": "main"}
            bundle = {"repo": env["BOT_REPO"], "clean_prs": [{"number": 41, "headRefOid": "expected-head"}]}
            executor.gh_json = lambda *args, **kwargs: {
                "number": 41,
                "state": "MERGED",
                "headRefOid": "different-head",
                "baseRefName": "main",
            }
            merged: list[int] = []
            ready, blockers = executor.verify_bundle(env, bundle, allow_merged=True, merged_prs=merged)
            self.assertEqual(ready, [])
            self.assertEqual(merged, [])
            self.assertIn("PR#41: merged_head_changed bundle=expected-h current=different-", blockers)

    def test_verify_bundle_rejects_live_file_set_or_base_changed_from_approval(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp) | {"BOT_DEFAULT_BRANCH": "main"}
            bundle = {
                "repo": env["BOT_REPO"],
                "clean_prs": [
                    {
                        "number": 41,
                        "headRefOid": "expected-head",
                        "baseRefName": "main",
                        "baseRefOid": "approved-base",
                        "targetBaseOid": "approved-target",
                        "files": [{"path": "safe.py"}],
                    }
                ],
            }
            executor.gh_json = lambda *args, **kwargs: {
                "number": 41,
                "state": "OPEN",
                "headRefOid": "expected-head",
                "baseRefName": "release",
                "baseRefOid": "current-base",
                "isDraft": False,
                "mergeStateStatus": "CLEAN",
                "mergeable": "MERGEABLE",
                "statusCheckRollup": [],
            }
            executor.pr_files = lambda repo, number, env: [".github/workflows/publish-npm.yml"]
            executor.unresolved_threads = lambda repo, number, env: {"unresolved": 0, "unresolved_current": 0}
            executor.codex_clean_for_head = lambda repo, number, head, env: (True, "test")
            executor.default_branch_oid = lambda env: "current-target"
            ready, blockers = executor.verify_bundle(env, bundle)
            self.assertEqual(ready, [])
            self.assertIn("PR#41: base_changed bundle=main current=release", blockers)
            self.assertIn("PR#41: pr_base_snapshot_changed bundle=approved-b current=current-ba", blockers)
            self.assertIn("bundle_target_base_changed approved_chain=approved-t current=current-ta", blockers)
            self.assertIn(
                "PR#41: files_changed bundle=['safe.py'] current=['.github/workflows/publish-npm.yml']",
                blockers,
            )

    def test_fully_merged_bundle_requires_exact_heads_and_base(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp) | {"BOT_DEFAULT_BRANCH": "main"}
            bundle = {"repo": env["BOT_REPO"], "clean_prs": [{"number": 42, "headRefOid": "exact-head"}]}
            executor.gh_json = lambda *args, **kwargs: {
                "number": 42,
                "state": "MERGED",
                "headRefOid": "exact-head",
                "baseRefName": "main",
                "mergeCommit": {"oid": "merge-exact"},
            }
            self.assertEqual(executor.fully_merged_bundle_blockers(env, bundle), [])
            executor.gh_json = lambda *args, **kwargs: {
                "number": 42,
                "state": "OPEN",
                "headRefOid": "exact-head",
                "baseRefName": "main",
            }
            self.assertIn("PR#42: final_state=OPEN expected=MERGED", executor.fully_merged_bundle_blockers(env, bundle))

    def test_release_bundle_digest_detects_mutated_approved_contents(self):
        executor = load_executor()
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
            "publish_readiness": {"package_name": "pkg", "package_version": "1.0.0", "publish_ready_after_merge": True, "blocker": ""},
            "allowed_after_gate": ["merge listed PRs"],
            "forbidden_without_gate": ["publish"],
        }
        bundle["bundle_digest"] = executor.release_bundle_digest(bundle)
        bundle["owner_approval_text"] = executor.release_owner_approval_text(bundle)
        self.assertEqual(executor.bundle_integrity_blockers(bundle), [])
        bundle["owner_approval_text"] = bundle["owner_approval_text"].replace("DO NOT publish", "publish")
        self.assertIn("bundle_owner_approval_text_mismatch", executor.bundle_integrity_blockers(bundle))
        bundle["owner_approval_text"] = executor.release_owner_approval_text(bundle)
        bundle["clean_prs"][0]["headRefOid"] = "tampered"
        self.assertTrue(executor.bundle_integrity_blockers(bundle)[0].startswith("bundle_digest_mismatch"))
        bundle["clean_prs"][0]["headRefOid"] = "abc"
        bundle["clean_prs"][0]["targetBaseOid"] = "tampered-target"
        self.assertTrue(executor.bundle_integrity_blockers(bundle)[0].startswith("bundle_digest_mismatch"))
        bundle["clean_prs"][0]["targetBaseOid"] = "target-abc"
        bundle["publish_request"]["npm_tag"] = "next"
        self.assertTrue(executor.bundle_integrity_blockers(bundle)[0].startswith("bundle_digest_mismatch"))

    def test_signed_release_approval_binds_bundle_digest(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp) | {"BOT_OWNER_APPROVERS": "owner-user"}
            digest = "d" * 64
            approval = f"APPROVE JOHN-LOMEIN BUNDLE repo-1-good DIGEST {digest}: merge listed PRs"
            env["JOHN_LOMEIN_TRUST_ASSERTION"] = self.trust_assertion(
                env,
                bundle_id="repo-1-good",
                bundle_digest="e" * 64,
                approval_text=approval,
            )
            blockers = executor.require_approval(
                "repo-1-good",
                text=approval,
                merge=True,
                publish=False,
                env=env,
                expected_approval=approval,
                bundle_digest=digest,
            )
            self.assertIn("approval_trust_assertion_digest_mismatch", blockers)

    def test_load_env_refuses_forged_instance_env_selector(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            expected = Path(env["BOT_HERMES_HOME"]) / "scripts" / "john-lomein-instance.env"
            expected.parent.mkdir(parents=True, exist_ok=True)
            expected.write_text("BOT_REPO='owner/repo'\nBOT_OWNER_APPROVERS='real-owner'\nBOT_TRUST_PUBLIC_KEY_SHA256='real-pin'\n", encoding="utf-8")
            forged = Path(tmp) / "forged.env"
            forged.write_text("BOT_REPO='evil/repo'\nBOT_OWNER_APPROVERS='attacker'\nBOT_TRUST_PUBLIC_KEY_SHA256='evil-pin'\n", encoding="utf-8")
            old_env = os.environ.copy()
            os.environ.clear()
            os.environ.update({"HERMES_HOME": env["BOT_HERMES_HOME"], "JOHN_LOMEIN_INSTANCE_ENV": str(forged)})
            try:
                with self.assertRaises(executor.ReleaseExecutionError):
                    executor.load_env()
            finally:
                os.environ.clear()
                os.environ.update(old_env)

    def test_parse_env_does_not_seed_authority_from_caller_env(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "john-lomein-instance.env"
            path.write_text("BOT_REPO='owner/repo'\n", encoding="utf-8")
            old_env = os.environ.copy()
            os.environ["BOT_OWNER_APPROVERS"] = "attacker"
            try:
                vals = executor.parse_env(path)
            finally:
                os.environ.clear()
                os.environ.update(old_env)
            self.assertEqual(vals.get("BOT_REPO"), "owner/repo")
            self.assertNotIn("BOT_OWNER_APPROVERS", vals)

    def test_gh_env_ignores_caller_auth_and_config(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            gh_config = Path(env["BOT_HERMES_HOME"]) / "profiles" / "john-lomein-maintainer" / "home" / ".config" / "gh"
            gh_config.mkdir(parents=True)
            old_env = os.environ.copy()
            os.environ.clear()
            os.environ.update({"GH_CONFIG_DIR": "/tmp/evil-gh", "GH_TOKEN": "evil", "PATH": "/tmp/evil-bin"})
            try:
                result = executor.gh_env(env)
            finally:
                os.environ.clear()
                os.environ.update(old_env)
            self.assertEqual(result.get("GH_CONFIG_DIR"), str(gh_config))
            self.assertNotIn("GH_TOKEN", result)
            self.assertNotIn("/tmp/evil-bin", result.get("PATH", ""))

    def test_merge_resume_skips_already_merged_prs(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            bundle = {
                "repo": env["BOT_REPO"],
                "clean_prs": [
                    {"number": 29, "headRefOid": "aaa111", "baseRefName": "main", "baseRefOid": "base-zero", "files": []},
                    {"number": 30, "headRefOid": "bbb222", "baseRefName": "main", "baseRefOid": "base-zero", "files": []},
                ],
            }

            def fake_gh_json(cmd, *, env=None, timeout=120):
                pr_number = int(cmd[cmd.index("view") + 1])
                if pr_number == 29:
                    return {
                        "number": 29,
                        "state": "MERGED",
                        "headRefOid": "aaa111",
                        "baseRefName": "main",
                        "baseRefOid": "base-zero",
                        "mergeCommit": {"oid": "merge-aaa111"},
                        "mergeStateStatus": "UNKNOWN",
                        "mergeable": "UNKNOWN",
                    }
                return {
                    "number": 30,
                    "state": "OPEN",
                    "headRefOid": "bbb222",
                    "baseRefName": "main",
                    "baseRefOid": "base-zero",
                    "isDraft": False,
                    "mergeStateStatus": "CLEAN",
                    "mergeable": "MERGEABLE",
                    "reviewDecision": None,
                    "statusCheckRollup": [],
                }

            executor.gh_json = fake_gh_json
            executor.pr_files = lambda repo, number, env: []
            executor.unresolved_threads = lambda repo, number, env: {"unresolved": 0, "unresolved_current": 0}
            executor.codex_clean_for_head = lambda repo, number, head, env: (True, "test-codex-clean")

            merged = []
            ready, blockers = executor.verify_bundle(env, bundle, allow_merged=True, merged_prs=merged)
            self.assertEqual(merged, [29])
            self.assertEqual([p["number"] for p in ready], [30])
            self.assertEqual(blockers, [])

            ready_without_resume, blockers_without_resume = executor.verify_bundle(env, bundle, allow_merged=False)
            self.assertEqual([p["number"] for p in ready_without_resume], [30])
            self.assertTrue(any("PR#29: state=MERGED" in b for b in blockers_without_resume))

    def test_merge_resume_accepts_only_the_exact_prior_bundle_merge_chain(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp) | {"BOT_DEFAULT_BRANCH": "main"}
            bundle = {
                "repo": env["BOT_REPO"],
                "clean_prs": [
                    {
                        "number": 7,
                        "headRefOid": "head-seven",
                        "baseRefName": "main",
                        "baseRefOid": "base-zero",
                        "targetBaseOid": "target-zero",
                        "files": [],
                    },
                    {
                        "number": 8,
                        "headRefOid": "head-eight",
                        "baseRefName": "main",
                        "baseRefOid": "base-zero",
                        "targetBaseOid": "target-zero",
                        "files": [],
                    },
                ],
            }

            def fake_gh_json(cmd, *, env=None, timeout=120):
                number = int(cmd[cmd.index("view") + 1])
                if number == 7:
                    return {
                        "number": 7,
                        "state": "MERGED",
                        "headRefOid": "head-seven",
                        "baseRefName": "main",
                        "baseRefOid": "base-zero",
                        "mergeCommit": {"oid": "merge-seven"},
                    }
                return {
                    "number": 8,
                    "state": "OPEN",
                    "headRefOid": "head-eight",
                    "baseRefName": "main",
                    "baseRefOid": "base-zero",
                    "isDraft": False,
                    "mergeStateStatus": "CLEAN",
                    "mergeable": "MERGEABLE",
                    "reviewDecision": None,
                    "statusCheckRollup": [],
                }

            executor.gh_json = fake_gh_json
            executor.pr_files = lambda repo, number, env: []
            executor.unresolved_threads = lambda repo, number, env: {"unresolved": 0, "unresolved_current": 0}
            executor.codex_clean_for_head = lambda repo, number, head, env: (True, "test-codex-clean")
            executor.commit_first_parent = lambda env, oid: "target-zero"
            executor.default_branch_oid = lambda env: "merge-seven"

            merged: list[int] = []
            ready, blockers = executor.verify_bundle(env, bundle, allow_merged=True, merged_prs=merged)

            self.assertEqual(merged, [7])
            self.assertEqual([pr["number"] for pr in ready], [8])
            self.assertEqual(blockers, [])

            def unrelated_advance(cmd, *, env=None, timeout=120):
                return fake_gh_json(cmd, env=env, timeout=timeout)

            executor.gh_json = unrelated_advance
            executor.default_branch_oid = lambda env: "unrelated-advance"
            ready, blockers = executor.verify_bundle(env, bundle, allow_merged=True, merged_prs=[])
            self.assertEqual(ready, [])
            self.assertIn("bundle_target_base_changed approved_chain=merge-seve current=unrelated-", blockers)

    def test_fully_merged_bundle_proves_the_actual_sequential_base_chain(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp) | {"BOT_DEFAULT_BRANCH": "main"}
            bundle = {
                "repo": env["BOT_REPO"],
                "clean_prs": [
                    {
                        "number": 7,
                        "headRefOid": "head-seven",
                        "baseRefName": "main",
                        "baseRefOid": "base-zero",
                        "targetBaseOid": "target-zero",
                        "files": [],
                    },
                    {
                        "number": 8,
                        "headRefOid": "head-eight",
                        "baseRefName": "main",
                        "baseRefOid": "base-zero",
                        "targetBaseOid": "target-zero",
                        "files": [],
                    },
                ],
            }

            def fake_gh_json(cmd, *, env=None, timeout=120):
                number = int(cmd[cmd.index("view") + 1])
                suffix = "seven" if number == 7 else "eight"
                return {
                    "number": number,
                    "state": "MERGED",
                    "headRefOid": f"head-{suffix}",
                    "baseRefName": "main",
                    "baseRefOid": "base-zero",
                    "mergeCommit": {"oid": f"merge-{suffix}"},
                }

            executor.gh_json = fake_gh_json
            executor.pr_files = lambda repo, number, env: []
            executor.commit_first_parent = lambda env, oid: "target-zero" if oid == "merge-seven" else "merge-seven"
            executor.default_branch_oid = lambda env: "merge-eight"
            self.assertEqual(executor.fully_merged_bundle_blockers(env, bundle), [])
            self.assertEqual(executor.fully_merged_bundle_proof(env, bundle), ([], "merge-eight"))

            executor.commit_first_parent = lambda env, oid: "target-zero"
            self.assertIn(
                "PR#8: final_merged_parent_changed bundle_chain=merge-seve current=target-zer",
                executor.fully_merged_bundle_blockers(env, bundle),
            )

    def test_bundle_integrity_rejects_mixed_target_base_snapshots(self):
        executor = load_executor()
        bundle = {
            "bundle_id": "repo-7-8",
            "repo": "owner/repo",
            "clean_prs": [
                {"number": 7, "headRefOid": "head-seven", "baseRefName": "main", "baseRefOid": "pr-base-a", "targetBaseOid": "target-a", "files": []},
                {"number": 8, "headRefOid": "head-eight", "baseRefName": "main", "baseRefOid": "pr-base-b", "targetBaseOid": "target-b", "files": []},
            ],
            "blockers": [],
            "approved_actions": {"merge": True, "publish": False},
            "publish_request": {"npm_tag": "latest"},
            "publish_readiness": {},
            "allowed_after_gate": [],
            "forbidden_without_gate": [],
        }
        bundle["bundle_digest"] = executor.release_bundle_digest(bundle)
        bundle["owner_approval_text"] = executor.release_owner_approval_text(bundle)
        self.assertIn("bundle_target_base_oid_inconsistent", executor.bundle_integrity_blockers(bundle))

    def test_bundle_integrity_allows_distinct_pr_base_snapshots_on_one_pinned_target(self):
        executor = load_executor()
        bundle = {
            "bundle_id": "repo-7-8",
            "repo": "owner/repo",
            "clean_prs": [
                {"number": 7, "headRefOid": "head-seven", "baseRefName": "main", "baseRefOid": "older-pr-base", "targetBaseOid": "target-base", "files": []},
                {"number": 8, "headRefOid": "head-eight", "baseRefName": "main", "baseRefOid": "newer-pr-base", "targetBaseOid": "target-base", "files": []},
            ],
            "blockers": [],
            "approved_actions": {"merge": True, "publish": False},
            "publish_request": {"npm_tag": "latest"},
            "publish_readiness": {},
            "allowed_after_gate": [],
            "forbidden_without_gate": [],
        }
        bundle["bundle_digest"] = executor.release_bundle_digest(bundle)
        bundle["owner_approval_text"] = executor.release_owner_approval_text(bundle)
        self.assertEqual(executor.bundle_integrity_blockers(bundle), [])

    def test_bundle_integrity_rejects_duplicate_pr_numbers(self):
        executor = load_executor()
        bundle = {
            "bundle_id": "repo-7-duplicate",
            "repo": "owner/repo",
            "clean_prs": [
                {"number": 7, "headRefOid": "head-one", "baseRefName": "main", "baseRefOid": "pr-base", "targetBaseOid": "target-base", "files": []},
                {"number": 7, "headRefOid": "head-two", "baseRefName": "main", "baseRefOid": "pr-base", "targetBaseOid": "target-base", "files": []},
            ],
            "blockers": [],
            "approved_actions": {"merge": True, "publish": False},
            "publish_request": {"npm_tag": "latest"},
            "publish_readiness": {},
            "allowed_after_gate": [],
            "forbidden_without_gate": [],
        }
        bundle["bundle_digest"] = executor.release_bundle_digest(bundle)
        bundle["owner_approval_text"] = executor.release_owner_approval_text(bundle)
        self.assertIn("PR#7: bundle_pr_duplicate", executor.bundle_integrity_blockers(bundle))

    def test_merge_ready_prs_has_no_callable_runtime_mutation_path(self):
        executor = load_executor()
        with self.assertRaisesRegex(
            executor.ReleaseExecutionError,
            "merge_requires_protected_broker",
        ):
            executor.merge_ready_prs(
                {"BOT_REPO": "owner/repo"},
                [{"number": 7}],
                "repo-7",
            )

    def test_merge_settle_retries_transient_unknown_mergeability(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            bundle = {"repo": env["BOT_REPO"], "clean_prs": [{"number": 31, "headRefOid": "ccc333"}]}
            calls = {"count": 0}

            def fake_gh_json(cmd, *, env=None, timeout=120):
                calls["count"] += 1
                if calls["count"] == 1:
                    return {
                        "number": 31,
                        "state": "OPEN",
                        "headRefOid": "ccc333",
                        "baseRefName": "main",
                        "isDraft": False,
                        "mergeStateStatus": "UNKNOWN",
                        "mergeable": "UNKNOWN",
                        "reviewDecision": None,
                        "statusCheckRollup": [],
                    }
                return {
                    "number": 31,
                    "state": "OPEN",
                    "headRefOid": "ccc333",
                    "baseRefName": "main",
                    "isDraft": False,
                    "mergeStateStatus": "CLEAN",
                    "mergeable": "MERGEABLE",
                    "reviewDecision": None,
                    "statusCheckRollup": [],
                }

            executor.gh_json = fake_gh_json
            executor.pr_files = lambda repo, number, env: []
            executor.unresolved_threads = lambda repo, number, env: {"unresolved": 0, "unresolved_current": 0}
            executor.codex_clean_for_head = lambda repo, number, head, env: (True, "test-codex-clean")
            executor.time.sleep = lambda seconds: None

            ready, blockers, merged = executor.verify_bundle_with_settle(env, bundle, attempts=2, delay=0)
            self.assertEqual([p["number"] for p in ready], [31])
            self.assertEqual(blockers, [])
            self.assertEqual(merged, [])
            self.assertGreaterEqual(calls["count"], 2)

    def test_human_approved_pr_still_requires_current_codex_evidence(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            bundle = {"repo": env["BOT_REPO"], "clean_prs": [{"number": 32, "headRefOid": "ddd444"}]}

            def fake_gh_json(cmd, *, env=None, timeout=120):
                return {
                    "number": 32,
                    "state": "OPEN",
                    "headRefOid": "ddd444",
                    "baseRefName": "main",
                    "isDraft": False,
                    "mergeStateStatus": "CLEAN",
                    "mergeable": "MERGEABLE",
                    "reviewDecision": "APPROVED",
                    "statusCheckRollup": [],
                }

            executor.gh_json = fake_gh_json
            executor.pr_files = lambda repo, number, env: []
            executor.unresolved_threads = lambda repo, number, env: {"unresolved": 0, "unresolved_current": 0}
            executor.codex_clean_for_head = lambda repo, number, head, env: (False, "missing_latest_head_codex_clean")
            ready, blockers = executor.verify_bundle(env, bundle)
            self.assertEqual(ready, [])
            self.assertIn("PR#32: missing_latest_head_codex_clean", blockers)

    def test_release_approval_requires_configured_owner_identity(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp) | {"BOT_OWNER_APPROVERS": "owner-user"}
            approval = "APPROVE JOHN-LOMEIN BUNDLE repo-1-good: merge listed PRs"
            unsigned = executor.require_approval("repo-1-good", text=approval, merge=True, publish=False, env=env, expected_approval=approval)
            self.assertIn("approval_trust_assertion_missing", unsigned)

            env["JOHN_LOMEIN_TRUST_ASSERTION"] = self.trust_assertion(env, bundle_id="repo-1-good", approval_text=approval, actor="drive-by-user")
            blockers = executor.require_approval("repo-1-good", text=approval, merge=True, publish=False, env=env, expected_approval=approval)
            self.assertIn("approval_actor_not_trusted_owner", blockers)

            env["JOHN_LOMEIN_TRUST_ASSERTION"] = self.trust_assertion(env, bundle_id="repo-1-good", approval_text=approval, actor="owner-user")
            legacy = executor.require_approval("repo-1-good", text=approval, merge=True, publish=False, env=env)
            self.assertIn("approval_bundle_missing_generated_text", legacy)
            env["JOHN_LOMEIN_TRUST_ASSERTION"] = self.trust_assertion(env, bundle_id="repo-1-good", approval_text=approval, actor="owner-user")
            ok = executor.require_approval("repo-1-good", text=approval, merge=True, publish=False, env=env, expected_approval=approval)
            self.assertEqual(ok, [])
            env["JOHN_LOMEIN_TRUST_ASSERTION"] = self.trust_assertion(env, bundle_id="repo-1-good", approval_text=approval, actor="owner-user")
            identity_blockers, approver = executor.require_approval_with_identity("repo-1-good", text=approval, merge=True, publish=False, env=env, expected_approval=approval)
            self.assertEqual(identity_blockers, [])
            self.assertEqual(approver, "owner-user")

    def test_legacy_john_lomein_owner_approvers_env_is_not_authority(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp) | {"JOHN_LOMEIN_OWNER_APPROVERS": "owner-user"}
            approval = "APPROVE JOHN-LOMEIN BUNDLE repo-1-good: merge listed PRs"
            env["JOHN_LOMEIN_TRUST_ASSERTION"] = self.trust_assertion(env, bundle_id="repo-1-good", approval_text=approval, actor="owner-user")
            blockers = executor.require_approval("repo-1-good", text=approval, merge=True, publish=False, env=env, expected_approval=approval)
            self.assertIn("approval_trusted_owner_registry_missing", blockers)

    def test_release_approval_can_require_exact_generated_text(self):
        executor = load_executor()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp) | {"BOT_OWNER_APPROVERS": "owner-user"}
            expected = "APPROVE JOHN-LOMEIN BUNDLE repo-1-good: merge listed PRs; then run release verification; DO NOT publish."
            env["JOHN_LOMEIN_TRUST_ASSERTION"] = self.trust_assertion(env, bundle_id="repo-1-good", approval_text=expected, actor="owner-user")
            loose = executor.require_approval(
                "repo-1-good",
                text="APPROVE JOHN-LOMEIN BUNDLE repo-1-good: merge listed PRs",
                merge=True,
                publish=False,
                env=env,
                expected_approval=expected,
            )
            self.assertIn("approval_not_exact_generated_text", loose)
            self.assertFalse(any(item.startswith("approval_trust_assertion_") for item in loose))

            exact = executor.require_approval(
                "repo-1-good",
                text=expected,
                merge=True,
                publish=False,
                env=env,
                expected_approval=expected,
            )
            self.assertEqual(exact, [])

    def test_release_approval_rejects_bundle_id_prefix_collision(self):
        executor = load_executor()
        blockers = executor.require_approval(
            "repo-1",
            text="APPROVE JOHN-LOMEIN BUNDLE repo-10: merge listed PRs",
            merge=True,
            publish=False,
            env={"BOT_OWNER_APPROVERS": "owner-user"},
        )
        self.assertIn("approval_missing_or_wrong_bundle expected_prefix='APPROVE JOHN-LOMEIN BUNDLE repo-1'", blockers)

    def test_formal_codex_review_with_suggestions_is_not_executor_clean(self):
        executor = load_executor()

        def fake_gh_json(cmd, *, env=None, timeout=90):
            joined = " ".join(cmd)
            if "issues/17/comments" in joined:
                return []
            if "pulls/17/reviews" in joined:
                return [
                    {
                        "user": {"login": "chatgpt-codex-connector[bot]"},
                        "body": "### Codex Review\nDidn't find any major issues.\n\nHere are some automated review suggestions.\n\n**Reviewed commit:** `abcdef1234`",
                        "commit_id": "abcdef1234567890",
                        "html_url": "https://example/review",
                    }
                ]
            return []

        old = executor.gh_json
        executor.gh_json = fake_gh_json
        try:
            ok, evidence = executor.codex_clean_for_head("owner/repo", 17, "abcdef1234567890", {})
        finally:
            executor.gh_json = old
        self.assertFalse(ok)
        self.assertEqual(evidence, "latest_head_codex_not_clean")

    def test_empty_head_never_matches_codex_evidence(self):
        executor = load_executor()
        ok, evidence = executor.codex_clean_for_head("owner/repo", 17, "", {})
        self.assertFalse(ok)
        self.assertEqual(evidence, "missing_latest_head_codex_head")

    def test_newer_suggestion_review_revokes_older_clean_executor_evidence(self):
        executor = load_executor()

        def fake_gh_json(cmd, *, env=None, timeout=90):
            joined = " ".join(cmd)
            if "issues/17/comments" in joined:
                return []
            if "pulls/17/reviews" in joined:
                return [
                    {
                        "user": {"login": "chatgpt-codex-connector[bot]"},
                        "body": "Didn't find any major issues.\n\nReviewed commit:** `abcdef1234`",
                        "commit_id": "abcdef1234567890",
                        "submitted_at": "2026-06-29T00:04:00Z",
                        "html_url": "https://example/review-clean",
                    },
                    {
                        "user": {"login": "chatgpt-codex-connector[bot]"},
                        "body": "### Codex Review\nDidn't find any major issues.\n\nHere are some automated review suggestions.\n\n**Reviewed commit:** `abcdef1234`",
                        "commit_id": "abcdef1234567890",
                        "submitted_at": "2026-06-29T00:05:00Z",
                        "html_url": "https://example/review-suggestions",
                    },
                ]
            return []

        old = executor.gh_json
        executor.gh_json = fake_gh_json
        try:
            ok, evidence = executor.codex_clean_for_head("owner/repo", 17, "abcdef1234567890", {})
        finally:
            executor.gh_json = old
        self.assertFalse(ok)
        self.assertEqual(evidence, "latest_head_codex_not_clean")

    def test_clean_formal_codex_review_counts_for_executor_when_threads_clear(self):
        executor = load_executor()

        def fake_gh_json(cmd, *, env=None, timeout=90):
            joined = " ".join(cmd)
            if "issues/17/comments" in joined:
                return []
            if "pulls/17/reviews" in joined:
                return [
                    {
                        "user": {"login": "chatgpt-codex-connector[bot]"},
                        "body": "Didn't find any major issues.\n\nReviewed commit:** `abcdef1234`",
                        "commit_id": "abcdef1234567890",
                        "html_url": "https://example/review",
                    }
                ]
            return []

        old = executor.gh_json
        executor.gh_json = fake_gh_json
        try:
            ok, evidence = executor.codex_clean_for_head("owner/repo", 17, "abcdef1234567890", {})
        finally:
            executor.gh_json = old
        self.assertTrue(ok)
        self.assertIn("formal_review", evidence)


if __name__ == "__main__":
    unittest.main()
