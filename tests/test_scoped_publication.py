#!/usr/bin/env python3
from __future__ import annotations

import json
import fcntl
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import john_lomein_scoped_publication as publication


def git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def git_subcommand(args: Sequence[str]) -> str:
    index = 0
    if index < len(args) and args[index] == "--no-optional-locks":
        index += 1
    while index < len(args) and args[index] == "-c":
        index += 2
    return str(args[index]) if index < len(args) else ""


class HybridGitRunner:
    """Runs local Git commands but simulates all network-facing Git operations."""

    def __init__(self) -> None:
        git_path = shutil.which("git")
        assert git_path
        self.local = publication.SubprocessRunner(git_path, env=os.environ.copy())
        self.base_head = ""
        self.remote_head = ""
        self.fail_pushes = 0
        self.fail_ls_remote = False
        self.inject_after_write_tree = False
        self.fail_after_update_ref_once = False
        self.move_head_before_push = False
        self._fail_next_head_lookup = False
        self.push_attempts = 0
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, args: Sequence[str], cwd: Path | None) -> publication.CommandResult:
        args = tuple(str(item) for item in args)
        self.calls.append(args)
        command = git_subcommand(args)
        if command == "ls-remote":
            if self.fail_ls_remote:
                return publication.CommandResult(2, "", "simulated lookup failure")
            ref = args[-1]
            head = self.base_head if ref == "refs/heads/main" else self.remote_head
            output = f"{head}\t{ref}\n" if head else ""
            return publication.CommandResult(0, output, "")
        if command == "push":
            self.push_attempts += 1
            if self.fail_pushes:
                self.fail_pushes -= 1
                return publication.CommandResult(1, "", "simulated push failure")
            assert cwd is not None
            source = args[-1].split(":", 1)[0]
            if self.move_head_before_push:
                self.move_head_before_push = False
                (cwd / "README.md").write_text("concurrent local ref move\n", encoding="utf-8")
                git(cwd, "add", "README.md")
                git(cwd, "commit", "-m", "concurrent local ref move")
            self.remote_head = git(cwd, "rev-parse", source)
            return publication.CommandResult(0, "ok\n", "")
        if command == "rev-parse" and args[-1] == "HEAD" and self._fail_next_head_lookup:
            self._fail_next_head_lookup = False
            return publication.CommandResult(1, "", "simulated post-commit crash")
        result = self.local(args, cwd)
        if command == "write-tree" and self.inject_after_write_tree:
            self.inject_after_write_tree = False
            assert cwd is not None
            (cwd / "README.md").write_text("raced out of scope\n", encoding="utf-8")
            git(cwd, "add", "README.md")
        if command == "update-ref" and self.fail_after_update_ref_once:
            self.fail_after_update_ref_once = False
            self._fail_next_head_lookup = True
        return result


class FakeGitHubRunner:
    def __init__(self, git_runner: HybridGitRunner, repo: str, branch: str, base: str = "main") -> None:
        self.git_runner = git_runner
        self.repo = repo
        self.branch = branch
        self.base = base
        self.pr: dict | None = None
        self.create_count = 0
        self.force_non_draft = False
        self.head_owner_override: str | None = None
        self.calls: list[tuple[str, ...]] = []

    @staticmethod
    def value(args: tuple[str, ...], name: str) -> str:
        return args[args.index(name) + 1]

    def __call__(self, args: Sequence[str], cwd: Path | None) -> publication.CommandResult:
        args = tuple(str(item) for item in args)
        self.calls.append(args)
        if args[:2] == ("pr", "list"):
            return publication.CommandResult(0, json.dumps([self.pr] if self.pr else []), "")
        if args[:2] == ("pr", "create"):
            self.create_count += 1
            body_path = Path(self.value(args, "--body-file"))
            number = 257
            self.pr = {
                "number": number,
                "url": f"https://github.com/{self.repo}/pull/{number}",
                "state": "OPEN",
                "isDraft": not self.force_non_draft,
                "headRefName": self.value(args, "--head"),
                "headRefOid": self.git_runner.remote_head,
                "baseRefName": self.value(args, "--base"),
                "baseRefOid": self.git_runner.base_head,
                # Match live `gh pr view` output, which may leave
                # headRepository.nameWithOwner empty while returning the repo
                # name and owner as separate objects.
                "headRepository": {"name": self.repo.split("/", 1)[1], "nameWithOwner": ""},
                "headRepositoryOwner": {"login": self.head_owner_override or self.repo.split("/", 1)[0]},
                "isCrossRepository": False,
                "title": self.value(args, "--title"),
                "body": body_path.read_text(encoding="utf-8"),
            }
            return publication.CommandResult(0, self.pr["url"] + "\n", "")
        if args[:2] == ("pr", "view") and self.pr:
            return publication.CommandResult(0, json.dumps(self.pr), "")
        return publication.CommandResult(2, "", "unexpected fake GitHub command")


class RepoFixture:
    repo = "example-owner/example-repo"
    issue = 256
    branch = "forge/issue-256-proof-fixture-policy"

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.managed = self.root / "managed"
        self.worktree_root = self.root / "worktrees"
        self.worktree = self.worktree_root / "issue-256-proof-fixture-policy"
        self.cycle = self.root / "cycle"
        self.managed.mkdir()
        self.worktree_root.mkdir()
        self.cycle.mkdir()
        git(self.managed, "init")
        git(self.managed, "checkout", "-b", "main")
        git(self.managed, "config", "user.name", "Scoped Publisher Test")
        git(self.managed, "config", "user.email", "scoped-publisher.invalid")
        (self.managed / "tests").mkdir()
        (self.managed / "README.md").write_text("base\n", encoding="utf-8")
        (self.managed / "tests" / "proof.test.ts").write_text("base proof\n", encoding="utf-8")
        git(self.managed, "add", "README.md", "tests/proof.test.ts")
        git(self.managed, "commit", "-m", "initial")
        self.base = git(self.managed, "rev-parse", "HEAD")
        git(self.managed, "update-ref", "refs/remotes/origin/main", self.base)
        git(self.managed, "remote", "add", "origin", f"https://github.com/{self.repo}.git")
        git(self.managed, "worktree", "add", "-b", self.branch, str(self.worktree), self.base)
        self.git_runner = HybridGitRunner()
        self.git_runner.base_head = self.base
        self.gh_runner = FakeGitHubRunner(self.git_runner, self.repo, self.branch)

    def scope(self, paths: list[str] | None = None) -> publication.OwnerScope:
        return publication.parse_owner_scope(
            json.dumps(
                {
                    "schema_version": publication.SCOPE_SCHEMA,
                    "repo": self.repo,
                    "issue": self.issue,
                    "branch": self.branch,
                    "default_branch": "main",
                    "base_sha": self.base,
                    "allowed_paths": paths or ["tests/proof.test.ts"],
                    "draft_only": True,
                }
            )
        )

    def publish(self, scope: publication.OwnerScope | None = None, *, forbidden: Sequence[str] = ()) -> publication.PublicationResult:
        scope = scope or self.scope()
        return publication.publish_scoped_draft(
            scope,
            expected_repo=self.repo,
            expected_issue=self.issue,
            expected_branch=self.branch,
            expected_base_sha=self.base,
            default_branch="main",
            worktree=self.worktree,
            expected_worktree=self.worktree,
            worktree_root=self.worktree_root,
            managed_checkout=self.managed,
            cycle=self.cycle,
            forbidden_paths=forbidden,
            git_runner=self.git_runner,
            github_runner=self.gh_runner,
        )


class OwnerScopeParsingTest(unittest.TestCase):
    def valid_payload(self) -> dict:
        return {
            "schema_version": publication.SCOPE_SCHEMA,
            "repo": "example-owner/example-repo",
            "issue": 256,
            "branch": "forge/issue-256-proof-fixture-policy",
            "default_branch": "main",
            "base_sha": "a" * 40,
            "allowed_paths": ["tests/proof.test.ts"],
            "draft_only": True,
        }

    def test_inline_scope_is_strict_and_bound(self):
        payload = self.valid_payload()
        scope = publication.load_owner_scope({publication.SCOPE_ENV_KEY: json.dumps(payload)})

        self.assertEqual(scope.repo, payload["repo"])
        self.assertEqual(scope.issue, 256)
        self.assertEqual(scope.allowed_paths, ("tests/proof.test.ts",))
        self.assertTrue(scope.draft_only)
        self.assertRegex(scope.digest, r"^[0-9a-f]{64}$")

    def test_scope_rejects_extra_duplicate_glob_and_non_draft_authority(self):
        invalid_payloads = []
        extra = self.valid_payload()
        extra["extra"] = "not allowed"
        invalid_payloads.append(json.dumps(extra))
        glob = self.valid_payload()
        glob["allowed_paths"] = ["tests/**"]
        invalid_payloads.append(json.dumps(glob))
        nondraft = self.valid_payload()
        nondraft["draft_only"] = False
        invalid_payloads.append(json.dumps(nondraft))
        invalid_payloads.append(
            '{"schema_version":"john-lomein.forge-owner-scope.v1",'
            '"repo":"example-owner/example-repo","repo":"other/repo",'
            '"issue":256,"branch":"forge/issue-256-proof-fixture-policy","default_branch":"main",'
            f'"base_sha":"{"a" * 40}","allowed_paths":["tests/proof.test.ts"],"draft_only":true}}'
        )

        for text in invalid_payloads:
            with self.subTest(text=text[:80]):
                with self.assertRaises(publication.ScopedPublicationError):
                    publication.parse_owner_scope(text)

    def test_scope_file_requires_exclusive_source_and_owner_only_mode(self):
        payload = json.dumps(self.valid_payload())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.json"
            path.write_text(payload, encoding="utf-8")
            path.chmod(0o600)
            scope = publication.load_owner_scope({publication.SCOPE_FILE_ENV_KEY: str(path)})
            self.assertEqual(scope.source_kind, "owner_file")

            with self.assertRaisesRegex(publication.ScopedPublicationError, "exactly one"):
                publication.load_owner_scope(
                    {
                        publication.SCOPE_ENV_KEY: payload,
                        publication.SCOPE_FILE_ENV_KEY: str(path),
                    }
                )

            path.chmod(0o666)
            with self.assertRaises(publication.ScopedPublicationError) as error:
                publication.load_owner_scope({publication.SCOPE_FILE_ENV_KEY: str(path)})
            self.assertEqual(error.exception.code, "scope_file_writable_by_others")

            target = Path(tmp) / "target.json"
            target.write_text(payload, encoding="utf-8")
            target.chmod(0o600)
            link = Path(tmp) / "scope-link.json"
            link.symlink_to(target)
            with self.assertRaises(publication.ScopedPublicationError) as error:
                publication.load_owner_scope({publication.SCOPE_FILE_ENV_KEY: str(link)})
            self.assertEqual(error.exception.code, "scope_file_symlink")

    def test_origin_parser_accepts_only_canonical_github_https(self):
        self.assertEqual(
            publication.canonical_github_origin("https://github.com/example-owner/example-repo.git"),
            "example-owner/example-repo",
        )
        for value in [
            f"git{chr(64)}github.com:example-owner/example-repo.git",
            f"https://token{chr(64)}github.com/example-owner/example-repo.git",
            "https://example.com/example-owner/example-repo.git",
        ]:
            with self.subTest(value=value):
                with self.assertRaises(publication.ScopedPublicationError):
                    publication.canonical_github_origin(value)


class ScopedPublicationTest(unittest.TestCase):
    def test_happy_path_is_draft_only_and_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = RepoFixture(Path(tmp))
            (fixture.worktree / "tests" / "proof.test.ts").write_text("scoped proof\n", encoding="utf-8")

            first = fixture.publish()

            self.assertEqual(first.changed_paths, ("tests/proof.test.ts",))
            self.assertEqual(first.head_sha, fixture.git_runner.remote_head)
            self.assertEqual(first.pr_number, 257)
            self.assertFalse(first.idempotent)
            self.assertEqual(git(fixture.worktree, "status", "--porcelain"), "")
            self.assertEqual(git(fixture.worktree, "rev-list", "--count", f"{fixture.base}..HEAD"), "1")
            self.assertEqual(fixture.git_runner.push_attempts, 1)
            self.assertEqual(fixture.gh_runner.create_count, 1)
            self.assertTrue(fixture.gh_runner.pr["isDraft"])
            self.assertIn("Closes #256", fixture.gh_runner.pr["body"])
            self.assertIn("does not authorize merge", fixture.gh_runner.pr["body"])
            push = next(call for call in fixture.git_runner.calls if git_subcommand(call) == "push")
            self.assertNotIn("--force", push)
            self.assertNotIn("--force-with-lease", push)
            self.assertIn("--no-follow-tags", push)
            self.assertEqual(push[-1], f"{first.head_sha}:refs/heads/{fixture.branch}")
            artifact = json.loads(first.artifact_path.read_text(encoding="utf-8"))
            self.assertEqual(artifact["status"], "complete")
            self.assertEqual(artifact["checkpoint"], "complete")
            self.assertEqual(artifact["pr"]["head_sha"], first.head_sha)

            second = fixture.publish()

            self.assertTrue(second.idempotent)
            self.assertEqual(second.head_sha, first.head_sha)
            self.assertEqual(fixture.git_runner.push_attempts, 1)
            self.assertEqual(fixture.gh_runner.create_count, 1)
            self.assertEqual(git(fixture.worktree, "rev-list", "--count", f"{fixture.base}..HEAD"), "1")

    def test_completed_checkpoint_never_creates_a_replacement_pr(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = RepoFixture(Path(tmp))
            (fixture.worktree / "tests" / "proof.test.ts").write_text("scoped proof\n", encoding="utf-8")
            fixture.publish()
            fixture.gh_runner.pr = None

            with self.assertRaises(publication.ScopedPublicationError) as error:
                fixture.publish()

            self.assertEqual(error.exception.code, "pr_readback_failed")
            self.assertEqual(fixture.gh_runner.create_count, 1)
            artifact = json.loads((fixture.cycle / publication.ARTIFACT_NAME).read_text(encoding="utf-8"))
            self.assertEqual(artifact["checkpoint"], "complete")
            self.assertEqual(artifact["status"], "repair_due")

    def test_out_of_scope_dirty_path_fails_before_stage_or_remote_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = RepoFixture(Path(tmp))
            (fixture.worktree / "tests" / "proof.test.ts").write_text("scoped proof\n", encoding="utf-8")
            (fixture.worktree / "README.md").write_text("unscoped\n", encoding="utf-8")

            with self.assertRaises(publication.ScopedPublicationError) as error:
                fixture.publish()

            self.assertEqual(error.exception.code, "dirty_paths_outside_scope")
            self.assertEqual(git(fixture.worktree, "rev-parse", "HEAD"), fixture.base)
            self.assertEqual(git(fixture.worktree, "diff", "--cached", "--name-only"), "")
            self.assertEqual(fixture.git_runner.push_attempts, 0)
            self.assertEqual(fixture.gh_runner.create_count, 0)
            artifact = json.loads((fixture.cycle / publication.ARTIFACT_NAME).read_text(encoding="utf-8"))
            self.assertEqual(artifact["status"], "repair_due")
            self.assertEqual(artifact["error"]["code"], "dirty_paths_outside_scope")

    def test_symlink_and_forbidden_path_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = RepoFixture(Path(tmp))
            proof = fixture.worktree / "tests" / "proof.test.ts"
            proof.unlink()
            proof.symlink_to(fixture.worktree / "README.md")
            with self.assertRaises(publication.ScopedPublicationError) as error:
                fixture.publish()
            self.assertEqual(error.exception.code, "changed_path_symlink")
            self.assertEqual(fixture.git_runner.push_attempts, 0)

        with tempfile.TemporaryDirectory() as tmp:
            fixture = RepoFixture(Path(tmp))
            (fixture.worktree / "tests" / "proof.test.ts").write_text("scoped proof\n", encoding="utf-8")
            with self.assertRaises(publication.ScopedPublicationError) as error:
                fixture.publish(forbidden=["tests/**"])
            self.assertEqual(error.exception.code, "scope_contains_forbidden_path")
            self.assertEqual(fixture.git_runner.push_attempts, 0)

    def test_remote_collision_blocks_before_local_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = RepoFixture(Path(tmp))
            (fixture.worktree / "tests" / "proof.test.ts").write_text("scoped proof\n", encoding="utf-8")
            fixture.git_runner.remote_head = "f" * 40

            with self.assertRaises(publication.ScopedPublicationError) as error:
                fixture.publish()

            self.assertEqual(error.exception.code, "remote_branch_collision")
            self.assertEqual(git(fixture.worktree, "rev-parse", "HEAD"), fixture.base)
            self.assertEqual(fixture.git_runner.push_attempts, 0)
            self.assertEqual(fixture.gh_runner.create_count, 0)

    def test_push_endpoint_rewrite_and_pushurl_are_rejected_before_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = RepoFixture(Path(tmp))
            (fixture.worktree / "tests" / "proof.test.ts").write_text("scoped proof\n", encoding="utf-8")
            git(fixture.managed, "config", "remote.origin.pushurl", "https://github.com/other/repo.git")
            with self.assertRaises(publication.ScopedPublicationError) as error:
                fixture.publish()
            self.assertEqual(error.exception.code, "origin_push_endpoint_mismatch")
            self.assertEqual(git(fixture.worktree, "rev-parse", "HEAD"), fixture.base)
            self.assertEqual(fixture.git_runner.push_attempts, 0)

        with tempfile.TemporaryDirectory() as tmp:
            fixture = RepoFixture(Path(tmp))
            (fixture.worktree / "tests" / "proof.test.ts").write_text("scoped proof\n", encoding="utf-8")
            git(
                fixture.managed,
                "config",
                "url.https://github.com/other/repo.git.pushInsteadOf",
                f"https://github.com/{fixture.repo}.git",
            )
            with self.assertRaises(publication.ScopedPublicationError) as error:
                fixture.publish()
            self.assertEqual(error.exception.code, "git_url_rewrite_forbidden")
            self.assertEqual(fixture.git_runner.push_attempts, 0)

    def test_live_remote_base_and_lookup_fail_closed_before_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = RepoFixture(Path(tmp))
            (fixture.worktree / "tests" / "proof.test.ts").write_text("scoped proof\n", encoding="utf-8")
            fixture.git_runner.base_head = "f" * 40
            with self.assertRaises(publication.ScopedPublicationError) as error:
                fixture.publish()
            self.assertEqual(error.exception.code, "live_remote_base_mismatch")
            self.assertEqual(git(fixture.worktree, "rev-parse", "HEAD"), fixture.base)

        with tempfile.TemporaryDirectory() as tmp:
            fixture = RepoFixture(Path(tmp))
            (fixture.worktree / "tests" / "proof.test.ts").write_text("scoped proof\n", encoding="utf-8")
            fixture.git_runner.fail_ls_remote = True
            with self.assertRaises(publication.ScopedPublicationError) as error:
                fixture.publish()
            self.assertEqual(error.exception.code, "remote_branch_lookup_failed")
            self.assertEqual(git(fixture.worktree, "rev-parse", "HEAD"), fixture.base)

    def test_index_race_cannot_enter_the_validated_commit_or_push(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = RepoFixture(Path(tmp))
            (fixture.worktree / "tests" / "proof.test.ts").write_text("scoped proof\n", encoding="utf-8")
            fixture.git_runner.inject_after_write_tree = True

            with self.assertRaises(publication.ScopedPublicationError) as error:
                fixture.publish()

            self.assertEqual(error.exception.code, "worktree_not_clean")
            self.assertEqual(git(fixture.worktree, "show", "HEAD:README.md"), "base")
            self.assertEqual(fixture.git_runner.push_attempts, 0)
            artifact = json.loads((fixture.cycle / publication.ARTIFACT_NAME).read_text(encoding="utf-8"))
            self.assertEqual(artifact["checkpoint"], "validated")
            self.assertRegex(artifact["expected_tree"], r"^[0-9a-f]{40}$")

    def test_head_move_before_push_cannot_change_the_exact_remote_ref(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = RepoFixture(Path(tmp))
            (fixture.worktree / "tests" / "proof.test.ts").write_text("scoped proof\n", encoding="utf-8")
            fixture.git_runner.move_head_before_push = True

            with self.assertRaises(publication.ScopedPublicationError) as error:
                fixture.publish()

            self.assertEqual(error.exception.code, "committed_head_mismatch")
            artifact = json.loads((fixture.cycle / publication.ARTIFACT_NAME).read_text(encoding="utf-8"))
            self.assertEqual(fixture.git_runner.remote_head, artifact["head_sha"])
            self.assertNotEqual(git(fixture.worktree, "rev-parse", "HEAD"), artifact["head_sha"])
            self.assertEqual(fixture.gh_runner.create_count, 0)

    def test_git_control_paths_must_be_owner_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = RepoFixture(Path(tmp))
            (fixture.worktree / ".git").chmod(0o666)
            (fixture.worktree / "tests" / "proof.test.ts").write_text("scoped proof\n", encoding="utf-8")
            with self.assertRaises(publication.ScopedPublicationError) as error:
                fixture.publish()
            self.assertEqual(error.exception.code, "worktree_git_pointer_unsafe")
            self.assertEqual(fixture.git_runner.push_attempts, 0)

        with tempfile.TemporaryDirectory() as tmp:
            fixture = RepoFixture(Path(tmp))
            (fixture.managed / ".git").chmod(0o777)
            (fixture.worktree / "tests" / "proof.test.ts").write_text("scoped proof\n", encoding="utf-8")
            with self.assertRaises(publication.ScopedPublicationError) as error:
                fixture.publish()
            self.assertEqual(error.exception.code, "worktree_common_git_unsafe")
            self.assertEqual(fixture.git_runner.push_attempts, 0)

    def test_post_commit_checkpoint_crash_recovers_exact_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = RepoFixture(Path(tmp))
            (fixture.worktree / "tests" / "proof.test.ts").write_text("scoped proof\n", encoding="utf-8")
            fixture.git_runner.fail_after_update_ref_once = True

            with self.assertRaises(publication.ScopedPublicationError):
                fixture.publish()

            interrupted_head = git(fixture.worktree, "rev-parse", "HEAD")
            artifact = json.loads((fixture.cycle / publication.ARTIFACT_NAME).read_text(encoding="utf-8"))
            self.assertEqual(artifact["checkpoint"], "validated")
            self.assertEqual(git(fixture.worktree, "rev-list", "--count", f"{fixture.base}..HEAD"), "1")

            result = fixture.publish()

            self.assertEqual(result.head_sha, interrupted_head)
            self.assertEqual(fixture.git_runner.push_attempts, 1)
            self.assertEqual(fixture.gh_runner.create_count, 1)

    def test_cycle_lock_serializes_publishers(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = RepoFixture(Path(tmp))
            (fixture.worktree / "tests" / "proof.test.ts").write_text("scoped proof\n", encoding="utf-8")
            lock_path = fixture.cycle / publication.LOCK_NAME
            fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(publication.ScopedPublicationError) as error:
                    fixture.publish()
                self.assertEqual(error.exception.code, "publication_lock_busy")
                self.assertEqual(fixture.git_runner.calls, [])
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    def test_failed_push_resumes_from_committed_checkpoint_without_recommit(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = RepoFixture(Path(tmp))
            (fixture.worktree / "tests" / "proof.test.ts").write_text("scoped proof\n", encoding="utf-8")
            fixture.git_runner.fail_pushes = 1

            with self.assertRaises(publication.ScopedPublicationError) as error:
                fixture.publish()

            self.assertEqual(error.exception.code, "push_failed")
            committed_head = git(fixture.worktree, "rev-parse", "HEAD")
            artifact = json.loads((fixture.cycle / publication.ARTIFACT_NAME).read_text(encoding="utf-8"))
            self.assertEqual(artifact["checkpoint"], "committed")
            self.assertEqual(artifact["head_sha"], committed_head)
            self.assertEqual(git(fixture.worktree, "status", "--porcelain"), "")

            result = fixture.publish()

            self.assertEqual(result.head_sha, committed_head)
            self.assertEqual(fixture.git_runner.push_attempts, 2)
            self.assertEqual(fixture.gh_runner.create_count, 1)
            self.assertEqual(git(fixture.worktree, "rev-list", "--count", f"{fixture.base}..HEAD"), "1")

    def test_non_draft_pr_readback_stays_repair_due(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = RepoFixture(Path(tmp))
            (fixture.worktree / "tests" / "proof.test.ts").write_text("scoped proof\n", encoding="utf-8")
            fixture.gh_runner.force_non_draft = True

            with self.assertRaises(publication.ScopedPublicationError) as error:
                fixture.publish()

            self.assertEqual(error.exception.code, "pr_readback_mismatch")
            artifact = json.loads((fixture.cycle / publication.ARTIFACT_NAME).read_text(encoding="utf-8"))
            self.assertEqual(artifact["checkpoint"], "pushed")
            self.assertEqual(artifact["status"], "repair_due")
            self.assertEqual(fixture.git_runner.remote_head, git(fixture.worktree, "rev-parse", "HEAD"))
            self.assertFalse(fixture.gh_runner.pr["isDraft"])

    def test_pr_readback_uses_separate_repo_name_and_owner_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = RepoFixture(Path(tmp))
            (fixture.worktree / "tests" / "proof.test.ts").write_text("scoped proof\n", encoding="utf-8")
            fixture.gh_runner.head_owner_override = "other-owner"

            with self.assertRaises(publication.ScopedPublicationError) as error:
                fixture.publish()

            self.assertEqual(error.exception.code, "pr_head_repository_mismatch")
            self.assertEqual(fixture.gh_runner.pr["headRepository"]["nameWithOwner"], "")
            self.assertEqual(fixture.gh_runner.pr["headRepository"]["name"], "example-repo")

    def test_binding_mismatch_runs_no_commands(self):
        payload = {
            "schema_version": publication.SCOPE_SCHEMA,
            "repo": "example-owner/example-repo",
            "issue": 256,
            "branch": "forge/issue-256-proof-fixture-policy",
            "default_branch": "main",
            "base_sha": "a" * 40,
            "allowed_paths": ["tests/proof.test.ts"],
            "draft_only": True,
        }
        scope = publication.parse_owner_scope(json.dumps(payload))
        calls = []

        def forbidden_runner(args: Sequence[str], cwd: Path | None) -> publication.CommandResult:
            calls.append(args)
            raise AssertionError("binding failure must happen before commands")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cycle = root / "cycle"
            cycle.mkdir()
            with self.assertRaises(publication.ScopedPublicationError) as error:
                publication.publish_scoped_draft(
                    scope,
                    expected_repo="other/repo",
                    expected_issue=256,
                    expected_branch=scope.branch,
                    expected_base_sha=scope.base_sha,
                    default_branch="main",
                    worktree=root / "worktree",
                    expected_worktree=root / "worktree",
                    worktree_root=root,
                    managed_checkout=root / "managed",
                    cycle=cycle,
                    forbidden_paths=(),
                    git_runner=forbidden_runner,
                    github_runner=forbidden_runner,
                )
            self.assertEqual(error.exception.code, "scope_binding_mismatch")
            self.assertEqual(calls, [])

    def test_direct_owner_scope_construction_cannot_bypass_path_validation(self):
        calls = []

        def forbidden_runner(args: Sequence[str], cwd: Path | None) -> publication.CommandResult:
            calls.append(args)
            raise AssertionError("invalid scope object must fail before commands")

        scope = publication.OwnerScope(
            repo="example-owner/example-repo",
            issue=256,
            branch="forge/issue-256-proof-fixture-policy",
            default_branch="main",
            base_sha="a" * 40,
            allowed_paths=("../outside",),
            draft_only=True,
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cycle = root / "cycle"
            cycle.mkdir()
            with self.assertRaises(publication.ScopedPublicationError):
                publication.publish_scoped_draft(
                    scope,
                    expected_repo=scope.repo,
                    expected_issue=scope.issue,
                    expected_branch=scope.branch,
                    expected_base_sha=scope.base_sha,
                    default_branch="main",
                    worktree=root / "worktree",
                    expected_worktree=root / "worktree",
                    worktree_root=root,
                    managed_checkout=root / "managed",
                    cycle=cycle,
                    forbidden_paths=(),
                    git_runner=forbidden_runner,
                    github_runner=forbidden_runner,
                )
        self.assertEqual(calls, [])

    def test_raw_mode_validator_rejects_symlink_gitlink_and_mode_changes(self):
        sha = "a" * 40
        zero = "0" * 40
        unsafe = [
            f":100644 120000 {sha} {sha} M\0path\0",
            f":000000 160000 {zero} {sha} A\0submodule\0",
            f":100644 100755 {sha} {sha} M\0script\0",
        ]
        for raw in unsafe:
            with self.subTest(raw=raw[:24]):
                with self.assertRaises(publication.ScopedPublicationError):
                    publication._validate_staged_modes(raw)


if __name__ == "__main__":
    unittest.main()
