#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
GUARD = SCRIPTS / "john-lomein-git-guard.py"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import john_lomein_autonomy as autonomy


class GitGuardTest(unittest.TestCase):
    def make_fake_git(
        self,
        tmp: str,
        *,
        changed_path: str = "src/example.py",
        remote_oid: str | None = None,
    ) -> tuple[Path, Path]:
        fake = Path(tmp) / "git"
        log = Path(tmp) / "git-calls.json"
        auth_env_log = Path(tmp) / "git-auth-env.json"
        objects = Path(tmp) / "objects"
        remote_state = Path(tmp) / "remote-head"
        if remote_oid is not None:
            remote_state.write_text(remote_oid, encoding="utf-8")
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "args=sys.argv[1:]\n"
            f"log=pathlib.Path({str(log)!r})\n"
            "calls=json.loads(log.read_text()) if log.exists() else []\n"
            "calls.append(args)\n"
            "log.write_text(json.dumps(calls))\n"
            "if len(args)>=2 and args[-2:]==['rev-parse','HEAD']:\n"
            " print('a'*40); raise SystemExit(0)\n"
            "if args[-2:]==['branch','--show-current']:\n"
            " print(os.environ['JL_GIT_CURRENT_BRANCH']); raise SystemExit(0)\n"
            "if 'rev-parse' in args and args[-1].startswith('refs/heads/'):\n"
            " print('a'*40); raise SystemExit(0)\n"
            "if '--show-toplevel' in args:\n"
            " print(os.environ['JL_GIT_TOP']); raise SystemExit(0)\n"
            "if '--git-common-dir' in args:\n"
            " print(os.environ['JL_GIT_COMMON']); raise SystemExit(0)\n"
            "if 'worktree' in args and 'list' in args:\n"
            " print('worktree '+os.environ['JL_GIT_MANAGED'])\n"
            " print('branch refs/heads/main')\n"
            " print()\n"
            " print('worktree '+os.environ['JL_GIT_TOP'])\n"
            " print('branch refs/heads/'+os.environ['JL_GIT_CURRENT_BRANCH'])\n"
            " raise SystemExit(0)\n"
            "if '--git-path' in args and args[-1]=='objects':\n"
            f" print({str(objects)!r}); raise SystemExit(0)\n"
            "if 'ls-remote' in args:\n"
            f" pathlib.Path({str(auth_env_log)!r}).write_text(json.dumps({{'GH_CONFIG_DIR':os.environ.get('GH_CONFIG_DIR','')}}))\n"
            " ref=args[-1]\n"
            " if ref=='refs/heads/main':\n"
            "  print('b'*40+'\\t'+ref)\n"
            f" elif pathlib.Path({str(remote_state)!r}).exists():\n"
            f"  print(pathlib.Path({str(remote_state)!r}).read_text().strip()+'\\t'+ref)\n"
            " raise SystemExit(0)\n"
            "if len(args)>=4 and args[-4:-1]==['remote','get-url','--push']:\n"
            " print('https://github.com/owner/repo.git'); raise SystemExit(0)\n"
            "if 'config' in args and '--get-regexp' in args:\n"
            " raise SystemExit(1)\n"
            "if 'diff' in args and '--name-only' in args:\n"
            f" sys.stdout.buffer.write({(changed_path + chr(0)).encode()!r}); raise SystemExit(0)\n"
            "if 'push' in args:\n"
            " source=next(x.split(':',1)[0] for x in reversed(args) if ':refs/heads/' in x)\n"
            f" pathlib.Path({str(remote_state)!r}).write_text(source)\n"
            " print('fake git ok'); raise SystemExit(0)\n"
            "print('fake git ok')\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        objects.mkdir()
        return fake, log

    def make_fake_gh(
        self,
        tmp: str,
        *,
        login: str = "john-lomein[bot]",
        prs: object | None = None,
        auth_ok: bool = True,
    ) -> tuple[Path, Path]:
        fake = Path(tmp) / "gh"
        log = Path(tmp) / "gh-calls.json"
        payload = json.dumps([] if prs is None else prs)
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "args=sys.argv[1:]\n"
            f"log=pathlib.Path({str(log)!r})\n"
            "calls=json.loads(log.read_text()) if log.exists() else []\n"
            "calls.append({'args': args, 'env': dict(os.environ)})\n"
            "log.write_text(json.dumps(calls))\n"
            "if args[:2]==['api','user']:\n"
            f" if not {auth_ok!r}: raise SystemExit(3)\n"
            f" print({login!r}); raise SystemExit(0)\n"
            "if args[:2]==['pr','list']:\n"
            f" print({payload!r}); raise SystemExit(0)\n"
            "raise SystemExit(4)\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        return fake, log

    def make_runtime(
        self,
        tmp: str,
        *,
        lane: str = "forge",
        mutation_enabled: bool = True,
        mission_complete: bool = True,
        portfolio_enabled: bool = True,
    ) -> tuple[Path, dict]:
        runtime = Path(tmp) / "runtime"
        (runtime / "state").mkdir(parents=True)
        (runtime / "scripts").mkdir()
        managed = Path(tmp) / "repo"
        managed.mkdir(exist_ok=True)
        forge_worktree = (
            runtime / "state" / "worktrees" / "forge" / "test"
        )
        forge_worktree.mkdir(parents=True)
        (Path(tmp) / "common").mkdir()
        for profile in (
            "john-lomein-forge",
            "john-lomein-maintainer",
        ):
            (
                runtime
                / "profiles"
                / profile
                / "home"
                / ".config"
                / "gh"
            ).mkdir(parents=True)
        (runtime / "scripts" / "john-lomein-instance.env").write_text(
            "\n".join(
                [
                    "BOT_SLUG='test-instance'",
                    "BOT_REPO='owner/repo'",
                    "BOT_DEFAULT_BRANCH='main'",
                    f"BOT_HERMES_HOME='{runtime}'",
                    f"BOT_LOCAL='{managed}'",
                    "BOT_FORBIDDEN_PATHS_JSON='[]'",
                    "BOT_FORGE_PROFILE='john-lomein-forge'",
                    (
                        "BOT_MAINTAINER_PROFILE="
                        "'john-lomein-maintainer'"
                    ),
                    (
                        "BOT_MISSION_COMPLETE='1'"
                        if mission_complete
                        else "BOT_MISSION_COMPLETE='0'"
                    ),
                    (
                        "BOT_MUTATION_ENABLED='1'"
                        if mutation_enabled
                        else "BOT_MUTATION_ENABLED='0'"
                    ),
                    (
                        "BOT_OSC_PORTFOLIO_ENABLED='1'"
                        if portfolio_enabled
                        else "BOT_OSC_PORTFOLIO_ENABLED='0'"
                    ),
                    "BOT_OSC_PORTFOLIO_BRANCH_PREFIX='portfolio/'",
                    (
                        "BOT_READINESS_LABELS="
                        "'maintainer-ready,forge-ready,"
                        "ready-for-implementation'"
                    ),
                    "BOT_AUTONOMOUS_SAFE_LABELS='triage-needed'",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        (runtime / "scripts" / "john-lomein-instance.env").chmod(0o600)
        policy = autonomy.normalize_policy({})
        (runtime / "state" / "john-lomein-autonomy-policy.json").write_text(
            json.dumps(
                {
                    "schema_version": (
                        "john-lomein.autonomy-deployment.v1"
                    ),
                    "policy": policy,
                    "policy_sha256": autonomy.sha256_json(policy),
                }
            ),
            encoding="utf-8",
        )
        run = autonomy.begin_run(
            runtime,
            policy,
            lane,
            idempotency_key=f"{lane}:git-guard",
        )
        return runtime, run

    def env(
        self,
        runtime: Path,
        fake: Path,
        log: Path,
        run: dict,
        lane: str,
        source_repo: Path | None = None,
        branch: str = "forge/issue-12",
    ) -> dict[str, str]:
        source_repo = source_repo or (
            runtime / "state" / "worktrees" / "forge" / "test"
        )
        env = dict(os.environ)
        env.update(
            {
                "JOHN_LOMEIN_REAL_GIT": str(fake),
                "JOHN_LOMEIN_REAL_GH": "/usr/bin/true",
                "BOT_HERMES_HOME": str(runtime),
                "HERMES_HOME": str(runtime),
                "GH_CONFIG_DIR": str(
                    runtime
                    / "profiles"
                    / (
                        "john-lomein-forge"
                        if lane == "forge"
                        else "john-lomein-maintainer"
                    )
                    / "home"
                    / ".config"
                    / "gh"
                ),
                "JL_GIT_TOP": str(source_repo),
                "JL_GIT_MANAGED": str(fake.parent / "repo"),
                "JL_GIT_COMMON": str(fake.parent / "common"),
                "JL_GIT_CURRENT_BRANCH": branch,
                "JOHN_LOMEIN_AUTONOMY_LANE": lane,
                "JOHN_LOMEIN_AUTONOMY_RUN_ID": run["run_id"],
            }
        )
        return env

    def test_local_mutation_requires_effective_journaled_run(self):
        cases = (
            (
                "mutation_disabled",
                {"mutation_enabled": False},
                None,
                "kill switch is disabled",
            ),
            (
                "portfolio_disabled",
                {
                    "lane": "portfolio",
                    "portfolio_enabled": False,
                },
                None,
                "portfolio authority is disabled",
            ),
            (
                "forged_run",
                {},
                "not-a-journaled-run",
                "does not belong to a journaled run",
            ),
        )
        for name, options, forged_run, expected in cases:
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as tmp:
                    fake, log = self.make_fake_git(tmp)
                    lane = str(options.get("lane") or "forge")
                    runtime, run = self.make_runtime(tmp, **options)
                    env = self.env(
                        runtime,
                        fake,
                        log,
                        run,
                        lane,
                    )
                    if forged_run:
                        env["JOHN_LOMEIN_AUTONOMY_RUN_ID"] = forged_run
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(GUARD),
                            "commit",
                            "--allow-empty",
                            "-m",
                            "must remain gated",
                        ],
                        capture_output=True,
                        text=True,
                        env=env,
                        timeout=30,
                    )
                    self.assertEqual(proc.returncode, 75)
                    self.assertIn(expected, proc.stderr)
                    self.assertFalse(log.exists())

    def test_read_only_local_git_remains_available_when_mutation_is_off(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_git(tmp)
            runtime, run = self.make_runtime(
                tmp,
                mutation_enabled=False,
            )
            env = self.env(runtime, fake, log, run, "forge")
            proc = subprocess.run(
                [sys.executable, str(GUARD), "status", "--short"],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(
                json.loads(log.read_text(encoding="utf-8")),
                [["status", "--short"]],
            )

    def test_missing_forbidden_path_policy_blocks_local_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_git(tmp)
            runtime, run = self.make_runtime(tmp)
            control = (
                runtime
                / "scripts"
                / "john-lomein-instance.env"
            )
            control.write_text(
                "\n".join(
                    line
                    for line in control.read_text(
                        encoding="utf-8"
                    ).splitlines()
                    if not line.startswith("BOT_FORBIDDEN_PATHS_JSON=")
                )
                + "\n",
                encoding="utf-8",
            )
            control.chmod(0o600)
            env = self.env(runtime, fake, log, run, "forge")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(GUARD),
                    "commit",
                    "--allow-empty",
                    "-m",
                    "must remain gated",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 75)
            self.assertIn(
                "forbidden-path policy is missing",
                proc.stderr,
            )
            self.assertFalse(log.exists())

    def test_branch_push_is_journaled_and_duplicate_is_not_replayed(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_git(tmp)
            runtime, run = self.make_runtime(tmp)
            repo = runtime / "state" / "worktrees" / "forge" / "test"
            env = self.env(
                runtime,
                fake,
                log,
                run,
                "forge",
                source_repo=repo,
            )
            env["GH_CONFIG_DIR"] = str(
                runtime
                / "profiles"
                / "john-lomein-maintainer"
                / "home"
                / ".config"
                / "gh"
            )
            command = [
                sys.executable,
                str(GUARD),
                "-C",
                str(repo),
                "push",
                "--no-follow-tags",
                "origin",
                "HEAD:refs/heads/forge/issue-12",
            ]
            first = subprocess.run(
                command,
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            second = subprocess.run(
                command,
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertIn("effect_idempotency_completed", second.stderr)
            calls = json.loads(log.read_text(encoding="utf-8"))
            pushes = [
                call
                for call in calls
                if "push" in call
            ]
            self.assertEqual(len(pushes), 1)
            self.assertIn("--git-dir", pushes[0])
            self.assertIn(
                "https://github.com/owner/repo.git",
                pushes[0],
            )
            self.assertIn(
                f"{'a' * 40}:refs/heads/forge/issue-12",
                pushes[0],
            )
            self.assertNotIn("origin", pushes[0])
            self.assertFalse(
                any(
                    value == "HEAD"
                    or value.startswith("HEAD:")
                    for value in pushes[0]
                )
            )
            auth_env = json.loads(
                (Path(tmp) / "git-auth-env.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                Path(auth_env["GH_CONFIG_DIR"]),
                (
                    runtime
                    / "profiles"
                    / "john-lomein-forge"
                    / "home"
                    / ".config"
                    / "gh"
                ).resolve(),
            )
            events = autonomy.read_events(runtime)
            self.assertEqual(
                [
                    event["event_type"]
                    for event in events
                    if event.get("effect_kind") == "branches"
                ],
                ["effect_pending", "effect_completed"],
            )

    def test_deployed_cross_role_profile_binding_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_git(tmp)
            runtime, run = self.make_runtime(tmp)
            control = (
                runtime / "scripts" / "john-lomein-instance.env"
            )
            control.write_text(
                control.read_text(encoding="utf-8").replace(
                    "BOT_FORGE_PROFILE='john-lomein-forge'",
                    (
                        "BOT_FORGE_PROFILE="
                        "'john-lomein-maintainer'"
                    ),
                ),
                encoding="utf-8",
            )
            control.chmod(0o600)
            repo = (
                runtime
                / "state"
                / "worktrees"
                / "forge"
                / "test"
            )
            env = self.env(
                runtime,
                fake,
                log,
                run,
                "forge",
                source_repo=repo,
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(GUARD),
                    "-C",
                    str(repo),
                    "push",
                    "--no-follow-tags",
                    "origin",
                    "HEAD:refs/heads/forge/cross-role-profile",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 75)
            self.assertIn(
                "BOT_FORGE_PROFILE must be john-lomein-forge",
                proc.stderr,
            )
            self.assertFalse(log.exists())

    def test_maintainer_push_requires_authenticated_bot_owned_pr(self):
        with tempfile.TemporaryDirectory() as tmp:
            remote_oid = "c" * 40
            fake, log = self.make_fake_git(
                tmp,
                remote_oid=remote_oid,
            )
            fake_gh, gh_log = self.make_fake_gh(
                tmp,
                prs=[
                    {
                        "number": 17,
                        "author": {"login": "john-lomein[bot]"},
                        "headRefName": "fix/pr-17",
                        "headRefOid": remote_oid,
                        "headRepositoryOwner": {"login": "owner"},
                        "isCrossRepository": False,
                    }
                ],
            )
            runtime, run = self.make_runtime(
                tmp,
                lane="maintainer",
            )
            managed = Path(tmp) / "repo"
            env = self.env(
                runtime,
                fake,
                log,
                run,
                "maintainer",
                source_repo=managed,
                branch="fix/pr-17",
            )
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake_gh),
                    "GH_CONFIG_DIR": str(
                        runtime
                        / "profiles"
                        / "john-lomein-forge"
                        / "home"
                        / ".config"
                        / "gh"
                    ),
                    "GH_TOKEN": "caller-token",
                    "GITHUB_TOKEN": "caller-github-token",
                    "HTTPS_PROXY": "https://caller-proxy.invalid",
                    "SSL_CERT_FILE": "/tmp/caller-ca.pem",
                    "GIT_ASKPASS": "/tmp/caller-askpass",
                }
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(GUARD),
                    "-C",
                    str(managed),
                    "push",
                    "--no-follow-tags",
                    "origin",
                    "HEAD:refs/heads/fix/pr-17",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            calls = json.loads(gh_log.read_text(encoding="utf-8"))
            self.assertEqual(
                [call["args"][:2] for call in calls],
                [["api", "user"], ["pr", "list"]],
            )
            pr_args = calls[1]["args"]
            self.assertIn("--state", pr_args)
            self.assertEqual(
                pr_args[pr_args.index("--state") + 1],
                "open",
            )
            self.assertEqual(
                pr_args[pr_args.index("--head") + 1],
                "fix/pr-17",
            )
            self.assertEqual(
                pr_args[pr_args.index("--limit") + 1],
                "2",
            )
            self.assertIn("headRefOid", pr_args[-1])
            self.assertIn("isCrossRepository", pr_args[-1])
            for call in calls:
                gh_env = call["env"]
                self.assertNotIn("GH_TOKEN", gh_env)
                self.assertNotIn("GITHUB_TOKEN", gh_env)
                self.assertNotIn("HTTPS_PROXY", gh_env)
                self.assertNotIn("SSL_CERT_FILE", gh_env)
                self.assertNotIn("GIT_ASKPASS", gh_env)
                self.assertEqual(gh_env["GH_HOST"], "github.com")
                self.assertEqual(
                    Path(gh_env["GH_CONFIG_DIR"]),
                    (
                        runtime
                        / "profiles"
                        / "john-lomein-maintainer"
                        / "home"
                        / ".config"
                        / "gh"
                    ).resolve(),
                )
            git_calls = json.loads(log.read_text(encoding="utf-8"))
            self.assertEqual(
                len([call for call in git_calls if "push" in call]),
                1,
            )
            completed = [
                event
                for event in autonomy.read_events(runtime)
                if event.get("event_type") == "effect_completed"
                and event.get("effect_kind") == "branches"
            ]
            self.assertEqual(
                completed[-1]["receipt"]["number"],
                17,
            )

    def test_maintainer_push_rejects_untrusted_or_ambiguous_prs(self):
        remote_oid = "c" * 40
        valid = {
            "number": 17,
            "author": {"login": "john-lomein[bot]"},
            "headRefName": "fix/pr-17",
            "headRefOid": remote_oid,
            "headRepositoryOwner": {"login": "owner"},
            "isCrossRepository": False,
        }
        cases = {
            "human_author": (
                [{**valid, "author": {"login": "human"}}],
                "authored by the authenticated GitHub bot",
                True,
            ),
            "cross_repository": (
                [{**valid, "isCrossRepository": True}],
                "same-repository open PR",
                True,
            ),
            "wrong_repository_owner": (
                [
                    {
                        **valid,
                        "headRepositoryOwner": {"login": "attacker"},
                    }
                ],
                "same-repository open PR",
                True,
            ),
            "duplicate_bot_prs": (
                [valid, {**valid, "number": 18}],
                "exactly one same-repository open PR",
                True,
            ),
            "mixed_author_duplicate": (
                [
                    valid,
                    {
                        **valid,
                        "number": 18,
                        "author": {"login": "human"},
                    },
                ],
                "exactly one same-repository open PR",
                True,
            ),
            "stale_pr_head": (
                [{**valid, "headRefOid": "d" * 40}],
                "PR head OID does not match",
                True,
            ),
            "authentication_failure": (
                [valid],
                "cannot authenticate the GitHub bot",
                False,
            ),
        }
        for name, (prs, expected, auth_ok) in cases.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as tmp:
                    fake, log = self.make_fake_git(
                        tmp,
                        remote_oid=remote_oid,
                    )
                    fake_gh, _gh_log = self.make_fake_gh(
                        tmp,
                        prs=prs,
                        auth_ok=auth_ok,
                    )
                    runtime, run = self.make_runtime(
                        tmp,
                        lane="maintainer",
                    )
                    managed = Path(tmp) / "repo"
                    env = self.env(
                        runtime,
                        fake,
                        log,
                        run,
                        "maintainer",
                        source_repo=managed,
                        branch="fix/pr-17",
                    )
                    env["JOHN_LOMEIN_REAL_GH"] = str(fake_gh)
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(GUARD),
                            "-C",
                            str(managed),
                            "push",
                            "--no-follow-tags",
                            "origin",
                            "HEAD:refs/heads/fix/pr-17",
                        ],
                        capture_output=True,
                        text=True,
                        env=env,
                        timeout=30,
                    )
                    self.assertEqual(proc.returncode, 75)
                    self.assertIn(expected, proc.stderr)
                    git_calls = json.loads(
                        log.read_text(encoding="utf-8")
                    )
                    self.assertFalse(
                        any("push" in call for call in git_calls)
                    )

    def test_scoped_publication_safe_root_prefix_reaches_exact_push(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            fake, log = self.make_fake_git(tmp)
            runtime, run = self.make_runtime(tmp)
            repo = runtime / "state" / "worktrees" / "forge" / "test"
            env = self.env(
                runtime,
                fake,
                log,
                run,
                "forge",
                source_repo=repo,
                branch="forge/issue-12-safe-prefix",
            )
            command = [
                sys.executable,
                str(GUARD),
                "--no-optional-locks",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "commit.gpgSign=false",
                "-c",
                "tag.gpgSign=false",
                "-c",
                "core.pager=cat",
                "-c",
                "pager.status=false",
                "-c",
                "diff.external=",
                "-c",
                "interactive.diffFilter=",
                "-c",
                "submodule.recurse=false",
                "-c",
                "push.followTags=false",
                "-c",
                "push.gpgSign=false",
                "-c",
                "push.recurseSubmodules=no",
                "-c",
                "http.followRedirects=false",
                "-C",
                str(repo),
                "push",
                "--porcelain",
                "--no-follow-tags",
                "https://github.com/owner/repo.git",
                f"{'a' * 40}:refs/heads/forge/issue-12-safe-prefix",
            ]
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            calls = json.loads(log.read_text(encoding="utf-8"))
            pushes = [call for call in calls if "push" in call]
            self.assertEqual(len(pushes), 1)
            self.assertIn("--porcelain", pushes[0])
            self.assertIn(
                f"{'a' * 40}:refs/heads/forge/issue-12-safe-prefix",
                pushes[0],
            )

    def test_unsafe_root_config_is_rejected_before_git_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_git(tmp)
            runtime, run = self.make_runtime(tmp)
            env = self.env(runtime, fake, log, run, "forge")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(GUARD),
                    "-c",
                    "url.https://evil.invalid/.insteadOf=https://github.com/",
                    "push",
                    "--no-follow-tags",
                    "origin",
                    "HEAD:refs/heads/forge/unsafe-config",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 75)
            self.assertIn(
                "unsupported root-level git configuration",
                proc.stderr,
            )
            self.assertFalse(log.exists())

    def test_set_upstream_is_rejected_instead_of_silently_discarded(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_git(tmp)
            runtime, run = self.make_runtime(tmp)
            env = self.env(runtime, fake, log, run, "forge")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(GUARD),
                    "push",
                    "-u",
                    "--no-follow-tags",
                    "origin",
                    "HEAD:refs/heads/forge/upstream",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 75)
            self.assertIn(
                "unsupported guarded git push option",
                proc.stderr,
            )
            self.assertFalse(log.exists())

    def test_push_from_unrelated_repository_or_worktree_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_git(tmp)
            runtime, run = self.make_runtime(tmp)
            unrelated = Path(tmp) / "unrelated"
            unrelated.mkdir()
            env = self.env(
                runtime,
                fake,
                log,
                run,
                "forge",
                source_repo=unrelated,
                branch="forge/untrusted",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(GUARD),
                    "-C",
                    str(unrelated),
                    "push",
                    "--no-follow-tags",
                    "origin",
                    "HEAD:refs/heads/forge/untrusted",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 75)
            self.assertIn(
                "runtime worktree root",
                proc.stderr,
            )
            calls = (
                json.loads(log.read_text(encoding="utf-8"))
                if log.exists()
                else []
            )
            self.assertFalse(
                any("push" in call for call in calls)
            )

    def test_push_delta_cannot_touch_hard_forbidden_workflows(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_git(
                tmp,
                changed_path=".github/workflows/untrusted.yml",
            )
            runtime, run = self.make_runtime(tmp)
            repo = (
                runtime
                / "state"
                / "worktrees"
                / "forge"
                / "test"
            )
            env = self.env(
                runtime,
                fake,
                log,
                run,
                "forge",
                source_repo=repo,
                branch="forge/workflow-change",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(GUARD),
                    "-C",
                    str(repo),
                    "push",
                    "--no-follow-tags",
                    "origin",
                    "HEAD:refs/heads/forge/workflow-change",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 75)
            self.assertIn(
                "touches forbidden paths",
                proc.stderr,
            )
            calls = json.loads(log.read_text(encoding="utf-8"))
            self.assertFalse(
                any("push" in call for call in calls)
            )

    def test_force_and_delete_pushes_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_git(tmp)
            runtime, run = self.make_runtime(tmp)
            env = self.env(runtime, fake, log, run, "forge")
            for push_args in (
                [
                    "push",
                    "--no-follow-tags",
                    "--force",
                    "origin",
                    "HEAD:refs/heads/forge/main",
                ],
                [
                    "push",
                    "--no-follow-tags",
                    "origin",
                    ":refs/heads/obsolete",
                ],
                [
                    "push",
                    "--no-follow-tags",
                    "--tags",
                    "origin",
                ],
                [
                    "push",
                    "--dry-run",
                    "--no-dry-run",
                    "--no-follow-tags",
                    "origin",
                    "HEAD:refs/heads/forge/dry-run-bypass",
                ],
            ):
                with self.subTest(push_args=push_args):
                    proc = subprocess.run(
                        [sys.executable, str(GUARD), *push_args],
                        capture_output=True,
                        text=True,
                        env=env,
                        timeout=30,
                    )
                    self.assertEqual(proc.returncode, 75)
            self.assertFalse(log.exists())

    def test_push_requires_active_authorized_lane(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_git(tmp)
            runtime, run = self.make_runtime(tmp, lane="release")
            env = self.env(runtime, fake, log, run, "release")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(GUARD),
                    "push",
                    "origin",
                    "release-branch",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 75)
            self.assertIn("lacks branch-push authority", proc.stderr)
            self.assertFalse(log.exists())

    def test_runtime_kill_switch_blocks_direct_push(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_git(tmp)
            runtime, run = self.make_runtime(
                tmp,
                mutation_enabled=False,
            )
            env = self.env(runtime, fake, log, run, "forge")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(GUARD),
                    "push",
                    "--no-follow-tags",
                    "origin",
                    "HEAD:refs/heads/forge/disabled",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 75)
            self.assertIn("kill switch is disabled", proc.stderr)
            self.assertFalse(log.exists())

    def test_incomplete_owner_mission_blocks_direct_push(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_git(tmp)
            runtime, run = self.make_runtime(
                tmp,
                mission_complete=False,
            )
            env = self.env(runtime, fake, log, run, "forge")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(GUARD),
                    "push",
                    "--no-follow-tags",
                    "origin",
                    "HEAD:refs/heads/forge/mission-blocked",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 75)
            self.assertIn("owner mission gate is incomplete", proc.stderr)
            self.assertFalse(log.exists())

    def test_alias_send_pack_and_implicit_push_bypasses_are_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, _log = self.make_fake_git(tmp)
            runtime, run = self.make_runtime(tmp)
            env = self.env(runtime, fake, Path(tmp) / "calls.json", run, "forge")
            commands = (
                [
                    "-c",
                    "alias.p=push",
                    "p",
                    "origin",
                    "HEAD:refs/heads/forge/alias",
                ],
                [
                    "p",
                    "origin",
                    "HEAD:refs/heads/forge/alias",
                ],
                [
                    "send-pack",
                    "origin",
                    "HEAD:refs/heads/forge/send-pack",
                ],
                ["push", "--no-follow-tags", "origin"],
            )
            for command in commands:
                with self.subTest(command=command):
                    proc = subprocess.run(
                        [sys.executable, str(GUARD), *command],
                        capture_output=True,
                        text=True,
                        env=env,
                        timeout=30,
                    )
                    self.assertEqual(proc.returncode, 75)

    def test_push_is_bound_to_configured_repo_and_nondefault_branch(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_git(tmp)
            runtime, run = self.make_runtime(tmp)
            env = self.env(runtime, fake, log, run, "forge")
            env["BOT_REPO"] = "other/repo"
            commands = (
                [
                    "push",
                    "--no-follow-tags",
                    "https://github.com/other/repo.git",
                    "HEAD:refs/heads/forge/wrong-repo",
                ],
                [
                    "push",
                    "--no-follow-tags",
                    "origin",
                    "HEAD:refs/heads/main",
                ],
                [
                    "push",
                    "--no-follow-tags",
                    "origin",
                    "HEAD:refs/tags/v1",
                ],
            )
            for command in commands:
                with self.subTest(command=command):
                    proc = subprocess.run(
                        [sys.executable, str(GUARD), *command],
                        capture_output=True,
                        text=True,
                        env=env,
                        timeout=30,
                    )
                    self.assertEqual(proc.returncode, 75)


if __name__ == "__main__":
    unittest.main()
