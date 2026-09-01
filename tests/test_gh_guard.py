#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
GUARD_PATH = ROOT / "scripts" / "john-lomein-gh-guard.py"
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
import john_lomein_autonomy as autonomy


def load_guard():
    spec = importlib.util.spec_from_file_location("john_lomein_gh_guard", GUARD_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class GhGuardCodexStateTest(unittest.TestCase):
    def make_fake_gh(self, tmp: str) -> tuple[Path, Path]:
        fake = Path(tmp) / "gh"
        log = Path(tmp) / "calls.json"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "args=sys.argv[1:]\n"
            "log=pathlib.Path(os.environ['GH_CALL_LOG'])\n"
            "calls=json.loads(log.read_text()) if log.exists() else []\n"
            "calls.append(args)\n"
            "log.write_text(json.dumps(calls))\n"
            "mode=os.environ.get('FAKE_GH_MODE','')\n"
            "if args[:2]==['pr','view']:\n"
            "    print(json.dumps({'headRefOid':'abcdef1234567890'})); raise SystemExit(0)\n"
            "if len(args)>=2 and args[0]=='api' and 'issues/37/comments' in args[1]:\n"
            "    if mode=='clean':\n"
            "        print(json.dumps([{'user':{'login':'chatgpt-codex-connector[bot]'},'body':'Codex Review: Didn\\'t find any major issues.\\n\\n**Reviewed commit:** `abcdef1234`','created_at':'2026-06-25T23:24:00Z'}])); raise SystemExit(0)\n"
            "    print(json.dumps([])); raise SystemExit(0)\n"
            "if len(args)>=2 and args[0]=='api' and 'pulls/37/reviews' in args[1]:\n"
            "    if mode=='reviews_fail':\n"
            "        print('reviews down', file=sys.stderr); raise SystemExit(1)\n"
            "    print(json.dumps([])); raise SystemExit(0)\n"
            "if args[:2]==['issue','create']:\n"
            "    print('https://github.com/owner/repo/issues/41'); raise SystemExit(0)\n"
            "if args[:2]==['pr','create']:\n"
            "    print('https://github.com/owner/repo/pull/42'); raise SystemExit(0)\n"
            "if len(args)>=3 and args[:2] in (['issue','comment'],['pr','comment']):\n"
            "    print('https://github.com/owner/repo/issues/'+args[2]+'#issuecomment-1'); raise SystemExit(0)\n"
            "print('passthrough')\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        return fake, log

    def make_autonomy_runtime(
        self,
        tmp: str,
        *,
        lane: str = "portfolio",
        mutation_enabled: bool = True,
        mission_complete: bool = True,
        portfolio_enabled: bool = True,
    ) -> tuple[Path, dict, dict]:
        runtime = Path(tmp) / "runtime"
        (runtime / "state").mkdir(parents=True)
        (runtime / "scripts").mkdir()
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
                    f"BOT_LOCAL='{Path(tmp) / 'repo'}'",
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
            idempotency_key=f"{lane}:guard-test",
        )
        return runtime, policy, run

    def test_deployed_gh_env_is_bound_to_the_lane_profile(self):
        guard = load_guard()
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _policy, _run = self.make_autonomy_runtime(tmp)
            cases = {
                "maintainer": (
                    "john-lomein-maintainer",
                    "john-lomein-forge",
                ),
                "portfolio": (
                    "john-lomein-maintainer",
                    "john-lomein-forge",
                ),
                "forge": (
                    "john-lomein-forge",
                    "john-lomein-maintainer",
                ),
            }
            with mock.patch.object(
                guard,
                "SCRIPT_DIR",
                runtime / "scripts",
            ):
                for lane, (expected, supplied) in cases.items():
                    with self.subTest(lane=lane):
                        supplied_config = (
                            runtime
                            / "profiles"
                            / supplied
                            / "home"
                            / ".config"
                            / "gh"
                        )
                        with mock.patch.dict(
                            os.environ,
                            {
                                "JOHN_LOMEIN_AUTONOMY_LANE": lane,
                                "GH_CONFIG_DIR": str(supplied_config),
                                "GH_TOKEN": "caller-token",
                                "HTTPS_PROXY": (
                                    "https://caller-proxy.invalid"
                                ),
                                "SSL_CERT_FILE": "/tmp/caller-ca.pem",
                            },
                        ):
                            env = guard.gh_env()
                        expected_home = (
                            runtime
                            / "profiles"
                            / expected
                            / "home"
                        ).resolve()
                        self.assertEqual(
                            Path(env["GH_CONFIG_DIR"]),
                            expected_home / ".config" / "gh",
                        )
                        self.assertEqual(
                            Path(env["HOME"]),
                            expected_home,
                        )
                        self.assertNotIn("GH_TOKEN", env)
                        self.assertNotIn("HTTPS_PROXY", env)
                        self.assertNotIn("SSL_CERT_FILE", env)
                        self.assertEqual(env["GH_HOST"], "github.com")

    def test_formal_suggestion_review_does_not_block_duplicate_codex_trigger(self):
        guard = load_guard()

        def fake_gh_json(gh, cmd):
            joined = " ".join(cmd)
            if cmd[:2] == ["pr", "view"]:
                return {"headRefOid": "abcdef1234567890"}
            if "issues/37/comments" in joined:
                return [{"user": {"login": "repo-owner"}, "body": "@Codex Review", "created_at": "2026-06-25T23:23:05Z"}]
            if "pulls/37/reviews" in joined:
                return [
                    {
                        "user": {"login": "chatgpt-codex-connector[bot]"},
                        "body": "### Codex Review\nDIDN'T FIND ANY MAJOR ISSUES.\n\nHere are some Automated Review Suggestions.\n\n**Reviewed commit:** `abcdef1234`",
                        "commit_id": "abcdef1234567890",
                        "submitted_at": "2026-06-25T23:24:00Z",
                    }
                ]
            return []

        old = guard.gh_json
        guard.gh_json = fake_gh_json
        try:
            state = guard.codex_state("gh", "owner/repo", "37")
        finally:
            guard.gh_json = old
        self.assertFalse(state["current_review"])
        self.assertFalse(state["pending"])
        self.assertFalse(state["clean_current"])

    def test_gh_guard_uses_exact_codex_login(self):
        guard = load_guard()
        self.assertTrue(guard.is_codex_login("chatgpt-codex-connector"))
        self.assertTrue(guard.is_codex_login("chatgpt-codex-connector[bot]"))
        self.assertFalse(guard.is_codex_login("chatgpt-codex-connector-evil"))
        self.assertTrue(guard.should_guard(["pr", "comment", "37", "--body", "@CODEX REVIEW"]))

    def test_pending_trigger_remains_pending_when_no_current_review_exists(self):
        guard = load_guard()

        def fake_gh_json(gh, cmd):
            joined = " ".join(cmd)
            if cmd[:2] == ["pr", "view"]:
                return {"headRefOid": "abcdef1234567890"}
            if "issues/37/comments" in joined:
                return [{"user": {"login": "repo-owner"}, "body": "@Codex Review", "created_at": "2026-06-25T23:23:05Z"}]
            if "pulls/37/reviews" in joined:
                return []
            return []

        old = guard.gh_json
        guard.gh_json = fake_gh_json
        try:
            state = guard.codex_state("gh", "owner/repo", "37")
        finally:
            guard.gh_json = old
        self.assertFalse(state["current_review"])
        self.assertTrue(state["pending"])

    def test_fake_gh_skips_duplicate_codex_review_for_clean_current_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            env = dict(os.environ)
            env.update({"JOHN_LOMEIN_REAL_GH": str(fake), "GH_CALL_LOG": str(log), "FAKE_GH_MODE": "clean"})
            proc = subprocess.run(
                [sys.executable, str(GUARD_PATH), "pr", "comment", "37", "--repo", "owner/repo", "--body", "@codex review"],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            self.assertIn("skipped duplicate @codex review", proc.stderr)
            calls = json.loads(log.read_text(encoding="utf-8"))
            self.assertFalse(any(call[:3] == ["pr", "comment", "37"] for call in calls))

    def test_fake_gh_skips_stdin_codex_review_for_clean_current_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            env = dict(os.environ)
            env.update({"JOHN_LOMEIN_REAL_GH": str(fake), "GH_CALL_LOG": str(log), "FAKE_GH_MODE": "clean"})
            proc = subprocess.run(
                [sys.executable, str(GUARD_PATH), "pr", "comment", "37", "--repo", "owner/repo", "--body-file", "-"],
                input="@CODEX REVIEW",
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            self.assertIn("skipped duplicate @codex review", proc.stderr)
            calls = json.loads(log.read_text(encoding="utf-8"))
            self.assertFalse(any(call[:3] == ["pr", "comment", "37"] for call in calls))

    def test_guarded_codex_review_fails_closed_when_state_lookup_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "gh"
            fake.write_text("#!/usr/bin/env python3\nimport sys\nprint('boom', file=sys.stderr)\nraise SystemExit(1)\n", encoding="utf-8")
            fake.chmod(0o755)
            env = dict(os.environ)
            env.update({"JOHN_LOMEIN_REAL_GH": str(fake)})
            proc = subprocess.run(
                [sys.executable, str(GUARD_PATH), "pr", "comment", "37", "--repo", "owner/repo", "--body", "@codex review"],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("refusing guarded @codex review", proc.stderr)

    def test_guarded_codex_review_fails_closed_when_review_lookup_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, _log = self.make_fake_gh(tmp)
            env = dict(os.environ)
            env.update({"JOHN_LOMEIN_REAL_GH": str(fake), "GH_CALL_LOG": str(Path(tmp) / "calls.json"), "FAKE_GH_MODE": "reviews_fail"})
            proc = subprocess.run(
                [sys.executable, str(GUARD_PATH), "pr", "comment", "37", "--repo", "owner/repo", "--body", "@codex review"],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("refusing guarded @codex review", proc.stderr)

    def test_guarded_codex_review_fails_closed_without_repo_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, _log = self.make_fake_gh(tmp)
            env = dict(os.environ)
            env.pop("BOT_REPO", None)
            env.update({"JOHN_LOMEIN_REAL_GH": str(fake), "GH_CALL_LOG": str(Path(tmp) / "calls.json")})
            proc = subprocess.run(
                [sys.executable, str(GUARD_PATH), "pr", "comment", "37", "--body", "@codex review"],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("without repo/pr metadata", proc.stderr)

    def test_fake_gh_passes_first_codex_review_request_through(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            runtime, _policy, run = self.make_autonomy_runtime(tmp, lane="maintainer")
            env = dict(os.environ)
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake),
                    "GH_CALL_LOG": str(log),
                    "FAKE_GH_MODE": "empty",
                    "BOT_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(runtime),
                    "JOHN_LOMEIN_AUTONOMY_LANE": "maintainer",
                    "JOHN_LOMEIN_AUTONOMY_RUN_ID": run["run_id"],
                }
            )
            proc = subprocess.run(
                [sys.executable, str(GUARD_PATH), "pr", "comment", "37", "--repo", "owner/repo", "--body", "@codex review"],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            calls = json.loads(log.read_text(encoding="utf-8"))
            self.assertTrue(any(call == ["pr", "comment", "37", "--repo", "owner/repo", "--body", "@codex review"] for call in calls))

    def test_protected_write_is_journaled_and_duplicate_is_not_replayed(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            runtime, _policy, run = self.make_autonomy_runtime(tmp)
            env = dict(os.environ)
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake),
                    "GH_CALL_LOG": str(log),
                    "BOT_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(runtime),
                    "JOHN_LOMEIN_AUTONOMY_LANE": "portfolio",
                    "JOHN_LOMEIN_AUTONOMY_RUN_ID": run["run_id"],
                }
            )
            command = [
                sys.executable,
                str(GUARD_PATH),
                "issue",
                "create",
                "--repo",
                "owner/repo",
                "--title",
                "Bounded work",
                "--body",
                "Evidence",
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
            self.assertEqual(
                first.stdout,
                "https://github.com/owner/repo/issues/41\n",
            )
            self.assertEqual(second.stdout, first.stdout)
            self.assertIn("effect_idempotency_completed", second.stderr)
            calls = json.loads(log.read_text(encoding="utf-8"))
            issue_creates = [
                call
                for call in calls
                if call[:2] == ["issue", "create"]
            ]
            self.assertEqual(len(issue_creates), 1)
            events = autonomy.read_events(runtime)
            self.assertEqual(
                [
                    event["event_type"]
                    for event in events
                    if event.get("effect_kind") == "issues"
                ],
                ["effect_pending", "effect_completed"],
            )

    def test_issue_idempotency_includes_captured_body_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            runtime, _policy, run = self.make_autonomy_runtime(tmp)
            env = dict(os.environ)
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake),
                    "GH_CALL_LOG": str(log),
                    "BOT_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(runtime),
                    "JOHN_LOMEIN_AUTONOMY_LANE": "portfolio",
                    "JOHN_LOMEIN_AUTONOMY_RUN_ID": run["run_id"],
                }
            )
            for body in ("First evidence", "Different evidence"):
                path = Path(tmp) / f"{body.split()[0]}.md"
                path.write_text(body, encoding="utf-8")
                proc = subprocess.run(
                    [
                        sys.executable,
                        str(GUARD_PATH),
                        "issue",
                        "create",
                        "--repo",
                        "owner/repo",
                        "--title",
                        "Same title",
                        "--body-file",
                        str(path),
                    ],
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=30,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
            calls = json.loads(log.read_text(encoding="utf-8"))
            self.assertEqual(
                len([call for call in calls if call[:2] == ["issue", "create"]]),
                2,
            )

    def test_public_writes_reject_secrets_and_private_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            runtime, _policy, run = self.make_autonomy_runtime(tmp)
            private_repo = "/" + "Users/operator/private/repo"
            synthetic_token = (
                "ghp" + "_" + "abcdefghijklmnopqrstuvwxyz123456"
            )
            env = dict(os.environ)
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake),
                    "GH_CALL_LOG": str(log),
                    "BOT_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(runtime),
                    "JOHN_LOMEIN_AUTONOMY_LANE": "portfolio",
                    "JOHN_LOMEIN_AUTONOMY_RUN_ID": run["run_id"],
                }
            )
            commands = (
                [
                    "issue",
                    "create",
                    "--repo",
                    "owner/repo",
                    "--title",
                    f"Leaked path {private_repo}",
                    "--body",
                    "This body is otherwise safe.",
                ],
                [
                    "issue",
                    "create",
                    "--repo",
                    "owner/repo",
                    "--title",
                    "Leaked credential",
                    "--body",
                    f"GH_TOKEN={synthetic_token}",
                ],
                [
                    "issue",
                    "comment",
                    "7",
                    "--repo",
                    "owner/repo",
                    "--body",
                    f"Failure log: {private_repo}/test.log",
                ],
            )
            for command in commands:
                with self.subTest(command=command):
                    proc = subprocess.run(
                        [sys.executable, str(GUARD_PATH), *command],
                        capture_output=True,
                        text=True,
                        env=env,
                        timeout=30,
                    )
                    self.assertEqual(proc.returncode, 75)
                    self.assertIn(
                        "contains secret-shaped content or a private path",
                        proc.stderr,
                    )
            self.assertFalse(log.exists())

    def test_protected_write_without_active_run_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            runtime, _policy, _run = self.make_autonomy_runtime(tmp)
            env = dict(os.environ)
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake),
                    "GH_CALL_LOG": str(log),
                    "BOT_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(runtime),
                }
            )
            env.pop("JOHN_LOMEIN_AUTONOMY_LANE", None)
            env.pop("JOHN_LOMEIN_AUTONOMY_RUN_ID", None)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(GUARD_PATH),
                    "pr",
                    "merge",
                    "17",
                    "--repo",
                    "owner/repo",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 75)
            self.assertIn("missing an active autonomy run", proc.stderr)
            self.assertFalse(log.exists())

    def test_runtime_kill_switch_blocks_direct_guard_invocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            runtime, _policy, run = self.make_autonomy_runtime(
                tmp,
                lane="portfolio",
                mutation_enabled=False,
            )
            env = dict(os.environ)
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake),
                    "GH_CALL_LOG": str(log),
                    "BOT_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(runtime),
                    "JOHN_LOMEIN_AUTONOMY_LANE": "portfolio",
                    "JOHN_LOMEIN_AUTONOMY_RUN_ID": run["run_id"],
                }
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(GUARD_PATH),
                    "issue",
                    "create",
                    "--repo",
                    "owner/repo",
                    "--title",
                    "Must stay disabled",
                    "--body",
                    "The manifest kill switch is authoritative.",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 75)
            self.assertIn("kill switch is disabled", proc.stderr)
            self.assertFalse(log.exists())

    def test_portfolio_capability_revocation_blocks_direct_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            runtime, _policy, run = self.make_autonomy_runtime(
                tmp,
                lane="portfolio",
                portfolio_enabled=False,
            )
            env = dict(os.environ)
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake),
                    "GH_CALL_LOG": str(log),
                    "BOT_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(runtime),
                    "JOHN_LOMEIN_AUTONOMY_LANE": "portfolio",
                    "JOHN_LOMEIN_AUTONOMY_RUN_ID": run["run_id"],
                }
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(GUARD_PATH),
                    "issue",
                    "create",
                    "--repo",
                    "owner/repo",
                    "--title",
                    "Must stay portfolio-gated",
                    "--body",
                    "The portfolio capability is disabled.",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 75)
            self.assertIn(
                "portfolio authority is disabled",
                proc.stderr,
            )
            self.assertFalse(log.exists())

    def test_incomplete_owner_mission_blocks_direct_guard_invocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            runtime, _policy, run = self.make_autonomy_runtime(
                tmp,
                mission_complete=False,
            )
            env = dict(os.environ)
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake),
                    "GH_CALL_LOG": str(log),
                    "BOT_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(runtime),
                    "JOHN_LOMEIN_AUTONOMY_LANE": "portfolio",
                    "JOHN_LOMEIN_AUTONOMY_RUN_ID": run["run_id"],
                }
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(GUARD_PATH),
                    "issue",
                    "create",
                    "--repo",
                    "owner/repo",
                    "--title",
                    "Must stay mission-gated",
                    "--body",
                    "The owner mission gate is authoritative.",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 75)
            self.assertIn("owner mission gate is incomplete", proc.stderr)
            self.assertFalse(log.exists())

    def test_budget_never_grants_merge_or_secret_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            runtime, _policy, run = self.make_autonomy_runtime(
                tmp,
                lane="release",
            )
            env = dict(os.environ)
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake),
                    "GH_CALL_LOG": str(log),
                    "BOT_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(runtime),
                    "JOHN_LOMEIN_AUTONOMY_LANE": "release",
                    "JOHN_LOMEIN_AUTONOMY_RUN_ID": run["run_id"],
                }
            )
            for command in (
                ["pr", "merge", "17", "--repo", "owner/repo"],
                ["secret", "set", "TOKEN", "--repo", "owner/repo"],
            ):
                with self.subTest(command=command):
                    proc = subprocess.run(
                        [sys.executable, str(GUARD_PATH), *command],
                        input="value",
                        capture_output=True,
                        text=True,
                        env=env,
                        timeout=30,
                    )
                    self.assertEqual(proc.returncode, 75)
                    self.assertIn("requires a protected broker", proc.stderr)
            self.assertFalse(log.exists())

    def test_root_repo_flag_is_rejected_for_protected_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            runtime, _policy, run = self.make_autonomy_runtime(tmp)
            env = dict(os.environ)
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake),
                    "GH_CALL_LOG": str(log),
                    "BOT_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(runtime),
                    "JOHN_LOMEIN_AUTONOMY_LANE": "portfolio",
                    "JOHN_LOMEIN_AUTONOMY_RUN_ID": run["run_id"],
                }
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(GUARD_PATH),
                    "-R",
                    "owner/repo",
                    "issue",
                    "create",
                    "--title",
                    "Root flag",
                    "--body",
                    "Still guarded",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 75)
            self.assertIn("root-level options", proc.stderr)
            self.assertFalse(log.exists())

    def test_read_only_command_does_not_require_autonomy_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            runtime, _policy, _run = self.make_autonomy_runtime(tmp)
            env = dict(os.environ)
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake),
                    "GH_CALL_LOG": str(log),
                    "BOT_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(runtime),
                }
            )
            env.pop("JOHN_LOMEIN_AUTONOMY_LANE", None)
            env.pop("JOHN_LOMEIN_AUTONOMY_RUN_ID", None)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(GUARD_PATH),
                    "issue",
                    "list",
                    "--repo",
                    "owner/repo",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            calls = json.loads(log.read_text(encoding="utf-8"))
            self.assertEqual(calls[-1][:2], ["issue", "list"])

    def test_unknown_or_destructive_commands_fail_closed_in_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            runtime, _policy, run = self.make_autonomy_runtime(
                tmp,
                lane="maintainer",
            )
            env = dict(os.environ)
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake),
                    "GH_CALL_LOG": str(log),
                    "BOT_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(runtime),
                    "JOHN_LOMEIN_AUTONOMY_LANE": "maintainer",
                    "JOHN_LOMEIN_AUTONOMY_RUN_ID": run["run_id"],
                }
            )
            commands = (
                ["run", "cancel", "123"],
                ["workflow", "disable", "ci.yml"],
                ["repo", "delete", "owner/repo"],
                [
                    "release",
                    "download",
                    "v1.0.0",
                    "--repo",
                    "owner/repo",
                    "--output",
                    "state/control.json",
                    "--clobber",
                ],
                [
                    "pr",
                    "checkout",
                    "17",
                    "--repo",
                    "owner/repo",
                    "--force",
                ],
                [
                    "api",
                    "repos/owner/repo/issues/1",
                    "-XDELETE",
                ],
                [
                    "api",
                    "repos/owner/repo/issues/1",
                    "-XGET",
                    "-XDELETE",
                ],
                ["api", "graphql", "--input", "payload.json"],
            )
            for command in commands:
                with self.subTest(command=command):
                    proc = subprocess.run(
                        [sys.executable, str(GUARD_PATH), *command],
                        capture_output=True,
                        text=True,
                        env=env,
                        timeout=30,
                    )
                    self.assertEqual(proc.returncode, 75)
            self.assertFalse(log.exists())

    def test_effects_are_bound_to_target_repo_and_cannot_self_route(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            runtime, _policy, run = self.make_autonomy_runtime(tmp)
            env = dict(os.environ)
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake),
                    "GH_CALL_LOG": str(log),
                    "BOT_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(runtime),
                    "JOHN_LOMEIN_AUTONOMY_LANE": "portfolio",
                    "JOHN_LOMEIN_AUTONOMY_RUN_ID": run["run_id"],
                }
            )
            commands = (
                [
                    "issue",
                    "create",
                    "--repo",
                    "other/repo",
                    "--title",
                    "Wrong target",
                    "--body",
                    "This must not escape.",
                ],
                [
                    "issue",
                    "create",
                    "--repo",
                    "owner/repo",
                    "--title",
                    "Self route",
                    "--body",
                    "This must not self route.",
                    "--label",
                    "forge-ready",
                ],
                [
                    "issue",
                    "create",
                    "--repo",
                    "owner/repo",
                    "--repo",
                    "other/repo",
                    "--title",
                    "Duplicate repo",
                    "--body",
                    "Ambiguous target must fail.",
                ],
                [
                    "issue",
                    "edit",
                    "1",
                    "2",
                    "--repo",
                    "owner/repo",
                    "--add-label",
                    "triage-needed",
                ],
                [
                    "issue",
                    "edit",
                    "1",
                    "--repo",
                    "owner/repo",
                    "--add-label",
                    "triage-needed",
                    "-t",
                    "Also edits title",
                ],
                [
                    "pr",
                    "comment",
                    "HTTPS://github.com/other/repo/pull/9",
                    "--repo",
                    "owner/repo",
                    "--body",
                    "A URL target must not override the repo flag.",
                ],
                [
                    "pr",
                    "comment",
                    "HTTPS://github.com/owner/repo/pull/9",
                    "--repo",
                    "owner/repo",
                    "--body",
                    "URL plus repo is intentionally ambiguous.",
                ],
            )
            for command in commands:
                with self.subTest(command=command):
                    proc = subprocess.run(
                        [sys.executable, str(GUARD_PATH), *command],
                        capture_output=True,
                        text=True,
                        env=env,
                        timeout=30,
                    )
                    self.assertEqual(proc.returncode, 75)
            self.assertFalse(log.exists())

    def test_body_file_is_captured_once_and_replayed_via_stdin(self):
        with tempfile.TemporaryDirectory() as tmp:
            body_path = Path(tmp) / "comment.md"
            body_path.write_text("Reviewed evidence only.", encoding="utf-8")
            fake = Path(tmp) / "gh"
            log = Path(tmp) / "capture.json"
            fake.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, sys\n"
                "pathlib.Path(os.environ['BODY_PATH']).write_text('/merge')\n"
                "body=sys.stdin.buffer.read().decode('utf-8')\n"
                "pathlib.Path(os.environ['GH_CALL_LOG']).write_text(\n"
                " json.dumps({'args':sys.argv[1:],'body':body})\n"
                ")\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            runtime, _policy, run = self.make_autonomy_runtime(
                tmp,
                lane="maintainer",
            )
            env = dict(os.environ)
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake),
                    "GH_CALL_LOG": str(log),
                    "BODY_PATH": str(body_path),
                    "BOT_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(runtime),
                    "JOHN_LOMEIN_AUTONOMY_LANE": "maintainer",
                    "JOHN_LOMEIN_AUTONOMY_RUN_ID": run["run_id"],
                }
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(GUARD_PATH),
                    "pr",
                    "comment",
                    "9",
                    "--repo",
                    "owner/repo",
                    "--body-file",
                    str(body_path),
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            captured = json.loads(log.read_text(encoding="utf-8"))
            self.assertEqual(captured["body"], "Reviewed evidence only.")
            self.assertEqual(captured["args"][-2:], ["--body-file", "-"])
            self.assertEqual(body_path.read_text(encoding="utf-8"), "/merge")

    def test_api_comment_payload_must_be_single_inline_safe_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            runtime, _policy, run = self.make_autonomy_runtime(
                tmp,
                lane="maintainer",
            )
            env = dict(os.environ)
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake),
                    "GH_CALL_LOG": str(log),
                    "BOT_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(runtime),
                    "JOHN_LOMEIN_AUTONOMY_LANE": "maintainer",
                    "JOHN_LOMEIN_AUTONOMY_RUN_ID": run["run_id"],
                }
            )
            commands = (
                [
                    "api",
                    "repos/owner/repo/issues/1/comments",
                    "--input",
                    "payload.json",
                ],
                [
                    "api",
                    "repos/owner/repo/issues/1/comments",
                    "-fbody=safe",
                    "-fbody=/merge",
                ],
            )
            for command in commands:
                with self.subTest(command=command):
                    proc = subprocess.run(
                        [sys.executable, str(GUARD_PATH), *command],
                        capture_output=True,
                        text=True,
                        env=env,
                        timeout=30,
                    )
                    self.assertEqual(proc.returncode, 75)
            self.assertFalse(log.exists())

    def test_pr_creation_requires_draft_default_base_and_lane_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            runtime, _policy, run = self.make_autonomy_runtime(
                tmp,
                lane="forge",
            )
            env = dict(os.environ)
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake),
                    "GH_CALL_LOG": str(log),
                    "BOT_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(runtime),
                    "JOHN_LOMEIN_AUTONOMY_LANE": "forge",
                    "JOHN_LOMEIN_AUTONOMY_RUN_ID": run["run_id"],
                }
            )
            invalid = subprocess.run(
                [
                    sys.executable,
                    str(GUARD_PATH),
                    "pr",
                    "create",
                    "--repo",
                    "owner/repo",
                    "--base",
                    "main",
                    "--head",
                    "forge/issue-1",
                    "--title",
                    "Not draft",
                    "--body",
                    "Missing the draft gate.",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(invalid.returncode, 75)
            valid = subprocess.run(
                [
                    sys.executable,
                    str(GUARD_PATH),
                    "pr",
                    "create",
                    "--repo",
                    "owner/repo",
                    "--draft",
                    "--base",
                    "main",
                    "--head",
                    "forge/issue-1",
                    "--title",
                    "Draft",
                    "--body",
                    "The protected draft path.",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(valid.returncode, 0, valid.stderr)
            calls = json.loads(log.read_text(encoding="utf-8"))
            self.assertEqual(
                len([call for call in calls if call[:2] == ["pr", "create"]]),
                1,
            )

    def test_allowed_writes_reject_privilege_expanding_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            runtime, _policy, run = self.make_autonomy_runtime(
                tmp,
                lane="portfolio",
            )
            env = dict(os.environ)
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake),
                    "GH_CALL_LOG": str(log),
                    "BOT_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(runtime),
                    "JOHN_LOMEIN_AUTONOMY_LANE": "portfolio",
                    "JOHN_LOMEIN_AUTONOMY_RUN_ID": run["run_id"],
                }
            )
            commands = (
                [
                    "issue",
                    "create",
                    "--repo",
                    "owner/repo",
                    "--title",
                    "Assigned",
                    "--body",
                    "Evidence",
                    "--assignee",
                    "@copilot",
                ],
                [
                    "issue",
                    "create",
                    "--repo",
                    "owner/repo",
                    "--title",
                    "Labeled",
                    "--body",
                    "Evidence",
                    "--label",
                    "triage-needed",
                ],
                [
                    "pr",
                    "create",
                    "--repo",
                    "owner/repo",
                    "--draft",
                    "--base",
                    "main",
                    "--head",
                    "portfolio/work",
                    "--title",
                    "Reviewer",
                    "--body",
                    "Evidence",
                    "--reviewer",
                    "owner",
                ],
                [
                    "issue",
                    "comment",
                    "1",
                    "--repo",
                    "owner/repo",
                    "--body",
                    "Evidence",
                    "--edit-last",
                ],
            )
            for command in commands:
                with self.subTest(command=command):
                    proc = subprocess.run(
                        [sys.executable, str(GUARD_PATH), *command],
                        capture_output=True,
                        text=True,
                        env=env,
                        timeout=30,
                    )
                    self.assertEqual(proc.returncode, 75)
            self.assertFalse(log.exists())

    def test_label_mutation_is_one_allowlisted_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            runtime, _policy, run = self.make_autonomy_runtime(
                tmp,
                lane="portfolio",
            )
            env = dict(os.environ)
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake),
                    "GH_CALL_LOG": str(log),
                    "BOT_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(runtime),
                    "JOHN_LOMEIN_AUTONOMY_LANE": "portfolio",
                    "JOHN_LOMEIN_AUTONOMY_RUN_ID": run["run_id"],
                }
            )
            valid = subprocess.run(
                [
                    sys.executable,
                    str(GUARD_PATH),
                    "issue",
                    "edit",
                    "9",
                    "--repo",
                    "owner/repo",
                    "--add-label",
                    "triage-needed",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(valid.returncode, 0, valid.stderr)
            for extra in (
                ["--add-label", "deploy"],
                ["--add-label", "triage-needed,deploy"],
                [
                    "--add-label",
                    "triage-needed",
                    "--remove-label",
                    "triage-needed",
                ],
            ):
                with self.subTest(extra=extra):
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(GUARD_PATH),
                            "issue",
                            "edit",
                            "10",
                            "--repo",
                            "owner/repo",
                            *extra,
                        ],
                        capture_output=True,
                        text=True,
                        env=env,
                        timeout=30,
                    )
                    self.assertEqual(proc.returncode, 75)
            calls = json.loads(log.read_text(encoding="utf-8"))
            self.assertEqual(
                len([call for call in calls if call[:2] == ["issue", "edit"]]),
                1,
            )

    def test_triage_lane_has_only_safe_label_effect_authority(self):
        guard = load_guard()
        guard.enforce_effect_authority(
            "triage",
            ["issue", "edit"],
            "labels",
        )
        for kind, command in (
            ("public_comments", ["issue", "comment"]),
            ("issues", ["issue", "create"]),
            ("pull_requests", ["pr", "create"]),
            ("pull_request_updates", ["pr", "ready"]),
        ):
            with self.subTest(kind=kind):
                with self.assertRaises(autonomy.AutonomyError):
                    guard.enforce_effect_authority(
                        "triage",
                        command,
                        kind,
                    )

    def test_pr_ready_requires_numeric_target_and_canonical_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            runtime, _policy, run = self.make_autonomy_runtime(
                tmp,
                lane="maintainer",
            )
            env = dict(os.environ)
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake),
                    "GH_CALL_LOG": str(log),
                    "BOT_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(runtime),
                    "JOHN_LOMEIN_AUTONOMY_LANE": "maintainer",
                    "JOHN_LOMEIN_AUTONOMY_RUN_ID": run["run_id"],
                }
            )
            for command in (
                ["pr", "ready", "--repo", "owner/repo"],
                ["pr", "ready", "9", "--repo", "owner/repo", "--undo"],
                ["pr", "ready", "9", "--repo", "owner/repo"],
            ):
                with self.subTest(command=command):
                    proc = subprocess.run(
                        [sys.executable, str(GUARD_PATH), *command],
                        capture_output=True,
                        text=True,
                        env=env,
                        timeout=30,
                    )
                    self.assertEqual(proc.returncode, 75)
            self.assertFalse(log.exists())

    def test_public_comments_cannot_issue_protected_bot_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, log = self.make_fake_gh(tmp)
            runtime, _policy, run = self.make_autonomy_runtime(
                tmp,
                lane="maintainer",
            )
            env = dict(os.environ)
            env.update(
                {
                    "JOHN_LOMEIN_REAL_GH": str(fake),
                    "GH_CALL_LOG": str(log),
                    "BOT_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(runtime),
                    "JOHN_LOMEIN_AUTONOMY_LANE": "maintainer",
                    "JOHN_LOMEIN_AUTONOMY_RUN_ID": run["run_id"],
                }
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(GUARD_PATH),
                    "pr",
                    "comment",
                    "9",
                    "--repo",
                    "owner/repo",
                    "--body",
                    "/merge",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 75)
            self.assertFalse(log.exists())


if __name__ == "__main__":
    unittest.main()
