#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRIAGE_PATH = ROOT / "scripts" / "john-lomein-issue-triage.py"
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
import john_lomein_autonomy as autonomy


def load_issue_triage():
    spec = importlib.util.spec_from_file_location("john_lomein_issue_triage", TRIAGE_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class IssueTriageTest(unittest.TestCase):
    def make_home(
        self,
        tmp: str,
        *,
        mutation_enabled: bool = True,
        mission_complete: bool = True,
        safe_labels: str = "triage-needed",
        triage_label: str = "triage-needed",
    ) -> Path:
        home = Path(tmp) / "hermes"
        (home / "scripts" / "bin").mkdir(parents=True)
        (home / "state").mkdir()
        (home / "instance.yaml").write_text(
            textwrap.dedent(
                f"""
                target:
                  repo: owner/repo
                  default_branch: main
                  local_checkout: {Path(tmp) / "repo"}
                runtime:
                  mutation_enabled: {str(mutation_enabled).lower()}
                gates:
                  readiness_labels:
                  - maintainer-ready
                  - forge-ready
                  - ready-for-implementation
                  triage_needed_label: {triage_label}
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        (home / "scripts" / "john-lomein-instance.env").write_text(
            "\n".join(
                [
                    "BOT_SLUG='test-instance'",
                    "BOT_REPO='owner/repo'",
                    "BOT_DEFAULT_BRANCH='main'",
                    f"BOT_HERMES_HOME='{home}'",
                    f"BOT_LOCAL='{Path(tmp) / 'repo'}'",
                    "BOT_FORBIDDEN_PATHS_JSON='[]'",
                    "BOT_FORGE_PROFILE='john-lomein-forge'",
                    "BOT_MAINTAINER_PROFILE='john-lomein-maintainer'",
                    "BOT_OSC_PORTFOLIO_ENABLED='0'",
                    "BOT_OSC_PORTFOLIO_BRANCH_PREFIX='portfolio/'",
                    (
                        "BOT_READINESS_LABELS="
                        "'maintainer-ready,forge-ready,"
                        "ready-for-implementation'"
                    ),
                    f"BOT_AUTONOMOUS_SAFE_LABELS='{safe_labels}'",
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
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        (home / "scripts" / "john-lomein-instance.env").chmod(0o600)
        policy = autonomy.normalize_policy({})
        (
            home / "state" / "john-lomein-autonomy-policy.json"
        ).write_text(
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
        return home

    def test_acceptance_criteria_issue_is_actionable(self):
        triage = load_issue_triage()
        issue = {
            "body": "Status: proposed\n\nAcceptance criteria\n- Adds deterministic tests\n- Keeps owner gates\n\nNext: automation triage.",
        }
        self.assertEqual(triage.actionable_reason(issue), "acceptance_criteria")

    def test_dry_run_marks_actionable_issue_for_trusted_route_without_granting_readiness(self):
        triage = load_issue_triage()
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            old_env = os.environ.copy()
            old_gh_json = triage.gh_json
            os.environ.clear()
            os.environ.update({"HERMES_HOME": str(home)})

            def fake_gh_json(cmd, *, timeout=45, run_id=None):
                if cmd[:3] == ["gh", "issue", "list"]:
                    return [
                        {
                            "number": 231,
                            "title": "Automate repair",
                            "labels": [],
                            "updatedAt": "2026-06-26T00:00:00Z",
                            "body": "Status: proposed\n\nAcceptance criteria\n- Patch source\n- Add tests",
                        }
                    ]
                self.fail(f"unexpected command: {cmd}")

            triage.gh_json = fake_gh_json
            out = StringIO()
            try:
                with redirect_stdout(out):
                    code = triage.main(["--dry-run", "--json"])
            finally:
                triage.gh_json = old_gh_json
                os.environ.clear()
                os.environ.update(old_env)
            self.assertEqual(code, 0)
            data = json.loads(out.getvalue())
            self.assertTrue(data["ok"])
            self.assertEqual(data["status"], "dry_run")
            self.assertEqual(data["label_actions"], [])
            self.assertEqual(data["routed_issues"], [])
            self.assertEqual(data["actionable_candidates"][0]["number"], 231)
            self.assertEqual(data["actionable_candidates"][0]["label"], "")
            self.assertEqual(data["actionable_candidates"][0]["required_action"], "signed_route_or_trusted_github_label")
            self.assertFalse((home / "state" / "autonomy").exists())

    def test_command_env_ignores_caller_path_tokens_and_gh_config(self):
        triage = load_issue_triage()
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            gh_config = home / "profiles" / "john-lomein-maintainer" / "home" / ".config" / "gh"
            gh_config.mkdir(parents=True)
            old = os.environ.copy()
            os.environ.clear()
            os.environ.update(
                {
                    "HERMES_HOME": str(home),
                    "PATH": "/tmp/attacker-bin",
                    "GH_TOKEN": "attacker-token",
                    "GH_CONFIG_DIR": "/tmp/attacker-gh",
                }
            )
            try:
                env = triage.command_env()
                guarded = triage.command_env(run_id="run-1")
            finally:
                os.environ.clear()
                os.environ.update(old)
            self.assertEqual(
                env["PATH"],
                (
                    f"{home.resolve() / 'scripts' / 'bin'}:"
                    f"{triage.CONTROLLED_PATH}"
                ),
            )
            self.assertNotIn("GH_TOKEN", env)
            self.assertEqual(
                env["GH_CONFIG_DIR"],
                str(
                    home.resolve()
                    / "profiles"
                    / "john-lomein-maintainer"
                    / "home"
                    / ".config"
                    / "gh"
                ),
            )

            self.assertEqual(
                guarded["JOHN_LOMEIN_AUTONOMY_LANE"],
                "triage",
            )
            self.assertEqual(
                guarded["JOHN_LOMEIN_AUTONOMY_RUN_ID"],
                "run-1",
            )

    def test_manifest_authority_cannot_be_overridden_by_caller_environment(self):
        triage = load_issue_triage()
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            old = os.environ.copy()
            os.environ.update(
                {
                    "BOT_REPO": "attacker/repo",
                    "BOT_MUTATION_ENABLED": "0",
                    "BOT_READINESS_LABELS": "attacker-ready",
                    "BOT_TRIAGE_NEEDED_LABEL": "attacker-triage",
                }
            )
            try:
                cfg = triage.runtime_config(home)
            finally:
                os.environ.clear()
                os.environ.update(old)
            self.assertEqual(cfg["repo"], "owner/repo")
            self.assertIs(cfg["mutation_enabled"], True)
            self.assertNotIn("attacker-ready", cfg["readiness_labels"])
            self.assertEqual(cfg["triage_needed_label"], "triage-needed")

    def test_deployed_safe_labels_exclude_readiness_and_gate_triage_label(self):
        triage = load_issue_triage()
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(
                tmp,
                safe_labels=(
                    "triage-needed,other-safe,"
                    "ready-for-implementation"
                ),
            )
            cfg = triage.runtime_config(home)
            self.assertEqual(
                cfg["autonomous_safe_labels"],
                ["triage-needed", "other-safe"],
            )
            self.assertEqual(
                cfg["triage_needed_label"],
                "triage-needed",
            )

        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(
                tmp,
                safe_labels="other-safe,forge-ready",
                triage_label="forge-ready",
            )
            cfg = triage.runtime_config(home)
            self.assertEqual(cfg["autonomous_safe_labels"], ["other-safe"])
            self.assertEqual(
                cfg["configured_triage_needed_label"],
                "forge-ready",
            )
            self.assertEqual(cfg["triage_needed_label"], "")

    def test_dry_run_reports_unsafe_triage_label_without_mutation(self):
        triage = load_issue_triage()
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, safe_labels="other-safe")
            cfg = triage.runtime_config(home)
            old_gh_json = triage.gh_json
            old_run = triage.run

            def fake_gh_json(cmd, *, timeout=45, run_id=None):
                self.assertIsNone(run_id)
                return [
                    {
                        "number": 19,
                        "title": "Needs scope",
                        "labels": [],
                        "body": "No acceptance criteria yet.",
                    }
                ]

            triage.gh_json = fake_gh_json
            triage.run = lambda *args, **kwargs: self.fail(
                "dry-run attempted a GitHub mutation"
            )
            try:
                result = triage.triage_issues(cfg, dry_run=True)
            finally:
                triage.gh_json = old_gh_json
                triage.run = old_run

            self.assertEqual(result["triage_needed_label"], "")
            self.assertEqual(
                result["triage_needed_issues"][0]["required_action"],
                "configure_triage_label_as_autonomous_safe",
            )
            self.assertFalse((home / "state" / "autonomy").exists())

    def test_live_triage_is_guarded_and_idempotent_per_utc_hour(self):
        triage = load_issue_triage()
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp)
            cfg = triage.runtime_config(home)
            old_gh_json = triage.gh_json
            old_run = triage.run
            scans: list[str | None] = []
            writes: list[tuple[list[str], str | None]] = []

            def fake_gh_json(cmd, *, timeout=45, run_id=None):
                scans.append(run_id)
                self.assertEqual(cmd[:3], ["gh", "issue", "list"])
                return [
                    {
                        "number": 23,
                        "title": "Needs acceptance criteria",
                        "labels": [],
                        "body": "Status: proposed",
                    }
                ]

            def fake_run(cmd, **kwargs):
                writes.append((cmd, kwargs.get("run_id")))
                return (0, "", "")

            triage.gh_json = fake_gh_json
            triage.run = fake_run
            now = datetime(
                2026,
                7,
                16,
                12,
                15,
                tzinfo=timezone.utc,
            )
            try:
                first = triage.triage_issues(
                    cfg,
                    dry_run=False,
                    now=now,
                )
                duplicate = triage.triage_issues(
                    cfg,
                    dry_run=False,
                    now=now,
                )
            finally:
                triage.gh_json = old_gh_json
                triage.run = old_run

            self.assertEqual(first["status"], "ok")
            self.assertEqual(first["autonomy"]["lane"], "triage")
            self.assertEqual(
                writes,
                [
                    (
                        [
                            "gh",
                            "issue",
                            "edit",
                            "23",
                            "--repo",
                            "owner/repo",
                            "--add-label",
                            "triage-needed",
                        ],
                        first["autonomy"]["run_id"],
                    )
                ],
            )
            self.assertEqual(scans, [first["autonomy"]["run_id"]])
            self.assertEqual(duplicate["status"], "idempotent_skip")
            events = autonomy.read_events(home)
            self.assertEqual(
                [event["event_type"] for event in events],
                ["run_started", "run_finished"],
            )
            self.assertTrue(
                all(event["lane"] == "triage" for event in events)
            )
            self.assertEqual(events[-1]["status"], "ok")

    def test_live_triage_finishes_failed_run_on_unexpected_scan_error(self):
        triage = load_issue_triage()
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp)
            cfg = triage.runtime_config(home)
            old_gh_json = triage.gh_json

            def fail_scan(*args, **kwargs):
                raise ValueError("invalid GitHub JSON")

            triage.gh_json = fail_scan
            try:
                with self.assertRaises(triage.TriageError) as error:
                    triage.triage_issues(
                        cfg,
                        dry_run=False,
                        now=datetime(
                            2026,
                            7,
                            16,
                            13,
                            0,
                            tzinfo=timezone.utc,
                        ),
                    )
            finally:
                triage.gh_json = old_gh_json

            self.assertEqual(
                error.exception.code,
                "triage_run_failed",
            )
            events = autonomy.read_events(home)
            self.assertEqual(
                [event["event_type"] for event in events],
                ["run_started", "run_finished"],
            )
            self.assertEqual(events[-1]["status"], "failed")
            self.assertEqual(events[-1]["exit_code"], 2)

    def test_deployed_runtime_home_cannot_be_selected_by_caller_environment(self):
        triage = load_issue_triage()
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            scripts = home / "scripts"
            (scripts / "john-lomein-instance.env").write_text("BOT_REPO='owner/repo'\n", encoding="utf-8")
            old_dir = triage.SCRIPT_DIR
            old_env = os.environ.copy()
            triage.SCRIPT_DIR = scripts
            os.environ.clear()
            os.environ.update({"BOT_HERMES_HOME": str(Path(tmp) / "attacker"), "HERMES_HOME": str(Path(tmp) / "attacker")})
            try:
                self.assertEqual(triage.runtime_home(), home.resolve())
                self.assertTrue(
                    triage.command_env()["PATH"].startswith(
                        f"{home.resolve() / 'scripts' / 'bin'}:"
                    )
                )
            finally:
                triage.SCRIPT_DIR = old_dir
                os.environ.clear()
                os.environ.update(old_env)

    def test_mutating_run_is_blocked_when_runtime_mutation_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=False)
            env = dict(os.environ)
            for key in ["BOT_REPO", "BOT_MUTATION_ENABLED", "JOHN_LOMEIN_INSTANCE_HERMES_HOME", "BOT_HERMES_HOME"]:
                env.pop(key, None)
            env.update({"HERMES_HOME": str(home)})
            proc = subprocess.run(
                [sys.executable, str(TRIAGE_PATH), "--json"],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 3)
            data = json.loads(proc.stdout)
            self.assertEqual(data["error"], "triage_disabled")

    def test_mutating_run_is_blocked_when_owner_mission_is_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mission_complete=False)
            env = dict(os.environ)
            for key in [
                "BOT_REPO",
                "BOT_MISSION_COMPLETE",
                "BOT_MUTATION_ENABLED",
                "JOHN_LOMEIN_INSTANCE_HERMES_HOME",
                "BOT_HERMES_HOME",
            ]:
                env.pop(key, None)
            env.update({"HERMES_HOME": str(home)})
            proc = subprocess.run(
                [sys.executable, str(TRIAGE_PATH), "--json"],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 3)
            data = json.loads(proc.stdout)
            self.assertEqual(data["error"], "triage_disabled")

    def test_quoted_false_mutation_flag_is_rejected_not_enabled(self):
        triage = load_issue_triage()
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            manifest = home / "instance.yaml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    "mutation_enabled: true",
                    'mutation_enabled: "false"',
                ),
                encoding="utf-8",
            )
            with self.assertRaises(triage.TriageError) as error:
                triage.runtime_config(home)
            self.assertEqual(error.exception.code, "unsafe_instance_manifest")


if __name__ == "__main__":
    unittest.main()
