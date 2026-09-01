#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any, cast
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
STEWARD_PATH = ROOT / "scripts" / "john-lomein-osc-portfolio-steward.py"
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
import john_lomein_autonomy as autonomy


def load_steward() -> Any:
    spec = importlib.util.spec_from_file_location("john_lomein_osc_portfolio_steward", STEWARD_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    import sys as _sys
    _sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return cast(Any, mod)


class OscPortfolioStewardTest(unittest.TestCase):
    def make_repo(self, tmp: str) -> Path:
        repo = Path(tmp) / "repo"
        (repo / ".osc/plans/active").mkdir(parents=True)
        (repo / ".osc/plans/backlog").mkdir(parents=True)
        (repo / ".osc/plans/done").mkdir(parents=True)
        (repo / ".osc/plans/active/163-proof-harness-v2.md").write_text(
            textwrap.dedent(
                """
                # Plan: 163-proof-harness-v2

                ## Status

                active

                ## Context

                Phase 3 proof harness work.

                ## Goal

                Build the proof harness.

                ## Open questions

                - Which judge model should be used?
                - Which adapter lane goes first?
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        (repo / ".osc/plans/backlog/114-work-usage-ledger-v1.md").write_text(
            textwrap.dedent(
                """
                # Plan: 114-work-usage-ledger-v1

                ## Status

                backlog

                ## Context

                Usage accounting backlog.

                ## Goal

                Add usage ledger.
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        (repo / ".osc/plans/backlog/164-distribution-launch.md").write_text(
            textwrap.dedent(
                """
                # Plan: 164-distribution-launch

                ## Status

                backlog

                ## Context

                Folds the intent of backlog plans 114 (usage ledger) into the launch proof story.

                ## Goal

                Launch distribution assets.
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        (repo / "ROADMAP.md").write_text(
            textwrap.dedent(
                """
                # Roadmap

                ## Parking lot

                - Visual dashboard beyond Discord posts.
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        return repo

    def make_home(self, tmp: str, repo: Path, *, enabled: bool = True, mutation_enabled: bool = True) -> Path:
        slug = "open" + "-scaffold"
        home = Path(tmp) / "hermes"
        (home / "scripts").mkdir(parents=True)
        (home / "instance.yaml").write_text(
            textwrap.dedent(
                f"""
                instance:
                  slug: {slug}
                target:
                  repo: owner/repo
                  default_branch: main
                  local_checkout: {repo}
                runtime:
                  mutation_enabled: {str(mutation_enabled).lower()}
                open_scaffold_portfolio:
                  enabled: {str(enabled).lower()}
                  max_gaps_per_tick: 3
                  issue_labels:
                  - portfolio-gap
                  - ready-for-implementation
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        (home / "scripts/john-lomein-instance.env").write_text(
            f"BOT_HERMES_HOME='{home}'\nHERMES_HOME='{home}'\nBOT_SLUG='{slug}'\nBOT_REPO='owner/repo'\nBOT_LOCAL='{repo}'\nBOT_DEFAULT_BRANCH='main'\nBOT_FORBIDDEN_PATHS_JSON='[]'\nBOT_FORGE_PROFILE='john-lomein-forge'\nBOT_MAINTAINER_PROFILE='john-lomein-maintainer'\nBOT_MISSION_COMPLETE='1'\nBOT_MUTATION_ENABLED='1'\nBOT_OSC_PORTFOLIO_ENABLED='1'\nBOT_OSC_PORTFOLIO_BRANCH_PREFIX='portfolio/'\nBOT_AUTONOMOUS_SAFE_LABELS='portfolio-gap'\nBOT_READINESS_LABELS='maintainer-ready,forge-ready,ready-for-implementation'\n",
            encoding="utf-8",
        )
        return home

    def test_apply_requires_effective_mission_and_authority_before_side_effects(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            home = self.make_home(
                tmp,
                repo,
                enabled=True,
                mutation_enabled=True,
            )
            env_file = home / "scripts" / "john-lomein-instance.env"
            env_file.write_text(
                env_file.read_text(encoding="utf-8")
                .replace(
                    "BOT_MISSION_COMPLETE='1'",
                    "BOT_MISSION_COMPLETE='0'",
                )
                .replace(
                    "BOT_MUTATION_ENABLED='1'",
                    "BOT_MUTATION_ENABLED='0'",
                )
                .replace(
                    "BOT_OSC_PORTFOLIO_ENABLED='1'",
                    "BOT_OSC_PORTFOLIO_ENABLED='0'",
                ),
                encoding="utf-8",
            )

            with mock.patch.object(
                steward,
                "SCRIPT_DIR",
                home / "scripts",
            ), mock.patch.object(
                steward,
                "detect_gaps",
            ) as detect, mock.patch.object(
                steward,
                "dedupe_state",
            ) as dedupe, mock.patch.object(
                steward,
                "persist_portfolio_receipt",
            ) as persist:
                with self.assertRaises(steward.PortfolioError) as caught:
                    steward.run_portfolio(
                        apply=True,
                        json_output=True,
                        issue_records=[],
                        pr_records=[],
                    )

            self.assertEqual(
                caught.exception.code,
                "portfolio_owner_mission_incomplete",
            )
            detect.assert_not_called()
            dedupe.assert_not_called()
            persist.assert_not_called()

    def test_detects_active_questions_folded_backlog_and_parking_lot(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            gaps = steward.detect_gaps(repo)
            kinds = [g.kind for g in gaps]
            self.assertIn("active_open_questions", kinds)
            self.assertIn("folded_backlog_unreconciled", kinds)
            self.assertIn("roadmap_parking_lot_unplanned", kinds)
            self.assertTrue(all(g.gap_id for g in gaps))
            private_user_prefix = "/" + "Users/"
            self.assertTrue(
                all(
                    private_user_prefix not in json.dumps(g.__dict__)
                    for g in gaps
                )
            )

    def test_dedupe_uses_existing_issue_and_pr_markers(self):
        steward = load_steward()
        records = [
            {"body": "<!-- john-lomein-osc-gap: active-open-questions-abc123 -->"},
            {"body": "text\n<!-- john-lomein-osc-gap: folded-backlog-def456 -->"},
        ]
        self.assertEqual(steward.existing_markers_from_records(records), {"active-open-questions-abc123", "folded-backlog-def456"})

    def test_dedupe_uses_github_marker_search_not_recent_page(self):
        steward = load_steward()
        seen: list[list[str]] = []
        old_run = steward.run

        def fake_run(cmd, **kwargs):
            seen.append(cmd)
            self.assertEqual(cmd[:3], ["gh", "search", "issues"])
            self.assertIn("--include-prs", cmd)
            self.assertIn("--match", cmd)
            self.assertIn("body", cmd)
            self.assertIn("--limit", cmd)
            self.assertIn("1000", cmd)
            return (
                0,
                '[{"body":"<!-- john-lomein-osc-gap: old-issue -->","state":"OPEN","number":10,"url":"https://example.invalid/issues/10","isPullRequest":false},{"body":"<!-- john-lomein-osc-gap: old-pr -->","state":"OPEN","number":11,"url":"https://example.invalid/pull/11","isPullRequest":true}]',
                "",
            )

        steward.run = fake_run
        try:
            dedupe, resumable = steward.dedupe_state("owner/repo", {"BOT_HERMES_HOME": "/tmp/hermes"})
        finally:
            steward.run = old_run
        self.assertEqual(dedupe, {"old-pr"})
        self.assertEqual(sorted(resumable), ["old-issue"])
        self.assertEqual(len(seen), 1)

    def test_dedupe_can_lookup_exact_current_gap_markers(self):
        steward = load_steward()
        seen: list[list[str]] = []
        old_run = steward.run

        def fake_run(cmd, **kwargs):
            seen.append(cmd)
            self.assertEqual(cmd[:3], ["gh", "search", "issues"])
            self.assertIn("target-gap", cmd)
            self.assertIn("--include-prs", cmd)
            self.assertIn("50", cmd)
            return (
                0,
                '[{"body":"<!-- john-lomein-osc-gap: target-gap -->","state":"CLOSED","number":10,"url":"https://example.invalid/issues/10","isPullRequest":false}]',
                "",
            )

        steward.run = fake_run
        try:
            dedupe, resumable = steward.dedupe_state("owner/repo", {"BOT_HERMES_HOME": "/tmp/hermes"}, gap_ids=["target-gap"])
        finally:
            steward.run = old_run
        self.assertEqual(dedupe, {"target-gap"})
        self.assertEqual(resumable, {})
        self.assertEqual(len(seen), 1)

    def test_next_plan_id_scans_all_plan_folders(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            (repo / ".osc/plans/done/199-done.md").write_text("# done\n", encoding="utf-8")
            self.assertEqual(steward.next_plan_id(repo), 200)

    def test_issue_create_is_label_free_then_applies_only_safe_non_readiness_labels(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            gap = steward.detect_gaps(repo)[0]
            calls: list[list[str]] = []
            old_run = steward.run

            def fake_run(cmd, **kwargs):
                calls.append(cmd)
                if cmd[:3] == ["gh", "issue", "create"]:
                    self.assertNotIn("--label", cmd)
                    self.assertNotIn("-l", cmd)
                    return (0, "https://github.com/owner/repo/issues/41", "")
                return (0, "", "")

            steward.run = fake_run
            try:
                issue = steward.create_issue(
                    "owner/repo",
                    gap,
                    ".osc/plans/backlog/200-gap.md",
                    [
                        "portfolio-gap",
                        "Needs Review",
                        "ready-for-implementation",
                        "not-autonomous-safe",
                        "PORTFOLIO-GAP",
                    ],
                    {
                        "BOT_HERMES_HOME": str(Path(tmp) / "hermes"),
                        "BOT_AUTONOMOUS_SAFE_LABELS": (
                            "portfolio-gap,Needs Review,"
                            "ready-for-implementation"
                        ),
                        "BOT_READINESS_LABELS": "custom-ready",
                    },
                )
            finally:
                steward.run = old_run

            self.assertEqual(
                calls,
                [
                    [
                        "gh",
                        "issue",
                        "create",
                        "--repo",
                        "owner/repo",
                        "--title",
                        steward.public_issue_title(gap),
                        "--body-file",
                        calls[0][-1],
                    ],
                    [
                        "gh",
                        "issue",
                        "edit",
                        "41",
                        "--repo",
                        "owner/repo",
                        "--add-label",
                        "portfolio-gap",
                    ],
                    [
                        "gh",
                        "issue",
                        "edit",
                        "41",
                        "--repo",
                        "owner/repo",
                        "--add-label",
                        "Needs Review",
                    ],
                ],
            )
            self.assertFalse(any(cmd[:3] == ["gh", "label", "create"] for cmd in calls))
            self.assertEqual(issue["label_status"], "applied")
            self.assertEqual(
                issue["labels_requested"],
                ["portfolio-gap", "Needs Review"],
            )
            self.assertEqual(
                issue["labels_applied"],
                ["portfolio-gap", "Needs Review"],
            )
            self.assertEqual(issue["label_failures"], [])

    def test_protected_issue_create_uses_guard_and_is_journaled(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            home = self.make_home(tmp, repo)
            guard_bin = home / "scripts" / "bin"
            guard_bin.mkdir()
            guard_wrapper = guard_bin / "gh"
            guard_wrapper.write_text(
                "#!/usr/bin/env python3\n"
                "import os, sys\n"
                "parts = os.environ.get('PATH', '').split(os.pathsep)\n"
                "os.environ['PATH'] = os.pathsep.join(parts[1:])\n"
                "os.execv(\n"
                "  sys.executable,\n"
                "  [\n"
                "    sys.executable,\n"
                f"    {str(ROOT / 'scripts' / 'john-lomein-gh-guard.py')!r},\n"
                "    *sys.argv[1:],\n"
                "  ],\n"
                ")\n",
                encoding="utf-8",
            )
            guard_wrapper.chmod(0o755)

            fake_bin = Path(tmp) / "trusted-bin"
            fake_bin.mkdir()
            call_log = Path(tmp) / "gh-calls.json"
            fake_gh = fake_bin / "gh"
            fake_gh.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, sys\n"
                f"log = pathlib.Path({str(call_log)!r})\n"
                "calls = json.loads(log.read_text()) if log.exists() else []\n"
                "calls.append({\n"
                "  'args': sys.argv[1:],\n"
                "  'leaked': {\n"
                "    key: os.environ.get(key)\n"
                "    for key in ('GH_TOKEN', 'GITHUB_TOKEN', "
                "'JOHN_LOMEIN_REAL_GH', 'BOT_REPO')\n"
                "    if os.environ.get(key)\n"
                "  },\n"
                "})\n"
                "log.write_text(json.dumps(calls))\n"
                "print('https://github.com/owner/repo/issues/41')\n",
                encoding="utf-8",
            )
            fake_gh.chmod(0o755)

            policy = autonomy.normalize_policy({})
            state = home / "state"
            state.mkdir()
            (state / "john-lomein-autonomy-policy.json").write_text(
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
                home,
                policy,
                "portfolio",
                idempotency_key="portfolio:steward-guard-integration",
            )
            gap = steward.detect_gaps(repo)[0]
            old_env = os.environ.copy()
            old_controlled_path = steward.CONTROLLED_PATH
            os.environ.clear()
            os.environ.update(
                {
                    "HERMES_HOME": str(home),
                    "JOHN_LOMEIN_AUTONOMY_LANE": "portfolio",
                    "JOHN_LOMEIN_AUTONOMY_RUN_ID": run["run_id"],
                    "GH_TOKEN": "caller-token-must-not-flow",
                    "GITHUB_TOKEN": "caller-token-must-not-flow",
                    "JOHN_LOMEIN_REAL_GH": "/caller/chosen/gh",
                    "BOT_REPO": "attacker/other-repo",
                }
            )
            steward.CONTROLLED_PATH = (
                f"{fake_bin}:{old_controlled_path}"
            )
            try:
                runtime_env = steward.load_env()
                command = steward.command_env(runtime_env)
                self.assertEqual(
                    command["PATH"].split(os.pathsep)[0],
                    str(guard_bin.resolve()),
                )
                self.assertEqual(
                    command["JOHN_LOMEIN_AUTONOMY_LANE"],
                    "portfolio",
                )
                self.assertEqual(
                    command["JOHN_LOMEIN_AUTONOMY_RUN_ID"],
                    run["run_id"],
                )
                self.assertNotIn("GH_TOKEN", command)
                self.assertNotIn("GITHUB_TOKEN", command)
                self.assertNotIn("JOHN_LOMEIN_REAL_GH", command)
                self.assertNotIn("BOT_REPO", command)
                issue = steward.create_issue(
                    "owner/repo",
                    gap,
                    ".osc/plans/backlog/200-gap.md",
                    [],
                    runtime_env,
                )
            finally:
                steward.CONTROLLED_PATH = old_controlled_path
                os.environ.clear()
                os.environ.update(old_env)

            self.assertEqual(issue["number"], 41)
            calls = json.loads(call_log.read_text(encoding="utf-8"))
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]["args"][:3], ["issue", "create", "--repo"])
            self.assertEqual(calls[0]["args"][-2:], ["--body-file", "-"])
            self.assertEqual(calls[0]["leaked"], {})
            events = autonomy.read_events(home)
            self.assertEqual(
                [
                    event["event_type"]
                    for event in events
                    if event.get("effect_kind") == "issues"
                ],
                ["effect_pending", "effect_completed"],
            )

    def test_command_env_rejects_non_portfolio_autonomy_authority(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "hermes"
            old_env = os.environ.copy()
            os.environ.update(
                {
                    "JOHN_LOMEIN_AUTONOMY_LANE": "forge",
                    "JOHN_LOMEIN_AUTONOMY_RUN_ID": "forged-run",
                }
            )
            try:
                with self.assertRaises(steward.PortfolioError) as cm:
                    steward.command_env({"BOT_HERMES_HOME": str(home)})
            finally:
                os.environ.clear()
                os.environ.update(old_env)
            self.assertEqual(
                cm.exception.code,
                "portfolio_wrong_autonomy_lane",
            )

    def test_optional_label_failure_does_not_undo_created_issue(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            gap = steward.detect_gaps(repo)[0]
            calls: list[list[str]] = []
            old_run = steward.run
            private_config = "/" + "Users/private/.config"

            def fake_run(cmd, **kwargs):
                calls.append(cmd)
                if cmd[:3] == ["gh", "issue", "create"]:
                    return (0, "https://github.com/owner/repo/issues/42", "")
                if cmd[-1] == "missing-safe-label":
                    return (
                        1,
                        "",
                        f"label not found in {private_config}",
                    )
                return (0, "", "")

            steward.run = fake_run
            try:
                issue = steward.create_issue(
                    "owner/repo",
                    gap,
                    ".osc/plans/backlog/200-gap.md",
                    ["portfolio-gap", "missing-safe-label"],
                    {
                        "BOT_HERMES_HOME": str(Path(tmp) / "hermes"),
                        "BOT_AUTONOMOUS_SAFE_LABELS": (
                            "portfolio-gap,missing-safe-label"
                        ),
                    },
                )
            finally:
                steward.run = old_run

            self.assertEqual(issue["number"], 42)
            self.assertEqual(
                issue["url"],
                "https://github.com/owner/repo/issues/42",
            )
            self.assertEqual(issue["label_status"], "partial")
            self.assertEqual(issue["labels_applied"], ["portfolio-gap"])
            self.assertEqual(
                issue["label_failures"][0]["label"],
                "missing-safe-label",
            )
            self.assertNotIn(
                "/" + "Users/private",
                issue["label_failures"][0]["error"],
            )
            self.assertEqual(len(calls), 3)

    def test_missing_created_issue_number_surfaces_optional_label_warning(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            gap = steward.detect_gaps(repo)[0]
            calls: list[list[str]] = []
            old_run = steward.run

            def fake_run(cmd, **kwargs):
                calls.append(cmd)
                return (0, "https://github.com/owner/repo/issues/new", "")

            steward.run = fake_run
            try:
                issue = steward.create_issue(
                    "owner/repo",
                    gap,
                    ".osc/plans/backlog/200-gap.md",
                    ["portfolio-gap"],
                    {
                        "BOT_HERMES_HOME": str(Path(tmp) / "hermes"),
                        "BOT_AUTONOMOUS_SAFE_LABELS": "portfolio-gap",
                    },
                )
            finally:
                steward.run = old_run

            self.assertIsNone(issue["number"])
            self.assertEqual(
                issue["label_status"],
                "skipped_issue_number_unavailable",
            )
            self.assertEqual(len(issue["label_failures"]), 1)
            self.assertEqual(len(calls), 1)

    def test_run_dry_run_reports_candidates_without_github_lookup(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            home = self.make_home(tmp, repo)
            old_env = os.environ.copy()
            os.environ.clear()
            os.environ.update({"HERMES_HOME": str(home)})
            try:
                data = steward.run_portfolio(apply=False, json_output=True)
            finally:
                os.environ.clear()
                os.environ.update(old_env)
            self.assertEqual(data["status"], "dry_run")
            self.assertGreaterEqual(data["candidate_count"], 2)
            self.assertTrue(data["selected_gap_ids"])
            receipt = json.loads((home / "state/factory/portfolio-receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["schema_version"], "john-lomein.factory-receipt.v1")
            self.assertEqual(receipt["loop"], "roadmap_portfolio")
            self.assertEqual(receipt["classification"], "roadmap_candidate")
            self.assertEqual(receipt["verifier"]["verdict"], "passed")
            self.assertGreaterEqual(len(receipt["evidence"]["roadmap_candidates"]), 2)
            self.assertNotIn(str(Path(tmp)), json.dumps(receipt, sort_keys=True))

    def test_disabled_config_fails_closed_cleanly(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            home = self.make_home(tmp, repo, enabled=False)
            old_env = os.environ.copy()
            os.environ.clear()
            os.environ.update({"HERMES_HOME": str(home)})
            try:
                data = steward.run_portfolio(apply=False, json_output=True)
            finally:
                os.environ.clear()
                os.environ.update(old_env)
            self.assertEqual(data["status"], "disabled")
            self.assertEqual(data["candidates"], [])
            receipt = json.loads((home / "state/factory/portfolio-receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["classification"], "clean_idle")
            self.assertEqual(receipt["evidence"]["roadmap_candidates"], [])
    def init_git_repo(self, repo: Path) -> None:
        subprocess.run(["git", "init"], cwd=repo, check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["git", "config", "user.email", "test.invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test Bot"], cwd=repo, check=True)
        subprocess.run(["git", "add", "."], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, stdout=subprocess.DEVNULL)

    def test_apply_preflights_dirty_checkout_before_public_issue(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            self.init_git_repo(repo)
            (repo / "dirty.txt").write_text("local work\n", encoding="utf-8")
            home = self.make_home(tmp, repo)
            calls: list[str] = []
            old_env = os.environ.copy()
            old_create_issue = steward.create_issue
            steward.create_issue = lambda *args, **kwargs: calls.append("issue") or {"number": 1, "url": "https://example.invalid/issues/1"}
            os.environ.clear()
            os.environ.update({"HERMES_HOME": str(home)})
            try:
                with self.assertRaises(steward.PortfolioError) as cm:
                    steward.run_portfolio(apply=True, json_output=True, issue_records=[], pr_records=[])
            finally:
                steward.create_issue = old_create_issue
                os.environ.clear()
                os.environ.update(old_env)
            self.assertEqual(cm.exception.code, "managed_checkout_dirty")
            self.assertEqual(calls, [])

    def test_unsafe_plan_dir_is_rejected_before_public_issue(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            self.init_git_repo(repo)
            home = self.make_home(tmp, repo)
            text = (home / "instance.yaml").read_text(encoding="utf-8")
            (home / "instance.yaml").write_text(text + "  plan_dir: ../../escape\n", encoding="utf-8")
            calls: list[str] = []
            old_env = os.environ.copy()
            old_create_issue = steward.create_issue
            steward.create_issue = lambda *args, **kwargs: calls.append("issue") or {"number": 1, "url": "https://example.invalid/issues/1"}
            os.environ.clear()
            os.environ.update({"HERMES_HOME": str(home)})
            try:
                with self.assertRaises(steward.PortfolioError) as cm:
                    steward.run_portfolio(apply=True, json_output=True, issue_records=[], pr_records=[])
            finally:
                steward.create_issue = old_create_issue
                os.environ.clear()
                os.environ.update(old_env)
            self.assertEqual(cm.exception.code, "unsafe_plan_dir")
            self.assertEqual(calls, [])

    def test_apply_assigns_unique_plan_paths_for_each_gap(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            self.init_git_repo(repo)
            home = self.make_home(tmp, repo)
            paths: list[str] = []
            old_env = os.environ.copy()
            old_create_issue = steward.create_issue
            old_create_plan_pr = steward.create_plan_pr
            old_preflight = steward.preflight_plan_prs

            def fake_issue(repo_name, gap, plan_path, labels, env):
                paths.append(plan_path)
                return {"number": len(paths), "url": f"https://example.invalid/issues/{len(paths)}"}

            def fake_pr(repo_name, repo_root, gap, issue, cfg, env, plan_rel, **kwargs):
                self.assertEqual(plan_rel, paths[-1])
                return {
                    "number": issue["number"],
                    "url": f"https://example.invalid/pull/{issue['number']}",
                    "branch": steward.branch_for_gap(cfg, gap),
                    "head_sha": "a" * 40,
                    "worktree": str(Path(tmp) / "private-worktree"),
                    "plan_path": plan_rel,
                }

            steward.create_issue = fake_issue
            steward.create_plan_pr = fake_pr
            steward.preflight_plan_prs = lambda *args, **kwargs: None
            os.environ.clear()
            os.environ.update({"HERMES_HOME": str(home)})
            try:
                data = steward.run_portfolio(apply=True, json_output=True, issue_records=[], pr_records=[])
            finally:
                steward.create_issue = old_create_issue
                steward.create_plan_pr = old_create_plan_pr
                steward.preflight_plan_prs = old_preflight
                os.environ.clear()
                os.environ.update(old_env)
            self.assertEqual(data["status"], "applied")
            self.assertGreaterEqual(len(paths), 3)
            self.assertEqual(len(paths), len(set(paths)))
            self.assertTrue(all(p.startswith(".osc/plans/backlog/") for p in paths))
            self.assertFalse(any("visual-dashboard" in p for p in paths))
            receipt = json.loads((home / "state/factory/portfolio-receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["classification"], "owner_action")
            self.assertEqual(receipt["verifier"]["verdict"], "passed")
            self.assertTrue(all(item["head_state"] == "observed" for item in receipt["evidence"]["mutation_progress"]))
            self.assertTrue(all(item["head_sha"] == "a" * 40 for item in receipt["evidence"]["mutation_progress"]))
            self.assertNotIn(str(Path(tmp)), json.dumps(receipt, sort_keys=True))
            self.assertNotIn("worktree", json.dumps(receipt, sort_keys=True))

    def test_apply_surfaces_optional_label_failure_without_blocking_pr(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            self.init_git_repo(repo)
            home = self.make_home(tmp, repo)
            old_env = os.environ.copy()
            old_create_issue = steward.create_issue
            old_create_plan_pr = steward.create_plan_pr
            old_preflight = steward.preflight_plan_prs
            created_prs: list[int] = []

            steward.create_issue = lambda *args, **kwargs: {
                "number": 41,
                "url": "https://example.invalid/issues/41",
                "label_status": "failed",
                "labels_requested": ["portfolio-gap"],
                "labels_applied": [],
                "label_failures": [
                    {
                        "label": "portfolio-gap",
                        "error": "label does not exist",
                    }
                ],
            }

            def fake_pr(
                repo_name,
                repo_root,
                gap,
                issue,
                cfg,
                env,
                plan_rel,
                **kwargs,
            ):
                created_prs.append(issue["number"])
                return {
                    "number": 51,
                    "url": "https://example.invalid/pull/51",
                    "branch": steward.branch_for_gap(cfg, gap),
                    "head_sha": "c" * 40,
                    "plan_path": plan_rel,
                }

            steward.create_plan_pr = fake_pr
            steward.preflight_plan_prs = lambda *args, **kwargs: None
            os.environ.clear()
            os.environ.update({"HERMES_HOME": str(home)})
            try:
                data = steward.run_portfolio(
                    apply=True,
                    json_output=True,
                    max_gaps=1,
                    issue_records=[],
                    pr_records=[],
                )
            finally:
                steward.create_issue = old_create_issue
                steward.create_plan_pr = old_create_plan_pr
                steward.preflight_plan_prs = old_preflight
                os.environ.clear()
                os.environ.update(old_env)

            self.assertEqual(created_prs, [41])
            self.assertEqual(data["status"], "applied_with_warnings")
            self.assertEqual(
                data["warnings"][0]["kind"],
                "optional_issue_labels",
            )
            self.assertEqual(
                data["warnings"][0]["status"],
                "failed",
            )
            self.assertEqual(
                data["actions"][0]["pr"]["number"],
                51,
            )
            receipt = json.loads(
                (
                    home / "state/factory/portfolio-receipt.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(
                receipt["executor_report"]["status"],
                "APPLIED_WITH_WARNINGS",
            )
            self.assertEqual(
                receipt["evidence"]["mutation_progress"][0]["issue"][
                    "label_status"
                ],
                "failed",
            )
            self.assertEqual(
                receipt["evidence"]["warnings"][0]["kind"],
                "optional_issue_labels",
            )

    def test_issue_created_then_pr_failure_persists_repair_due_checkpoint(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            self.init_git_repo(repo)
            home = self.make_home(tmp, repo)
            receipt_path = home / "state/factory/portfolio-receipt.json"
            old_env = os.environ.copy()
            old_create_issue = steward.create_issue
            old_create_plan_pr = steward.create_plan_pr
            old_preflight = steward.preflight_plan_prs
            checkpoints: list[dict[str, Any]] = []

            def fake_issue(*args, **kwargs):
                pending = json.loads(receipt_path.read_text(encoding="utf-8"))
                self.assertEqual(pending["classification"], "in_progress")
                self.assertEqual(pending["phase"], "mutation_pending")
                self.assertEqual(pending["evidence"]["mutation_progress"], [])
                self.assertEqual(len(pending["evidence"]["planned_actions"]), 1)
                return {
                    "number": 41,
                    "url": "https://example.invalid/issues/41",
                    "worktree": str(Path(tmp) / "must-not-leak"),
                    "token": "ghp" + "_" + "abcdefghijklmnopqrstuvwxyz0123456789",
                }

            def fake_pr(*args, **kwargs):
                issue_checkpoint = json.loads(receipt_path.read_text(encoding="utf-8"))
                checkpoints.append(issue_checkpoint)
                progress = issue_checkpoint["evidence"]["mutation_progress"]
                self.assertEqual(issue_checkpoint["classification"], "in_progress")
                self.assertEqual(issue_checkpoint["phase"], "applying")
                self.assertEqual(progress[0]["progress"], "issue_recorded")
                self.assertEqual(progress[0]["issue"]["number"], 41)
                self.assertEqual(progress[0]["issue"]["url"], "https://example.invalid/issues/41")
                self.assertTrue(progress[0]["branch"].startswith("portfolio/"))
                kwargs["progress_callback"](
                    {
                        "progress": "branch_pushed",
                        "branch": progress[0]["branch"],
                        "head_sha": "b" * 40,
                    }
                )
                raise steward.PortfolioError("pr_create_failed", "draft PR creation failed")

            steward.create_issue = fake_issue
            steward.create_plan_pr = fake_pr
            steward.preflight_plan_prs = lambda *args, **kwargs: None
            os.environ.clear()
            os.environ.update({"HERMES_HOME": str(home)})
            try:
                with self.assertRaises(steward.PortfolioError) as cm:
                    steward.run_portfolio(
                        apply=True,
                        json_output=True,
                        max_gaps=1,
                        issue_records=[],
                        pr_records=[],
                    )
            finally:
                steward.create_issue = old_create_issue
                steward.create_plan_pr = old_create_plan_pr
                steward.preflight_plan_prs = old_preflight
                os.environ.clear()
                os.environ.update(old_env)

            self.assertEqual(cm.exception.code, "pr_create_failed")
            self.assertEqual(len(checkpoints), 1)
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["classification"], "repair_due")
            self.assertEqual(receipt["phase"], "blocked_partial")
            self.assertEqual(receipt["verifier"]["verdict"], "blocked")
            self.assertEqual(receipt["executor_report"]["status"], "BLOCKED_PARTIAL")
            self.assertEqual(receipt["evidence"]["error"], "pr_create_failed")
            progress = receipt["evidence"]["mutation_progress"]
            self.assertEqual(progress[0]["issue"]["number"], 41)
            self.assertIsNone(progress[0]["pr"])
            self.assertEqual(progress[0]["progress"], "branch_pushed")
            self.assertEqual(progress[0]["head_state"], "observed")
            self.assertEqual(progress[0]["head_sha"], "b" * 40)
            self.assertTrue(progress[0]["plan_path"].startswith(".osc/plans/backlog/"))
            serialized = json.dumps(receipt, sort_keys=True)
            self.assertNotIn(str(Path(tmp)), serialized)
            self.assertNotIn("must-not-leak", serialized)
            self.assertNotIn("ghp_", serialized)
            self.assertNotIn("worktree", serialized)

    def test_invalid_label_is_rejected_before_public_mutation(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            self.init_git_repo(repo)
            home = self.make_home(tmp, repo)
            text = (home / "instance.yaml").read_text(encoding="utf-8")
            (home / "instance.yaml").write_text(text.replace("- portfolio-gap", "- bad,label"), encoding="utf-8")
            calls: list[str] = []
            old_env = os.environ.copy()
            old_create_issue = steward.create_issue
            old_preflight = steward.preflight_plan_prs
            steward.create_issue = lambda *args, **kwargs: calls.append("issue") or {"number": 1, "url": "https://example.invalid/issues/1"}
            steward.preflight_plan_prs = lambda *args, **kwargs: calls.append("preflight")
            os.environ.clear()
            os.environ.update({"HERMES_HOME": str(home)})
            try:
                with self.assertRaises(steward.PortfolioError) as cm:
                    steward.run_portfolio(apply=True, json_output=True, issue_records=[], pr_records=[])
            finally:
                steward.create_issue = old_create_issue
                steward.preflight_plan_prs = old_preflight
                os.environ.clear()
                os.environ.update(old_env)
            self.assertEqual(cm.exception.code, "unsafe_label")
            self.assertEqual(calls, [])

    def test_open_issue_marker_resumes_pr_without_duplicate_issue(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            self.init_git_repo(repo)
            home = self.make_home(tmp, repo)
            first_gap = steward.detect_gaps(repo)[0]
            created_issues: list[str] = []
            pr_issues: list[int] = []
            old_env = os.environ.copy()
            old_create_issue = steward.create_issue
            old_create_plan_pr = steward.create_plan_pr
            old_preflight = steward.preflight_plan_prs
            steward.create_issue = lambda *args, **kwargs: created_issues.append("issue") or {"number": 1, "url": "https://example.invalid/issues/1"}
            steward.create_plan_pr = lambda repo_name, repo_root, gap, issue, cfg, env, plan_rel, **kwargs: pr_issues.append(issue["number"]) or {"url": "https://example.invalid/pull/42", "plan_path": plan_rel}
            steward.preflight_plan_prs = lambda *args, **kwargs: None
            os.environ.clear()
            os.environ.update({"HERMES_HOME": str(home)})
            try:
                data = steward.run_portfolio(
                    apply=True,
                    json_output=True,
                    max_gaps=1,
                    issue_records=[{"body": first_gap.marker, "state": "OPEN", "number": 42, "url": "https://example.invalid/issues/42"}],
                    pr_records=[],
                )
            finally:
                steward.create_issue = old_create_issue
                steward.create_plan_pr = old_create_plan_pr
                steward.preflight_plan_prs = old_preflight
                os.environ.clear()
                os.environ.update(old_env)
            self.assertEqual(created_issues, [])
            self.assertEqual(pr_issues, [42])
            self.assertTrue(data["actions"][0]["issue_reused"])

    def test_closed_issue_marker_suppresses_without_resume(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            first_gap = steward.detect_gaps(repo)[0]
            dedupe, resumable = steward.dedupe_state(
                "owner/repo",
                {},
                issue_records=[{"body": first_gap.marker, "state": "CLOSED", "number": 42, "url": "https://example.invalid/issues/42"}],
                pr_records=[],
            )
            self.assertIn(first_gap.gap_id, dedupe)
            self.assertEqual(resumable, {})

    def test_preflight_allows_owned_stale_worktree_for_resume_only(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            home = self.make_home(tmp, repo)
            gap = steward.detect_gaps(repo)[0]
            branch = steward.branch_for_gap({}, gap)
            worktree_root = steward.safe_portfolio_worktree_root(home)
            (worktree_root / steward.slugify(branch, 96)).mkdir(parents=True)
            env = {"BOT_HERMES_HOME": str(home), "BOT_DEFAULT_BRANCH": "main"}
            plan_rel = steward.plan_rel_for_gap({}, 200, gap)
            old_run = steward.run

            def fake_run(cmd, **kwargs):
                if "ls-remote" in cmd:
                    return (2, "", "")
                return (0, "", "")

            steward.run = fake_run
            try:
                with self.assertRaises(steward.PortfolioError) as cm:
                    steward.preflight_plan_prs("owner/repo", repo, [gap], {}, env, [plan_rel], set())
                self.assertEqual(cm.exception.code, "portfolio_worktree_exists")
                steward.preflight_plan_prs("owner/repo", repo, [gap], {}, env, [plan_rel], {gap.gap_id})
            finally:
                steward.run = old_run

    def test_preflight_rejects_symlinked_worktree_even_for_resume(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            home = self.make_home(tmp, repo)
            gap = steward.detect_gaps(repo)[0]
            branch = steward.branch_for_gap({}, gap)
            worktree_root = steward.safe_portfolio_worktree_root(home)
            target = Path(tmp) / "outside-worktree"
            target.mkdir()
            (worktree_root / steward.slugify(branch, 96)).symlink_to(target)
            env = {"BOT_HERMES_HOME": str(home), "BOT_DEFAULT_BRANCH": "main"}
            plan_rel = steward.plan_rel_for_gap({}, 200, gap)
            old_run = steward.run
            steward.run = lambda *args, **kwargs: (0, "", "")
            try:
                with self.assertRaises(steward.PortfolioError) as cm:
                    steward.preflight_plan_prs("owner/repo", repo, [gap], {}, env, [plan_rel], {gap.gap_id})
                self.assertEqual(cm.exception.code, "portfolio_worktree_symlink")
            finally:
                steward.run = old_run

    def test_resume_remote_branch_must_contain_only_expected_plan(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            gap = steward.detect_gaps(repo)[0]
            env = {"BOT_HERMES_HOME": str(Path(tmp) / "hermes"), "BOT_DEFAULT_BRANCH": "main"}
            plan_rel = steward.plan_rel_for_gap({}, 200, gap)
            old_run = steward.run

            def fake_run(cmd, **kwargs):
                if "fetch" in cmd:
                    return (0, "", "")
                if "diff" in cmd:
                    return (0, f"A\t{plan_rel}\nM\tREADME.md\n", "")
                if "show" in cmd:
                    return (0, steward.render_plan(gap, "#42"), "")
                return (0, "", "")

            steward.run = fake_run
            try:
                with self.assertRaises(steward.PortfolioError) as cm:
                    steward.validate_resume_branch(repo, gap, env, plan_rel, steward.branch_for_gap({}, gap))
                self.assertEqual(cm.exception.code, "portfolio_resume_branch_unsafe")
            finally:
                steward.run = old_run

    def test_detect_refuses_symlinked_plan_input(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            outside = Path(tmp) / "outside.md"
            outside.write_text("# outside\n\n## Status\n\nactive\n", encoding="utf-8")
            plan = repo / ".osc/plans/active/163-proof-harness-v2.md"
            plan.unlink()
            plan.symlink_to(outside)
            with self.assertRaises(steward.PortfolioError) as cm:
                steward.detect_gaps(repo)
            self.assertEqual(cm.exception.code, "unsafe_repo_symlink")

    def test_detect_refuses_symlinked_roadmap_input(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            outside = Path(tmp) / "ROADMAP-outside.md"
            outside.write_text("# outside\n\n## Parking lot\n\n- Private outside item\n", encoding="utf-8")
            roadmap = repo / "ROADMAP.md"
            roadmap.unlink()
            roadmap.symlink_to(outside)
            with self.assertRaises(steward.PortfolioError) as cm:
                steward.detect_gaps(repo)
            self.assertEqual(cm.exception.code, "unsafe_repo_symlink")

    def test_detect_refuses_symlinked_plan_parent_dir(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            outside = Path(tmp) / "outside-active"
            outside.mkdir()
            (outside / "777-outside.md").write_text(
                "# outside\n\n## Status\n\nactive\n\n## Open questions\n\n- Private outside sentinel\n",
                encoding="utf-8",
            )
            active_dir = repo / ".osc/plans/active"
            shutil.rmtree(active_dir)
            active_dir.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(steward.PortfolioError) as cm:
                steward.detect_gaps(repo)
            self.assertEqual(cm.exception.code, "unsafe_repo_symlink")

    def test_detect_refuses_symlinked_done_plan_input(self):
        steward = load_steward()
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            outside = Path(tmp) / "outside-done.md"
            outside.write_text("# outside done\n\n## Status\n\ndone\n", encoding="utf-8")
            plan = repo / ".osc/plans/done/090-done.md"
            plan.write_text("# done\n", encoding="utf-8")
            plan.unlink()
            plan.symlink_to(outside)
            with self.assertRaises(steward.PortfolioError) as cm:
                steward.detect_gaps(repo)
            self.assertEqual(cm.exception.code, "unsafe_repo_symlink")


if __name__ == "__main__":
    unittest.main()
