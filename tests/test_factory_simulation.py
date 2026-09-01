#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
SIMULATOR_PATH = ROOT / "scripts" / "john-lomein-factory-simulate.py"


def load_simulator() -> Any:
    spec = importlib.util.spec_from_file_location("john_lomein_factory_simulate", SIMULATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return cast(Any, module)


def write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).strip() + "\n", encoding="utf-8")


def file_snapshot(root: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            snapshot[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return snapshot


class FactorySimulationTest(unittest.TestCase):
    @unittest.skipUnless(
        sys.platform == "darwin" and Path("/usr/bin/git").is_file(),
        "macOS system Git launcher required",
    )
    def test_trusted_git_prefers_portable_system_launcher(self):
        simulator = load_simulator()
        expected = Path("/Library/Developer/CommandLineTools/usr/bin/git")
        if not expected.is_file():
            expected = Path("/Applications/Xcode.app/Contents/Developer/usr/bin/git")
        self.assertEqual(simulator._trusted_git(), expected)

    def make_repo(self, base: Path) -> Path:
        repo = base / "repo"
        for folder in ("active", "backlog", "blocked", "done"):
            (repo / ".osc" / "plans" / folder).mkdir(parents=True, exist_ok=True)
        write(
            repo / ".osc/plans/active/201-proof-plan.md",
            """
            # Plan: 201-proof-plan

            ## Status

            active

            ## Context

            This plan folds the intent of backlog plans 114 into one proof lane.

            ## Goal

            Produce reviewable evidence.

            ## Open questions

            - Should the parent or amendment be the active source of truth?
            """,
        )
        write(
            repo / ".osc/plans/active/201-proof-plan-amendment-1.md",
            """
            # Amendment 1: 201-proof-plan

            ## Parent

            201-proof-plan

            ## New direction

            Keep the proof lane small and independently reviewable.
            """,
        )
        write(
            repo / ".osc/plans/backlog/114-usage-ledger.md",
            """
            # Plan: 114-usage-ledger

            ## Status

            backlog

            ## Context

            Usage evidence needs reconciliation.

            ## Goal

            Record usage evidence without private inputs.
            """,
        )
        write(
            repo / "ROADMAP.md",
            """
            # Roadmap

            ## Parking lot

            - Add a compact proof dashboard.
            """,
        )
        write(
            repo / "MISSION.md",
            """
            # Durable Work Mission

            Preserve reviewable repository evidence so future sessions can recover context and check claims.

            ## Goals

            - Keep records compact.
            """,
        )
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=" + "fixture" + "@example.invalid",
                "commit",
                "-q",
                "-m",
                "fixture",
            ],
            check=True,
        )
        (repo / "untracked-note.txt").write_text("fixture dirty state\n", encoding="utf-8")
        return repo

    def make_instance(self, base: Path) -> tuple[Path, str]:
        instance = base / "instance"
        write(
            instance / "instance.yaml",
            """
            instance:
              slug: fixture-maintainer
            runtime:
              mutation_enabled: true
            """,
        )
        sensitive = "sensitive-value-that-must-not-appear"
        write(instance / "private/local.env", "PRIVATE_VALUE=" + sensitive)
        return instance, sensitive

    def test_read_only_scenario_is_deterministic_public_safe_and_routes_ambiguity(self):
        simulator = load_simulator()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo = self.make_repo(base)
            instance, sensitive = self.make_instance(base)
            repo_before = file_snapshot(repo)
            instance_before = file_snapshot(instance)
            commands: list[list[str]] = []
            original_run = simulator.subprocess.run
            old_parent_credential = os.environ.get("GH_TOKEN")
            os.environ["GH_TOKEN"] = "parent-credential-sentinel"

            def guarded_run(command, **kwargs):
                commands.append(list(command))
                if simulator._git_sandbox_available():
                    self.assertEqual(Path(command[0]).name, "sandbox-exec")
                else:
                    self.assertEqual(Path(command[0]).name, "git")
                self.assertIn("git", [Path(str(part)).name for part in command])
                self.assertNotIn("gh", [Path(str(part)).name for part in command])
                self.assertNotIn("GH_TOKEN", kwargs["env"])
                self.assertNotIn("parent-credential-sentinel", kwargs["env"].values())
                return original_run(command, **kwargs)

            simulator.subprocess.run = guarded_run
            try:
                first = simulator.simulate(instance=instance, repo=repo)
                second = simulator.simulate(instance=instance, repo=repo)
            finally:
                simulator.subprocess.run = original_run
                if old_parent_credential is None:
                    os.environ.pop("GH_TOKEN", None)
                else:
                    os.environ["GH_TOKEN"] = old_parent_credential

            self.assertEqual(first, second)
            self.assertTrue(commands)
            self.assertEqual(repo_before, file_snapshot(repo))
            self.assertEqual(instance_before, file_snapshot(instance))
            self.assertEqual(first["result"], "pass")
            self.assertEqual(first["repo_seed"]["branch"], "main")
            self.assertTrue(first["repo_seed"]["dirty"])
            self.assertEqual(first["intake"]["classification"], "triage")
            self.assertEqual(first["intake"]["route"], "triage")
            self.assertEqual(first["intake"]["active_plan_ambiguities"][0]["route"], "triage")
            self.assertEqual(first["selected_candidate"]["kind"], "folded_backlog_unreconciled")
            self.assertEqual(first["work_packet"]["status"], "counterfactual_contract_exercise_after_triage")
            self.assertFalse(first["ambiguity_gate"]["live_path"]["execution_allowed"])
            self.assertFalse(first["ambiguity_gate"]["contract_exercise_path"]["authority_granted"])
            self.assertEqual(first["inputs"]["mission_summary"]["source"], "MISSION.md")
            self.assertEqual(first["inputs"]["mission_summary"], first["work_packet"]["mission_summary"])
            self.assertEqual(
                first["inputs"]["mission_summary"],
                first["receipts"][0]["evidence"]["mission_summary"],
            )
            blob = json.dumps(first, sort_keys=True)
            self.assertNotIn(str(repo), blob)
            self.assertNotIn(str(instance), blob)
            self.assertNotIn(sensitive, blob)
            self.assertTrue(simulator.receipts.public_safe(first))

            def assert_no_absolute_paths(value: Any) -> None:
                if isinstance(value, dict):
                    for child in value.values():
                        assert_no_absolute_paths(child)
                elif isinstance(value, list):
                    for child in value:
                        assert_no_absolute_paths(child)
                elif isinstance(value, str):
                    self.assertFalse(os.path.isabs(value), value)

            assert_no_absolute_paths(first)

    @unittest.skipUnless(sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").is_file(), "macOS sandbox required")
    def test_repo_configured_filter_cannot_execute_during_simulation_git_probe(self):
        simulator = load_simulator()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo = self.make_repo(base)
            instance, _ = self.make_instance(base)
            write(repo / ".gitattributes", "MISSION.md filter=simulation-probe")
            subprocess.run(["git", "-C", str(repo), "add", ".gitattributes"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=" + "fixture" + "@example.invalid",
                    "commit",
                    "-q",
                    "-m",
                    "attributes fixture",
                ],
                check=True,
            )
            escaped = base / "filter-escaped"
            helper = base / "configured-filter.sh"
            helper.write_text(f"#!/bin/sh\nprintf escaped > {escaped}\ncat\n", encoding="utf-8")
            helper.chmod(0o755)
            subprocess.run(
                ["git", "-C", str(repo), "config", "filter.simulation-probe.clean", str(helper)],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repo), "config", "filter.simulation-probe.required", "true"],
                check=True,
            )
            with (repo / "MISSION.md").open("a", encoding="utf-8") as handle:
                handle.write("\nPending local mission note.\n")

            with self.assertRaisesRegex(simulator.SimulationError, "repo_git_read_failed"):
                simulator._run_git(repo, ["hash-object", "--path=MISSION.md", "MISSION.md"])

            result = simulator.simulate(instance=instance, repo=repo)

            self.assertFalse(escaped.exists())
            self.assertEqual(result["result"], "pass")

    def test_false_green_and_synthetic_evidence_remain_repair_due_in_production_projection(self):
        simulator = load_simulator()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo = self.make_repo(base)
            instance, _ = self.make_instance(base)
            result = simulator.simulate(instance=instance, repo=repo)

        false_green = result["false_green_guard"]
        self.assertEqual(false_green["executor_report"]["status"], "COMPLETE")
        self.assertEqual(false_green["executor_report"]["exit_code"], 0)
        self.assertEqual(false_green["classification"], "repair_due")
        self.assertEqual(false_green["verifier_verdict"], "blocked")
        self.assertTrue(false_green["missing_checks"])
        self.assertTrue(false_green["contract_exercised"])
        self.assertNotIn("proved", false_green)
        self.assertNotIn("files", result["receipts"][1]["evidence"])

        verified = result["synthetic_contract_assessment"]
        self.assertEqual(verified["authority"], "john-lomein-simulation-contract-checker")
        self.assertEqual(verified["classification"], "simulation_only_owner_gate")
        self.assertEqual(verified["contract_status"], "exercised")
        self.assertEqual(verified["production_completion_verdict"], "blocked")
        self.assertEqual(verified["structural_missing_checks"], [])
        self.assertEqual(verified["missing_live_requirements"], ["live_verifier_evidence"])
        self.assertTrue(verified["files"])
        self.assertEqual(verified["remote_calls"], 0)
        self.assertTrue(verified["contract_exercised"])
        self.assertNotIn("proved", verified)
        self.assertTrue(all(not os.path.isabs(path) for path in verified["files"]))
        self.assertEqual(result["final_state"]["live_path"]["loop"], "triage")
        self.assertFalse(result["final_state"]["live_path"]["execution_allowed"])
        self.assertEqual(result["final_state"]["contract_exercise_path"]["loop"], "owner_gate")
        self.assertEqual(result["final_state"]["contract_exercise_path"]["contract_status"], "exercised")
        self.assertEqual(result["final_state"]["contract_exercise_path"]["production_completion_verdict"], "blocked")
        self.assertEqual(result["final_state"]["contract_exercise_path"]["production_queue_classification"], "repair_due")
        self.assertTrue(result["final_state"]["contract_exercise_path"]["synthetic_only"])
        self.assertEqual(result["queue_health"]["projection_source"], "production_queue_health_functions")
        self.assertFalse(simulator.receipts.forge_receipt_verified_complete(result["receipts"][2]))
        handoff = {
            item["name"]: item for item in result["receipts"][2]["verifier"]["checks"]
        }["codex_review_handoff_recorded"]
        self.assertEqual(handoff["evidence"], "synthetic_handoff_only")
        self.assertTrue(result["owner_gate"]["required"])
        self.assertEqual(result["owner_gate"]["scope"], "simulation_only_contract")
        self.assertEqual(result["owner_gate"]["production_queue_classification"], "repair_due")
        self.assertEqual(result["owner_gate"]["executed_actions"], [])
        self.assertEqual(
            set(result["owner_gate"]["blocked_actions"]),
            {"merge", "publish", "release", "workflow dispatch"},
        )
        self.assertTrue(result["factory_loops"]["triage"])
        self.assertEqual(len(result["factory_loops"]["repair_due"]), 1)
        self.assertEqual(result["factory_loops"]["owner_gate"], [])
        self.assertFalse(result["factory_loops"]["clean_idle"])
        self.assertEqual(result["queue_health"]["receipt_count"], 2)
        self.assertEqual(result["queue_health"]["historical_receipt_count"], 3)
        self.assertEqual(result["feedback"]["roadmap"]["selected_kind"], "folded_backlog_unreconciled")
        self.assertEqual(result["feedback"]["learning"][0]["route"], "verifier_policy")

    def test_output_artifacts_are_atomic_external_and_cli_json_is_public(self):
        simulator = load_simulator()
        scenario = "roadmap-maintainer"
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as artifact_tmp:
            base = Path(tmp)
            repo = self.make_repo(base)
            instance, _ = self.make_instance(base)
            output = Path(artifact_tmp) / "artifacts"
            repo_before = file_snapshot(repo)
            instance_before = file_snapshot(instance)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(SIMULATOR_PATH),
                    "--instance",
                    str(instance),
                    "--repo",
                    str(repo),
                    "--scenario",
                    scenario,
                    "--dry-run",
                    "--json",
                    "--output-dir",
                    str(output),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            result = json.loads(proc.stdout)
            self.assertEqual(result["scenario"], scenario)
            self.assertEqual(result["artifacts"], simulator.ARTIFACT_NAMES)
            self.assertEqual(
                sorted(path.name for path in output.iterdir()),
                sorted(simulator.ARTIFACT_NAMES),
            )
            self.assertEqual(list(output.glob(".*.tmp")), [])
            self.assertEqual(repo_before, file_snapshot(repo))
            self.assertEqual(instance_before, file_snapshot(instance))
            self.assertNotIn(str(repo), proc.stdout)
            self.assertNotIn(str(instance), proc.stdout)
            persisted = json.loads((output / "simulation-result.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted, result)

            with self.assertRaisesRegex(simulator.SimulationError, "output_dir_overlaps_inputs"):
                simulator.simulate(instance=instance, repo=repo, output_dir=repo / "artifacts")
            self.assertFalse((repo / "artifacts").exists())


if __name__ == "__main__":
    unittest.main()
