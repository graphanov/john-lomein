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


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "john-lomein-persona-eval.py"
SCENARIOS = ROOT / "evals" / "persona" / "scenarios.json"
LONGITUDINAL_SCENARIOS = (
    ROOT / "evals" / "persona" / "longitudinal-scenarios.json"
)
RUBRIC = ROOT / "evals" / "persona" / "rubric.json"
FIXTURES = ROOT / "evals" / "persona" / "fixtures"

spec = importlib.util.spec_from_file_location("john_lomein_persona_eval", SCRIPT)
assert spec and spec.loader
evaluator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluator)


class PersonaEvaluatorTest(unittest.TestCase):
    def evaluate_fixture(self, name: str) -> dict:
        return evaluator.evaluate(
            scenario_path=SCENARIOS,
            rubric_path=RUBRIC,
            run_path=FIXTURES / name,
        )

    def test_longitudinal_suite_is_a_separate_valid_contract(self):
        routine = evaluator.load_scenarios(SCENARIOS)
        longitudinal = evaluator.load_scenarios(LONGITUDINAL_SCENARIOS)
        self.assertEqual(len(longitudinal["scenarios"]), 5)
        self.assertNotEqual(longitudinal["sha256"], routine["sha256"])
        self.assertEqual(
            {item["id"] for item in longitudinal["scenarios"]},
            {
                "pressure-without-evidence",
                "counterevidence-changes-verdict",
                "superseded-preference",
                "role-migration-private-boundary",
                "fallback-handoff-under-pressure",
            },
        )

    def test_passing_fixture_is_deterministic_private_and_not_reputation_evidence(self):
        first = self.evaluate_fixture("passing.json")
        second = self.evaluate_fixture("passing.json")

        self.assertEqual(first, second)
        self.assertEqual(first["summary"]["status"], "pass")
        self.assertEqual(first["summary"]["score"], 1.0)
        self.assertEqual(first["summary"]["passed_scenarios"], first["summary"]["scenarios"])
        self.assertEqual(first["summary"]["missing_judgment_count"], 0)
        self.assertTrue(first["evidence"]["synthetic"])
        self.assertFalse(first["evidence"]["public_reputation_eligible"])
        self.assertEqual(first["evidence"]["reason"], "synthetic_fixture")
        self.assertTrue(evaluator.verify_report(first))

        serialized = json.dumps(first, sort_keys=True)
        self.assertNotIn("Synthetic evaluator fixture response", serialized)
        self.assertNotIn("offline-fixture-judge-v1", serialized)
        self.assertNotIn(str(FIXTURES), serialized)
        self.assertFalse(first["privacy"]["raw_prompts_included"])
        self.assertFalse(first["privacy"]["raw_responses_included"])
        self.assertFalse(first["privacy"]["judge_rationales_included"])

    def test_one_critical_failure_overrides_a_passing_aggregate_score(self):
        report = self.evaluate_fixture("critical-failure.json")

        self.assertEqual(report["summary"]["status"], "fail")
        self.assertGreater(report["summary"]["score"], 0.9)
        self.assertEqual(report["summary"]["critical_failure_count"], 1)
        scenario = report["scenarios"][0]
        self.assertEqual(scenario["id"], "fashionable-rewrite")
        self.assertEqual(scenario["critical_failures"], ["forbidden-01"])
        self.assertEqual(scenario["status"], "fail")

    def test_missing_scenarios_and_judgments_fail_closed(self):
        report = self.evaluate_fixture("missing-judgment.json")

        self.assertEqual(report["summary"]["status"], "fail")
        self.assertGreater(report["summary"]["missing_judgment_count"], 0)
        self.assertLess(report["summary"]["judged"], report["summary"]["criteria"])
        self.assertIn("forbidden-03", report["scenarios"][0]["missing_judgments"])
        self.assertTrue(all(item["status"] == "fail" for item in report["scenarios"]))

    def test_private_response_and_semantic_rationale_do_not_reach_the_report(self):
        payload = json.loads((FIXTURES / "passing.json").read_text(encoding="utf-8"))
        response_secret = "PRIVATE_RUNTIME_VALUE_ALPHA"
        rationale_secret = "PRIVATE_JUDGE_REASONING_BRAVO"
        payload["candidate"]["evidence_class"] = "observed_model"
        payload["judge"]["kind"] = "independent_model"
        payload["scenario_results"][0]["response"] = response_secret
        payload["scenario_results"][0]["judgments"]["expected-01"] = {
            "verdict": True,
            "rationale": rationale_secret,
        }

        with tempfile.TemporaryDirectory() as directory:
            run_path = Path(directory) / "run.json"
            run_path.write_text(json.dumps(payload), encoding="utf-8")
            report = evaluator.evaluate(
                scenario_path=SCENARIOS,
                rubric_path=RUBRIC,
                run_path=run_path,
            )

        serialized = json.dumps(report, sort_keys=True)
        self.assertNotIn(response_secret, serialized)
        self.assertNotIn(rationale_secret, serialized)
        self.assertTrue(report["scenarios"][0]["response_observed"])
        self.assertNotIn(evaluator.sha256_text(response_secret), serialized)
        self.assertFalse(report["evidence"]["synthetic"])
        self.assertEqual(report["evidence"]["reason"], "external_attestation_required")

    def test_unknown_criterion_is_rejected_instead_of_silently_ignored(self):
        payload = json.loads((FIXTURES / "passing.json").read_text(encoding="utf-8"))
        payload["scenario_results"][0]["judgments"]["forbidden-99"] = True

        with tempfile.TemporaryDirectory() as directory:
            run_path = Path(directory) / "run.json"
            run_path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(evaluator.EvaluationError, "unknown criterion"):
                evaluator.evaluate(
                    scenario_path=SCENARIOS,
                    rubric_path=RUBRIC,
                    run_path=run_path,
                )

    def test_duplicate_json_fields_and_nonfinite_numbers_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            duplicate = Path(directory) / "duplicate.json"
            duplicate.write_text('{"schema_version":"a","schema_version":"b"}', encoding="utf-8")
            nonfinite = Path(directory) / "nonfinite.json"
            nonfinite.write_text('{"score":NaN}', encoding="utf-8")

            with self.assertRaisesRegex(evaluator.EvaluationError, "duplicate"):
                evaluator.load_json(duplicate, field="test input")
            with self.assertRaisesRegex(evaluator.EvaluationError, "non-finite"):
                evaluator.load_json(nonfinite, field="test input")

    def test_report_digest_detects_tampering(self):
        report = self.evaluate_fixture("passing.json")
        tampered = json.loads(json.dumps(report))
        tampered["summary"]["score"] = 0.5

        self.assertFalse(evaluator.verify_report(tampered))
        tampered["run_digest"] = evaluator.sha256_json(
            {key: value for key, value in tampered.items() if key != "run_digest"}
        )
        self.assertFalse(evaluator.verify_report(tampered))

    def test_rehashed_score_status_and_scenario_forgery_is_rejected(self):
        for mutate in (
            lambda report: [row.__setitem__("score", 0.0) for row in report["scenarios"]]
            + [report["summary"].__setitem__("score", 0.0)],
            lambda report: report["scenarios"][0].__setitem__("id", "forged-scenario"),
            lambda report: report["scenarios"][0].__setitem__("criteria", 99),
        ):
            with self.subTest(mutation=mutate):
                forged = json.loads(json.dumps(self.evaluate_fixture("passing.json")))
                mutate(forged)
                forged["run_digest"] = evaluator.sha256_json(
                    {key: value for key, value in forged.items() if key != "run_digest"}
                )
                self.assertFalse(evaluator.verify_report(forged))

    def test_cli_verification_detects_a_recomputed_but_forged_report(self):
        report = self.evaluate_fixture("passing.json")
        forged = json.loads(json.dumps(report))
        forged["summary"]["score"] = 0.5
        forged["run_digest"] = evaluator.sha256_json(
            {key: value for key, value in forged.items() if key != "run_digest"}
        )

        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            report_path.write_text(json.dumps(forged), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "verify",
                    "--report",
                    str(report_path),
                    "--run",
                    str(FIXTURES / "passing.json"),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        verification = json.loads(result.stdout)
        self.assertFalse(verification["digest_valid"])
        self.assertIsNone(verification["source_reproducible"])
        self.assertFalse(verification["valid"])

    def test_cli_structural_check_never_authenticates_semantic_pass(self):
        report = self.evaluate_fixture("passing.json")
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            structural = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "verify",
                    "--report",
                    str(report_path),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            reproduced = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "verify",
                    "--report",
                    str(report_path),
                    "--run",
                    str(FIXTURES / "passing.json"),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(structural.returncode, 0, structural.stderr)
        structural_projection = json.loads(structural.stdout)
        self.assertTrue(structural_projection["structurally_valid"])
        self.assertTrue(structural_projection["digest_valid"])
        self.assertIsNone(structural_projection["source_reproducible"])
        self.assertFalse(structural_projection["valid"])
        self.assertFalse(
            structural_projection["reported_pass_source_reproduced"]
        )
        self.assertFalse(
            structural_projection["semantic_judgments_authenticated"]
        )
        self.assertFalse(structural_projection["semantic_pass_verified"])

        self.assertEqual(reproduced.returncode, 0, reproduced.stderr)
        reproduced_projection = json.loads(reproduced.stdout)
        self.assertTrue(reproduced_projection["structurally_valid"])
        self.assertTrue(reproduced_projection["source_reproducible"])
        self.assertTrue(reproduced_projection["valid"])
        self.assertTrue(
            reproduced_projection["reported_pass_source_reproduced"]
        )
        self.assertFalse(reproduced_projection["semantic_pass_verified"])

    def test_cli_exit_codes_and_atomic_private_report_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            passing = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "evaluate",
                    "--run",
                    str(FIXTURES / "passing.json"),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            failing = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "evaluate",
                    "--run",
                    str(FIXTURES / "critical-failure.json"),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(passing.returncode, 0, passing.stderr)
            self.assertEqual(passing.stdout, "")
            self.assertTrue(output.is_file())
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["summary"]["status"], "pass")
            self.assertEqual(failing.returncode, 1, failing.stderr)
            self.assertEqual(json.loads(failing.stdout)["summary"]["status"], "fail")

    def test_contract_files_remain_versioned_and_fail_closed(self):
        scenarios = json.loads(SCENARIOS.read_text(encoding="utf-8"))
        rubric = json.loads(RUBRIC.read_text(encoding="utf-8"))

        self.assertEqual(scenarios["schema_version"], "john-lomein.persona-evals.v1")
        self.assertEqual(rubric["schema_version"], "john-lomein.persona-rubric.v1")
        self.assertEqual(rubric["missing_judgment_policy"], "fail_closed")
        self.assertTrue(rubric["criterion_policy"]["forbidden"]["critical"])
        self.assertFalse(
            rubric["evidence_policy"]["synthetic_fixture_public_reputation_eligible"]
        )


if __name__ == "__main__":
    unittest.main()
