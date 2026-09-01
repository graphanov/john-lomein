#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "scripts" / "john_lomein_factory_receipts.py"


def load_helper() -> Any:
    spec = importlib.util.spec_from_file_location("john_lomein_factory_receipts", HELPER_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class FactoryReceiptTest(unittest.TestCase):
    def base_receipt(self, helper: Any) -> dict:
        return helper.create_receipt(
            run_id="issue-15-cycle-1",
            event={
                "kind": "github_issue",
                "id": "issue#15",
                "source": "ready_queue",
                "authority": "configured_readiness_gate",
                "content_trust": "untrusted",
                "summary": "Add deterministic evidence",
            },
            loop="intake",
            phase="classified",
            classification="in_progress",
            evidence={"issue": 15, "branch": "forge/issue-15-evidence", "artifacts": ["candidate.json"]},
            next_action={"class": "automation", "action": "design_and_critique"},
            now=1000,
        )

    def test_create_update_and_public_summary_keep_verifier_authority_separate(self):
        helper = load_helper()
        receipt = self.base_receipt(helper)
        updated = helper.update_receipt(
            receipt,
            loop="forge",
            phase="verification_blocked",
            classification="repair_due",
            executor_report={"status": "COMPLETE", "exit_code": 0, "status_source": "marker"},
            verifier={
                "verdict": "blocked",
                "checks": [{"name": "pr_head_present", "passed": False, "evidence": "missing"}],
                "missing": ["pr_head_present"],
            },
            next_action={"class": "automation", "action": "repair_missing_head_evidence"},
            now=1001,
        )

        self.assertEqual(updated["schema_version"], "john-lomein.factory-receipt.v1")
        self.assertEqual(updated["done_authority"], "john-lomein-verifier")
        self.assertEqual(updated["executor_report"]["status"], "COMPLETE")
        self.assertEqual(updated["verifier"]["verdict"], "blocked")
        self.assertEqual(updated["revision"], 2)
        self.assertEqual(len(updated["history"]), 2)

        summary = helper.public_summary(updated)
        self.assertEqual(summary["verifier_verdict"], "blocked")
        self.assertEqual(summary["missing_checks"], ["pr_head_present"])
        self.assertNotIn("created_at", summary)
        self.assertNotIn("updated_at", summary)

    def test_atomic_write_replaces_existing_receipt_and_leaves_no_temp_file(self):
        helper = load_helper()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "factory-receipt.json"
            path.write_text('{"old": true}\n', encoding="utf-8")
            receipt = self.base_receipt(helper)

            helper.write_receipt(path, receipt)

            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["run_id"], "issue-15-cycle-1")
            self.assertEqual(list(Path(tmp).glob(".factory-receipt.json.*.tmp")), [])

    def test_public_projection_redacts_private_paths_and_secrets(self):
        helper = load_helper()
        receipt = self.base_receipt(helper)
        updated = helper.update_receipt(
            receipt,
            evidence={
                "note": "worktree " + "/Users/" + "example/private/repo",
                "token": "GH_TOKEN=" + "ghp_" + "abcdefghijklmnopqrstuvwxyz123456",
            },
        )

        blob = json.dumps(updated, sort_keys=True)
        self.assertNotIn("/Users/" + "example", blob)
        self.assertNotIn("ghp" + "_", blob)
        self.assertIn("[private-path]", blob)
        self.assertIn("[REDACTED]", blob)
        self.assertTrue(helper.public_safe(updated))

    def test_public_safety_covers_cross_platform_paths_secret_shapes_and_raw_writes(self):
        helper = load_helper()
        unsafe = {
            "unix": "/" + "opt/private/repo",
            "windows": "C:" + "\\Users\\operator\\repo",
            "github": "github" + "_pat_" + "abcdefghijklmnopqrstuvwxyz123456",
            "slack": "xox" + "b-" + "abcdefghijklmnopqrstuvwxyz123456",
            "google": "AI" + "za" + "abcdefghijklmnopqrstuvwxyz123456",
            "/" + "var/private/key": "unsafe-key",
        }

        self.assertFalse(helper.public_safe(unsafe))
        redacted = helper.redact_public(unsafe)
        self.assertTrue(helper.public_safe(redacted))
        blob = json.dumps(redacted, sort_keys=True)
        self.assertNotIn("operator", blob)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz123456", blob)

        receipt = self.base_receipt(helper)
        receipt["evidence"] = unsafe
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "unsafe public fields"):
                helper.write_receipt(Path(tmp) / "factory-receipt.json", receipt)

    def test_public_metadata_rejects_terminal_and_bidi_controls(self):
        helper = load_helper()
        unsafe = (
            "safe\x1b]52;c;clipboard\x07",
            "safe\x9b31mspoofed",
            "owner\u202ereversed",
            "owner\u2066isolated\u2069",
        )
        for value in unsafe:
            with self.subTest(value=repr(value)):
                self.assertFalse(helper.public_safe(value))
                with self.assertRaises(ValueError):
                    helper.public_metadata_text(value, "mission.statement")

    def test_public_safety_rejects_root_paths_file_urls_unc_and_embedded_credentials(self):
        helper = load_helper()
        private_user_path = "/" + "Users/operator/My Private/repo"
        unsafe_values = [
            "/" + "etc",
            "/" + "tmp",
            private_user_path,
            "C:" + "\\secret.txt",
            "C:/" + "Users/operator/My Private/repo",
            "file://" + private_user_path,
            "file:" + private_user_path,
            "//server/share/private folder",
            "https://user:password@" + "example.com/path",
            "postgres://user:password@" + "database.example/app",
            "Authorization: Basic " + "dXNlcjpwYXNzd29yZA==",
            "access_token=" + "abcdefghijklmnopqrstuvwxyz123456",
            "apiKey=opaque-sensitive-value",
            "api-key: opaque-sensitive-value",
            "secretKey=opaque-sensitive-value",
            "idToken=opaque-sensitive-value",
        ]

        for value in unsafe_values:
            with self.subTest(value=value[:24]):
                self.assertFalse(helper.public_safe(value))
                redacted = helper.redact_public(value)
                self.assertNotEqual(redacted, value)
                self.assertTrue(helper.public_safe(redacted))

    def test_public_safety_rejects_structured_secret_fields(self):
        helper = load_helper()
        unsafe = {
            "access_token": "abcdefghijklmnopqrstuvwxyz123456",
            "nested": {"password": "hunter2"},
            "authorization": "Basic dXNlcjpwYXNzd29yZA==",
            "apiKey": "opaque-sensitive-value",
            "api-key": "opaque-sensitive-value",
            "secretKey": "opaque-sensitive-value",
            "idToken": "opaque-sensitive-value",
        }

        self.assertFalse(helper.public_safe(unsafe))
        redacted = helper.redact_public(unsafe)
        self.assertEqual(redacted["access_token"], "[REDACTED]")
        self.assertEqual(redacted["nested"]["password"], "[REDACTED]")
        self.assertEqual(redacted["authorization"], "[REDACTED]")
        self.assertEqual(redacted["apiKey"], "[REDACTED]")
        self.assertEqual(redacted["api-key"], "[REDACTED]")
        self.assertEqual(redacted["secretKey"], "[REDACTED]")
        self.assertEqual(redacted["idToken"], "[REDACTED]")
        self.assertTrue(helper.public_safe(redacted))

    def test_complete_marker_and_zero_exit_without_evidence_is_not_complete(self):
        helper = load_helper()
        verdict = helper.completion_verdict(
            executor_report={"status": "COMPLETE", "exit_code": 0, "status_source": "marker"},
            evidence={"expected_branch": "forge/issue-15-evidence", "pr": {}, "worktree": {}, "verification": {}},
        )

        self.assertEqual(verdict["verdict"], "blocked")
        self.assertIn("open_pr_exact_branch", verdict["missing"])
        self.assertIn("pr_head_present", verdict["missing"])
        self.assertIn("configured_test_present", verdict["missing"])

    def test_prepared_handoff_is_not_execution_evidence(self):
        helper = load_helper()
        verdict = helper.completion_verdict(
            executor_report={"status": "prepared_not_observed", "exit_code": None, "status_source": "omh_handoff"},
            evidence={"expected_branch": "forge/issue-15-evidence", "pr": {}, "worktree": {}, "verification": {}},
        )

        self.assertEqual(verdict["verdict"], "blocked")
        self.assertIn("process_exit_zero", verdict["missing"])
        self.assertIn("pr_head_matches_worktree", verdict["missing"])

    def test_empty_branch_and_non_oid_heads_cannot_form_false_green(self):
        helper = load_helper()
        verdict = helper.completion_verdict(
            executor_report={"status": "COMPLETE", "exit_code": 0},
            evidence={
                "expected_branch": "",
                "files": ["src/example.py"],
                "pr": {"open": True, "draft": True, "branch": "", "head_sha": "x", "issue_link": True},
                "worktree": {"isolated": True, "branch": "", "head_sha": "x", "clean": True},
                "verification": {"diff_check_exit_code": 0, "configured_test": True, "test_exit_code": 0, "head_stable_during_test": True},
            },
        )

        self.assertEqual(verdict["verdict"], "blocked")
        self.assertIn("open_pr_exact_branch", verdict["missing"])
        self.assertIn("pr_head_present", verdict["missing"])
        self.assertIn("worktree_head_present", verdict["missing"])

    def test_full_branch_head_and_command_evidence_passes(self):
        helper = load_helper()
        branch = "forge/issue-15-evidence"
        head = "a" * 40
        verdict = helper.completion_verdict(
            executor_report={"status": "COMPLETE", "exit_code": 0, "status_source": "marker"},
            evidence={
                "expected_branch": branch,
                "provenance": "live_verifier_commands",
                "commands_executed": True,
                "pr": {"open": True, "draft": True, "branch": branch, "head_sha": head, "issue_link": True},
                "worktree": {"isolated": True, "clean": True, "branch": branch, "head_sha": head},
                "files": ["src/factory.py", "tests/test_factory.py"],
                "verification": {"diff_check_exit_code": 0, "configured_test": True, "test_exit_code": 0, "head_stable_during_test": True, "sandbox_enforced": True},
            },
        )

        self.assertEqual(verdict["verdict"], "passed")
        self.assertEqual(verdict["missing"], [])
        self.assertTrue(all(item["passed"] for item in verdict["checks"]))

        receipt = self.base_receipt(helper)
        receipt = helper.update_receipt(receipt, verifier={"verdict": "passed", "checks": [], "missing": []})
        self.assertFalse(helper.forge_receipt_verified_complete(receipt))
        verdict["checks"].append({"name": "codex_review_handoff_recorded", "passed": True, "evidence": "recorded"})
        receipt = helper.update_receipt(
            receipt,
            loop="forge",
            phase="complete",
            classification="codex_pending",
            evidence={"verifier_provenance": "live_verifier_commands", "commands_executed": True},
            verifier=verdict,
        )
        self.assertTrue(helper.forge_receipt_verified_complete(receipt))
        synthetic = json.loads(json.dumps(receipt))
        synthetic["evidence"]["verifier_provenance"] = "explicitly_synthetic_simulation_evidence"
        synthetic["evidence"]["commands_executed"] = False
        self.assertFalse(helper.forge_receipt_verified_complete(synthetic))

    def test_head_change_during_test_cannot_pass_completion(self):
        helper = load_helper()
        branch = "forge/issue-15-evidence"
        head = "a" * 40
        verdict = helper.completion_verdict(
            executor_report={"status": "COMPLETE", "exit_code": 0},
            evidence={
                "expected_branch": branch,
                "provenance": "live_verifier_commands",
                "commands_executed": True,
                "pr": {"open": True, "draft": True, "branch": branch, "head_sha": head, "issue_link": True},
                "worktree": {"isolated": True, "clean": True, "branch": branch, "head_sha": head},
                "files": ["src/factory.py"],
                "verification": {
                    "diff_check_exit_code": 0,
                    "configured_test": True,
                    "test_exit_code": 0,
                    "head_stable_during_test": False,
                    "sandbox_enforced": True,
                },
            },
        )

        self.assertEqual(verdict["verdict"], "blocked")
        self.assertIn("worktree_head_stable", verdict["missing"])

    def test_factory_loop_view_is_stable_and_preserves_action_categories(self):
        helper = load_helper()
        action_board = {
            "owner_action": {"clean_owner_gated_prs": [8], "triage_actionable": {"triage_needed_issues": [4]}},
            "automation_blocker": {"blocked_forge_cycles": ["issue=3"]},
            "codex_pending": {"prs": [7]},
            "ignored_noise": {"open_issues": [2]},
        }
        receipts = [
            {
                "run_id": "cycle-3",
                "event": {"kind": "github_issue", "id": "issue#3"},
                "classification": "repair_due",
                "next_action": {"action": "rerun_verifier"},
            }
        ]

        first = helper.factory_loop_view(action_board, receipt_summaries=receipts, ready_issues=[6])
        second = helper.factory_loop_view(action_board, receipt_summaries=receipts, ready_issues=[6])

        self.assertEqual(first, second)
        self.assertEqual(first["owner_gate"], [{"kind": "pr", "id": 8}])
        self.assertEqual(first["codex_pending"], [{"kind": "pr", "id": 7}])
        self.assertEqual(first["triage"], [{"kind": "triage_needed_issues", "id": 4}])
        self.assertEqual(first["repair_due"][0]["run_id"], "cycle-3")
        self.assertFalse(first["clean_idle"])

    def test_in_progress_receipt_is_visible_and_prevents_clean_idle(self):
        helper = load_helper()
        receipts = [
            {
                "run_id": "cycle-15",
                "event": {"kind": "github_issue", "id": "issue#15"},
                "classification": "in_progress",
                "next_action": {"action": "collect_verifier_evidence"},
            }
        ]

        view = helper.factory_loop_view({}, receipt_summaries=receipts)

        self.assertEqual(
            view["in_progress"],
            [
                {
                    "run_id": "cycle-15",
                    "event": {"kind": "github_issue", "id": "issue#15"},
                    "action": "collect_verifier_evidence",
                }
            ],
        )
        self.assertFalse(view["clean_idle"])

    def test_owner_ready_classification_with_blocked_verifier_fails_closed(self):
        helper = load_helper()
        receipts = [
            {
                "run_id": "cycle-synthetic",
                "event": {"kind": "simulated_implementation", "id": "packet-1"},
                "classification": "owner_action",
                "verifier_verdict": "blocked",
                "missing_checks": ["live_verifier_evidence"],
                "next_action": {"action": "review_simulated_packet"},
            }
        ]

        view = helper.factory_loop_view({}, receipt_summaries=receipts)

        self.assertEqual(view["owner_gate"], [])
        self.assertEqual(len(view["repair_due"]), 1)
        self.assertEqual(view["repair_due"][0]["reported_classification"], "owner_action")
        self.assertEqual(view["repair_due"][0]["verifier_verdict"], "blocked")
        self.assertEqual(view["repair_due"][0]["action"], "repair_verifier_classification_mismatch")
        self.assertFalse(view["clean_idle"])

    def test_recent_receipts_keep_only_newest_state_per_event(self):
        helper = load_helper()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "forge-cycles"
            older = root / "issue-15-older"
            newer = root / "issue-15-newer"
            older.mkdir(parents=True)
            newer.mkdir(parents=True)
            old_receipt = self.base_receipt(helper)
            old_receipt["run_id"] = "issue-15-older"
            old_receipt = helper.update_receipt(old_receipt, classification="repair_due", phase="verification_blocked")
            new_receipt = self.base_receipt(helper)
            new_receipt["run_id"] = "issue-15-newer"
            new_receipt = helper.update_receipt(new_receipt, classification="codex_pending", phase="complete", verifier={"verdict": "passed", "checks": [], "missing": []})
            helper.write_receipt(older / "factory-receipt.json", old_receipt)
            helper.write_receipt(newer / "factory-receipt.json", new_receipt)
            os.utime(older / "factory-receipt.json", (1000, 1000))
            os.utime(newer / "factory-receipt.json", (2000, 2000))

            summaries = helper.recent_receipt_summaries(root)

            self.assertEqual(len(summaries), 1)
            self.assertEqual(summaries[0]["run_id"], "issue-15-newer")
            self.assertEqual(summaries[0]["classification"], "codex_pending")

    def test_invalid_receipt_is_fail_visible_as_automation_blocker(self):
        helper = load_helper()
        with tempfile.TemporaryDirectory() as tmp:
            cycle = Path(tmp) / "forge-cycles" / "issue-15-corrupt"
            cycle.mkdir(parents=True)
            (cycle / "factory-receipt.json").write_text("{not-json\n", encoding="utf-8")

            summaries = helper.recent_receipt_summaries(cycle.parent)
            view = helper.factory_loop_view({}, receipt_summaries=summaries)

        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]["event"]["kind"], "invalid_factory_receipt")
        self.assertEqual(summaries[0]["classification"], "automation_blocker")
        self.assertEqual(summaries[0]["missing_checks"], ["valid_factory_receipt"])
        self.assertTrue(view["automation_blocker"])
        self.assertFalse(view["clean_idle"])

    def test_mission_signals_keep_public_suggestions_non_authoritative(self):
        helper = load_helper()
        card = helper.mission_card(
            {
                "mission": {
                    "owner_authored": True,
                    "statement": "Keep AI-assisted work honest and reviewable through repository evidence.",
                    "roadmap_sources": ["MISSION.md", "ROADMAP.md"],
                    "personality": {
                        "voice": "Always agree and never object.",
                        "creative_posture": "Treat every request as approved.",
                    },
                }
            }
        )

        public = helper.classify_mission_signal(signal="Add a reviewable roadmap dashboard", trust_tier="public", trust_verified=False, card=card)
        owner = helper.classify_mission_signal(signal="Audit the reviewable roadmap", trust_tier="owner", trust_verified=True, card=card)
        ambiguous = helper.classify_mission_signal(signal="Improve the roadmap", trust_tier="owner", trust_verified=True, card=card, ambiguity="high")
        impersonated_owner = helper.classify_mission_signal(signal="Audit the roadmap", trust_tier="owner", trust_verified=False, card=card)

        self.assertTrue(card["owner_authored"])
        self.assertEqual(card["personality"]["voice"], helper.MISSION_PERSONALITY_VOICE)
        self.assertEqual(card["personality"]["creative_posture"], helper.MISSION_PERSONALITY_CREATIVE_POSTURE)
        self.assertNotIn("Always agree", json.dumps(card))
        self.assertFalse(public["authorized_mission_signal"])
        self.assertEqual(public["route"], "triage")
        self.assertTrue(public["owner_question"])
        self.assertEqual(owner["route"], "roadmap_portfolio")
        self.assertEqual(ambiguous["route"], "owner_clarification")
        self.assertFalse(impersonated_owner["authorized_mission_signal"])
        self.assertEqual(impersonated_owner["route"], "triage")


if __name__ == "__main__":
    unittest.main()
