#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "runtime_plugins" / "john-lomein-guide-lifecycle" / "__init__.py"
PLUGIN_YAML = ROOT / "runtime_plugins" / "john-lomein-guide-lifecycle" / "plugin.yaml"
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def load_plugin():
    if not PLUGIN.is_file():
        raise AssertionError("Guide lifecycle plugin is missing")
    spec = importlib.util.spec_from_file_location("john_lomein_guide_lifecycle_plugin", PLUGIN)
    if spec is None or spec.loader is None:
        raise AssertionError("Guide lifecycle plugin cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GuideLifecyclePolicyTest(unittest.TestCase):
    def test_policy_defaults_are_bounded_and_fail_closed(self):
        from john_lomein_guide_lifecycle import guide_dialogue_policy

        policy = guide_dialogue_policy({})
        self.assertEqual(policy["max_refinement_turns"], 4)
        self.assertEqual(policy["max_questions_per_reply"], 1)
        self.assertTrue(policy["proposal_on_exhaustion"])

        hostile = [
            {"workflows": {"guide_dialogue": "four"}},
            {"workflows": {"guide_dialogue": {"max_refinement_turns": True}}},
            {"workflows": {"guide_dialogue": {"max_refinement_turns": 0}}},
            {"workflows": {"guide_dialogue": {"max_refinement_turns": 13}}},
            {"workflows": {"guide_dialogue": {"max_questions_per_reply": 2}}},
            {"workflows": {"guide_dialogue": {"proposal_on_exhaustion": "true"}}},
            {"workflows": {"guide_dialogue": {"unknown": 1}}},
        ]
        for manifest in hostile:
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                guide_dialogue_policy(manifest)

    def test_signals_allow_multi_turn_refinement_but_stop_at_cap(self):
        from john_lomein_guide_lifecycle import dialogue_signals, guide_dialogue_policy

        policy = guide_dialogue_policy(
            {"workflows": {"guide_dialogue": {"max_refinement_turns": 2}}}
        )
        one_round = [
            {"role": "assistant", "content": "Clarifying question: Which users feel this pain?"},
            {"role": "user", "content": "Maintainers of small libraries."},
        ]
        signals = dialogue_signals(one_round, "It should work on macOS.", policy)
        self.assertEqual(signals["stage"], "REFINE")
        self.assertTrue(signals["questioning_permitted"])
        self.assertFalse(signals["hard_stop"])

        two_rounds = one_round + [
            {"role": "assistant", "content": "Clarifying question: What must remain compatible?"},
            {"role": "user", "content": "The current release format."},
        ]
        signals = dialogue_signals(two_rounds, "Proceed with that.", policy)
        self.assertEqual(signals["stage"], "EXHAUSTED")
        self.assertFalse(signals["questioning_permitted"])
        self.assertTrue(signals["hard_stop"])
        self.assertIn("refinement_cap", signals["stop_reasons"])

    def test_signals_stop_a_repeated_question_exchange(self):
        from john_lomein_guide_lifecycle import dialogue_signals, guide_dialogue_policy

        history = [
            {"role": "assistant", "content": "Clarifying question: Which release must this support?"},
            {"role": "user", "content": "Release 125y71."},
            {"role": "assistant", "content": "Clarifying question: Which release must this support?"},
        ]
        signals = dialogue_signals(
            history,
            "Release 125y71.",
            guide_dialogue_policy({}),
        )
        self.assertTrue(signals["hard_stop"])
        self.assertFalse(signals["questioning_permitted"])
        self.assertIn("repeated_question", signals["stop_reasons"])
        self.assertIn("repeated_exchange", signals["stop_reasons"])

    def test_context_contains_contract_not_untrusted_conversation_text(self):
        from john_lomein_guide_lifecycle import (
            dialogue_signals,
            guide_dialogue_policy,
            render_lifecycle_context,
        )

        secret = "DO-NOT-ECHO-UNTRUSTED-CONTENT"
        policy = guide_dialogue_policy({})
        signals = dialogue_signals(
            [{"role": "user", "content": secret}],
            secret,
            policy,
        )
        context = render_lifecycle_context(policy, signals)
        self.assertNotIn(secret, context)
        self.assertIn("EXPLORE", context)
        self.assertIn("REFINE", context)
        self.assertIn("PROPOSE", context)
        self.assertIn("one useful clarification question", context)
        self.assertIn("Success signals", context)
        self.assertIn("not owner readiness", context)
        self.assertIn("Forge owns the design and final acceptance criteria", context)

    def test_output_guard_allows_only_one_prefixed_question(self):
        from john_lomein_guide_lifecycle import GUIDE_OUTPUT_BLOCKED, enforce_guide_output

        signals = {"hard_stop": False, "stage": "REFINE"}
        policy = {"max_questions_per_reply": 1}
        valid = "Useful context.\n\nClarifying question: Which release must remain compatible?"
        self.assertEqual(enforce_guide_output(valid, policy, signals), GUIDE_OUTPUT_BLOCKED)

        unsafe = (
            "Clarifying question: Which release must remain compatible?\n"
            "Clarifying question: Which platform matters most?"
        )
        guarded = enforce_guide_output(unsafe, policy, signals)
        self.assertEqual(guarded, GUIDE_OUTPUT_BLOCKED)
        self.assertEqual(guarded.count("?"), 0)

    def test_output_guard_rejects_unprefixed_or_statement_only_drafts(self):
        from john_lomein_guide_lifecycle import GUIDE_OUTPUT_BLOCKED, enforce_guide_output

        signals = {"hard_stop": False, "stage": "EXPLORE"}
        policy = {"max_questions_per_reply": 1}
        self.assertEqual(
            enforce_guide_output("Which platform matters?", policy, signals),
            GUIDE_OUTPUT_BLOCKED,
        )
        self.assertEqual(
            enforce_guide_output("I will think about it.", policy, signals),
            GUIDE_OUTPUT_BLOCKED,
        )

    def test_output_guard_requires_structured_proposal_on_hard_stop(self):
        from john_lomein_guide_lifecycle import GUIDE_OUTPUT_BLOCKED, enforce_guide_output

        signals = {"hard_stop": True, "stage": "EXHAUSTED"}
        policy = {"max_questions_per_reply": 1}
        self.assertEqual(
            enforce_guide_output(
                "Clarifying question: Can you repeat the requirement?",
                policy,
                signals,
            ),
            GUIDE_OUTPUT_BLOCKED,
        )
        self.assertNotIn("?", GUIDE_OUTPUT_BLOCKED)

        proposal = "\n".join(
            [
                "## Proposal",
                "### Problem",
                "A concrete problem.",
                "### Desired outcome",
                "A concrete outcome.",
                "### Scope",
                "- One bounded change.",
                "### Out of scope",
                "- Publishing.",
                "### Constraints and compatibility",
                "- Preserve release 125y71.",
                "### Success signals",
                "- Observable behavior.",
                "### Evidence plan",
                "- Deterministic tests.",
                "### Risks and open questions",
                "- None blocking.",
                "### Authority note",
                "Proposal only; owner readiness and merge remain required.",
            ]
        )
        self.assertEqual(enforce_guide_output(proposal, policy, signals), proposal)


class GuideLifecyclePluginTest(unittest.TestCase):
    def test_doctor_requires_the_deployed_proposal_skill(self):
        doctor = (ROOT / "scripts" / "doctor-instance.py").read_text(encoding="utf-8")
        self.assertIn("john-lomein-guide-proposals", doctor)

    def test_deploy_enables_lifecycle_only_for_guide(self):
        deploy = (ROOT / "scripts" / "deploy-instance.sh").read_text(encoding="utf-8")
        self.assertIn("lifecycle_plugin='john-lomein-guide-lifecycle'", deploy)
        self.assertIn("x != lifecycle_plugin]+[lifecycle_plugin]", deploy)
        self.assertIn("x for x in disabled_plugins if x != lifecycle_plugin", deploy)
        self.assertIn("lifecycle_plugin_link.symlink_to(", deploy)

    def test_plugin_declares_and_registers_pre_and_output_hooks(self):
        plugin = load_plugin()
        self.assertTrue(PLUGIN_YAML.is_file())
        metadata = yaml.safe_load(PLUGIN_YAML.read_text(encoding="utf-8"))
        self.assertIn("pre_llm_call", metadata["provides_hooks"])
        self.assertIn("transform_llm_output", metadata["provides_hooks"])

        class Context:
            def __init__(self):
                self.calls = []

            def register_hook(self, name, callback):
                self.calls.append((name, callback))

        ctx = Context()
        plugin.register(ctx)
        self.assertEqual(len(ctx.calls), 2)
        self.assertEqual(ctx.calls[0][0], "pre_llm_call")
        self.assertIs(ctx.calls[0][1], plugin.pre_llm_call)
        self.assertEqual(ctx.calls[1][0], "transform_llm_output")
        self.assertIs(ctx.calls[1][1], plugin.transform_llm_output)

    def test_non_guide_profile_is_ignored(self):
        plugin = load_plugin()
        result = plugin.process_guide_lifecycle(
            user_message="shape this",
            conversation_history=[],
            session_getter=lambda key, default="": (
                "john-lomein-forge" if key == "HERMES_SESSION_PROFILE" else default
            ),
            manifest_loader=lambda: {},
        )
        self.assertIsNone(result)

    def test_default_profile_comes_from_task_local_gateway_context(self):
        plugin = load_plugin()
        with mock.patch.object(
            plugin,
            "_default_session_getter",
            side_effect=lambda key, default="": (
                "john-lomein-guide"
                if key == "HERMES_SESSION_PROFILE"
                else default
            ),
        ):
            result = plugin.process_guide_lifecycle(
                user_message="Shape this",
                conversation_history=[],
                manifest_loader=lambda: {},
            )
        self.assertIsInstance(result, dict)

    def test_guide_receives_mechanical_signals_and_policy_context(self):
        plugin = load_plugin()
        result = plugin.process_guide_lifecycle(
            user_message="Please keep talking this through.",
            conversation_history=[
                {"role": "assistant", "content": "Clarifying question: Who is affected?"},
                {"role": "user", "content": "Plugin authors."},
            ],
            session_getter=lambda key, default="": (
                "john-lomein-guide" if key == "HERMES_SESSION_PROFILE" else default
            ),
            manifest_loader=lambda: {
                "workflows": {"guide_dialogue": {"max_refinement_turns": 3}}
            },
        )
        self.assertIsInstance(result, dict)
        context = result["context"]
        self.assertIn('"refinement_turns":1', context)
        self.assertIn('"questioning_permitted":true', context)
        self.assertIn('"max_refinement_turns":3', context)

    def test_pre_llm_hook_fails_closed_when_policy_loading_breaks(self):
        plugin = load_plugin()
        with mock.patch.object(
            plugin,
            "_default_session_getter",
            side_effect=lambda key, default="": (
                "john-lomein-guide" if key == "HERMES_SESSION_PROFILE" else default
            ),
        ), mock.patch.object(
            plugin,
            "load_runtime_manifest",
            side_effect=RuntimeError("boom"),
        ):
            result = plugin.pre_llm_call(
                user_message="Continue",
                conversation_history=[],
            )
        self.assertIsInstance(result, dict)
        self.assertIn('"hard_stop":true', result["context"])
        self.assertIn("must not ask another question", result["context"])

    def test_transform_hook_uses_and_consumes_turn_state(self):
        plugin = load_plugin()
        plugin._clear_turn_states_for_test()
        guide_profile = lambda key, default="": (
            "john-lomein-guide" if key == "HERMES_SESSION_PROFILE" else default
        )
        with mock.patch.object(plugin, "_default_session_getter", side_effect=guide_profile):
            plugin.pre_llm_call(
                session_id="guide-session",
                user_message="Continue",
                conversation_history=[],
            )
            transformed = plugin.transform_llm_output(
                session_id="guide-session",
                response_text=(
                    "Clarifying question: Which user is affected?\n"
                    "Clarifying question: Which release matters?"
                ),
            )
            missing_state = plugin.transform_llm_output(
                session_id="guide-session",
                response_text="Clarifying question: Which user is affected?",
            )
        self.assertEqual(transformed, plugin.GUIDE_OUTPUT_BLOCKED)
        self.assertEqual(missing_state, plugin.GUIDE_OUTPUT_BLOCKED)

    def test_transform_hook_ignores_non_guide_profiles(self):
        plugin = load_plugin()
        with mock.patch.object(
            plugin,
            "_default_session_getter",
            side_effect=lambda key, default="": (
                "john-lomein-forge" if key == "HERMES_SESSION_PROFILE" else default
            ),
        ):
            result = plugin.transform_llm_output(
                session_id="forge-session",
                response_text="Two questions? Really?",
            )
        self.assertIsNone(result)

    def test_ingestion_pause_blocks_guide_output_without_another_question(self):
        plugin = load_plugin()
        plugin._clear_turn_states_for_test()
        result = plugin.process_guide_lifecycle(
            user_message="Build this",
            conversation_history=[],
            session_id="paused-session",
            session_getter=lambda key, default="": "john-lomein-guide",
            manifest_loader=lambda: {},
            pause_loader=lambda: {"active": True, "reasons": ["memory_unhealthy"]},
        )
        self.assertIn("INGESTION_PAUSED", result["context"])
        with mock.patch.object(plugin, "_default_session_getter", return_value="john-lomein-guide"):
            transformed = plugin.transform_llm_output(
                session_id="paused-session", response_text="Should I continue?"
            )
        self.assertEqual(transformed, plugin.GUIDE_MEMORY_PAUSED_OUTPUT)
        self.assertNotIn("?", transformed)

    def test_late_timed_out_pre_hook_cannot_poison_next_turn(self):
        plugin = load_plugin()
        plugin._clear_turn_states_for_test()
        old = plugin._begin_turn("same-session")
        current = plugin._begin_turn("same-session")
        plugin._remember_turn_state("same-session", old, {}, {"stage": "OLD"})
        plugin._remember_turn_state("same-session", current, {}, {"stage": "CURRENT"})
        state = plugin._consume_turn_state("same-session")
        self.assertEqual(state[1]["stage"], "CURRENT")

    def test_deploy_script_installs_plugin_and_policy_module(self):
        deploy = (ROOT / "scripts" / "deploy-instance.sh").read_text(encoding="utf-8")
        self.assertIn("john_lomein_guide_lifecycle.py", deploy)
        self.assertIn("john-lomein-guide-lifecycle", deploy)
        self.assertIn("lifecycle_plugin_link=pdir/'plugins'/'john-lomein-guide-lifecycle'", deploy)
        self.assertIn(
            "lifecycle_plugin_link.symlink_to(",
            deploy,
        )
        self.assertIn(
            "home / \"plugins\" / \"john-lomein-guide-lifecycle\"",
            (ROOT / "scripts" / "john_lomein_manifest_contract.py").read_text(
                encoding="utf-8"
            ),
        )

    def test_gateway_verifies_discovery_hooks_workspace_and_tombstone_gate_before_launch(self):
        installer = (ROOT / "scripts" / "install-guide-gateway.sh").read_text(
            encoding="utf-8"
        )
        preflight = "john_lomein_guide_runtime_preflight.py"
        self.assertIn(preflight, installer)
        preflight_position = installer.index(preflight)
        self.assertLess(preflight_position, installer.index("launchctl bootstrap"))
        self.assertIn("--expected-workspace", installer)
        self.assertIn("startup-gate", installer)
        self.assertLess(installer.index("startup-gate"), installer.index("launchctl bootstrap"))


if __name__ == "__main__":
    unittest.main()
