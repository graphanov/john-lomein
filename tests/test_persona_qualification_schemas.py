from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "evals" / "persona" / "schemas"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RUNNER = load_module(
    "persona_qualification_schema_runner",
    ROOT / "scripts" / "john-lomein-persona-qualification.py",
)
ADAPTER = load_module(
    "persona_qualification_schema_adapter",
    ROOT / "qualification_adapters" / "openai_responses.py",
)

SCHEMA_FILES = {
    "command": "persona-qualification-command.v1.schema.json",
    "candidate_request": "persona-candidate-request.v1.schema.json",
    "candidate_result": "persona-candidate-result.v1.schema.json",
    "judge_request": "persona-judge-request.v1.schema.json",
    "judge_result": "persona-judge-result.v1.schema.json",
}

EXPECTED_SCHEMA_IDS = {
    "command": "urn:john-lomein:schema:persona-qualification-command:v1",
    "candidate_request": "urn:john-lomein:schema:persona-candidate-request:v1",
    "candidate_result": "urn:john-lomein:schema:persona-candidate-result:v1",
    "judge_request": "urn:john-lomein:schema:persona-judge-request:v1",
    "judge_result": "urn:john-lomein:schema:persona-judge-result:v1",
}


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def isolation_result() -> dict[str, object]:
    return {
        "fresh_home": True,
        "fresh_hermes_home": True,
        "empty_cwd": True,
        "fresh_session": True,
        "tools": [],
        "memory_loaded": False,
        "skills_loaded": False,
        "plugins_loaded": False,
        "mcp_servers": [],
        "prior_session_loaded": False,
        "production_credentials_present": False,
        "hermes_kanban_task_present": False,
    }


def provider_response(
    *, response_id: str, model: str, effort: str, output: str, max_output_tokens: int
) -> dict[str, object]:
    return {
        "id": response_id,
        "object": "response",
        "status": "completed",
        "error": None,
        "incomplete_details": None,
        "model": model,
        "reasoning": {"effort": effort, "summary": None},
        "output": [
            {
                "id": f"message_{response_id}",
                "type": "message",
                "status": "completed",
                "role": "assistant",
                "content": [
                    {"type": "output_text", "text": output, "annotations": []}
                ],
            }
        ],
        "usage": {"input_tokens": 120, "output_tokens": 30, "total_tokens": 150},
        "store": False,
        "previous_response_id": None,
        "conversation": None,
        "tools": [],
        "background": False,
        "truncation": "disabled",
        "max_output_tokens": max_output_tokens,
    }


def representative_contract_objects() -> dict[str, object]:
    scenario = read_json(ROOT / "evals" / "persona" / "scenarios.json")["scenarios"][0]
    candidate = {
        "id": "candidate-01-contract",
        "slots": ["primary"],
        "provider": "openai",
        "model": "gpt-candidate-contract-snapshot",
        "reasoning_effort": "high",
    }
    soul = "# John Lomein\n\nSenior maintainer judgment under test."
    candidate_request = RUNNER.candidate_request(
        run_id="qualification-schema-contract",
        candidate=candidate,
        scenario=scenario,
        profile="john-lomein-maintainer",
        soul=soul,
        persona={
            "version": "john-lomein.persona.v1",
            "sha256": sha256_text("john-lomein.persona.v1 contract source"),
        },
        descriptor={
            "id": "openai-responses-candidate-v1",
            "route_id": "qualification-candidate-route-v1",
        },
        remaining_token_budget=20_000,
    )
    candidate_provider_response = provider_response(
        response_id="resp_candidate_schema_contract",
        model=candidate["model"],
        effort=candidate["reasoning_effort"],
        output="No. Show the architectural boundary before we fund a rewrite.",
        max_output_tokens=2_000,
    )
    with mock.patch.object(
        ADAPTER, "_post_responses", return_value=candidate_provider_response
    ):
        candidate_result = ADAPTER._run_candidate(
            ADAPTER.validate_candidate_request(candidate_request),
            "qualification-test-key",
            isolation_result(),
        )

    judge_descriptor = {
        "id": "openai-responses-judge-v1",
        "route_id": "qualification-judge-route-v1",
        "model": {
            "provider": "openai",
            "model": "gpt-judge-contract-snapshot",
            "reasoning_effort": "medium",
        },
    }
    judge_request = RUNNER.judge_request(
        run_id="qualification-schema-contract",
        candidate=candidate,
        scenario=scenario,
        response=candidate_result["response"],
        descriptor=judge_descriptor,
        remaining_token_budget=19_850,
    )
    structured_judgments = {
        "judgments": {
            item["id"]: {
                "verdict": True,
                "rationale": f"The response satisfies {item['id']} under the supplied evidence.",
            }
            for item in judge_request["criteria"]
        }
    }
    judge_provider_response = provider_response(
        response_id="resp_judge_schema_contract",
        model=judge_descriptor["model"]["model"],
        effort=judge_descriptor["model"]["reasoning_effort"],
        output=json.dumps(structured_judgments, sort_keys=True, separators=(",", ":")),
        max_output_tokens=4_000,
    )
    with mock.patch.object(
        ADAPTER, "_post_responses", return_value=judge_provider_response
    ):
        judge_result = ADAPTER._run_judge(
            ADAPTER.validate_judge_request(judge_request),
            "qualification-test-key",
            isolation_result(),
        )

    return {
        "command": [
            read_json(ROOT / "templates" / "persona-qualification-candidate-command.json.example"),
            read_json(ROOT / "templates" / "persona-qualification-judge-command.json.example"),
        ],
        "candidate_request": candidate_request,
        "candidate_result": candidate_result,
        "judge_request": judge_request,
        "judge_result": judge_result,
    }


class PersonaQualificationSchemaContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schemas = {
            name: read_json(SCHEMA_ROOT / filename)
            for name, filename in SCHEMA_FILES.items()
        }
        cls.validators = {
            name: Draft202012Validator(schema)
            for name, schema in cls.schemas.items()
        }
        cls.objects = representative_contract_objects()

    def assertSchemaValid(self, schema_name: str, value: object) -> None:
        errors = sorted(
            self.validators[schema_name].iter_errors(value),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
        if errors:
            details = "\n".join(
                f"{list(error.absolute_path)!r}: {error.message}" for error in errors
            )
            self.fail(f"{schema_name} rejected a representative wire object:\n{details}")

    def assertSchemaRejected(self, schema_name: str, value: object) -> None:
        if self.validators[schema_name].is_valid(value):
            self.fail(f"{schema_name} accepted a fail-closed negative fixture")

    def test_all_advertised_schemas_are_valid_draft_2020_12_documents(self):
        for name, schema in self.schemas.items():
            with self.subTest(schema=name):
                Draft202012Validator.check_schema(schema)
                self.assertEqual(
                    schema["$schema"], "https://json-schema.org/draft/2020-12/schema"
                )
                self.assertEqual(schema["$id"], EXPECTED_SCHEMA_IDS[name])

    def test_runner_adapter_and_template_outputs_match_every_schema(self):
        for name, values in self.objects.items():
            if not isinstance(values, list):
                values = [values]
            for index, value in enumerate(values):
                with self.subTest(schema=name, representative=index):
                    self.assertSchemaValid(name, value)

    def test_every_shipped_scenario_projects_into_both_request_schemas(self):
        scenarios = read_json(ROOT / "evals" / "persona" / "scenarios.json")["scenarios"]
        baseline = self.objects["candidate_request"]
        candidate = copy.deepcopy(baseline["candidate"])
        persona = copy.deepcopy(baseline["persona"])
        candidate_descriptor = copy.deepcopy(baseline["adapter"])
        judge_descriptor = {
            "id": self.objects["judge_request"]["judge"]["id"],
            "route_id": self.objects["judge_request"]["judge"]["route_id"],
            "model": {
                field: self.objects["judge_request"]["judge"][field]
                for field in ("provider", "model", "reasoning_effort")
            },
        }
        profile_names = {
            "maintainer": "john-lomein-maintainer",
            "forge": "john-lomein-forge",
            "guide": "john-lomein-guide",
            "overwatch": "john-lomein-overwatch",
            "learning_steward": "john-lomein-learning-steward",
        }
        for scenario in scenarios:
            candidate_request = RUNNER.candidate_request(
                run_id="qualification-all-scenarios-contract",
                candidate=candidate,
                scenario=scenario,
                profile=profile_names[scenario["role"]],
                soul="# John Lomein\n\nShipped scenario contract projection.",
                persona=persona,
                descriptor=candidate_descriptor,
                remaining_token_budget=20_000,
            )
            judge_request = RUNNER.judge_request(
                run_id="qualification-all-scenarios-contract",
                candidate=candidate,
                scenario=scenario,
                response="A bounded maintainer response used only for schema validation.",
                descriptor=judge_descriptor,
                remaining_token_budget=19_000,
            )
            with self.subTest(schema="candidate_request", scenario=scenario["id"]):
                self.assertSchemaValid("candidate_request", candidate_request)
            with self.subTest(schema="judge_request", scenario=scenario["id"]):
                self.assertSchemaValid("judge_request", judge_request)

    def test_unknown_fields_fail_closed_at_every_wire_root(self):
        for name, values in self.objects.items():
            value = copy.deepcopy(values[0] if isinstance(values, list) else values)
            value["unexpected_wire_field"] = "must-not-pass"
            with self.subTest(schema=name):
                self.assertSchemaRejected(name, value)

    def test_filesystem_sensitive_scenario_ids_must_be_safe_components(self):
        mutations = (
            ("candidate_request", lambda value: value["scenario"].__setitem__("id", "../escape")),
            ("candidate_result", lambda value: value.__setitem__("scenario_id", "path/escape")),
            ("judge_request", lambda value: value["scenario"].__setitem__("id", "..")),
            ("judge_result", lambda value: value.__setitem__("scenario_id", "path/escape")),
        )
        for schema_name, mutate in mutations:
            value = copy.deepcopy(self.objects[schema_name])
            mutate(value)
            with self.subTest(schema=schema_name):
                self.assertSchemaRejected(schema_name, value)

    def test_candidate_contract_rejects_answer_key_leakage_and_exposed_capabilities(self):
        leaked = copy.deepcopy(self.objects["candidate_request"])
        leaked["scenario"]["expected"] = ["coach the candidate"]
        self.assertSchemaRejected("candidate_request", leaked)

        tools = copy.deepcopy(self.objects["candidate_request"])
        tools["execution_policy"]["tools"] = ["shell"]
        self.assertSchemaRejected("candidate_request", tools)

        reused_context = copy.deepcopy(self.objects["candidate_result"])
        reused_context["execution"]["isolation"]["prior_session_loaded"] = True
        self.assertSchemaRejected("candidate_result", reused_context)

        excessive_output = copy.deepcopy(self.objects["candidate_result"])
        excessive_output["execution"]["usage"]["output_tokens"] = 2_001
        self.assertSchemaRejected("candidate_result", excessive_output)

    def test_judge_contract_rejects_weakened_policy_or_incomplete_judgments(self):
        trusted_response = copy.deepcopy(self.objects["judge_request"])
        trusted_response["judge_policy"]["candidate_response_is_untrusted_data"] = False
        self.assertSchemaRejected("judge_request", trusted_response)

        tools = copy.deepcopy(self.objects["judge_request"])
        tools["execution_policy"]["tools"] = ["repository"]
        self.assertSchemaRejected("judge_request", tools)

        not_independent = copy.deepcopy(self.objects["judge_result"])
        not_independent["judge"]["independent"] = False
        self.assertSchemaRejected("judge_result", not_independent)

        incomplete = copy.deepcopy(self.objects["judge_result"])
        incomplete["judgments"] = incomplete["judgments"][:1]
        self.assertSchemaRejected("judge_result", incomplete)


    def test_results_require_positive_provider_usage(self):
        for schema_name in ("candidate_result", "judge_result"):
            for field in ("input_tokens", "output_tokens"):
                value = copy.deepcopy(self.objects[schema_name])
                value["execution"]["usage"][field] = 0
                with self.subTest(schema=schema_name, usage=field):
                    self.assertSchemaRejected(schema_name, value)

    def test_untrusted_text_rejects_nul_and_blank_payloads(self):
        mutations = (
            (
                "candidate_request",
                lambda value: value.__setitem__("effective_prompt", "valid\u0000hidden"),
            ),
            (
                "candidate_request",
                lambda value: value["scenario"].__setitem__("authority_state", " \t\n"),
            ),
            ("candidate_result", lambda value: value.__setitem__("response", "ok\u0000bad")),
            (
                "judge_request",
                lambda value: value["scenario"].__setitem__("permitted_action", "ok\u0000bad"),
            ),
            (
                "judge_result",
                lambda value: value["judgments"][0].__setitem__("rationale", " \n"),
            ),
        )
        for schema_name, mutate in mutations:
            value = copy.deepcopy(self.objects[schema_name])
            mutate(value)
            with self.subTest(schema=schema_name):
                self.assertSchemaRejected(schema_name, value)

    def test_command_descriptor_rejects_unsafe_credentials_and_ambiguous_models(self):
        candidate, judge = copy.deepcopy(self.objects["command"])

        candidate["credential_env"] = ["QUALIFICATION_GITHUB_API_KEY"]
        self.assertSchemaRejected("command", candidate)

        candidate = copy.deepcopy(self.objects["command"][0])
        candidate["models"].append(copy.deepcopy(candidate["models"][0]))
        self.assertSchemaRejected("command", candidate)

        judge["model"]["undeclared_provider_option"] = True
        self.assertSchemaRejected("command", judge)


if __name__ == "__main__":
    unittest.main()
