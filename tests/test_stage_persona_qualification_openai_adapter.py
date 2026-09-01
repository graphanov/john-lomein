from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
STAGER = ROOT / "scripts" / "stage-persona-qualification-openai-adapter.py"
ADAPTER = ROOT / "qualification_adapters" / "openai_responses.py"
RUNNER_PATH = ROOT / "scripts" / "john-lomein-persona-qualification.py"
RUNNER_SPEC = importlib.util.spec_from_file_location(
    "persona_qualification_runner_for_stager", RUNNER_PATH
)
assert RUNNER_SPEC and RUNNER_SPEC.loader
runner = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(runner)
STAGER_SPEC = importlib.util.spec_from_file_location(
    "persona_qualification_openai_stager_for_tests", STAGER
)
assert STAGER_SPEC and STAGER_SPEC.loader
stager = importlib.util.module_from_spec(STAGER_SPEC)
STAGER_SPEC.loader.exec_module(stager)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class OpenAIQualificationAdapterStagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.instance = self.base / "instance"
        self.runtime = self.base / "runtime" / "hermes"
        self.checkout = self.base / "managed" / "checkout"
        self.operator = self.base / "operator"
        for path in (self.instance, self.runtime, self.checkout, self.operator):
            path.mkdir(parents=True, mode=0o700)
            path.chmod(0o700)

        self.python = self.operator / "python-binary"
        shutil.copyfile(Path(sys.executable).resolve(strict=True), self.python)
        self.python.chmod(0o700)

        self.manifest = yaml.safe_load(
            (ROOT / "templates" / "instance.yaml.example").read_text(encoding="utf-8")
        )
        self.manifest["instance"]["slug"] = "openai-stage-test"
        self.manifest["target"]["local_checkout"] = str(self.checkout)
        self.manifest["runtime"]["hermes_home"] = str(self.runtime)
        self.manifest["model"] = {
            "provider": "openai",
            "default": "gpt-candidate-primary-snapshot",
            "reasoning_effort": "high",
            "fallback": {
                "provider": "openai",
                "model": "gpt-candidate-fallback-snapshot",
                "reasoning_effort": "medium",
            },
        }
        self._write_manifest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_manifest(self) -> None:
        path = self.instance / "instance.yaml"
        path.write_text(
            yaml.safe_dump(self.manifest, sort_keys=False),
            encoding="utf-8",
        )
        path.chmod(0o600)

    def _invoke(self, *extra: str, destination: Path | None = None):
        destination = destination or (self.operator / "staged")
        command = [
            sys.executable,
            str(STAGER),
            "--instance",
            str(self.instance),
            "--destination",
            str(destination),
            "--python",
            str(self.python),
            "--judge-provider",
            "openai",
            "--judge-model",
            "gpt-independent-judge-snapshot",
            "--judge-reasoning-effort",
            "xhigh",
            *extra,
        ]
        environment = os.environ.copy()
        environment["QUALIFICATION_CANDIDATE_API_KEY"] = "PRIVATE-CANDIDATE-VALUE"
        environment["QUALIFICATION_JUDGE_API_KEY"] = "PRIVATE-JUDGE-VALUE"
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        result = json.loads(completed.stdout) if completed.stdout else None
        return completed, result, destination

    def test_stages_private_fixed_commands_and_public_safe_hashes(self) -> None:
        completed, result, destination = self._invoke()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["status"], "staged")
        self.assertEqual(result["destination"], str(destination))
        self.assertEqual(stat.S_IMODE(destination.lstat().st_mode), 0o700)
        self.assertEqual(
            sorted(path.name for path in destination.iterdir()),
            ["candidate-command.json", "judge-command.json", "openai_responses.py"],
        )
        for path in destination.iterdir():
            self.assertEqual(stat.S_IMODE(path.lstat().st_mode), 0o600)
            self.assertTrue(path.is_file())
            self.assertFalse(path.is_symlink())

        staged_adapter = destination / "openai_responses.py"
        self.assertEqual(staged_adapter.read_bytes(), ADAPTER.read_bytes())
        candidate_path = destination / "candidate-command.json"
        judge_path = destination / "judge-command.json"
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        judge = json.loads(judge_path.read_text(encoding="utf-8"))

        self.assertEqual(candidate["kind"], "candidate")
        self.assertEqual(judge["kind"], "judge")
        self.assertNotEqual(candidate["id"], judge["id"])
        self.assertNotEqual(candidate["route_id"], judge["route_id"])
        self.assertNotEqual(candidate["argv"], judge["argv"])
        self.assertEqual(candidate["argv"][0], str(self.python))
        self.assertEqual(candidate["argv"][1], str(staged_adapter))
        self.assertEqual(
            candidate["argv"][2:],
            [
                "--kind",
                "candidate",
                "--api-key-env",
                "QUALIFICATION_CANDIDATE_API_KEY",
            ],
        )
        self.assertEqual(
            candidate["credential_env"], ["QUALIFICATION_CANDIDATE_API_KEY"]
        )
        self.assertEqual(
            judge["credential_env"], ["QUALIFICATION_JUDGE_API_KEY"]
        )
        self.assertEqual(
            candidate["models"],
            [
                {
                    "provider": "openai",
                    "model": "gpt-candidate-primary-snapshot",
                    "reasoning_effort": "high",
                },
                {
                    "provider": "openai",
                    "model": "gpt-candidate-fallback-snapshot",
                    "reasoning_effort": "medium",
                },
            ],
        )
        self.assertEqual(judge["model"], result["judge_model"])

        loaded_candidate = runner.load_command_descriptor(candidate_path, kind="candidate")
        loaded_judge = runner.load_command_descriptor(judge_path, kind="judge")
        runner.validate_descriptors(
            loaded_candidate,
            loaded_judge,
            runner.configured_candidates(self.manifest),
            forbidden_roots=[ROOT.resolve(), self.runtime, self.checkout],
        )

        artifacts = result["artifacts"]
        self.assertEqual(
            artifacts["adapter"]["file_sha256"],
            sha256_bytes(staged_adapter.read_bytes()),
        )
        self.assertEqual(
            artifacts["candidate_command"]["file_sha256"],
            sha256_bytes(candidate_path.read_bytes()),
        )
        self.assertEqual(
            artifacts["candidate_command"]["descriptor_sha256"],
            sha256_bytes(canonical_json(candidate).encode("utf-8")),
        )
        self.assertEqual(
            artifacts["judge_command"]["descriptor_sha256"],
            sha256_bytes(canonical_json(judge).encode("utf-8")),
        )

        combined = completed.stdout + completed.stderr
        for secret in ("PRIVATE-CANDIDATE-VALUE", "PRIVATE-JUDGE-VALUE"):
            self.assertNotIn(secret, combined)
            self.assertNotIn(
                secret,
                "".join(path.read_text(encoding="utf-8", errors="ignore") for path in destination.iterdir()),
            )

    def test_deduplicates_identical_primary_and_fallback_in_order(self) -> None:
        self.manifest["model"]["fallback"] = {
            "provider": "openai",
            "model": "gpt-candidate-primary-snapshot",
            "reasoning_effort": "high",
        }
        self._write_manifest()

        completed, result, destination = self._invoke()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(len(result["candidate_models"]), 1)
        candidate = json.loads(
            (destination / "candidate-command.json").read_text(encoding="utf-8")
        )
        self.assertEqual(candidate["models"], result["candidate_models"])

    def test_fallback_model_field_matches_runner_precedence(self) -> None:
        self.manifest["model"]["fallback"] = {
            "provider": "openai",
            "model": "gpt-fallback-model-field",
            "default": "gpt-fallback-default-field",
            "reasoning_effort": "medium",
        }
        self._write_manifest()

        completed, result, destination = self._invoke()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            result["candidate_models"][1]["model"],
            "gpt-fallback-model-field",
        )
        candidate = runner.load_command_descriptor(
            destination / "candidate-command.json", kind="candidate"
        )
        judge = runner.load_command_descriptor(
            destination / "judge-command.json", kind="judge"
        )
        runner.validate_descriptors(
            candidate,
            judge,
            runner.configured_candidates(self.manifest),
            forbidden_roots=[ROOT.resolve(), self.runtime, self.checkout],
        )

    def test_shipped_openai_codex_and_any_non_openai_fallback_fail_closed(self) -> None:
        self.manifest["model"]["provider"] = "openai-codex"
        self.manifest["model"]["fallback"]["provider"] = "openai-codex"
        self._write_manifest()
        completed, result, destination = self._invoke()
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(result["reason"], "candidate-provider-openai-codex-unsupported")
        self.assertFalse(destination.exists())

        self.manifest["model"]["provider"] = "openai"
        self.manifest["model"]["fallback"]["provider"] = "other-provider"
        self._write_manifest()
        completed, result, destination = self._invoke()
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(result["reason"], "candidate-provider-not-openai")
        self.assertFalse(destination.exists())

    def test_rejects_slug_the_qualification_runner_cannot_load(self) -> None:
        self.manifest["instance"]["slug"] = "bad/slug"
        self._write_manifest()

        completed, result, destination = self._invoke()

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(result["reason"], "instance-slug")
        self.assertFalse(destination.exists())

    def test_judge_model_must_be_independent_even_if_reasoning_differs(self) -> None:
        completed, result, destination = self._invoke(
            "--judge-model",
            "gpt-candidate-primary-snapshot",
            "--judge-reasoning-effort",
            "low",
        )

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(result["reason"], "judge-model-not-independent")
        self.assertFalse(destination.exists())

    def test_rejects_relative_overlapping_symlinked_and_writable_destination(self) -> None:
        completed, result, _ = self._invoke(destination=Path("relative-stage"))
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(result["reason"], "destination-not-normalized-absolute")

        completed, result, _ = self._invoke(destination=ROOT / "unsafe-stage")
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(
            result["reason"], "destination-overlaps-repository-runtime-or-checkout"
        )

        link = self.operator / "linked-stage"
        link.symlink_to(self.operator / "absent-target")
        completed, result, _ = self._invoke(destination=link)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(result["reason"], "destination-symlink")

        unsafe = self.base / "unsafe-parent"
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        completed, result, _ = self._invoke(destination=unsafe / "stage")
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(result["reason"], "destination-parent-writable-by-others")

        composed_checkout = self.operator / "\u00e9"
        composed_checkout.mkdir(mode=0o700)
        decomposed_alias = self.operator / "e\u0301"
        try:
            decomposed_alias.mkdir(mode=0o700)
        except FileExistsError:
            pass
        self.manifest["target"]["local_checkout"] = str(composed_checkout)
        self._write_manifest()
        completed, result, _ = self._invoke(
            destination=decomposed_alias / "stage"
        )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(
            result["reason"],
            "destination-overlaps-repository-runtime-or-checkout",
        )

    def test_rejects_symlink_script_interpreter_and_invalid_credential_name(self) -> None:
        symlink = self.operator / "python-link"
        symlink.symlink_to(self.python)
        original = self.python
        self.python = symlink
        completed, result, destination = self._invoke()
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(result["reason"], "python-not-resolved-or-symlink")
        self.assertFalse(destination.exists())

        script = self.operator / "python-script"
        script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        script.chmod(0o700)
        self.python = script
        completed, result, destination = self._invoke()
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(result["reason"], "python-not-regular-binary")
        self.assertFalse(destination.exists())

        self.python = original
        completed, result, destination = self._invoke(
            "--candidate-api-key-env", "OPENAI_API_KEY"
        )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(result["reason"], "candidate-api-key-env-invalid")
        self.assertFalse(destination.exists())

        for flag, reason in (
            (
                "--candidate-api-key-env",
                "candidate-api-key-env-forbidden",
            ),
            ("--judge-api-key-env", "judge-api-key-env-forbidden"),
        ):
            with self.subTest(flag=flag):
                completed, result, destination = self._invoke(
                    flag, "QUALIFICATION_GITHUB_API_KEY"
                )
                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertEqual(result["reason"], reason)
                self.assertFalse(destination.exists())

        oversized = "QUALIFICATION_" + ("A" * 110) + "_API_KEY"
        self.assertGreater(len(oversized), 128)
        for flag, reason in (
            ("--candidate-api-key-env", "candidate-api-key-env-invalid"),
            ("--judge-api-key-env", "judge-api-key-env-invalid"),
        ):
            with self.subTest(flag=flag, oversized=True):
                completed, result, destination = self._invoke(flag, oversized)
                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertEqual(result["reason"], reason)
                self.assertFalse(destination.exists())

    def test_fresh_destination_is_never_overwritten(self) -> None:
        completed, _, destination = self._invoke()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        adapter = destination / "openai_responses.py"
        original_hash = sha256_bytes(adapter.read_bytes())

        completed, result, _ = self._invoke()

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(result["reason"], "destination-exists")
        self.assertEqual(sha256_bytes(adapter.read_bytes()), original_hash)
        self.assertFalse(list(destination.parent.glob(".john-lomein-qualification-adapter.*")))

    def test_destination_created_in_race_window_is_not_replaced(self) -> None:
        destination = self.operator / "raced-stage"
        marker = destination / "attacker-marker"
        original_destination = stager._destination

        def create_after_preflight(value, *, forbidden_roots):
            result = original_destination(value, forbidden_roots=forbidden_roots)
            result.mkdir(mode=0o700)
            marker.write_text("preserve me", encoding="utf-8")
            return result

        args = SimpleNamespace(
            instance=self.instance,
            destination=str(destination),
            python=str(self.python),
            judge_provider="openai",
            judge_model="gpt-independent-judge-snapshot",
            judge_reasoning_effort="xhigh",
            candidate_api_key_env="QUALIFICATION_CANDIDATE_API_KEY",
            judge_api_key_env="QUALIFICATION_JUDGE_API_KEY",
        )
        with mock.patch.object(
            stager, "_destination", side_effect=create_after_preflight
        ):
            with self.assertRaises(stager.StageError) as caught:
                stager.stage(args)

        self.assertEqual(caught.exception.code, "destination-appeared-during-stage")
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve me")


if __name__ == "__main__":
    unittest.main()
