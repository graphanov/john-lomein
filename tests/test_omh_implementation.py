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
from types import SimpleNamespace
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
OMH_IMPL_PATH = ROOT / "scripts" / "john-lomein-omh-implementation.py"


def load_omh_impl() -> Any:
    spec = importlib.util.spec_from_file_location("john_lomein_omh_implementation", OMH_IMPL_PATH)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


class OmhImplementationPathTest(unittest.TestCase):
    def test_instance_omh_setup_installs_the_full_role_skill_contract(self):
        deploy = (ROOT / "scripts" / "deploy-instance.sh").read_text(encoding="utf-8")
        doctor = (ROOT / "scripts" / "doctor-instance.py").read_text(encoding="utf-8")
        self.assertIn('"setup", "--full", "--yes"', deploy)
        self.assertNotIn("memory-curation-review", deploy)
        self.assertNotIn("memory-curation-review", doctor)
        self.assertIn("'memory-sync'", deploy)
        self.assertIn("'memory-sync'", doctor)
        self.assertIn('catalog_path = omh_home / "manifest.json"', deploy)
        self.assertIn("source_component=source_component", deploy)
        self.assertIn("omh_catalog_skill_sources", doctor)

    def test_command_env_strips_git_publication_credentials(self):
        mod = load_omh_impl()
        with tempfile.TemporaryDirectory() as tmp:
            args = SimpleNamespace(
                hermes_home=Path(tmp) / "hermes",
                omh_home=Path(tmp) / "omh",
                codex_home=Path(tmp) / "codex",
            )
            with mock.patch.dict(
                os.environ,
                {
                    "GH_TOKEN": "secret",
                    "GITHUB_TOKEN": "secret",
                    "GH_CONFIG_DIR": str(Path(tmp) / "gh"),
                    "SSH_AUTH_SOCK": str(Path(tmp) / "agent"),
                    "MNEMOSYNE_DATA_DIR": str(Path(tmp) / "memory"),
                },
                clear=False,
            ):
                env = mod.command_env(args)

        self.assertNotIn("GH_TOKEN", env)
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("GH_CONFIG_DIR", env)
        self.assertNotIn("SSH_AUTH_SOCK", env)
        self.assertNotIn("MNEMOSYNE_DATA_DIR", env)

    def test_command_env_resolves_owner_local_bin_from_instance_home(self):
        mod = load_omh_impl()
        with tempfile.TemporaryDirectory() as tmp:
            owner = Path(tmp) / "owner"
            bin_dir = owner / ".local" / "bin"
            bin_dir.mkdir(parents=True)
            omh = bin_dir / "omh"
            omh.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            omh.chmod(0o755)
            hermes_home = owner / ".john-lomein" / "instances" / "example" / "hermes"
            args = SimpleNamespace(hermes_home=hermes_home, omh_home=None, codex_home=None)
            old_path = os.environ.get("PATH")
            old_real = os.environ.get("HERMES_REAL_HOME")
            old_bot_real = os.environ.get("BOT_REAL_HOME")
            try:
                os.environ["PATH"] = "/usr/bin"
                os.environ.pop("HERMES_REAL_HOME", None)
                os.environ.pop("BOT_REAL_HOME", None)
                env = mod.command_env(args)
            finally:
                if old_path is None:
                    os.environ.pop("PATH", None)
                else:
                    os.environ["PATH"] = old_path
                if old_real is None:
                    os.environ.pop("HERMES_REAL_HOME", None)
                else:
                    os.environ["HERMES_REAL_HOME"] = old_real
                if old_bot_real is None:
                    os.environ.pop("BOT_REAL_HOME", None)
                else:
                    os.environ["BOT_REAL_HOME"] = old_bot_real

            self.assertIn(str(bin_dir), env["PATH"].split(os.pathsep))
            self.assertEqual(mod.resolve_command("omh", env), str(omh))

    def run_wrapper_with_fakes(
        self,
        root: Path,
        *,
        delegate_payload: Any,
        final_answer: str,
        readiness_payload: Any = None,
        prompt_text: str = "implement the issue",
        codex_stdout: str = "",
        codex_stderr: str = "",
        codex_launchable: bool = True,
        codex_final_mode: str = "file",
        prompt_mode: str = "file",
        preexisting_final: str | None = None,
        preexisting_artifacts: dict[str, str] | None = None,
        runtime_home_mode: str = "directory",
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        readiness_payload = readiness_payload or {"status": "ready", "available": True}
        owner = root / "owner"
        bin_dir = owner / ".local" / "bin"
        bin_dir.mkdir(parents=True)
        hermes_home = owner / ".john-lomein" / "instances" / "example" / "hermes"
        local = root / "repo"
        cycle = root / "cycle"
        prompt = root / "prompt.md"
        local.mkdir()
        hermes_home.mkdir(parents=True)
        cycle.mkdir()
        if prompt_mode == "directory":
            prompt.mkdir()
        else:
            prompt.write_text(prompt_text, encoding="utf-8")
        if runtime_home_mode == "file":
            (cycle / "codex-runtime-home").write_text("not-a-directory", encoding="utf-8")
        write_executable(
            bin_dir / "omh",
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            f"delegate_payload = json.loads({json.dumps(delegate_payload)!r})\n"
            f"readiness_payload = json.loads({json.dumps(readiness_payload)!r})\n"
            "joined = ' '.join(sys.argv)\n"
            "if 'executor-readiness' in joined:\n"
            "    print(json.dumps(readiness_payload))\n"
            "elif 'coding' in joined and 'delegate' in joined:\n"
            "    print(json.dumps(delegate_payload))\n"
            "elif 'chat' in joined and 'interact' in joined and '--json' not in sys.argv:\n"
            "    print('human-readable chat interaction; use --json for the machine envelope')\n"
            "else:\n"
            "    print(json.dumps({'status': 'ok'}))\n",
        )
        if codex_launchable:
            if codex_final_mode == "directory":
                final_write = (
                    "path.mkdir()\n"
                    "(path / 'sentinel').write_text('preserve-me', encoding='utf-8')\n"
                )
            elif codex_final_mode == "invalid_utf8":
                final_write = "path.write_bytes(b'bad-utf8-\\xff\\nJOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE\\n')\n"
            else:
                final_write = f"path.write_text({final_answer!r}, encoding='utf-8')\n"
            codex_program = (
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, sys\n"
                "pathlib.Path('codex-cwd.txt').write_text(str(pathlib.Path.cwd()), encoding='utf-8')\n"
                "pathlib.Path('codex-argv.txt').write_text('\\n'.join(sys.argv), encoding='utf-8')\n"
                "pathlib.Path('codex-env.json').write_text(json.dumps(dict(os.environ), sort_keys=True), encoding='utf-8')\n"
                "path = pathlib.Path(sys.argv[sys.argv.index('--output-last-message') + 1])\n"
                + final_write
                + "sys.stdin.read()\n"
                + f"sys.stdout.write({codex_stdout!r})\n"
                + f"sys.stderr.write({codex_stderr!r})\n"
                + "sys.exit(0)\n"
            )
        else:
            codex_program = "#!/definitely/missing/python\n"
        write_executable(bin_dir / "codex", codex_program)
        if preexisting_final is not None:
            (cycle / "codex-final.md").write_text(preexisting_final, encoding="utf-8")
        for name, content in (preexisting_artifacts or {}).items():
            (cycle / name).write_text(content, encoding="utf-8")
        env = os.environ.copy()
        env["PATH"] = "/usr/bin"
        env["HERMES_REAL_HOME"] = str(owner)
        env["BOT_REAL_HOME"] = str(owner)
        env["GH_TOKEN"] = "must-not-reach-codex"
        env["GITHUB_TOKEN"] = "must-not-reach-codex-either"
        env["GH_CONFIG_DIR"] = str(root / "private-gh-config")
        env["SSH_AUTH_SOCK"] = str(root / "private-ssh-agent")
        # This subprocess fixture is not a deployed appliance. Dedicated
        # integration tests exercise the required OS boundary itself.
        env["BOT_MODEL_MEMORY_ISOLATION"] = "disabled"
        proc = subprocess.run(
            [
                sys.executable,
                str(OMH_IMPL_PATH),
                "--repo",
                "owner/repo",
                "--local",
                str(local),
                "--branch",
                "forge/issue-1",
                "--issue",
                "1",
                "--cycle",
                str(cycle),
                "--prompt-file",
                str(prompt),
                "--hermes-home",
                str(hermes_home),
                "--omh-home",
                str(root / "omh-home"),
                "--timeout",
                "5",
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=20,
        )
        return proc, cycle

    def test_codex_zero_exit_blocked_marker_records_blocked_and_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc, cycle = self.run_wrapper_with_fakes(
                Path(tmp),
                delegate_payload={"status": "ok"},
                final_answer="Implementation could not create a PR.\nJOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED\n",
                codex_stdout="Implementation could not create a PR.\nJOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED\n",
                codex_stderr="transcript tail\nJOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED\n",
            )

            self.assertNotEqual(proc.returncode, 0)
            result = json.loads((cycle / "executor-result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["semantic_status"], "BLOCKED")
            self.assertIn(result["semantic_status_source"], {"codex_final", "duplicate_marker", "ambiguous_marker"})
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(proc.stdout.splitlines().count("JOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED"), 1)
            self.assertNotIn("JOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE", proc.stdout)

    def test_codex_launch_error_is_recorded_and_emits_one_blocked_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc, cycle = self.run_wrapper_with_fakes(
                Path(tmp),
                delegate_payload={"status": "ok"},
                final_answer="",
                codex_launchable=False,
            )

            self.assertEqual(proc.returncode, 1)
            self.assertEqual(proc.stdout.splitlines().count("JOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED"), 1)
            self.assertNotIn("JOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE", proc.stdout)
            self.assertNotIn("Traceback", proc.stdout + proc.stderr)
            result = json.loads((cycle / "executor-result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["blocker"], "codex_process_launch_failed")
            self.assertEqual(result["semantic_status"], "BLOCKED")
            self.assertEqual(result["semantic_status_source"], "missing_marker")
            self.assertFalse(result["observed"])
            self.assertEqual(result["exit_code"], 1)
            self.assertEqual(result["semantic_marker_evidence"], [])
            self.assertEqual(result["process_errors"][0]["artifact"], "codex_process")
            self.assertEqual(result["process_errors"][0]["operation"], "launch")
            self.assertTrue(result["process_errors"][0]["error_type"])
            self.assertEqual((cycle / "codex-stdout.log").read_text(encoding="utf-8"), "")
            self.assertIn("codex process launch failed", (cycle / "codex-stderr.log").read_text(encoding="utf-8"))
            self.assertFalse((cycle / "codex-final.md").exists())

    def test_codex_final_read_error_blocks_and_preserves_raw_artifacts(self):
        raw_stdout = "raw stdout\nJOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE\n"
        raw_stderr = "raw stderr\nJOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE\n"
        with tempfile.TemporaryDirectory() as tmp:
            proc, cycle = self.run_wrapper_with_fakes(
                Path(tmp),
                delegate_payload={"status": "ok"},
                final_answer="",
                codex_stdout=raw_stdout,
                codex_stderr=raw_stderr,
                codex_final_mode="directory",
            )

            self.assertEqual(proc.returncode, 1)
            self.assertEqual(proc.stdout.splitlines().count("JOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED"), 1)
            self.assertNotIn("JOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE", proc.stdout)
            self.assertNotIn("Traceback", proc.stdout + proc.stderr)
            result = json.loads((cycle / "executor-result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["blocker"], "codex_final_artifact_read_failed")
            self.assertEqual(result["semantic_status"], "COMPLETE")
            self.assertEqual(result["semantic_status_source"], "codex_stdout")
            self.assertTrue(result["observed"])
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(
                result["semantic_marker_evidence"],
                [{"source": "codex_stdout", "status": "COMPLETE"}],
            )
            self.assertEqual(result["artifact_read_errors"][0]["artifact"], "codex_final")
            self.assertEqual(result["artifact_read_errors"][0]["operation"], "read")
            self.assertEqual((cycle / "codex-stdout.log").read_text(encoding="utf-8"), raw_stdout)
            self.assertEqual((cycle / "codex-stderr.log").read_text(encoding="utf-8"), raw_stderr)
            self.assertTrue((cycle / "codex-final.md").is_dir())
            self.assertEqual((cycle / "codex-final.md" / "sentinel").read_text(encoding="utf-8"), "preserve-me")

    def test_invalid_utf8_final_artifact_cannot_become_complete_from_stdout(self):
        raw_stdout = "raw stdout\nJOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE\n"
        with tempfile.TemporaryDirectory() as tmp:
            proc, cycle = self.run_wrapper_with_fakes(
                Path(tmp),
                delegate_payload={"status": "ok"},
                final_answer="",
                codex_stdout=raw_stdout,
                codex_final_mode="invalid_utf8",
            )

            self.assertEqual(proc.returncode, 1)
            self.assertEqual(proc.stdout.splitlines().count("JOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED"), 1)
            self.assertNotIn("JOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE", proc.stdout)
            result = json.loads((cycle / "executor-result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["blocker"], "codex_final_artifact_read_failed")
            self.assertEqual(result["artifact_read_errors"][0]["error_type"], "UnicodeDecodeError")
            self.assertIn(b"\xff", (cycle / "codex-final.md").read_bytes())

    def test_prompt_read_error_records_blocked_without_launching_codex(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc, cycle = self.run_wrapper_with_fakes(
                root,
                delegate_payload={"status": "ok"},
                final_answer="Done.\nJOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE\n",
                prompt_mode="directory",
            )

            self.assertEqual(proc.returncode, 1)
            self.assertEqual(proc.stdout.splitlines().count("JOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED"), 1)
            self.assertNotIn("JOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE", proc.stdout)
            self.assertNotIn("Traceback", proc.stdout + proc.stderr)
            result = json.loads((cycle / "executor-result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["blocker"], "implementation_prompt_artifact_read_failed")
            self.assertEqual(result["artifact_read_errors"][0]["artifact"], "implementation_prompt")
            self.assertFalse((root / "repo" / "codex-cwd.txt").exists())

    def test_codex_process_environment_prepare_error_is_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc, cycle = self.run_wrapper_with_fakes(
                root,
                delegate_payload={"status": "ok"},
                final_answer="Done.\nJOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE\n",
                runtime_home_mode="file",
            )

            self.assertEqual(proc.returncode, 1)
            self.assertEqual(proc.stdout.splitlines().count("JOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED"), 1)
            self.assertNotIn("JOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE", proc.stdout)
            self.assertNotIn("Traceback", proc.stdout + proc.stderr)
            result = json.loads((cycle / "executor-result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["blocker"], "codex_process_prepare_failed")
            self.assertEqual(result["process_errors"][0]["operation"], "prepare")
            self.assertFalse(result["observed"])
            self.assertFalse((root / "repo" / "codex-cwd.txt").exists())

    def test_preexisting_final_artifact_blocks_without_reusing_stale_complete(self):
        stale = "stale result\nJOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE\n"
        prior_artifacts = {
            "omh-chat-interact.json": '{"prior":"chat"}\n',
            "omh-chat-interact.err": "prior chat stderr\n",
            "omh-coding-delegate.json": '{"prior":"delegate"}\n',
            "omh-coding-delegate.err": "prior delegate stderr\n",
            "executor-readiness.json": '{"prior":"readiness"}\n',
            "executor-readiness.err": "prior readiness stderr\n",
            "codex-stdout.log": "prior stdout\n",
            "codex-stderr.log": "prior stderr\n",
            "executor-result.json": '{"prior":"result"}\n',
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc, cycle = self.run_wrapper_with_fakes(
                root,
                delegate_payload={"status": "ok"},
                final_answer="This must not run.\nJOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE\n",
                preexisting_final=stale,
                preexisting_artifacts=prior_artifacts,
            )

            self.assertEqual(proc.returncode, 1)
            self.assertEqual(proc.stdout.splitlines().count("JOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED"), 1)
            self.assertNotIn("JOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE", proc.stdout)
            receipts = list(cycle.glob("executor-preflight-blocked-*.json"))
            self.assertEqual(len(receipts), 1)
            result = json.loads(receipts[0].read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["blocker"], "codex_final_artifact_preexisting")
            self.assertEqual((cycle / "codex-final.md").read_text(encoding="utf-8"), stale)
            for name, content in prior_artifacts.items():
                self.assertEqual((cycle / name).read_text(encoding="utf-8"), content)
            self.assertFalse((root / "repo" / "codex-cwd.txt").exists())

    def test_preexisting_executor_artifact_without_final_is_preserved(self):
        prior = '{"prior":"launch-failure"}\n'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc, cycle = self.run_wrapper_with_fakes(
                root,
                delegate_payload={"status": "ok"},
                final_answer="This must not run.\nJOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE\n",
                preexisting_artifacts={"executor-result.json": prior},
            )

            self.assertEqual(proc.returncode, 1)
            self.assertEqual(proc.stdout.splitlines().count("JOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED"), 1)
            receipts = list(cycle.glob("executor-preflight-blocked-*.json"))
            self.assertEqual(len(receipts), 1)
            result = json.loads(receipts[0].read_text(encoding="utf-8"))
            self.assertEqual(result["blocker"], "executor_artifact_preexisting")
            self.assertEqual((cycle / "executor-result.json").read_text(encoding="utf-8"), prior)
            self.assertFalse((root / "repo" / "codex-cwd.txt").exists())

    def test_omh_delegate_semantic_blocked_requirements_missing_blocks_zero_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc, cycle = self.run_wrapper_with_fakes(
                Path(tmp),
                delegate_payload={"status": "blocked_requirements_missing", "missing": ["repo_context"]},
                final_answer="This should not run.\nJOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE\n",
            )

            self.assertNotEqual(proc.returncode, 0)
            result = json.loads((cycle / "executor-result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["blocker"], "omh_handoff_or_readiness_failed")
            self.assertTrue(any("blocked_requirements_missing" in item for item in result["blockers"]))
            self.assertFalse((cycle / "codex-final.md").exists())

    def test_dispatchable_omh_prepared_handoff_with_concrete_prompt_runs_codex(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "repo"
            prompt = f"""
Implement the approved plan for owner/repo in implementation worktree {local}.
Allowed side effects: edit scoped repo files inside implementation worktree {local}, run tests there, commit scoped changes on branch forge/issue-1, push branch, open/update a DRAFT PR.
Forbidden side effects: merge, publish, release, workflow dispatch, force-push, branch-protection changes, settings changes, secrets.

Issue #1: Prepare release prep

Implementation requirements:
- branch name must be forge/issue-1;
- repository cwd/local path must be the implementation worktree {local};
- run git diff --check;
- do not merge or publish.

End with exactly one marker line:
JOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE
or
JOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED
""".strip()
            proc, cycle = self.run_wrapper_with_fakes(
                root,
                delegate_payload={
                    "schema_version": "coding_delegation/v1",
                    "status": "blocked_requirements_missing",
                    "dispatchable": True,
                    "dispatch_policy": "ask_before_dispatch",
                    "selected_executor_profile": "codex",
                    "executor_handoff_prompt": "You are Codex; implement the prepared john-lomein handoff.",
                    "runtime": {
                        "reason": "requirements_or_dispatch_intent_missing",
                        "record_status": "blocked_requirements_missing",
                        "recorded": False,
                        "run_created": False,
                    },
                },
                final_answer="Done.\nJOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE\n",
                prompt_text=prompt,
            )

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            result = json.loads((cycle / "executor-result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "COMPLETE")
            self.assertTrue(result["coding_delegate_prepared_handoff_accepted"])
            self.assertTrue((local / "codex-cwd.txt").exists())

    def test_nested_informational_unknown_or_missing_statuses_are_not_blockers(self):
        mod = load_omh_impl()
        blockers = mod.semantic_blockers(
            "coding_delegate",
            {
                "status": "ok",
                "metadata": {"status": "unknown", "result": "missing"},
                "details": [{"state": "not_ready_yet", "missing": True}],
            },
        )

        self.assertEqual(blockers, [])

    def test_nested_omh_command_error_schema_still_blocks(self):
        mod = load_omh_impl()
        blockers = mod.semantic_blockers(
            "coding_delegate",
            {"status": "ok", "artifacts": [{"schema_version": "john_lomein_omh_command_error/v1"}]},
        )

        self.assertEqual(blockers, ["coding_delegate:artifacts[0]:command_error"])

    def test_readiness_available_normalizes_false_like_strings(self):
        mod = load_omh_impl()

        for value in ["false", "0", "no", "off", "unavailable", "not-available"]:
            self.assertFalse(mod.readiness_available(value), value)
        for value in [None, True, "true", "1", "yes", "available"]:
            self.assertTrue(mod.readiness_available(value), value)

    def test_string_false_executor_readiness_available_blocks_before_codex(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc, cycle = self.run_wrapper_with_fakes(
                Path(tmp),
                delegate_payload={"status": "ok"},
                readiness_payload={"status": "ready", "available": "false"},
                final_answer="Done.\nJOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE\n",
            )

            self.assertNotEqual(proc.returncode, 0)
            result = json.loads((cycle / "executor-result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["blocker"], "omh_handoff_or_readiness_failed")
            self.assertFalse((cycle / "codex-final.md").exists())

    def test_non_object_omh_machine_envelope_blocks_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc, cycle = self.run_wrapper_with_fakes(
                root,
                delegate_payload={"status": "ok"},
                readiness_payload=["ready"],
                final_answer="This must not run.\nJOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE\n",
            )

            self.assertEqual(proc.returncode, 1)
            self.assertEqual(proc.stdout.splitlines().count("JOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED"), 1)
            self.assertNotIn("JOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE", proc.stdout)
            self.assertNotIn("Traceback", proc.stdout + proc.stderr)
            result = json.loads((cycle / "executor-result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["blocker"], "omh_handoff_or_readiness_failed")
            self.assertTrue(any("command_error" in item for item in result["blockers"]))
            readiness = json.loads((cycle / "executor-readiness.json").read_text(encoding="utf-8"))
            self.assertEqual(readiness["schema_version"], "john_lomein_omh_command_error/v1")
            self.assertFalse((root / "repo" / "codex-cwd.txt").exists())

    def test_codex_invocation_uses_local_path_as_cd_and_cwd(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc, cycle = self.run_wrapper_with_fakes(
                root,
                delegate_payload={"status": "ok"},
                final_answer="Done.\nJOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE\n",
                codex_stdout="Done.\nJOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE\n",
                codex_stderr="transcript tail\nJOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE\n",
            )

            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stdout.splitlines().count("JOHN_LOMEIN_IMPLEMENT_STATUS: COMPLETE"), 1)
            self.assertNotIn("JOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED", proc.stdout)
            local = root / "repo"
            result = json.loads((cycle / "executor-result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["local"], str(local))
            cmd = result["codex_command"]
            self.assertEqual(cmd[cmd.index("--cd") + 1], str(local))
            self.assertIn("--ignore-user-config", cmd)
            self.assertIn("--ignore-rules", cmd)
            self.assertIn("--ephemeral", cmd)
            self.assertIn("shell_environment_policy.inherit=none", cmd)
            self.assertIn("mcp_servers={}", cmd)
            self.assertEqual(Path((local / "codex-cwd.txt").read_text(encoding="utf-8")).resolve(), local.resolve())
            child_env = json.loads((local / "codex-env.json").read_text(encoding="utf-8"))
            self.assertNotIn("GH_TOKEN", child_env)
            self.assertNotIn("GITHUB_TOKEN", child_env)
            self.assertNotIn("GH_CONFIG_DIR", child_env)
            self.assertNotIn("SSH_AUTH_SOCK", child_env)
            self.assertFalse(any(key.startswith("BOT_") for key in child_env))
            self.assertNotIn("must-not-reach-codex", repr(child_env))
            self.assertNotIn("private-gh-config", repr(child_env))


if __name__ == "__main__":
    unittest.main()
