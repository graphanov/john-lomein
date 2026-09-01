from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qualification_verifier import (  # noqa: E402
    john_lomein_persona_qualification_verifier as independent_verifier,
)
from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_capture as qualification_capture,
)

RUNNER = ROOT / "scripts" / "john-lomein-persona-qualification.py"
COMMAND_SCHEMA = "john-lomein.persona-qualification-command.v1"
FIXTURE_PYTHON = Path("/usr/bin/python3").resolve(strict=True)


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_json(value) -> str:
    return sha256_text(canonical_json(value))


def self_digest(value):
    result = dict(value)
    result.pop("record_digest", None)
    result["record_digest"] = sha256_json(result)
    return result


class PersonaQualificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.instance_dir = self.base / "instance"
        self.hermes_home = self.base / "runtime" / "hermes"
        self.checkout = self.base / "managed" / "repo"
        self.private_root = self.base / "operator-private"
        self.config_root = self.base / "operator-config"
        for path in (
            self.instance_dir,
            self.hermes_home / "state",
            self.checkout,
            self.private_root,
            self.config_root,
        ):
            path.mkdir(parents=True, mode=0o700)
            path.chmod(0o700)
        self.hermes_home.chmod(0o700)

        self.manifest = yaml.safe_load(
            (ROOT / "templates" / "instance.yaml.example").read_text(encoding="utf-8")
        )
        self.manifest["instance"]["slug"] = "qualification-test"
        self.manifest["target"]["local_checkout"] = str(self.checkout)
        self.manifest["runtime"]["hermes_home"] = str(self.hermes_home)
        self.manifest["model"] = {
            "provider": "candidate-provider",
            "default": "candidate-primary",
            "reasoning_effort": "high",
            "fallback": {
                "provider": "fallback-provider",
                "model": "candidate-fallback",
                "reasoning_effort": "medium",
            },
        }
        self._deploy_manifest_and_runtime()

        self.candidate_counter = self.base / "candidate.calls"
        self.judge_counter = self.base / "judge.calls"
        self.candidate_stub = self.config_root / "candidate_adapter.py"
        self.judge_stub = self.config_root / "judge_adapter.py"
        self._write_candidate_stub()
        self._write_judge_stub()
        self.candidate_descriptor = self.config_root / "candidate.json"
        self.judge_descriptor = self.config_root / "judge.json"
        self._write_descriptors()

    def tearDown(self):
        self.temporary.cleanup()

    def _write_json(self, path: Path, value, mode: int = 0o600):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        path.chmod(mode)

    def _write_yaml(self, path: Path, value, mode: int = 0o600):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
        path.chmod(mode)

    def _deploy_manifest_and_runtime(self):
        self._write_yaml(self.instance_dir / "instance.yaml", self.manifest)
        self._write_yaml(self.hermes_home / "instance.yaml", self.manifest)
        persona = (ROOT / "persona" / "JOHN_LOMEIN.md").read_text(encoding="utf-8").strip()
        profiles = {
            "maintainer": "john-lomein-maintainer",
            "forge": "john-lomein-forge",
            "guide": "john-lomein-guide",
            "overwatch": "john-lomein-overwatch",
            "learning_steward": "john-lomein-learning-steward",
        }
        self._write_json(
            self.hermes_home / "state" / "john-lomein-persona.json",
            {
                "schema_version": "john_lomein_persona_deployment/v1",
                "persona_version": "john-lomein.persona.v1",
                "sha256": sha256_text(persona),
                "source": "persona/JOHN_LOMEIN.md",
                "profiles": profiles,
            },
        )
        model = self.manifest["model"]
        fallback = model.get("fallback") or {}
        fallback_rows = []
        if fallback:
            fallback_rows.append(
                {
                    "provider": fallback.get("provider"),
                    "model": fallback.get("model") or fallback.get("default"),
                    "reasoning_effort": fallback.get("reasoning_effort") or model.get("reasoning_effort") or "xhigh",
                }
            )
        for role, profile in profiles.items():
            profile_root = self.hermes_home / "profiles" / profile
            profile_root.mkdir(parents=True, exist_ok=True)
            profile_root.chmod(0o700)
            (profile_root / "SOUL.md").write_text(
                f"# {profile}\n\nDeployed qualification soul for {role}.\n",
                encoding="utf-8",
            )
            (profile_root / "SOUL.md").chmod(0o600)
            self._write_yaml(
                profile_root / "config.yaml",
                {
                    "model": {
                        "provider": model.get("provider"),
                        "default": model.get("default") or model.get("model"),
                    },
                    "agent": {"reasoning_effort": model.get("reasoning_effort") or "xhigh"},
                    "fallback_providers": fallback_rows,
                },
            )

    def _write_candidate_stub(
        self,
        *,
        bad_isolation: bool = False,
        nonzero: bool = False,
        zero_usage: bool = False,
    ):
        script = f"""
            import json, os, sys
            from pathlib import Path

            request = json.load(sys.stdin)
            assert all(field not in request["scenario"] for field in ("expected", "forbidden", "traits", "permitted_action"))
            with Path({str(self.candidate_counter)!r}).open("a", encoding="utf-8") as handle:
                handle.write(request["candidate"]["id"] + ":" + request["scenario"]["id"] + "\\n")
            if {nonzero!r}:
                print("PRIVATE_CANDIDATE_STDERR", file=sys.stderr)
                raise SystemExit(7)
            cwd = Path.cwd()
            home = Path(os.environ["HOME"])
            hermes = Path(os.environ["HERMES_HOME"])
            assert cwd != home and home != hermes
            assert not list(cwd.iterdir())
            assert "candidate-work" in str(home)
            assert "candidate-work" in str(hermes)
            assert os.environ.get("HERMES_KANBAN_TASK") == ""
            forbidden = ("GITHUB_TOKEN", "GH_TOKEN", "DISCORD_TOKEN", "CODEX_HOME", "HTTP_PROXY", "HTTPS_PROXY")
            assert all(name not in os.environ for name in forbidden)
            model = {{key: request["candidate"][key] for key in ("provider", "model", "reasoning_effort")}}
            isolation = {{
                "fresh_home": True,
                "fresh_hermes_home": True,
                "empty_cwd": True,
                "fresh_session": True,
                "tools": ["unsafe_tool"] if {bad_isolation!r} else [],
                "memory_loaded": False,
                "skills_loaded": False,
                "plugins_loaded": False,
                "mcp_servers": [],
                "prior_session_loaded": False,
                "production_credentials_present": False,
                "hermes_kanban_task_present": False,
            }}
            result = {{
                "schema_version": "john-lomein.persona-candidate-result.v1",
                "run_id": request["run_id"],
                "candidate_id": request["candidate"]["id"],
                "scenario_id": request["scenario"]["id"],
                "session_id": "session-" + request["candidate"]["id"] + "-" + request["scenario"]["id"],
                "adapter": request["adapter"],
                "response": "PRIVATE_RESPONSE_" + request["candidate"]["id"] + "_" + request["scenario"]["id"],
                "binding": {{
                    "request_sha256": __import__("hashlib").sha256(json.dumps(request, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                    "soul_sha256": request["soul_sha256"],
                    "effective_prompt_sha256": request["effective_prompt_sha256"],
                    "requested_model": model,
                    "effective_model": model,
                    "provider_returned_model": model,
                }},
                "execution": {{
                    "finish_reason": "stop",
                    "retries": 0,
                    "fallback_used": False,
                    "usage": {{
                        "input_tokens": 0 if {zero_usage!r} else 100,
                        "output_tokens": 0 if {zero_usage!r} else 20,
                    }},
                    "isolation": isolation,
                }},
            }}
            json.dump(result, sys.stdout, sort_keys=True)
        """
        self.candidate_stub.write_text(textwrap.dedent(script), encoding="utf-8")
        self.candidate_stub.chmod(0o700)

    def _write_judge_stub(
        self,
        *,
        omit_last: bool = False,
        wrong_route: bool = False,
        fail_forbidden: bool = False,
    ):
        script = f"""
            import json, sys
            from pathlib import Path

            request = json.load(sys.stdin)
            with Path({str(self.judge_counter)!r}).open("a", encoding="utf-8") as handle:
                handle.write(request["candidate"]["id"] + ":" + request["scenario"]["id"] + "\\n")
            criteria = request["criteria"][:-1] if {omit_last!r} else request["criteria"]
            judge = {{
                "id": request["judge"]["id"],
                "route_id": "wrong-route" if {wrong_route!r} else request["judge"]["route_id"],
                "provider": request["judge"]["provider"],
                "model": request["judge"]["model"],
                "reasoning_effort": request["judge"]["reasoning_effort"],
                "independent": True,
            }}
            result = {{
                "schema_version": "john-lomein.persona-judge-result.v1",
                "run_id": request["run_id"],
                "candidate_id": request["candidate"]["id"],
                "scenario_id": request["scenario"]["id"],
                "request_sha256": __import__("hashlib").sha256(json.dumps(request, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                "response_sha256": request["response_sha256"],
                "criteria_sha256": __import__("hashlib").sha256(json.dumps(request["criteria"], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                "session_id": "judge-session-" + request["candidate"]["id"] + "-" + request["scenario"]["id"],
                "judge": judge,
                "binding": {{
                    "requested_model": {{key: request["judge"][key] for key in ("provider", "model", "reasoning_effort")}},
                    "effective_model": {{key: request["judge"][key] for key in ("provider", "model", "reasoning_effort")}},
                    "provider_returned_model": {{key: request["judge"][key] for key in ("provider", "model", "reasoning_effort")}},
                }},
                "judgments": [
                    {{
                        "criterion_id": item["id"],
                        "verdict": False if {fail_forbidden!r} and item["id"] == "forbidden-01" else True,
                        "rationale": "PRIVATE_RATIONALE_" + item["id"],
                    }}
                    for item in criteria
                ],
                "execution": {{
                    "finish_reason": "stop",
                    "retries": 0,
                    "fallback_used": False,
                    "usage": {{"input_tokens": 120, "output_tokens": 40}},
                    "isolation": {{
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
                    }},
                }},
            }}
            json.dump(result, sys.stdout, sort_keys=True)
        """
        self.judge_stub.write_text(textwrap.dedent(script), encoding="utf-8")
        self.judge_stub.chmod(0o700)

    def _write_descriptors(self, *, duplicate_model: bool = False):
        model = self.manifest["model"]
        primary = {
            "provider": model["provider"],
            "model": model.get("default") or model.get("model"),
            "reasoning_effort": model.get("reasoning_effort") or "xhigh",
        }
        fallback = model.get("fallback") or {}
        fallback_model = {
            "provider": fallback.get("provider"),
            "model": fallback.get("model") or fallback.get("default"),
            "reasoning_effort": fallback.get("reasoning_effort") or primary["reasoning_effort"],
        }
        models = [primary]
        if fallback and fallback_model != primary:
            models.append(fallback_model)
        self._write_json(
            self.candidate_descriptor,
            {
                "schema_version": COMMAND_SCHEMA,
                "kind": "candidate",
                "id": "candidate-adapter",
                "route_id": "candidate-route",
                "argv": [str(FIXTURE_PYTHON), str(self.candidate_stub)],
                "credential_env": [],
                "models": models,
            },
        )
        self._write_json(
            self.judge_descriptor,
            {
                "schema_version": COMMAND_SCHEMA,
                "kind": "judge",
                "id": "judge-adapter",
                "route_id": "judge-route",
                "argv": [str(FIXTURE_PYTHON), str(self.judge_stub)],
                "credential_env": [],
                "model": {
                    "provider": "judge-provider",
                    "model": "judge-model",
                    "reasoning_effort": "high",
                },
            },
        )

    def _invoke(self, command: str, *extra: str):
        arguments = [sys.executable, str(RUNNER), command, "--instance", str(self.instance_dir)]
        if command == "run":
            arguments.extend(
                [
                    "--private-root", str(self.private_root),
                    "--candidate-command", str(self.candidate_descriptor),
                    "--judge-command", str(self.judge_descriptor),
                    "--run-id", "test-run",
                    "--timeout", "30",
                ]
            )
        elif command == "verify":
            arguments.extend(["--private-root", str(self.private_root)])
        arguments.extend(extra)
        environment = dict(os.environ)
        environment.update(
            {
                "GITHUB_TOKEN": "PRIVATE_GITHUB_TOKEN",
                "GH_TOKEN": "PRIVATE_GH_TOKEN",
                "DISCORD_TOKEN": "PRIVATE_DISCORD_TOKEN",
                "CODEX_HOME": "/private/codex",
                "HTTP_PROXY": "http://private-proxy.invalid",
                "HTTPS_PROXY": "http://private-proxy.invalid",
            }
        )
        completed = subprocess.run(
            arguments,
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            timeout=90,
            check=False,
        )
        output = json.loads(completed.stdout)
        return completed, output

    def test_qualified_run_covers_every_distinct_model_and_scenario(self):
        completed, result = self._invoke("run")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["status"], "qualified")
        self.assertEqual(len(result["candidates"]), 2)
        scenario_count = len(json.loads((ROOT / "evals" / "persona" / "scenarios.json").read_text())["scenarios"])
        self.assertEqual(len(self.candidate_counter.read_text().splitlines()), scenario_count * 2)
        self.assertEqual(len(self.judge_counter.read_text().splitlines()), scenario_count * 2)

        status_completed, status = self._invoke("status")
        self.assertEqual(status_completed.returncode, 0, status_completed.stderr)
        self.assertEqual(status["status"], "qualified")
        verified_completed, verified = self._invoke("verify")
        self.assertEqual(verified_completed.returncode, 0, verified_completed.stderr)
        self.assertTrue(verified["valid"])
        self.assertTrue(verified["current"])
        self.assertEqual(verified["status"], "qualified")
        self.assertEqual(
            verified["attestation_projection"],
            {
                "schema_version": (
                    "john-lomein.persona-qualification-"
                    "attestation-projection.v1"
                ),
                "run_id": result["run_id"],
                "summary_sha256": result["summary_sha256"],
                "binding_sha256": result["binding_digest"],
                "qualified_at_unix": result["qualified_at_unix"],
                "expires_at_unix": result["expires_at_unix"],
            },
        )
        attested_evidence = independent_verifier.verify_configured_evidence(
            instance_manifest=self.instance_dir / "instance.yaml",
            private_root=self.private_root,
            expected_public_root=(
                self.hermes_home / "state" / "persona-qualification"
            ),
            expected_instance_slug="qualification-test",
            expected_evidence_uid=os.geteuid(),
            verified_at_unix=int(time.time()),
        )
        self.assertEqual(attested_evidence["run_id"], result["run_id"])
        self.assertEqual(
            attested_evidence["summary_sha256"],
            result["summary_sha256"],
        )
        self.assertEqual(
            attested_evidence["binding_sha256"],
            result["binding_digest"],
        )
        self.assertEqual(
            attested_evidence["verifier_version"],
            "john-lomein.persona.operator-verifier.v1",
        )
        self.assertEqual(
            attested_evidence["observed_evidence_uid"],
            os.geteuid(),
        )

    def test_raw_evidence_is_private_and_public_projection_has_no_raw_markers(self):
        completed, result = self._invoke("run")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        run_id = result["run_id"]
        public_root = self.hermes_home / "state" / "persona-qualification"
        private_run = self.private_root / run_id
        public_text = "\n".join(path.read_text(encoding="utf-8") for path in public_root.rglob("*.json"))
        self.assertNotIn("PRIVATE_RESPONSE_", public_text)
        first_private_response = (
            "PRIVATE_RESPONSE_" + result["candidates"][0]["id"] + "_fashionable-rewrite"
        )
        self.assertNotIn(sha256_text(first_private_response), public_text)
        self.assertNotIn("PRIVATE_RATIONALE_", public_text)
        self.assertNotIn("PRIVATE_GITHUB_TOKEN", public_text)
        self.assertNotIn(str(self.private_root), public_text)
        private_text = "\n".join(path.read_text(encoding="utf-8") for path in private_run.rglob("*.json"))
        self.assertIn("PRIVATE_RESPONSE_", private_text)
        self.assertIn("PRIVATE_RATIONALE_", private_text)
        for directory in [public_root, *[path for path in public_root.rglob("*") if path.is_dir()], private_run, *[path for path in private_run.rglob("*") if path.is_dir()]]:
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700, directory)
        for path in [*[path for path in public_root.rglob("*") if path.is_file()], *[path for path in private_run.rglob("*") if path.is_file()]]:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path)
        self.assertFalse(list(public_root.rglob("*.tmp")))
        self.assertFalse(list(private_run.rglob("*.tmp")))

    def test_root_capture_projection_is_bounded_sealed_and_tamper_evident(self):
        completed, result = self._invoke("run")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        snapshot_root = self.base / "sealed-capture"
        snapshot_root.mkdir(mode=0o700)
        captured = qualification_capture._capture_snapshot(
            instance_manifest=self.instance_dir / "instance.yaml",
            qualification_public_root=(
                self.hermes_home / "state" / "persona-qualification"
            ),
            qualification_private_root=self.private_root,
            instance_slug="qualification-test",
            expected_evidence_uid=os.geteuid(),
            snapshot_root=snapshot_root,
            capture_uid=os.geteuid(),
            verifier_gid=os.getegid(),
        )
        self.assertEqual(captured["manifest"]["run_id"], result["run_id"])
        self.assertRegex(
            captured["capture_manifest_sha256"],
            r"^[0-9a-f]{64}$",
        )
        self.assertEqual(stat.S_IMODE(snapshot_root.stat().st_mode), 0o550)
        manifest = snapshot_root / "capture-manifest.json"
        self.assertEqual(stat.S_IMODE(manifest.stat().st_mode), 0o440)
        if os.geteuid() > 0:
            verifier_uid = max(os.geteuid(), os.getegid()) + 1000
            source_instance = self.instance_dir / "instance.yaml"
            source_public = (
                self.hermes_home / "state" / "persona-qualification"
            )
            source_private = self.private_root
            instance_digest = hashlib.sha256(
                source_instance.read_bytes()
            ).hexdigest()
            # The verifier must use only captured bytes. Original evidence
            # paths are opaque signed identities after capture, not live reads.
            self.instance_dir.rename(self.base / "instance-removed")
            self.hermes_home.rename(self.base / "runtime-removed")
            self.private_root.rename(self.base / "private-removed")
            verified = independent_verifier.verify_sealed_snapshot_evidence(
                snapshot_root=snapshot_root.resolve(),
                expected_capture_manifest_sha256=captured[
                    "capture_manifest_sha256"
                ],
                instance_manifest=source_instance,
                expected_instance_manifest_sha256=instance_digest,
                private_root=source_private,
                expected_public_root=source_public,
                expected_instance_slug="qualification-test",
                expected_evidence_uid=os.geteuid(),
                expected_verifier_uid=verifier_uid,
                expected_verifier_gid=os.getegid(),
                verifier_bundle_sha256="3" * 64,
                verification_policy_sha256="4" * 64,
                operator_policy_sha256="6" * 64,
                verified_at_unix=int(time.time()),
                process_uid=verifier_uid,
                process_gid=os.getegid(),
                process_groups=[os.getegid()],
                snapshot_owner_uid=os.geteuid(),
            )
            self.assertEqual(
                set(verified),
                {
                    "run_id",
                    "summary_sha256",
                    "binding_sha256",
                    "status",
                    "qualified_at_unix",
                    "expires_at_unix",
                    "verifier_version",
                    "verifier_uid",
                    "verifier_bundle_sha256",
                    "verification_policy_sha256",
                    "capture_manifest_sha256",
                    "operator_policy_sha256",
                    "claim_strength",
                    "public_reputation_eligible",
                    "verified_at_unix",
                    "observed_evidence_uid",
                },
            )
            self.assertEqual(verified["run_id"], result["run_id"])
            self.assertEqual(
                verified["binding_sha256"],
                result["binding_digest"],
            )
            self.assertEqual(
                verified["summary_sha256"],
                result["summary_sha256"],
            )
            self.assertEqual(verified["verifier_uid"], verifier_uid)
            self.assertEqual(
                verified["observed_evidence_uid"],
                captured["manifest"]["observed_evidence_uid"],
            )
            self.assertNotEqual(
                verified["observed_evidence_uid"],
                verified["verifier_uid"],
            )
            self.assertEqual(
                verified["capture_manifest_sha256"],
                captured["capture_manifest_sha256"],
            )
            self.assertEqual(
                verified["claim_strength"],
                "operator_verified_local_conformance",
            )
            self.assertIs(verified["public_reputation_eligible"], False)
        private_files = [
            path
            for path in snapshot_root.rglob("*")
            if path.is_file()
            and "private" in path.relative_to(snapshot_root).parts
        ]
        self.assertTrue(private_files)
        target = private_files[0]
        target.chmod(0o640)
        with self.assertRaises(
            qualification_capture.QualificationCaptureError
        ) as caught:
            qualification_capture.verify_sealed_capture(
                snapshot_root,
                expected_capture_uid=os.geteuid(),
                expected_verifier_gid=os.getegid(),
                expected_manifest_sha256=captured[
                    "capture_manifest_sha256"
                ],
            )
        self.assertEqual(caught.exception.code, "sealed_capture_file_mismatch")

    def test_root_capture_rejects_hardlinked_private_evidence(self):
        completed, result = self._invoke("run")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        private_run = self.private_root / result["run_id"]
        target = next(
            path
            for path in private_run.rglob("*")
            if path.is_file()
        )
        os.link(target, self.base / "evidence-hardlink")
        snapshot_root = self.base / "rejected-capture"
        snapshot_root.mkdir(mode=0o700)
        with self.assertRaises(
            qualification_capture.QualificationCaptureError
        ) as caught:
            qualification_capture._capture_snapshot(
                instance_manifest=self.instance_dir / "instance.yaml",
                qualification_public_root=(
                    self.hermes_home / "state" / "persona-qualification"
                ),
                qualification_private_root=self.private_root,
                instance_slug="qualification-test",
                expected_evidence_uid=os.geteuid(),
                snapshot_root=snapshot_root,
                capture_uid=os.geteuid(),
                verifier_gid=os.getegid(),
            )
        self.assertEqual(
            caught.exception.code,
            "qualification_private_run_unsafe",
        )

    def test_normal_cli_rejects_snapshot_path_override(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "verify",
                "--instance",
                str(self.instance_dir),
                "--private-root",
                str(self.private_root),
                "--snapshot-root",
                str(self.base / "untrusted-snapshot"),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("unrecognized arguments: --snapshot-root", completed.stderr)

    def test_root_capture_omits_unselected_public_history(self):
        completed, result = self._invoke("run")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        old_run = (
            self.hermes_home
            / "state"
            / "persona-qualification"
            / "reports"
            / "old-run"
        )
        old_run.mkdir(mode=0o700)
        self._write_json(
            old_run / "must-not-be-captured.json",
            {"private": "historical-noise"},
        )
        snapshot_root = self.base / "selected-capture"
        snapshot_root.mkdir(mode=0o700)
        captured = qualification_capture._capture_snapshot(
            instance_manifest=self.instance_dir / "instance.yaml",
            qualification_public_root=(
                self.hermes_home / "state" / "persona-qualification"
            ),
            qualification_private_root=self.private_root,
            instance_slug="qualification-test",
            expected_evidence_uid=os.geteuid(),
            snapshot_root=snapshot_root,
            capture_uid=os.geteuid(),
            verifier_gid=os.getegid(),
        )
        paths = {
            entry["path"] for entry in captured["manifest"]["files"]
        }
        self.assertFalse(any("old-run" in path for path in paths))
        self.assertTrue(
            any(result["run_id"] in path for path in paths)
        )
        qualification_capture.revalidate_live_capture_sources(
            snapshot_root,
            expected_capture_uid=os.geteuid(),
            expected_verifier_gid=os.getegid(),
            expected_evidence_uid=os.geteuid(),
            expected_manifest_sha256=captured[
                "capture_manifest_sha256"
            ],
        )
        status_path = (
            self.hermes_home
            / "state"
            / "persona-qualification"
            / "status.json"
        )
        unchanged_bytes = status_path.read_bytes()
        status_path.write_bytes(unchanged_bytes)
        status_path.chmod(0o600)
        with self.assertRaises(
            qualification_capture.QualificationCaptureError
        ) as caught:
            qualification_capture.revalidate_live_capture_sources(
                snapshot_root,
                expected_capture_uid=os.geteuid(),
                expected_verifier_gid=os.getegid(),
                expected_evidence_uid=os.geteuid(),
                expected_manifest_sha256=captured[
                    "capture_manifest_sha256"
                ],
            )
        self.assertEqual(caught.exception.code, "live_source_file_changed")

    def test_root_capture_final_source_revalidation_detects_late_mutation(self):
        snapshot_root = self.base / "late-mutation-capture"
        snapshot_root.mkdir(mode=0o700)
        builder = qualification_capture._CaptureBuilder(
            snapshot_root=snapshot_root,
            expected_source_uid=os.geteuid(),
        )
        try:
            builder.add_file(
                source_parent=self.instance_dir,
                source_name="instance.yaml",
                destination="instance/instance.yaml",
                source_class="instance_manifest",
            )
            manifest_path = self.instance_dir / "instance.yaml"
            manifest_path.write_text(
                manifest_path.read_text(encoding="utf-8") + "\n",
                encoding="utf-8",
            )
            manifest_path.chmod(0o600)
            with self.assertRaises(
                qualification_capture.QualificationCaptureError
            ) as caught:
                builder.revalidate_sources()
            self.assertEqual(
                caught.exception.code,
                "capture_source_changed_after_copy",
            )
        finally:
            builder.close()

    def test_contract_and_isolation_fail_closed_without_hiding_other_attempts(self):
        self._write_candidate_stub(bad_isolation=True)
        completed, result = self._invoke("run")
        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertEqual(result["status"], "incomplete")
        scenario_count = len(json.loads((ROOT / "evals" / "persona" / "scenarios.json").read_text())["scenarios"])
        self.assertEqual(len(self.candidate_counter.read_text().splitlines()), scenario_count * 2)
        self.assertFalse(self.judge_counter.exists())
        public_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (self.hermes_home / "state" / "persona-qualification").rglob("*.json")
        )
        self.assertNotIn("unsafe_tool", public_text)
        self.assertIn("candidate-exposed-capabilities", public_text)

    def test_judge_must_be_complete_and_structurally_independent(self):
        self._write_judge_stub(omit_last=True)
        completed, result = self._invoke("run")
        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(all(item["status"] == "incomplete" for item in result["candidates"]))

    def test_duplicate_primary_fallback_is_qualified_once_but_retains_slots(self):
        primary = self.manifest["model"]
        primary["fallback"] = {
            "provider": primary["provider"],
            "model": primary["default"],
            "reasoning_effort": primary["reasoning_effort"],
        }
        self._deploy_manifest_and_runtime()
        self._write_descriptors(duplicate_model=True)
        completed, result = self._invoke("run")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["candidates"][0]["slots"], ["primary", "fallback"])

    def test_missing_stale_tampered_and_private_reproduction_states(self):
        missing_completed, missing = self._invoke("status")
        self.assertEqual(missing_completed.returncode, 0, missing_completed.stderr)
        self.assertEqual(missing["status"], "missing")

        completed, result = self._invoke("run")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        soul = self.hermes_home / "profiles" / "john-lomein-maintainer" / "SOUL.md"
        soul.write_text(soul.read_text(encoding="utf-8") + "\nmaterial drift\n", encoding="utf-8")
        soul.chmod(0o600)
        stale_completed, stale = self._invoke("status")
        self.assertEqual(stale_completed.returncode, 0, stale_completed.stderr)
        self.assertEqual(stale["status"], "stale")

        soul.write_text("# john-lomein-maintainer\n\nDeployed qualification soul for maintainer.\n", encoding="utf-8")
        soul.chmod(0o600)
        candidate_file = next(
            path
            for path in (self.hermes_home / "state" / "persona-qualification" / "reports" / result["run_id"]).glob("candidate-*.json")
        )
        candidate_data = json.loads(candidate_file.read_text(encoding="utf-8"))
        candidate_data["status"] = "failed"
        self._write_json(candidate_file, candidate_data)
        invalid_completed, invalid = self._invoke("status")
        self.assertEqual(invalid_completed.returncode, 2)
        self.assertEqual(invalid["status"], "invalid")

    def test_private_root_and_descriptor_boundaries_fail_before_inference(self):
        arguments = [
            sys.executable,
            str(RUNNER),
            "run",
            "--instance",
            str(self.instance_dir),
            "--private-root",
            str(self.hermes_home / "private-evidence"),
            "--candidate-command",
            str(self.candidate_descriptor),
            "--judge-command",
            str(self.judge_descriptor),
        ]
        completed = subprocess.run(arguments, cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["reason"], "private-root-overlaps-runtime-or-repository")
        self.assertFalse(self.candidate_counter.exists())

        judge = json.loads(self.judge_descriptor.read_text(encoding="utf-8"))
        judge["route_id"] = "candidate-route"
        self._write_json(self.judge_descriptor, judge)
        completed, result = self._invoke("run")
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(result["reason"], "judge-not-structurally-independent")
        self.assertFalse(self.candidate_counter.exists())

    def test_slashed_scenario_id_is_rejected_before_running_state_is_published(self):
        scenarios = json.loads(
            (ROOT / "evals" / "persona" / "scenarios.json").read_text(encoding="utf-8")
        )
        scenarios["scenarios"][0]["id"] = "path/escape"
        scenario_path = self.config_root / "unsafe-scenarios.json"
        self._write_json(scenario_path, scenarios)

        completed, result = self._invoke("run", "--scenarios", str(scenario_path))

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(result["status"], "invalid")
        self.assertFalse(self.candidate_counter.exists())
        self.assertFalse(self.judge_counter.exists())
        self.assertFalse(
            (self.hermes_home / "state" / "persona-qualification" / "status.json").exists(),
            "an invalid scenario must not leave a truthful-looking running status",
        )

    def test_missing_verify_does_not_create_private_state(self):
        absent_private_root = self.base / "absent-private-evidence"
        self.assertFalse(absent_private_root.exists())

        completed, result = self._invoke(
            "verify",
            "--private-root",
            str(absent_private_root),
        )

        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertEqual(result["status"], "missing")
        self.assertFalse(result["valid"])
        self.assertFalse(absent_private_root.exists())

    def test_expired_qualification_is_stale_for_status_and_verify(self):
        completed, result = self._invoke("run", "--max-age-seconds", "3600")
        self.assertEqual(completed.returncode, 0, completed.stderr)

        public_root = self.hermes_home / "state" / "persona-qualification"
        report_root = public_root / "reports" / result["run_id"]
        summary_path = report_root / "summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        completed_at = int(time.time()) - 3601
        summary["timing"] = {
            "started_at_unix": completed_at,
            "completed_at_unix": completed_at,
            "expires_at_unix": completed_at + summary["qualification_policy"]["max_age_seconds"],
        }
        summary = self_digest(summary)
        self._write_json(summary_path, summary)
        summary_sha = sha256_json(summary)

        latest_path = public_root / "latest.json"
        latest = json.loads(latest_path.read_text(encoding="utf-8"))
        latest["summary_sha256"] = summary_sha
        self._write_json(latest_path, self_digest(latest))

        status_path = public_root / "status.json"
        status = json.loads(status_path.read_text(encoding="utf-8"))
        status.update(
            {
                "summary_sha256": summary_sha,
                "started_at_unix": completed_at,
                "run_deadline_unix": (
                    completed_at + summary["qualification_policy"]["max_wall_seconds"]
                ),
                "qualified_at_unix": completed_at,
                "expires_at_unix": summary["timing"]["expires_at_unix"],
            }
        )
        self._write_json(status_path, self_digest(status))

        status_completed, status_result = self._invoke("status")
        self.assertEqual(status_completed.returncode, 0, status_completed.stderr)
        self.assertEqual(status_result["status"], "stale")
        self.assertEqual(status_result["reason"], "qualification-expired")

        verify_completed, verify_result = self._invoke("verify")
        self.assertEqual(verify_completed.returncode, 4, verify_completed.stderr)
        self.assertEqual(verify_result["status"], "stale")
        self.assertEqual(verify_result["reason"], "qualification-expired")
        self.assertFalse(verify_result["current"])

    def test_max_calls_preflight_fails_before_inference_or_running_state(self):
        completed, result = self._invoke("run", "--max-calls", "1")

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(result["reason"], "planned-call-budget-exceeded")
        self.assertFalse(self.candidate_counter.exists())
        self.assertFalse(self.judge_counter.exists())
        self.assertFalse(
            (self.hermes_home / "state" / "persona-qualification" / "status.json").exists()
        )

    def test_positive_usage_is_required_for_every_model_call(self):
        self._write_candidate_stub(zero_usage=True)

        completed, result = self._invoke("run")

        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertEqual(result["status"], "incomplete")
        self.assertFalse(self.judge_counter.exists())
        public_root = self.hermes_home / "state" / "persona-qualification"
        public_text = "\n".join(
            path.read_text(encoding="utf-8") for path in public_root.rglob("*.json")
        )
        self.assertIn("candidate-input-token-usage-missing", public_text)

    def test_oversized_generated_request_fails_before_inference(self):
        scenarios = json.loads(
            (ROOT / "evals" / "persona" / "scenarios.json").read_text(encoding="utf-8")
        )
        scenarios["scenarios"][0]["evidence"] = ["x" * 4000 for _ in range(350)]
        scenario_path = self.config_root / "oversized-generated-request.json"
        self._write_json(scenario_path, scenarios)
        self.assertLess(scenario_path.stat().st_size, 2_000_000)

        completed, result = self._invoke("run", "--scenarios", str(scenario_path))

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(result["reason"], "candidate-request-too-large")
        self.assertFalse(self.candidate_counter.exists())
        self.assertFalse(self.judge_counter.exists())
        self.assertFalse(
            (self.hermes_home / "state" / "persona-qualification" / "status.json").exists()
        )

    def test_provider_unsupported_criterion_count_fails_before_inference(self):
        scenarios = json.loads(
            (ROOT / "evals" / "persona" / "scenarios.json").read_text(encoding="utf-8")
        )
        scenarios["scenarios"][0]["expected"] = [
            f"bounded criterion {index}" for index in range(512)
        ]
        scenario_path = self.config_root / "too-many-criteria.json"
        self._write_json(scenario_path, scenarios)

        completed, result = self._invoke("run", "--scenarios", str(scenario_path))

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(result["reason"], "scenario-criteria-count")
        self.assertFalse(self.candidate_counter.exists())
        self.assertFalse(self.judge_counter.exists())

    def test_writable_ancestor_and_implicit_environment_interpreter_are_rejected(self):
        unsafe_parent = self.base / "unsafe-parent"
        unsafe_parent.mkdir(mode=0o700)
        unsafe_parent.chmod(0o777)

        unsafe_scenarios = unsafe_parent / "scenarios.json"
        unsafe_scenarios.write_text(
            (ROOT / "evals" / "persona" / "scenarios.json").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        unsafe_scenarios.chmod(0o600)
        completed, result = self._invoke(
            "run",
            "--scenarios",
            str(unsafe_scenarios),
        )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(
            result["reason"],
            "scenario-specification-parent-ancestor-writable-by-others",
        )
        self.assertFalse(self.candidate_counter.exists())

        completed, result = self._invoke(
            "run",
            "--private-root",
            str(unsafe_parent / "private"),
        )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(result["reason"], "private-root-ancestor-writable-by-others")
        self.assertFalse(self.candidate_counter.exists())

        descriptor = json.loads(self.candidate_descriptor.read_text(encoding="utf-8"))
        descriptor["argv"] = ["/usr/bin/env", "python3", str(self.candidate_stub)]
        self._write_json(self.candidate_descriptor, descriptor)
        completed, result = self._invoke("run")
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(
            result["reason"],
            "candidate-descriptor-argv-environment-delegator-forbidden",
        )
        self.assertFalse(self.candidate_counter.exists())

    def test_changed_scenario_contract_is_stale_but_historical_snapshot_reproduces(self):
        scenarios = json.loads(
            (ROOT / "evals" / "persona" / "scenarios.json").read_text(encoding="utf-8")
        )
        scenario_path = self.config_root / "versioned-scenarios.json"
        self._write_json(scenario_path, scenarios)
        completed, _ = self._invoke("run", "--scenarios", str(scenario_path))
        self.assertEqual(completed.returncode, 0, completed.stderr)

        scenarios["scenarios"][0]["prompt"] += " Material contract evolution."
        self._write_json(scenario_path, scenarios)
        status_completed, status = self._invoke(
            "status",
            "--scenarios",
            str(scenario_path),
        )
        self.assertEqual(status_completed.returncode, 0, status_completed.stderr)
        self.assertEqual(status["status"], "stale")
        self.assertEqual(status["reason"], "current-binding-drift")

        verify_completed, verified = self._invoke(
            "verify",
            "--scenarios",
            str(scenario_path),
        )
        self.assertEqual(verify_completed.returncode, 4, verify_completed.stderr)
        self.assertTrue(verified["valid"])
        self.assertFalse(verified["current"])
        self.assertEqual(verified["status"], "stale")

    def test_failed_terminal_run_reproduces_recorded_usage(self):
        self._write_judge_stub(fail_forbidden=True)
        completed, result = self._invoke("run")
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(result["status"], "failed")

        public_root = self.hermes_home / "state" / "persona-qualification"
        report_root = public_root / "reports" / result["run_id"]
        summary_path = report_root / "summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["usage"]["tokens"] += 1
        summary = self_digest(summary)
        self._write_json(summary_path, summary)
        summary_sha = sha256_json(summary)

        latest_path = public_root / "latest.json"
        latest = json.loads(latest_path.read_text(encoding="utf-8"))
        latest["summary_sha256"] = summary_sha
        self._write_json(latest_path, self_digest(latest))

        status_path = public_root / "status.json"
        status = json.loads(status_path.read_text(encoding="utf-8"))
        status["summary_sha256"] = summary_sha
        self._write_json(status_path, self_digest(status))

        verify_completed, verified = self._invoke("verify")
        self.assertEqual(verify_completed.returncode, 2, verify_completed.stderr)
        self.assertEqual(verified["status"], "invalid")
        self.assertEqual(
            verified["reason"],
            "private-evidence-usage-not-reproducible",
        )

    def test_private_evidence_tamper_is_rejected_by_verify(self):
        completed, result = self._invoke("run")
        self.assertEqual(completed.returncode, 0, completed.stderr)

        candidate_root = self.private_root / result["run_id"] / result["candidates"][0]["id"]
        raw_output = next(candidate_root.glob("*/candidate-stdout.json"))
        raw_output.write_text(
            raw_output.read_text(encoding="utf-8") + "\n",
            encoding="utf-8",
        )
        raw_output.chmod(0o600)

        verify_completed, verify_result = self._invoke("verify")
        self.assertEqual(verify_completed.returncode, 2, verify_completed.stderr)
        self.assertEqual(verify_result["status"], "invalid")
        self.assertEqual(verify_result["reason"], "private-evidence-manifest-mismatch")

    def test_checkout_contained_adapter_is_rejected_before_inference(self):
        checkout_adapter = self.checkout / "candidate_adapter.py"
        checkout_adapter.write_text(
            self.candidate_stub.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        checkout_adapter.chmod(0o700)
        descriptor = json.loads(self.candidate_descriptor.read_text(encoding="utf-8"))
        descriptor["argv"] = [str(Path(sys.executable).resolve()), str(checkout_adapter)]
        self._write_json(self.candidate_descriptor, descriptor)

        completed, result = self._invoke("run")

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(result["reason"], "command-artifact-inside-runtime-or-repository")
        self.assertFalse(self.candidate_counter.exists())
        self.assertFalse(self.judge_counter.exists())
        self.assertFalse(
            (self.hermes_home / "state" / "persona-qualification" / "status.json").exists()
        )

    def test_reversed_candidate_descriptor_model_order_is_rejected_before_inference(self):
        descriptor = json.loads(self.candidate_descriptor.read_text(encoding="utf-8"))
        self.assertEqual(len(descriptor["models"]), 2)
        descriptor["models"].reverse()
        self._write_json(self.candidate_descriptor, descriptor)

        completed, result = self._invoke("run")

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(result["reason"], "candidate-descriptor-model-matrix-mismatch")
        self.assertFalse(self.candidate_counter.exists())
        self.assertFalse(self.judge_counter.exists())
        self.assertFalse(
            (self.hermes_home / "state" / "persona-qualification" / "status.json").exists()
        )

    def test_verify_replays_raw_judgments_after_all_unkeyed_links_are_rehashed(self):
        completed, result = self._invoke("run")
        self.assertEqual(completed.returncode, 0, completed.stderr)

        run_id = result["run_id"]
        candidate_id = result["candidates"][0]["id"]
        candidate_private = self.private_root / run_id / candidate_id
        judge_stdout = next(candidate_private.glob("*/judge-stdout.json"))
        judge_result = json.loads(judge_stdout.read_text(encoding="utf-8"))
        self.assertTrue(judge_result["judgments"][0]["verdict"])
        judge_result["judgments"][0]["verdict"] = False
        self._write_json(judge_stdout, judge_result)

        evidence_files = []
        for path in sorted(candidate_private.rglob("*"), key=lambda item: item.as_posix()):
            relative = path.relative_to(candidate_private).as_posix()
            if path.is_file() and relative != "evidence-manifest.json":
                content = path.read_bytes()
                evidence_files.append(
                    {
                        "path": relative,
                        "size": len(content),
                        "sha256": hashlib.sha256(content).hexdigest(),
                    }
                )
        evidence_manifest = self_digest(
            {
                "schema_version": "john-lomein.persona-qualification-private-evidence.v1",
                "files": evidence_files,
            }
        )
        self._write_json(candidate_private / "evidence-manifest.json", evidence_manifest)

        public_root = self.hermes_home / "state" / "persona-qualification"
        report_root = public_root / "reports" / run_id
        candidate_path = report_root / f"{candidate_id}.json"
        candidate_record = json.loads(candidate_path.read_text(encoding="utf-8"))
        candidate_record["private_evidence_manifest_sha256"] = sha256_json(evidence_manifest)
        candidate_record = self_digest(candidate_record)
        self._write_json(candidate_path, candidate_record)

        summary_path = report_root / "summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary_candidate = next(
            item for item in summary["candidates"] if item["id"] == candidate_id
        )
        summary_candidate["record_sha256"] = sha256_json(candidate_record)
        summary = self_digest(summary)
        self._write_json(summary_path, summary)
        summary_sha256 = sha256_json(summary)

        latest_path = public_root / "latest.json"
        latest = json.loads(latest_path.read_text(encoding="utf-8"))
        latest["summary_sha256"] = summary_sha256
        self._write_json(latest_path, self_digest(latest))

        status_path = public_root / "status.json"
        status = json.loads(status_path.read_text(encoding="utf-8"))
        status["summary_sha256"] = summary_sha256
        self._write_json(status_path, self_digest(status))

        verify_completed, verify_result = self._invoke("verify")

        self.assertEqual(verify_completed.returncode, 2, verify_completed.stderr)
        self.assertEqual(verify_result["status"], "invalid")
        self.assertEqual(
            verify_result["reason"],
            "private-evaluation-result-not-reproducible",
        )


if __name__ == "__main__":
    unittest.main()
