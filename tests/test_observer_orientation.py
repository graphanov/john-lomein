#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import john_lomein_continuity as continuity  # noqa: E402
import john_lomein_orientation as orientation  # noqa: E402
from john_lomein_persona_contract import load_persona_core  # noqa: E402
from john_lomein_profile_contract import canonical_role_profiles  # noqa: E402


INIT_SCRIPT = SCRIPTS / "john-lomein-init.py"
ORIENT_SCRIPT = SCRIPTS / "john-lomein-orient.py"


def load_initializer():
    spec = importlib.util.spec_from_file_location(
        "john_lomein_orientation_initializer",
        INIT_SCRIPT,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load observer initializer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


initializer = load_initializer()


def load_orient_cli():
    spec = importlib.util.spec_from_file_location(
        "john_lomein_orientation_cli",
        ORIENT_SCRIPT,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load orientation CLI")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


orient_cli = load_orient_cli()


class ObserverOrientationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.instance = self.root / "instance"
        self.runtime = self.root / "runtime"
        self.checkout = self.root / "checkout"
        manifest = initializer.build_observer_manifest(
            repo="owner/sample-repo",
            mission=(
                "Keep the repository reliable while moving its documented "
                "roadmap through reviewable evidence."
            ),
            test_cmd="uv run --frozen pytest -q",
            runtime_home=str(self.runtime),
            local_checkout=str(self.checkout),
        )
        initializer.create_instance(self.instance, manifest)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def manifest(self) -> dict:
        return yaml.safe_load(
            (self.instance / "instance.yaml").read_text(encoding="utf-8")
        )

    def write_manifest(self, value: dict) -> None:
        path = self.instance / "instance.yaml"
        path.write_text(
            yaml.safe_dump(value, sort_keys=False),
            encoding="utf-8",
        )
        os.chmod(path, 0o600)

    def deploy_local_proof(self) -> None:
        state = self.runtime / "state"
        state.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(self.runtime, 0o700)
        os.chmod(state, 0o700)
        desired = (self.instance / "instance.yaml").read_bytes()
        deployed = self.runtime / "instance.yaml"
        deployed.write_bytes(desired)
        os.chmod(deployed, 0o600)
        manifest = self.manifest()
        _, version, digest = load_persona_core(
            ROOT / "persona" / "JOHN_LOMEIN.md"
        )
        persona = state / "john-lomein-persona.json"
        persona.write_text(
            json.dumps(
                {
                    "schema_version": "john_lomein_persona_deployment/v1",
                    "persona_version": version,
                    "sha256": digest,
                    "source": "persona/JOHN_LOMEIN.md",
                    "profiles": canonical_role_profiles(manifest),
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        os.chmod(persona, 0o600)
        continuity.initialize_store(
            state / "continuity",
            ledger_id="jlcl-000000000000000000000901",
        )

    def test_fresh_observer_is_healthy_configured_and_product_facing(self):
        report = orientation.build_orientation(self.instance)
        self.assertEqual(report["status"], "healthy")
        self.assertEqual(report["stage"], "configured_observer")
        self.assertEqual(report["proof"]["deployment"]["status"], "not_installed")
        self.assertEqual(report["proof"]["continuity"]["status"], "not_installed")
        self.assertEqual(report["capabilities"]["mutation"], "gated")
        self.assertEqual(
            report["mission"]["source"],
            "unconfirmed_candidate",
        )
        self.assertTrue(report["mission"]["candidate_complete"])
        self.assertFalse(report["mission"]["complete"])
        self.assertEqual(
            [step["code"] for step in report["next_steps"]],
            ["confirm_owner_mission", "install_observer"],
        )
        rendered = orientation.render_human(report)
        self.assertIn("Verdict", rendered)
        self.assertIn("Evidence", rendered)
        self.assertIn("Next", rendered)
        self.assertIn("fictional AI software maintainer", rendered)
        self.assertNotIn(str(self.root), rendered)

    def test_exact_deployment_and_empty_continuity_prove_observer(self):
        self.deploy_local_proof()
        report = orientation.build_orientation(self.instance)
        self.assertEqual(report["status"], "healthy")
        self.assertEqual(report["stage"], "proven_observer")
        self.assertEqual(report["proof"]["deployment"]["status"], "proven")
        self.assertEqual(report["proof"]["persona"]["status"], "proven")
        self.assertEqual(report["proof"]["continuity"]["status"], "proven")
        self.assertEqual(report["proof"]["continuity"]["sequence"], 0)
        self.assertEqual(report["proof"]["continuity"]["entry_count"], 0)
        self.assertEqual(
            [step["code"] for step in report["next_steps"]],
            ["confirm_owner_mission", "observe_before_activation"],
        )

    def test_continuity_reports_only_aggregate_state(self):
        self.deploy_local_proof()
        secret_summary = "private-decision-sentinel"
        continuity.append_entry(
            self.runtime / "state" / "continuity",
            {
                "schema_version": continuity.WRITE_SCHEMA,
                "entry_id": "jlce-000000000000000000000902",
                "kind": "decision",
                "subject": "architecture",
                "summary": secret_summary,
                "payload": {"disposition": "accepted"},
                "source": {
                    "kind": "automation",
                    "trust": "product_observed",
                    "actor": "maintainer-orchestrator",
                    "locator": "automation:orientation-test",
                    "sha256": hashlib.sha256(b"orientation-test").hexdigest(),
                },
                "scope": {
                    "privacy": "private",
                    "visible_to_roles": ["maintainer"],
                    "repository": "owner/sample-repo",
                },
                "expires_at": None,
                "supersedes_entry_id": None,
            },
        )
        report = orientation.build_orientation(self.instance)
        rendered = orientation.render_json(report)
        self.assertEqual(report["proof"]["continuity"]["entry_count"], 1)
        self.assertEqual(report["proof"]["continuity"]["sequence"], 1)
        self.assertNotIn(secret_summary, rendered)
        self.assertNotIn("orientation-test", rendered)

    def test_stale_persona_and_corrupt_continuity_require_attention(self):
        self.deploy_local_proof()
        persona_path = self.runtime / "state" / "john-lomein-persona.json"
        persona = json.loads(persona_path.read_text(encoding="utf-8"))
        persona["sha256"] = "f" * 64
        persona_path.write_text(json.dumps(persona), encoding="utf-8")
        os.chmod(persona_path, 0o600)
        report = orientation.build_orientation(self.instance)
        self.assertEqual(report["status"], "attention_required")
        self.assertEqual(report["proof"]["persona"]["status"], "stale")
        self.assertIn(
            "reconcile_runtime",
            [step["code"] for step in report["next_steps"]],
        )

        self.deploy_local_proof()
        head = (
            self.runtime
            / "state"
            / "continuity"
            / continuity.HEAD_FILENAME
        )
        head.write_bytes(b"{\"status\":\"healthy\"}\n")
        os.chmod(head, 0o600)
        report = orientation.build_orientation(self.instance)
        self.assertEqual(report["status"], "attention_required")
        self.assertEqual(report["proof"]["continuity"]["status"], "invalid")
        self.assertIn(
            "repair_continuity",
            [step["code"] for step in report["next_steps"]],
        )

    def test_pending_continuity_transaction_is_not_recovered_or_changed(self):
        self.deploy_local_proof()
        store = self.runtime / "state" / "continuity"
        transaction = store / continuity.TRANSACTION_FILENAME
        transaction.write_bytes(b"{}\n")
        os.chmod(transaction, 0o600)

        def snapshot() -> dict[str, tuple[int, int, int, int, bytes]]:
            result: dict[str, tuple[int, int, int, int, bytes]] = {}
            for path in sorted(store.iterdir()):
                info = path.lstat()
                result[path.name] = (
                    info.st_ino,
                    info.st_size,
                    info.st_mtime_ns,
                    stat.S_IMODE(info.st_mode),
                    path.read_bytes(),
                )
            return result

        before = snapshot()
        report = orientation.build_orientation(self.instance)
        self.assertEqual(report["proof"]["continuity"]["status"], "invalid")
        self.assertEqual(
            report["proof"]["continuity"]["error_code"],
            "transaction_pending",
        )
        self.assertEqual(snapshot(), before)

    def test_stale_signed_import_state_invalidates_runtime_projection(self):
        self.deploy_local_proof()
        store = self.runtime / "state" / "continuity"
        stale = store / "continuity-import-journal.jsonl"
        stale.write_bytes(b"")
        os.chmod(stale, 0o600)
        before = {
            path.name: (path.lstat().st_mtime_ns, path.read_bytes())
            for path in store.iterdir()
            if path.is_file()
        }

        report = orientation.build_orientation(self.instance)

        self.assertEqual(report["status"], "attention_required")
        self.assertEqual(report["proof"]["continuity"]["status"], "invalid")
        self.assertEqual(
            report["proof"]["continuity"]["error_code"],
            "configuration_missing",
        )
        self.assertEqual(
            {
                path.name: (path.lstat().st_mtime_ns, path.read_bytes())
                for path in store.iterdir()
                if path.is_file()
            },
            before,
        )

    def test_active_posture_without_owner_mission_never_claims_readiness(self):
        manifest = self.manifest()
        manifest["mission"]["owner_authored"] = False
        manifest["runtime"]["activation"] = "active"
        manifest["runtime"]["mutation_enabled"] = True
        self.write_manifest(manifest)
        self.deploy_local_proof()
        report = orientation.build_orientation(self.instance)
        self.assertEqual(report["status"], "attention_required")
        self.assertEqual(report["stage"], "active_attention")
        self.assertFalse(report["assurances"]["live_readiness_claimed"])
        self.assertEqual(
            report["capabilities"]["mutation"],
            "blocked_missing_owner_mission",
        )
        self.assertEqual(
            report["mission"]["source"],
            "unconfirmed_candidate",
        )
        self.assertIn(
            "confirm_owner_mission",
            [step["code"] for step in report["next_steps"]],
        )
        self.assertIn(
            "owner_mission_required_for_active_posture",
            report["attention_codes"],
        )
        self.assertIn(
            "Attention: owner_mission_required_for_active_posture",
            orientation.render_human(report),
        )
        self.assertNotIn("ready", report["stage"])

    def test_every_authority_dimension_is_exposed_without_live_proof(self):
        manifest = self.manifest()
        manifest["mission"]["owner_authored"] = True
        manifest["runtime"]["activation"] = "active"
        manifest["runtime"]["mutation_enabled"] = True
        manifest["runtime"]["discord_enabled"] = True
        manifest["runtime"]["guide_gateway_enabled"] = True
        manifest.setdefault("authority", {})["owner_github_logins"] = ["owner"]
        manifest["discord"]["enabled"] = True
        manifest["discord"]["guide_gateway_enabled"] = True
        manifest["release"]["protected_broker_enabled"] = True
        manifest["open_scaffold_portfolio"]["enabled"] = True
        manifest["memory"]["honcho"].update({
            "watchdog_enabled": True,
            "expected_memory_model": "honcho-memory:test",
            "server_root": str(
                Path(manifest["runtime"]["hermes_home"])
                / "services"
                / "public-honcho"
                / "server"
            ),
        })
        self.write_manifest(manifest)
        self.deploy_local_proof()

        report = orientation.build_orientation(self.instance)

        self.assertEqual(report["stage"], "active_configured")
        for capability in (
            "activation",
            "mutation",
            "discord",
            "guide_gateway",
            "protected_release",
            "portfolio",
        ):
            self.assertEqual(
                report["capabilities"][capability],
                "configured_not_live_proven",
                capability,
            )
        self.assertFalse(report["assurances"]["live_readiness_claimed"])

    def test_owner_authored_defaults_do_not_count_as_a_complete_mission(self):
        original = self.manifest()
        for missing_field in ("statement", "owner_signal_policy"):
            with self.subTest(missing_field=missing_field):
                manifest = json.loads(json.dumps(original))
                manifest["runtime"]["activation"] = "active"
                manifest["runtime"]["mutation_enabled"] = True
                manifest["mission"]["owner_authored"] = True
                manifest["mission"].pop(missing_field)
                self.write_manifest(manifest)
                self.deploy_local_proof()
                report = orientation.build_orientation(self.instance)
                self.assertEqual(report["status"], "attention_required")
                self.assertEqual(report["stage"], "active_attention")
                self.assertFalse(report["mission"]["complete"])
                self.assertEqual(
                    report["mission"]["source"],
                    "conservative_default",
                )
                self.assertTrue(
                    report["mission"]["owner_authored_declared"]
                )
                self.assertIn(
                    "owner_mission_required_for_active_posture",
                    report["attention_codes"],
                )

    def test_output_is_deterministic_private_path_free_and_credential_free(self):
        self.deploy_local_proof()
        with mock.patch.dict(
            os.environ,
            {
                "DISCORD_BOT_TOKEN": "token-private-sentinel",
                "OPENAI_API_KEY": "sk-" + "x" * 32,
            },
            clear=False,
        ):
            first = orientation.render_json(
                orientation.build_orientation(self.instance)
            )
            second = orientation.render_json(
                orientation.build_orientation(self.instance)
            )
        self.assertEqual(first, second)
        self.assertNotIn(str(self.root), first)
        self.assertNotIn("token-private-sentinel", first)
        self.assertNotIn("sk-" + "x" * 32, first)

    def test_invalid_manifest_and_symlink_fail_with_bounded_error(self):
        hostile = "sk-" + "x" * 32
        manifest = self.manifest()
        manifest["mission"]["statement"] = hostile
        self.write_manifest(manifest)
        with self.assertRaises(orientation.OrientationError) as caught:
            orientation.build_orientation(self.instance)
        self.assertEqual(caught.exception.code, "manifest_contract_invalid")
        self.assertNotIn(hostile, str(caught.exception))

        real = self.instance / "instance.yaml"
        alias = self.root / "manifest-link.yaml"
        alias.symlink_to(real)
        with self.assertRaises(orientation.OrientationError) as caught:
            orientation.build_orientation(alias)
        self.assertEqual(caught.exception.code, "manifest_path_unsafe")

        ancestor = self.root / "parent-alias"
        ancestor.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(orientation.OrientationError) as caught:
            orientation.build_orientation(ancestor / "instance")
        self.assertEqual(caught.exception.code, "manifest_unsafe")

        os.chmod(real, 0o644)
        with self.assertRaises(orientation.OrientationError) as caught:
            orientation.build_orientation(self.instance)
        self.assertEqual(caught.exception.code, "manifest_unsafe")
        os.chmod(real, 0o600)

    def test_unsafe_present_paths_are_not_downgraded_to_missing(self):
        manifest_path = self.instance / "instance.yaml"
        legacy_path = self.instance / "bot.yaml"
        legacy_path.write_bytes(manifest_path.read_bytes())
        os.chmod(legacy_path, 0o600)
        manifest_path.unlink()
        manifest_path.symlink_to(self.root / "absent-manifest.yaml")
        with self.assertRaises(orientation.OrientationError) as caught:
            orientation.build_orientation(self.instance)
        self.assertEqual(caught.exception.code, "manifest_unsafe")

        manifest_path.unlink()
        legacy_path.replace(manifest_path)
        self.deploy_local_proof()
        persona_path = (
            self.runtime / "state" / "john-lomein-persona.json"
        )
        persona_path.unlink()
        persona_path.symlink_to(self.root / "absent-persona.json")
        report = orientation.build_orientation(self.instance)
        self.assertEqual(report["proof"]["persona"]["status"], "invalid")
        self.assertEqual(
            report["proof"]["persona"]["error_code"],
            "store_unsafe",
        )

    def test_two_authoritative_manifests_are_rejected(self):
        primary = self.instance / "instance.yaml"
        legacy = self.instance / "bot.yaml"
        legacy.write_bytes(primary.read_bytes())
        os.chmod(legacy, 0o600)

        with self.assertRaises(
            orientation.OrientationError,
        ) as caught:
            orientation.build_orientation(self.instance)

        self.assertEqual(caught.exception.code, "manifest_ambiguous")

    def test_cli_json_and_human_modes_share_one_report_contract(self):
        for extra in ([], ["--json"]):
            with self.subTest(extra=extra):
                result = subprocess.run(
                    [sys.executable, str(ORIENT_SCRIPT), str(self.instance), *extra],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=20,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "")
                if extra:
                    report = json.loads(result.stdout)
                    self.assertEqual(
                        report["schema_version"],
                        "john_lomein_orientation/v1",
                    )
                else:
                    self.assertIn("Verdict", result.stdout)
                    self.assertIn("Evidence", result.stdout)
                    self.assertIn("Next", result.stdout)

    def test_evaluation_does_not_use_subprocess_network_or_model_surfaces(self):
        with mock.patch(
            "subprocess.run",
            side_effect=AssertionError("subprocess forbidden"),
        ), mock.patch(
            "socket.socket",
            side_effect=AssertionError("network forbidden"),
        ):
            report = orientation.build_orientation(self.instance)
        self.assertEqual(report["status"], "healthy")
        self.assertFalse(report["assurances"]["model_invoked"])
        self.assertFalse(
            report["assurances"]["credential_files_opened"]
        )
        self.assertFalse(
            report["assurances"]["credential_environment_read"]
        )

    def test_unexpected_cli_failures_are_bounded_broken_reports(self):
        private_sentinel = str(self.root / "private" / "secret")
        for extra in ([], ["--json"]):
            with self.subTest(extra=extra), mock.patch.object(
                orient_cli,
                "build_orientation",
                side_effect=OSError(private_sentinel),
            ), mock.patch("builtins.print") as output:
                code = orient_cli.main([str(self.instance), *extra])

            self.assertEqual(code, 2)
            rendered = str(output.call_args_list[0].args[0])
            self.assertNotIn(private_sentinel, rendered)
            self.assertIn("could not complete safely", rendered)
            if extra:
                report = json.loads(rendered)
                self.assertEqual(report["status"], "broken")

    def test_broken_human_report_exposes_only_bounded_attention_code(self):
        report = orientation.broken_report(
            orientation.OrientationError(
                "manifest_unsafe",
                "manifest metadata is unsafe",
            )
        )
        rendered = orientation.render_human(report)
        self.assertIn("Evidence", rendered)
        self.assertIn("Attention: manifest_unsafe", rendered)
        self.assertEqual(
            report["next_steps"][0]["code"],
            "repair_manifest_metadata",
        )
        self.assertIn("mode-0600 manifest", rendered)
        self.assertIn("make status INSTANCE=<instance>", rendered)
        self.assertNotIn("bypass", rendered.casefold())
        self.assertNotIn(str(self.root), rendered)

    def test_broken_recovery_is_error_specific_and_unknown_is_fail_safe(self):
        cases = (
            ("manifest_missing", "restore_manifest", "exactly one"),
            (
                "manifest_ambiguous",
                "select_authoritative_manifest",
                "Stop concurrent manifest edits",
            ),
            (
                "manifest_contract_invalid",
                "repair_manifest_contract",
                "templates/instance.yaml.example",
            ),
            (
                "persona_source_invalid",
                "restore_persona_source",
                "persona/JOHN_LOMEIN.md",
            ),
            (
                "future_orientation_error",
                "repair_product_orientation",
                "make verify",
            ),
        )
        private_sentinel = str(self.root / "private" / "rejected")
        for error_code, next_code, expected_text in cases:
            with self.subTest(error_code=error_code):
                report = orientation.broken_report(
                    orientation.OrientationError(
                        error_code,
                        "bounded failure",
                    )
                )
                step = report["next_steps"][0]
                self.assertEqual(step["code"], next_code)
                self.assertIn(expected_text, step["text"])
                self.assertNotIn(private_sentinel, json.dumps(report))
                self.assertTrue(report["assurances"]["read_only"])


if __name__ == "__main__":
    unittest.main()
