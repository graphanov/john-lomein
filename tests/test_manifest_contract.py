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
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from john_lomein_manifest_contract import (
    MAX_AUTONOMOUS_SAFE_LABELS,
    MAX_FORBIDDEN_PATHS,
    MAX_MISSION_STATEMENT_CHARS,
    MAX_PUBLIC_LIST_ITEMS,
    MAX_READINESS_LABELS,
    MAX_ROADMAP_SOURCES,
    confined_omh_copy_paths,
    effective_authority_posture,
    mission_candidate_complete,
    omh_catalog_skill_sources,
    validate_deploy_managed_paths,
    validate_manifest_contract,
    validate_omh_source_tree,
    validate_runtime_checkout_separation,
)
from john_lomein_profile_contract import CANONICAL_ROLE_PROFILES
from john_lomein_memory_contract import (
    agent_memory_boundary_errors,
    agent_memory_managed_policy_errors,
    managed_policy_directory,
)


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == '/health' else 404)
        self.end_headers()

    def log_message(self, format, *args):
        return None


def base_manifest(root: Path) -> dict:
    return {
        "instance": {"slug": "manifest-contract", "display_name": "Manifest Contract"},
        "target": {
            "repo": "owner/repo",
            "default_branch": "main",
            "local_checkout": str(root / "checkout"),
        },
        "runtime": {
            "hermes_home": str(root / "runtime"),
            "mutation_enabled": False,
            "discord_enabled": False,
            "guide_gateway_enabled": False,
            "keep_awake_on_ac": False,
        },
        "workflows": {
            "omh_enabled": False,
            "omh_required": False,
            "omh_skills_by_role": {},
        },
        "learning": {"enabled": False},
        "open_scaffold_portfolio": {
            "enabled": False,
            "open_scaffold_instance_only": True,
            "draft_prs": True,
        },
    }


def add_complete_owner_mission(manifest: dict) -> None:
    manifest["mission"] = {
        "owner_authored": True,
        "statement": "Maintain the repository through reviewable evidence.",
        "roadmap_sources": ["ROADMAP.md"],
        "owner_signal_policy": (
            "Only authenticated owner signals set or revise priorities."
        ),
    }


class ManifestContractTest(unittest.TestCase):
    def test_complete_candidate_does_not_assert_owner_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = base_manifest(Path(tmp))
            manifest["mission"] = {
                "owner_authored": False,
                "statement": "Maintain the repository through reviewable evidence.",
                "roadmap_sources": ["ROADMAP.md"],
                "owner_signal_policy": (
                    "Only authenticated owner signals set or revise priorities."
                ),
            }

            contract = validate_manifest_contract(manifest)

            self.assertTrue(mission_candidate_complete(manifest))
            self.assertTrue(contract["mission_candidate_complete"])
            self.assertFalse(contract["mission_complete"])
            self.assertFalse(
                effective_authority_posture(
                    manifest,
                    contract=contract,
                )["mission_complete"]
            )

            manifest["mission"].pop("statement")
            contract = validate_manifest_contract(manifest)
            self.assertFalse(mission_candidate_complete(manifest))
            self.assertFalse(contract["mission_candidate_complete"])
            self.assertFalse(contract["mission_complete"])

    def test_quoted_execution_and_authority_booleans_are_rejected(self):
        fields = [
            ("mission", "owner_authored"),
            ("runtime", "mutation_enabled"),
            ("runtime", "discord_enabled"),
            ("runtime", "guide_gateway_enabled"),
            ("runtime", "keep_awake_on_ac"),
            ("runtime", "review_only_profiles_qualified"),
            ("release", "protected_broker_enabled"),
            ("discord", "enabled"),
            ("discord", "guide_gateway_enabled"),
            ("workflows", "omh_enabled"),
            ("workflows", "omh_required"),
            ("learning", "enabled"),
            ("open_scaffold_portfolio", "enabled"),
            ("open_scaffold_portfolio", "open_scaffold_instance_only"),
            ("open_scaffold_portfolio", "draft_prs"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            for section, key in fields:
                for value in ("false", "true"):
                    manifest = base_manifest(Path(tmp))
                    manifest.setdefault(section, {})[key] = value
                    with self.subTest(field=f"{section}.{key}", value=value):
                        with self.assertRaisesRegex(
                            ValueError,
                            rf"{section}\.{key}",
                        ):
                            validate_manifest_contract(manifest)

    def test_owner_github_login_registry_is_strict(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = base_manifest(Path(tmp))
            add_complete_owner_mission(manifest)
            manifest["runtime"]["mutation_enabled"] = True
            with self.assertRaisesRegex(
                ValueError,
                "owner_github_logins",
            ):
                validate_manifest_contract(manifest)

            manifest.setdefault("authority", {})["owner_github_logins"] = ["repo-owner"]
            contract = validate_manifest_contract(manifest)
            self.assertEqual(contract["owner_github_logins"], ["repo-owner"])

            invalid_values = (
                "repo-owner",
                [],
                ["bad login"],
                ["repo-owner", "REPO-OWNER"],
            )
            for value in invalid_values:
                manifest["authority"]["owner_github_logins"] = value
                with self.subTest(value=value), self.assertRaisesRegex(
                    ValueError,
                    "authority.owner_github_logins",
                ):
                    validate_manifest_contract(manifest)

    def test_review_only_profile_qualification_is_explicit_and_strict(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = base_manifest(Path(tmp))
            contract = validate_manifest_contract(manifest)
            self.assertFalse(contract["flags"]["review_only_profiles_qualified"])

            manifest["runtime"]["review_only_profiles_qualified"] = True
            contract = validate_manifest_contract(manifest)
            self.assertTrue(contract["flags"]["review_only_profiles_qualified"])

    def test_collaboration_policy_is_fail_closed_and_exposed(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = base_manifest(Path(tmp))
            contract = validate_manifest_contract(manifest)
            self.assertEqual(contract["collaboration"]["mode"], "disabled")
            self.assertFalse(
                contract["collaboration"]["bot_chat_protocol_enabled"]
            )

            manifest["collaboration"] = {
                "schema_version": "john-lomein.collaboration.v1",
                "mode": "prepared",
                "authority": "advisory_only",
                "bot_chat_protocol_enabled": False,
                "peer_messaging_enabled": False,
                "max_message_chars": 4000,
                "allowed_routes": {"guide": ["forge"]},
                "peer_targets": [],
            }
            contract = validate_manifest_contract(manifest)
            self.assertEqual(
                contract["collaboration"]["allowed_routes"],
                {"guide": ["forge"]},
            )

            manifest["collaboration"]["bot_chat_protocol_enabled"] = True
            with self.assertRaisesRegex(ValueError, "collaboration transport"):
                validate_manifest_contract(manifest)

    def test_guide_dialogue_policy_is_validated_and_exposed(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = base_manifest(Path(tmp))
            contract = validate_manifest_contract(manifest)
            self.assertEqual(contract["guide_dialogue"]["max_refinement_turns"], 4)
            self.assertEqual(contract["guide_dialogue"]["max_questions_per_reply"], 1)

            manifest["workflows"]["guide_dialogue"] = {
                "max_refinement_turns": 6,
                "max_questions_per_reply": 1,
                "proposal_on_exhaustion": True,
            }
            contract = validate_manifest_contract(manifest)
            self.assertEqual(contract["guide_dialogue"]["max_refinement_turns"], 6)

            invalid_values = (
                {"max_refinement_turns": "6"},
                {"max_questions_per_reply": 2},
                {"proposal_on_exhaustion": "true"},
                {"unexpected": 1},
            )
            for value in invalid_values:
                manifest["workflows"]["guide_dialogue"] = value
                with self.subTest(value=value), self.assertRaisesRegex(
                    ValueError,
                    "workflows.guide_dialogue",
                ):
                    validate_manifest_contract(manifest)

    def test_owner_override_transport_is_disabled_and_strict_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = base_manifest(Path(tmp))
            contract = validate_manifest_contract(manifest)
            self.assertFalse(contract["owner_override"]["enabled"])
            self.assertEqual(contract["owner_override"]["transport"], "discord")
            self.assertEqual(
                contract["owner_override"]["authority"],
                "acceptance_constraints_only",
            )

            manifest["owner_override"] = {
                "schema_version": "john-lomein.owner-override-policy.v1",
                "enabled": True,
                "transport": "discord",
                "authority": "acceptance_constraints_only",
                "key_id": "owner-override-2026-01",
                "public_key_sha256": "a" * 64,
                "allowed_discord_user_ids": ["5" * 17],
            }
            manifest.setdefault("authority", {})["owner_github_logins"] = [
                "repoowner"
            ]
            contract = validate_manifest_contract(manifest)
            self.assertTrue(contract["owner_override"]["enabled"])

            manifest["owner_override"]["authority"] = "merge"
            with self.assertRaisesRegex(ValueError, "owner_override.authority"):
                validate_manifest_contract(manifest)

            manifest["owner_override"]["authority"] = (
                "acceptance_constraints_only"
            )
            manifest["owner_override"]["allowed_discord_user_ids"] = []
            with self.assertRaisesRegex(
                ValueError,
                "owner_override.allowed_discord_user_ids",
            ):
                validate_manifest_contract(manifest)

    def test_review_quorum_is_strict_and_exact_head_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = base_manifest(Path(tmp))
            contract = validate_manifest_contract(manifest)
            self.assertFalse(contract["review_quorum"]["enabled"])
            self.assertEqual(
                contract["review_quorum"]["required_roles"],
                ["maintainer", "overwatch"],
            )
            manifest["review_quorum"] = {
                "schema_version": "john-lomein.review-quorum-policy.v1",
                "enabled": True,
                "required_roles": ["maintainer", "overwatch"],
                "require_tests": True,
                "require_codex": True,
                "minimum_human_reviews": 1,
                "human_reviewer_logins": ["RepoOwner"],
            }
            contract = validate_manifest_contract(manifest)
            self.assertTrue(contract["review_quorum"]["enabled"])
            manifest["review_quorum"]["require_codex"] = False
            with self.assertRaisesRegex(ValueError, "require_codex"):
                validate_manifest_contract(manifest)

    def test_omh_codex_requires_enabled_legacy_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest=base_manifest(Path(tmp))
            manifest["workflows"]["implementation_mode"]="omh_codex"
            with self.assertRaisesRegex(ValueError,'omh_codex requires'):
                validate_manifest_contract(manifest)
            manifest["workflows"]["omh_enabled"]=True
            validate_manifest_contract(manifest)

    def test_manifest_contract_rejects_invalid_omh_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            homes=('relative/omh',str(root/'runtime'/'work'),str(root/'outside'))
            for home in homes:
                manifest=base_manifest(root)
                manifest['workflows']['omh_home']=home
                with self.subTest(home=home), self.assertRaises(ValueError):
                    validate_manifest_contract(manifest)
            manifest=base_manifest(root)
            manifest['workflows']['omh_required']=True
            with self.assertRaisesRegex(ValueError,'omh_required requires'):
                validate_manifest_contract(manifest)

    def test_manifest_accepts_canonical_equivalent_omh_alias(self):
        if not Path('/tmp').is_symlink():
            self.skipTest('/tmp is not a symlink alias')
        root=Path('/tmp')/'john-lomein-alias-test'
        manifest=base_manifest(root)
        manifest['workflows']['omh_home']=str(root/'runtime'/'omh')
        validate_manifest_contract(manifest)

    def test_manifest_contract_rejects_invalid_honcho(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest=base_manifest(Path(tmp))
            manifest['memory']={'provider':'builtin'}
            with self.assertRaisesRegex(ValueError,'provider'):
                validate_manifest_contract(manifest)

    def test_protected_release_broker_requires_mutation_and_exports_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = base_manifest(root)
            manifest["release"] = {"protected_broker_enabled": True}
            with self.assertRaisesRegex(
                ValueError,
                "protected release broker requires runtime mutation",
            ):
                validate_manifest_contract(manifest)

            manifest["runtime"]["mutation_enabled"] = True
            add_complete_owner_mission(manifest)
            manifest.setdefault("authority", {})["owner_github_logins"] = ["owner"]
            contract = validate_manifest_contract(manifest)
            self.assertTrue(
                contract["flags"]["protected_release_broker_enabled"]
            )
            path = root / "instance.yaml"
            path.write_text(
                yaml.safe_dump(manifest, sort_keys=False),
                encoding="utf-8",
            )
            path.chmod(0o600)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "read-instance-env.py"),
                    str(path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn(
                "BOT_PROTECTED_RELEASE_BROKER_ENABLED=1",
                proc.stdout,
            )

    def test_incomplete_owner_mission_forces_requested_authority_off(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = base_manifest(root)
            manifest["mission"] = {"owner_authored": True}
            manifest["runtime"].update(
                {
                    "activation": "active",
                    "mutation_enabled": True,
                    "discord_enabled": True,
                    "guide_gateway_enabled": True,
                }
            )
            manifest["release"] = {"protected_broker_enabled": True}
            manifest["open_scaffold_portfolio"]["enabled"] = True
            contract = validate_manifest_contract(manifest)
            posture = effective_authority_posture(
                manifest,
                contract=contract,
            )
            self.assertFalse(contract["mission_candidate_complete"])
            self.assertFalse(contract["mission_complete"])
            self.assertEqual(posture["requested_activation"], "active")
            self.assertEqual(posture["activation"], "owner_gated")
            for field in (
                "mutation_enabled",
                "discord_enabled",
                "guide_gateway_enabled",
                "protected_release_broker_enabled",
                "portfolio_enabled",
            ):
                self.assertFalse(posture[field], field)

            path = root / "instance.yaml"
            path.write_text(
                yaml.safe_dump(manifest, sort_keys=False),
                encoding="utf-8",
            )
            path.chmod(0o600)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "read-instance-env.py"),
                    str(path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("BOT_MISSION_COMPLETE=0", proc.stdout)
            self.assertIn("BOT_REQUESTED_ACTIVATION=active", proc.stdout)
            self.assertIn("BOT_ACTIVATION=owner_gated", proc.stdout)
            self.assertIn("BOT_MUTATION_REQUESTED=1", proc.stdout)
            self.assertIn("BOT_MUTATION_ENABLED=0", proc.stdout)
            self.assertIn("BOT_DISCORD_REQUESTED=1", proc.stdout)
            self.assertIn("BOT_DISCORD_ENABLED=0", proc.stdout)
            self.assertIn("BOT_GUIDE_GATEWAY_REQUESTED=1", proc.stdout)
            self.assertIn("BOT_GUIDE_GATEWAY_ENABLED=0", proc.stdout)
            self.assertIn(
                "BOT_PROTECTED_RELEASE_BROKER_REQUESTED=1",
                proc.stdout,
            )
            self.assertIn(
                "BOT_PROTECTED_RELEASE_BROKER_ENABLED=0",
                proc.stdout,
            )
            self.assertIn("BOT_OSC_PORTFOLIO_REQUESTED=1", proc.stdout)
            self.assertIn("BOT_OSC_PORTFOLIO_ENABLED=0", proc.stdout)

            spec = importlib.util.spec_from_file_location(
                "doctor_authority_projection",
                SCRIPTS / "doctor-instance.py",
            )
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader)
            doctor = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(doctor)
            evidence = doctor.authority_projection_evidence(posture)
            self.assertEqual(evidence["requested"]["activation"], "active")
            self.assertTrue(
                all(
                    evidence["requested"][field]
                    for field in (
                        "mutation",
                        "discord",
                        "guide_gateway",
                        "protected_release",
                        "portfolio",
                    )
                )
            )
            self.assertEqual(
                evidence["effective"],
                {
                    "activation": "owner_gated",
                    "mutation": False,
                    "discord": False,
                    "guide_gateway": False,
                    "protected_release": False,
                    "portfolio": False,
                    "scheduler_required": False,
                    "guide_required": False,
                },
            )
            doctor.FAIL.clear()
            doctor.WARN.clear()
            doctor.note(
                doctor.mission_authority_level(
                    mission_complete=False,
                    mission_public_safe=True,
                    authority_requested=True,
                ),
                "active authority is blocked because the owner mission card is incomplete",
            )
            self.assertEqual(doctor.diagnostic_exit_code(), 2)

    def test_read_instance_env_rejects_quoted_false_before_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = base_manifest(root)
            manifest["runtime"]["mutation_enabled"] = "false"
            path = root / "instance.yaml"
            path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
            path.chmod(0o600)
            proc = subprocess.run(
                [sys.executable, str(SCRIPTS / "read-instance-env.py"), str(path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("runtime.mutation_enabled", proc.stdout + proc.stderr)
            self.assertNotIn("BOT_MUTATION_ENABLED=", proc.stdout)

    def test_omh_role_entries_are_safe_single_components(self):
        hostile = [
            "../escape",
            "nested/skill",
            r"nested\skill",
            "/absolute",
            ".",
            "..",
            " skill",
            "skill ",
            "",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            for value in hostile:
                manifest = base_manifest(Path(tmp))
                manifest["workflows"]["omh_skills_by_role"] = {
                    "forge": [value],
                }
                with self.subTest(value=value):
                    with self.assertRaisesRegex(ValueError, "component"):
                        validate_manifest_contract(manifest)

            manifest = base_manifest(Path(tmp))
            manifest["workflows"]["omh_skills_by_role"] = {
                "attacker": ["safe-name"],
            }
            with self.assertRaisesRegex(ValueError, "unknown roles"):
                validate_manifest_contract(manifest)

            manifest["workflows"]["omh_skills_by_role"] = {
                "forge": "safe-name",
            }
            with self.assertRaisesRegex(ValueError, "must be a list"):
                validate_manifest_contract(manifest)

    def test_omh_copy_paths_and_tree_cannot_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "source"
            destination_root = root / "destination"
            skill = source_root / "safe-skill"
            skill.mkdir(parents=True)
            (skill / "SKILL.md").write_text("# safe\n", encoding="utf-8")

            source, destination = confined_omh_copy_paths(
                source_root,
                destination_root,
                "safe-skill",
            )
            validate_omh_source_tree(source_root, source)
            self.assertEqual(source, skill.resolve())
            self.assertEqual(destination, (destination_root / "safe-skill").resolve())

            catalog_skill = source_root / "omh-safe-skill"
            catalog_skill.mkdir()
            (catalog_skill / "SKILL.md").write_text("# catalog safe\n", encoding="utf-8")
            catalog_source, catalog_destination = confined_omh_copy_paths(
                source_root,
                destination_root,
                "safe-skill",
                source_component="omh-safe-skill",
            )
            self.assertEqual(catalog_source, catalog_skill.resolve())
            self.assertEqual(
                catalog_destination,
                (destination_root / "safe-skill").resolve(),
            )

            omh_home = root / "omh"
            omh_skill = omh_home / "skills" / "omh-safe-skill"
            omh_skill.mkdir(parents=True)
            (omh_skill / "SKILL.md").write_text("# catalog safe\n", encoding="utf-8")
            (omh_home / "manifest.json").write_text(
                json.dumps(
                    {
                        "skills": [
                            {
                                "name": "safe-skill",
                                "path": "omh-safe-skill/SKILL.md",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                omh_catalog_skill_sources(omh_home),
                {"safe-skill": "omh-safe-skill"},
            )

            outside = root / "outside"
            outside.mkdir()
            escaped = source_root / "escaped"
            escaped.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "source skill is symlink"):
                confined_omh_copy_paths(source_root, destination_root, "escaped")

            nested_link = skill / "outside-link"
            nested_link.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlinks are not allowed"):
                validate_omh_source_tree(source_root, skill)
            nested_link.unlink()

            destination_root.rmdir()
            destination_root.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "destination root is symlink"):
                confined_omh_copy_paths(source_root, destination_root, "safe-skill")

    def test_public_prompt_fields_have_count_length_and_aggregate_caps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = base_manifest(root)
            manifest["mission"] = {
                "statement": "x" * (MAX_MISSION_STATEMENT_CHARS + 1),
            }
            with self.assertRaisesRegex(ValueError, "mission.statement"):
                validate_manifest_contract(manifest)

            for field, limit in (
                ("roadmap_sources", MAX_ROADMAP_SOURCES),
                ("forbidden_paths", MAX_FORBIDDEN_PATHS),
                ("readiness_labels", MAX_READINESS_LABELS),
                ("autonomous_safe_labels", MAX_AUTONOMOUS_SAFE_LABELS),
            ):
                manifest = base_manifest(root)
                section = "mission" if field == "roadmap_sources" else "gates"
                manifest.setdefault(section, {})[field] = [
                    f"item-{index}" for index in range(limit + 1)
                ]
                with self.subTest(field=field):
                    with self.assertRaisesRegex(ValueError, "exceeds"):
                        validate_manifest_contract(manifest)

            manifest = base_manifest(root)
            manifest["mission"] = {
                "roadmap_sources": ["r" * 200 for _ in range(MAX_ROADMAP_SOURCES)],
            }
            manifest["gates"] = {
                "forbidden_paths": ["f" * 200 for _ in range(20)],
            }
            with self.assertRaisesRegex(ValueError, "aggregate byte limit"):
                validate_manifest_contract(manifest)

            manifest = base_manifest(root)
            manifest["mission"] = {
                "roadmap_sources": [
                    f"r-{index}" for index in range(MAX_ROADMAP_SOURCES)
                ],
            }
            manifest["gates"] = {
                "forbidden_paths": [
                    f"f-{index}" for index in range(MAX_FORBIDDEN_PATHS)
                ],
                "readiness_labels": [
                    f"l-{index}"
                    for index in range(
                        MAX_PUBLIC_LIST_ITEMS
                        - MAX_ROADMAP_SOURCES
                        - MAX_FORBIDDEN_PATHS
                        + 1
                    )
                ],
            }
            with self.assertRaisesRegex(ValueError, "aggregate item limit"):
                validate_manifest_contract(manifest)

    def test_autonomous_safe_labels_are_explicit_unique_and_not_readiness(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = base_manifest(root)
            manifest["gates"] = {
                "readiness_labels": ["forge-ready"],
                "autonomous_safe_labels": ["triage-needed", "TRIAGE-NEEDED"],
            }
            with self.assertRaisesRegex(ValueError, "contains duplicates"):
                validate_manifest_contract(manifest)

            manifest["gates"]["autonomous_safe_labels"] = ["forge-ready"]
            with self.assertRaisesRegex(ValueError, "readiness labels"):
                validate_manifest_contract(manifest)

            manifest["gates"]["autonomous_safe_labels"] = ["safe,unsafe"]
            with self.assertRaisesRegex(ValueError, "cannot contain commas"):
                validate_manifest_contract(manifest)

    def test_runtime_and_checkout_must_not_overlap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = [
                (root / "same", root / "same"),
                (root / "runtime" / "repo", root / "runtime"),
                (root / "repo", root / "repo" / ".john-runtime"),
            ]
            for checkout, runtime in cases:
                with self.subTest(checkout=checkout, runtime=runtime):
                    with self.assertRaisesRegex(ValueError, "must not overlap"):
                        validate_runtime_checkout_separation(checkout, runtime)

            outside = root / "outside-runtime"
            outside.mkdir()
            symlinked_runtime = root / "runtime-link"
            symlinked_runtime.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink component"):
                validate_runtime_checkout_separation(
                    root / "checkout",
                    symlinked_runtime,
                )
            parent_link = root / "parent-link"
            parent_link.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink component"):
                validate_runtime_checkout_separation(
                    root / "checkout",
                    parent_link / "nested-runtime",
                )

    def test_deploy_preflight_rejects_symlinked_managed_write_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "runtime"
            outside = root / "outside"
            outside.mkdir()

            (home / "profiles").parent.mkdir(parents=True)
            (home / "profiles").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "managed path is symlink"):
                validate_deploy_managed_paths(home, CANONICAL_ROLE_PROFILES)

            (home / "profiles").unlink()
            profile = home / "profiles" / "john-lomein-guide"
            profile.mkdir(parents=True)
            (profile / "config.yaml").symlink_to(outside / "config.yaml")
            with self.assertRaisesRegex(ValueError, "managed path is symlink"):
                validate_deploy_managed_paths(home, CANONICAL_ROLE_PROFILES)

            (profile / "config.yaml").unlink()
            (profile / "distribution.yaml").symlink_to(outside / "distribution.yaml")
            with self.assertRaisesRegex(ValueError, "managed path is symlink"):
                validate_deploy_managed_paths(home, CANONICAL_ROLE_PROFILES)
            (profile / "distribution.yaml").unlink()
            (profile / "honcho.json").symlink_to(outside / "honcho.json")
            with self.assertRaisesRegex(ValueError, "managed path is symlink"):
                validate_deploy_managed_paths(home, CANONICAL_ROLE_PROFILES)
            (profile / "honcho.json").unlink()
            hardlink_source=outside/"control.json"
            hardlink_source.write_text("{}\n", encoding="utf-8")
            os.link(hardlink_source, profile/"distribution.yaml")
            with self.assertRaisesRegex(ValueError, "runtime file metadata"):
                validate_deploy_managed_paths(home, CANONICAL_ROLE_PROFILES)
            (profile/"distribution.yaml").unlink()
            os.link(hardlink_source,home/"config.yaml")
            with self.assertRaisesRegex(ValueError,"runtime file metadata"):
                validate_deploy_managed_paths(home,CANONICAL_ROLE_PROFILES)
            (home/"config.yaml").unlink()
            scripts = home / "scripts"
            scripts.mkdir()
            os.link(hardlink_source, scripts / "unlisted.py")
            with self.assertRaisesRegex(ValueError, "runtime tree metadata"):
                validate_deploy_managed_paths(home, CANONICAL_ROLE_PROFILES)
            (scripts / "unlisted.py").unlink()
            state = home / "state"
            state.mkdir()
            (state / "nested-link").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "managed tree contains symlink"):
                validate_deploy_managed_paths(home, CANONICAL_ROLE_PROFILES)

            (state / "nested-link").unlink()
            opaque = state / "forge-cycles" / "run-1" / "fixture"
            opaque.mkdir(parents=True)
            (opaque / "legitimate-test-link").symlink_to(outside)
            worktree = state / "worktrees" / "forge" / "checkout"
            worktree.mkdir(parents=True)
            (worktree / "node-module-link").symlink_to(outside)
            validate_deploy_managed_paths(home, CANONICAL_ROLE_PROFILES)

            for dynamic_root in ("forge-cycles", "worktrees"):
                with self.subTest(dynamic_root=dynamic_root):
                    redirected = state / dynamic_root
                    if redirected.exists():
                        for child in sorted(
                            redirected.rglob("*"),
                            key=lambda item: len(item.parts),
                            reverse=True,
                        ):
                            if child.is_symlink() or child.is_file():
                                child.unlink()
                            elif child.is_dir():
                                child.rmdir()
                        redirected.rmdir()
                    redirected.symlink_to(outside, target_is_directory=True)
                    with self.assertRaisesRegex(
                        ValueError,
                        "managed tree contains symlink",
                    ):
                        validate_deploy_managed_paths(
                            home,
                            CANONICAL_ROLE_PROFILES,
                        )
                    redirected.unlink()

            protected = state / "continuity"
            protected.mkdir()
            (protected / "redirect").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "managed tree contains symlink"):
                validate_deploy_managed_paths(home, CANONICAL_ROLE_PROFILES)

            root_link = root / "runtime-link"
            root_link.symlink_to(home, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "runtime root contains symlink"):
                validate_deploy_managed_paths(
                    root_link,
                    CANONICAL_ROLE_PROFILES,
                )

    def test_raw_profile_consumers_reject_traversal_before_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = root / "runtime"
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "config.yaml"
            sentinel.write_text("sentinel: true\n", encoding="utf-8")
            manifest = base_manifest(root)
            manifest["profiles"] = {"guide": "../../outside"}
            manifest_path = root / "instance.yaml"
            manifest_path.write_text(
                yaml.safe_dump(manifest, sort_keys=False),
                encoding="utf-8",
            )
            manifest_path.chmod(0o600)

            for script, extra in (
                ("apply-guide-discord-config.py", []),
                ("repair-profile-gh-auth.py", ["--check"]),
            ):
                with self.subTest(script=script):
                    proc = subprocess.run(
                        [sys.executable, str(SCRIPTS / script), str(manifest_path), *extra],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    self.assertEqual(proc.returncode, 2)
                    self.assertIn("expected john-lomein-guide", proc.stdout + proc.stderr)
                    self.assertEqual(
                        sentinel.read_text(encoding="utf-8"),
                        "sentinel: true\n",
                    )

            runtime.mkdir(parents=True)
            (runtime / "instance.yaml").write_text(
                yaml.safe_dump(manifest, sort_keys=False),
                encoding="utf-8",
            )
            runtime_scripts = runtime / "scripts"
            runtime_scripts.mkdir()
            (runtime_scripts / "john-lomein-instance.env").write_text(
                "BOT_REPO='owner/repo'\n",
                encoding="utf-8",
            )
            spec = importlib.util.spec_from_file_location(
                "manifest_contract_issue_intake",
                SCRIPTS / "john-lomein-issue-intake.py",
            )
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader)
            intake = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(intake)
            original_script_dir = intake.SCRIPT_DIR
            intake.SCRIPT_DIR = runtime_scripts
            try:
                with self.assertRaises(intake.IntakeError) as error:
                    intake.gh_env()
            finally:
                intake.SCRIPT_DIR = original_script_dir
            self.assertEqual(error.exception.code, "unsafe_profile_contract")
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "sentinel: true\n")

    def test_stubbed_full_deploy_receives_exported_bootstrap_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            health_server=ThreadingHTTPServer(('127.0.0.1',0),_HealthHandler)
            health_thread=threading.Thread(target=health_server.serve_forever,daemon=True)
            health_thread.start()
            self.addCleanup(health_server.server_close)
            self.addCleanup(health_server.shutdown)
            fake_bin=root/"bin"
            fake_bin.mkdir()
            hermes = fake_bin / "hermes"
            hermes.write_text(
                textwrap.dedent(
                    f"""\
                    #!{sys.executable}
                    import json
                    import os
                    import re
                    import shutil
                    import sys
                    import urllib.request
                    from pathlib import Path

                    argv = sys.argv[1:]
                    if argv[:2] == ["profile", "install"]:
                        source = Path(argv[2])
                        profile = argv[argv.index("--name") + 1]
                        home = Path(os.environ["HERMES_HOME"])
                        target = home / "profiles" / profile
                        target.mkdir(parents=True, exist_ok=True)
                        for asset in ("SOUL.md", "distribution.yaml"):
                            shutil.copy2(source / asset, target / asset)
                        calls = home / ".fake-profile-installs.jsonl"
                        with calls.open("a", encoding="utf-8") as stream:
                            stream.write(json.dumps(argv) + "\\n")
                        raise SystemExit(0)
                    if "profile" in argv and "show" in argv:
                        raise SystemExit(1)
                    if "cron" in argv:
                        root = Path(os.environ["HERMES_HOME"])
                        profile = argv[argv.index("-p") + 1]
                        state = (
                            root
                            / "profiles"
                            / profile
                            / ".fake-crons.json"
                        )
                        jobs = (
                            json.loads(state.read_text(encoding="utf-8"))
                            if state.exists()
                            else {{}}
                        )
                        action = argv[argv.index("cron") + 1]
                        if action == "create":
                            name = argv[argv.index("--name") + 1]
                            job_id = ("%08x" % (len(jobs) + 1))
                            jobs[job_id] = name
                            state.write_text(
                                json.dumps(jobs),
                                encoding="utf-8",
                            )
                            print("created " + name)
                        elif action == "remove":
                            jobs.pop(argv[-1], None)
                            state.write_text(
                                json.dumps(jobs),
                                encoding="utf-8",
                            )
                        elif action == "list":
                            for job_id, name in sorted(jobs.items()):
                                print(job_id + " [enabled]")
                                print("  Name: " + name)
                        raise SystemExit(0)
                    if "chat" in argv:
                        home = Path(os.environ["HERMES_HOME"])
                        config = (home / "config.yaml").read_text(encoding="utf-8")
                        match = re.search(
                            r"base_url:\\s*(http://127\\.0\\.0\\.1:[0-9]+/v1)",
                            config,
                        )
                        if match is None:
                            raise SystemExit(2)
                        nonce = os.environ.get(
                            "JOHN_CONTINUITY_CANARY_NONCE", ""
                        )
                        if not nonce:
                            runtime = home.parents[1]
                            ledger = (
                                runtime / "state" / "continuity" / "continuity.jsonl"
                            )
                            event = json.loads(ledger.read_text(encoding="utf-8").splitlines()[-1])
                            nonce = event["summary"]
                        body = json.dumps(
                            {{
                                "model": "john-continuity-canary",
                                "stream": False,
                                "messages": [
                                    {{
                                        "role": "user",
                                        "content": "canary request\\n\\n" + nonce,
                                    }}
                                ],
                            }}
                        ).encode("utf-8")
                        request = urllib.request.Request(
                            match.group(1) + "/chat/completions",
                            data=body,
                            headers={{"Content-Type": "application/json"}},
                        )
                        with urllib.request.urlopen(request, timeout=10) as response:
                            response.read()
                    raise SystemExit(0)
                    """
                ),
                encoding="utf-8",
            )
            git = fake_bin / "git"
            git.write_text(
                textwrap.dedent(
                    """\
                    #!/bin/bash
                    if [ "${1:-}" = "clone" ]; then
                      destination="${@: -1}"
                      mkdir -p "$destination/.git"
                    fi
                    exit 0
                    """
                ),
                encoding="utf-8",
            )
            gh = fake_bin / "gh"
            gh.write_text("#!/bin/bash\nexit 1\n", encoding="utf-8")
            real_uv = shutil.which("uv")
            self.assertIsNotNone(real_uv)
            uv = fake_bin / "uv"
            uv.write_text(
                textwrap.dedent(
                    f"""\
                    #!{sys.executable}
                    import os
                    import sys
                    from pathlib import Path

                    if any(
                        Path(arg).name == "john-lomein-continuity-hook-canary.py"
                        for arg in sys.argv[1:]
                    ):
                        raise SystemExit(0)
                    os.execv({real_uv!r}, [{real_uv!r}, *sys.argv[1:]])
                    """
                ),
                encoding="utf-8",
            )
            for path in (hermes, git, gh, uv):
                path.chmod(0o755)

            deterministic_provider = (
                root / "home" / "mnemosyne" / "hermes_memory_provider"
            )
            deterministic_provider.mkdir(parents=True)
            manifest = base_manifest(root)
            manifest["memory"]={"provider":"honcho","honcho":{"base_url":f"http://127.0.0.1:{health_server.server_port}"}}
            # This fixture proves bootstrap/export behavior with a fake Hermes
            # binary and intentionally has no OAuth authority. Keep its model
            # credential-free so the real projection gate is not bypassed.
            manifest["model"] = {
                "provider": "zai",
                "default": "fixture-model",
            }
            manifest_path = root / "instance.yaml"
            manifest_path.write_text(
                yaml.safe_dump(manifest, sort_keys=False),
                encoding="utf-8",
            )
            manifest_path.chmod(0o600)
            env = dict(os.environ)
            env["HOME"] = str(root / "home")
            env["PATH"] = f"{fake_bin}:{env['PATH']}"
            proc = subprocess.run(
                ["bash", str(SCRIPTS / "deploy-instance.sh"), str(manifest_path)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            runtime = Path(manifest["runtime"]["hermes_home"])
            generated = (
                runtime / "scripts" / "john-lomein-instance.env"
            ).read_text(encoding="utf-8")
            self.assertIn("BOT_SLUG='manifest-contract'", generated)
            self.assertIn("BOT_REPO='owner/repo'", generated)
            self.assertIn("BOT_HERMES_MANAGED_ROOT=", generated)
            self.assertIn(
                "BOT_MODEL_MEMORY_ISOLATION='required'",
                generated,
            )
            self.assertIn("BOT_STEWARD_PRIVATE_ROOT=", generated)
            self.assertIn("BOT_STEWARD_PROJECTION_ROOT=", generated)
            self.assertNotIn("MNEMOSYNE_DATA_DIR=", generated)
            self.assertTrue(
                (runtime / "state" / "john-lomein-persona.json").is_file()
            )
            self.assertTrue((runtime / "plugins" / "mnemosyne").is_symlink())
            self.assertTrue(
                (
                    runtime
                    / "private"
                    / "learning-steward"
                    / "mnemosyne"
                    / "data"
                ).is_dir()
            )
            self.assertTrue((runtime / "state" / "learning").is_dir())
            self.assertFalse((runtime / "mnemosyne").exists())
            profile_install_calls = [
                json.loads(line)
                for line in (
                    runtime / ".fake-profile-installs.jsonl"
                ).read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(
                profile_install_calls,
                [
                    [
                        "profile",
                        "install",
                        str((runtime / "distributions" / profile).resolve()),
                        "--name",
                        profile,
                        "--force",
                        "-y",
                    ]
                    for profile in CANONICAL_ROLE_PROFILES.values()
                ],
            )
            for role, profile in CANONICAL_ROLE_PROFILES.items():
                profile_dir = runtime / "profiles" / profile
                self.assertNotIn("{{JOHN_LOMEIN_PERSONA_CORE}}",(profile_dir/"SOUL.md").read_text(encoding="utf-8"))
                distribution = yaml.safe_load(
                    (profile_dir / "distribution.yaml").read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual(distribution["name"], profile)
                self.assertEqual(distribution["version"], "0.1.0")
                config_path = profile_dir / "config.yaml"
                config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
                initial_enabled_plugins = set(config.get("plugins", {}).get("enabled", []))
                initial_disabled_plugins = set(config.get("plugins", {}).get("disabled", []))
                if role == "guide":
                    self.assertIn("john-lomein-guide-lifecycle", initial_enabled_plugins)
                    self.assertNotIn("john-lomein-guide-lifecycle", initial_disabled_plugins)
                else:
                    self.assertNotIn("john-lomein-guide-lifecycle", initial_enabled_plugins)
                    self.assertIn("john-lomein-guide-lifecycle", initial_disabled_plugins)
                config["fixture_local_config"] = "preserve"
                config_path.write_text(
                    yaml.safe_dump(config, sort_keys=False),
                    encoding="utf-8",
                )
                sessions = profile_dir / "sessions"
                sessions.mkdir(exist_ok=True)
                (sessions / "preserve.json").write_text(
                    '{"preserve":true}\n', encoding="utf-8"
                )
                (profile_dir / "state.db").write_bytes(b"preserve-runtime-state")
            continuity = (
                runtime
                / "private"
                / "learning-steward"
                / "learning"
                / "continuity-sentinel.json"
            )
            continuity.write_text('{"preserve":true}\n', encoding="utf-8")
            continuity.chmod(0o600)
            redeploy = subprocess.run(
                [
                    "bash",
                    str(SCRIPTS / "deploy-instance.sh"),
                    str(manifest_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(
                redeploy.returncode,
                0,
                redeploy.stderr + redeploy.stdout,
            )
            self.assertEqual(
                continuity.read_text(encoding="utf-8"),
                '{"preserve":true}\n',
            )
            for role, profile in CANONICAL_ROLE_PROFILES.items():
                with self.subTest(role=role):
                    profile_dir = runtime / "profiles" / profile
                    config = yaml.safe_load(
                        (profile_dir / "config.yaml").read_text(
                            encoding="utf-8"
                        )
                    )
                    self.assertEqual(
                        agent_memory_boundary_errors(config, role),
                        [],
                    )
                    self.assertEqual(
                        config["fixture_local_config"],
                        "preserve",
                    )
                    self.assertIs(
                        config["agent"]["bot_mode_protocol"],
                        False,
                    )
                    enabled_plugins = set(config.get("plugins", {}).get("enabled", []))
                    disabled_plugins = set(config.get("plugins", {}).get("disabled", []))
                    if role == "guide":
                        self.assertIn("john-lomein-guide-lifecycle", enabled_plugins)
                        self.assertNotIn("john-lomein-guide-lifecycle", disabled_plugins)
                    else:
                        self.assertNotIn("john-lomein-guide-lifecycle", enabled_plugins)
                        self.assertIn("john-lomein-guide-lifecycle", disabled_plugins)
                    self.assertEqual(
                        (profile_dir / "sessions" / "preserve.json").read_text(
                            encoding="utf-8"
                        ),
                        '{"preserve":true}\n',
                    )
                    self.assertEqual(
                        (profile_dir / "state.db").read_bytes(),
                        b"preserve-runtime-state",
                    )
                    managed_policy = yaml.safe_load(
                        (
                            managed_policy_directory(runtime, profile)
                            / "config.yaml"
                        ).read_text(encoding="utf-8")
                    )
                    self.assertEqual(
                        agent_memory_managed_policy_errors(
                            managed_policy,
                            role,
                        ),
                        [],
                    )
                    self.assertFalse(
                        (profile_dir / "plugins" / "mnemosyne").exists()
                    )
                    self.assertFalse(
                        (profile_dir / "plugins" / "mnemosyne").is_symlink()
                    )
                    self.assertNotIn(
                        "MNEMOSYNE_DATA_DIR",
                        (profile_dir / ".env").read_text(encoding="utf-8"),
                    )
            collaboration_state = json.loads(
                (runtime / "state" / "john-lomein-collaboration-policy.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                collaboration_state["schema_version"],
                "john-lomein.collaboration.v1",
            )
            self.assertEqual(collaboration_state["mode"], "disabled")
            self.assertFalse(collaboration_state["bot_chat_protocol_enabled"])
            boundary_marker = (
                runtime
                / "private"
                / "learning-steward"
                / ".model-memory-boundary-v1"
            )
            boundary_marker.unlink()
            boundary_marker.symlink_to(root / "outside-boundary-marker")
            refused = subprocess.run(
                [
                    "bash",
                    str(SCRIPTS / "deploy-instance.sh"),
                    str(manifest_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn(
                "unsafe model-memory boundary marker",
                refused.stderr + refused.stdout,
            )
            self.assertFalse((root / "outside-boundary-marker").exists())


if __name__ == "__main__":
    unittest.main()
