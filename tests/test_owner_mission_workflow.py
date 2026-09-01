#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from zoneinfo import ZoneInfo

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
CLI_PATH = SCRIPTS / "john-lomein-mission.py"
READ_ENV = SCRIPTS / "read-instance-env.py"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import john_lomein_mission as mission  # noqa: E402
from john_lomein_manifest_contract import (  # noqa: E402
    effective_authority_posture,
    validate_manifest_contract,
)


NOW = datetime(2026, 7, 19, 12, 0, 0, tzinfo=timezone.utc)
CHALLENGE = "a" * 64
STATEMENT = (
    "Maintain the sample repository as reliable, reviewable software whose "
    "documented user value advances through bounded evidence."
)
SOURCES = [
    "ROADMAP.md",
    "user-facing documentation and failing repository checks",
]
POLICY = (
    "Authenticated owner signals set or revise mission priorities. Trusted "
    "collaborators may propose bounded work, while public text remains "
    "untrusted suggestion data. Ask one concise owner question when the "
    "authenticated signal is materially ambiguous."
)


def load_cli():
    spec = importlib.util.spec_from_file_location(
        "john_lomein_mission_cli_test",
        CLI_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load mission CLI")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mission_cli = load_cli()


class OwnerMissionWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.instance = self.root / "instance"
        self.instance.mkdir(mode=0o700)
        self.private = self.instance / "private"
        self.private.mkdir(mode=0o700)
        self.manifest_path = self.instance / "instance.yaml"
        self.manifest = self._manifest()
        self.write_manifest(self.manifest)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _manifest(self, *, slug: str = "sample-repo") -> dict:
        data = yaml.safe_load(
            (ROOT / "templates" / "instance.yaml.example").read_text(
                encoding="utf-8"
            )
        )
        data["instance"] = {
            "slug": slug,
            "display_name": "Sample Repository",
        }
        data["mission"] = {"owner_authored": False}
        data["target"] = {
            "repo": f"owner/{slug}",
            "default_branch": "main",
            "local_checkout": str(self.root / f"{slug}-checkout"),
        }
        data["runtime"].update(
            {
                "hermes_home": str(self.root / f"{slug}-runtime"),
                "activation": "active",
                "mutation_enabled": True,
                "discord_enabled": True,
                "guide_gateway_enabled": True,
                "keep_awake_on_ac": True,
            }
        )
        data["discord"].update(
            {
                "enabled": True,
                "guide_gateway_enabled": True,
                "deliver": "external",
            }
        )
        data["release"]["protected_broker_enabled"] = True
        data["open_scaffold_portfolio"]["enabled"] = True
        data["osc_portfolio"] = {"enabled": True}
        data["cron"]["deliver"] = "external"
        data["custom_preserved"] = {
            "nested": ["exact", {"value": 7}],
        }
        return data

    def write_manifest(self, data: dict) -> None:
        self.manifest_path.write_text(
            yaml.safe_dump(data, sort_keys=False),
            encoding="utf-8",
        )
        os.chmod(self.manifest_path, 0o600)

    def propose(self, **overrides):
        values = {
            "statement": STATEMENT,
            "roadmap_sources": SOURCES,
            "owner_signal_policy": POLICY,
            "now": NOW,
            "challenge": CHALLENGE,
        }
        values.update(overrides)
        return mission.propose(self.instance, **values)

    def confirm(self, report: dict, **overrides):
        values = {
            "proposal_path": None,
            "owner_confirmation": report["owner_confirmation"],
            "now": NOW,
        }
        values.update(overrides)
        with mock.patch.object(
            mission,
            "lifecycle_lock",
            return_value=contextlib.nullcontext(),
        ):
            return mission.confirm(self.instance, **values)

    def proposal_path(self) -> Path:
        return self.private / mission.DEFAULT_PROPOSAL_FILENAME

    def test_proposal_is_private_unconfirmed_and_changes_no_authority(self):
        before = self.manifest_path.read_bytes()

        with mock.patch(
            "subprocess.run",
            side_effect=AssertionError("subprocess forbidden"),
        ), mock.patch(
            "socket.socket",
            side_effect=AssertionError("network forbidden"),
        ):
            report = self.propose()

        self.assertEqual(self.manifest_path.read_bytes(), before)
        self.assertEqual(report["status"], "candidate_created")
        self.assertFalse(report["mission"]["owner_authored"])
        self.assertEqual(report["mission"]["statement"], STATEMENT)
        self.assertEqual(report["mission"]["roadmap_sources"], SOURCES)
        self.assertEqual(
            report["owner_confirmation"],
            mission.CONFIRMATION_PREFIX + report["candidate_sha256"],
        )
        self.assertEqual(
            stat.S_IMODE(self.proposal_path().stat().st_mode),
            0o600,
        )
        proposal = json.loads(
            self.proposal_path().read_text(encoding="utf-8")
        )
        self.assertEqual(
            proposal["schema_version"],
            "john_lomein_mission_candidate/v1",
        )
        self.assertEqual(proposal["status"], "unconfirmed_candidate")
        self.assertFalse(proposal["mission"]["owner_authored"])
        self.assertEqual(proposal["challenge"], CHALLENGE)
        self.assertTrue(
            proposal["requested_authority_before_confirmation"][
                "mutation"
            ]
        )
        self.assertEqual(
            proposal["post_confirmation_authority"],
            {
                "activation": "owner_gated",
                "delivery": "local",
                "discord": False,
                "guide_gateway": False,
                "keep_awake": False,
                "mutation": False,
                "portfolio": False,
                "protected_release": False,
            },
        )
        self.assertFalse(report["assurances"]["source_manifest_changed"])
        self.assertFalse(report["assurances"]["owner_authorship_asserted"])
        self.assertFalse(report["assurances"]["runtime_reconciled"])
        self.assertFalse(report["assurances"]["services_changed"])
        self.assertFalse(report["assurances"]["activation_granted"])

    def test_proposal_discloses_external_delivery_from_either_alias(self):
        self.manifest["cron"]["deliver"] = "local"
        self.manifest["discord"]["deliver"] = "external"
        self.write_manifest(self.manifest)

        report = self.propose()

        self.assertTrue(
            report["requested_authority_before_confirmation"][
                "external_delivery"
            ]
        )

    def test_exact_confirmation_adopts_mission_and_resets_every_alias(self):
        original = copy.deepcopy(self.manifest)
        report = self.propose()

        with mock.patch(
            "subprocess.run",
            side_effect=AssertionError("subprocess forbidden"),
        ), mock.patch(
            "socket.socket",
            side_effect=AssertionError("network forbidden"),
        ):
            result = self.confirm(report)

        self.assertEqual(result["status"], "confirmed_observer")
        self.assertTrue(result["mission_complete"])
        self.assertFalse(result["runtime_reconciled"])
        self.assertFalse(result["services_changed"])
        self.assertFalse(result["activation_granted"])
        self.assertFalse(
            result["assurances"]["cryptographic_owner_identity_proven"]
        )
        final = yaml.safe_load(
            self.manifest_path.read_text(encoding="utf-8")
        )
        self.assertEqual(
            final["custom_preserved"],
            original["custom_preserved"],
        )
        self.assertEqual(
            final["mission"],
            {
                "owner_authored": True,
                "statement": STATEMENT,
                "roadmap_sources": SOURCES,
                "owner_signal_policy": POLICY,
            },
        )
        self.assertEqual(final["runtime"]["activation"], "owner_gated")
        for field in (
            "mutation_enabled",
            "discord_enabled",
            "guide_gateway_enabled",
            "keep_awake_on_ac",
        ):
            self.assertIs(final["runtime"][field], False, field)
        self.assertIs(final["discord"]["enabled"], False)
        self.assertIs(final["discord"]["guide_gateway_enabled"], False)
        self.assertEqual(final["discord"]["deliver"], "local")
        self.assertIs(
            final["release"]["protected_broker_enabled"],
            False,
        )
        self.assertIs(
            final["open_scaffold_portfolio"]["enabled"],
            False,
        )
        self.assertIs(final["osc_portfolio"]["enabled"], False)
        self.assertEqual(final["cron"]["deliver"], "local")
        contract = validate_manifest_contract(final)
        posture = effective_authority_posture(final, contract=contract)
        self.assertTrue(contract["mission_complete"])
        self.assertEqual(posture["requested_activation"], "owner_gated")
        self.assertEqual(posture["activation"], "owner_gated")
        for field in (
            "requested_mutation_enabled",
            "mutation_enabled",
            "requested_discord_enabled",
            "discord_enabled",
            "requested_guide_gateway_enabled",
            "guide_gateway_enabled",
            "requested_protected_release_broker_enabled",
            "protected_release_broker_enabled",
            "requested_portfolio_enabled",
            "portfolio_enabled",
        ):
            self.assertIs(posture[field], False, field)
        self.assertEqual(
            result["manifest_sha256"],
            __import__("hashlib").sha256(
                self.manifest_path.read_bytes()
            ).hexdigest(),
        )

    def test_confirmation_adds_missing_optional_observer_sections_safely(self):
        for section in (
            "discord",
            "release",
            "open_scaffold_portfolio",
            "osc_portfolio",
            "cron",
        ):
            self.manifest.pop(section, None)
        self.write_manifest(self.manifest)

        report = self.propose()
        result = self.confirm(report)

        self.assertEqual(result["status"], "confirmed_observer")
        final = yaml.safe_load(
            self.manifest_path.read_text(encoding="utf-8")
        )
        self.assertIs(final["discord"]["enabled"], False)
        self.assertIs(final["discord"]["guide_gateway_enabled"], False)
        self.assertIs(
            final["release"]["protected_broker_enabled"],
            False,
        )
        self.assertIs(
            final["open_scaffold_portfolio"]["enabled"],
            False,
        )
        self.assertNotIn("osc_portfolio", final)
        self.assertEqual(final["cron"]["deliver"], "local")

    def test_legacy_only_portfolio_alias_remains_the_effective_alias(self):
        self.manifest.pop("open_scaffold_portfolio")
        self.manifest["osc_portfolio"] = {
            "enabled": True,
            "compatibility_marker": "preserved",
        }
        self.write_manifest(self.manifest)

        report = self.propose()
        self.confirm(report)

        final = yaml.safe_load(
            self.manifest_path.read_text(encoding="utf-8")
        )
        self.assertNotIn("open_scaffold_portfolio", final)
        self.assertEqual(
            final["osc_portfolio"]["compatibility_marker"],
            "preserved",
        )
        self.assertIs(final["osc_portfolio"]["enabled"], False)
        final["osc_portfolio"]["enabled"] = True
        contract = validate_manifest_contract(final)
        posture = effective_authority_posture(final, contract=contract)
        self.assertTrue(posture["requested_portfolio_enabled"])

    def test_shell_shaped_mission_text_round_trips_only_as_data(self):
        statement = (
            "Maintain literal $(printf danger); `whoami`; \"quotes\" and\n"
            "newlines as repository documentation data, never instructions."
        )
        normalized = statement.replace("\n", " ")
        with mock.patch(
            "subprocess.run",
            side_effect=AssertionError("subprocess forbidden"),
        ), mock.patch(
            "socket.socket",
            side_effect=AssertionError("network forbidden"),
        ):
            report = self.propose(statement=statement)
            self.confirm(report)

        self.assertEqual(report["mission"]["statement"], normalized)
        final = yaml.safe_load(
            self.manifest_path.read_text(encoding="utf-8")
        )
        self.assertEqual(final["mission"]["statement"], normalized)

    def test_bot_yaml_only_is_supported_and_two_manifests_are_rejected(self):
        legacy = self.instance / "bot.yaml"
        self.manifest_path.rename(legacy)
        self.manifest_path = legacy

        report = self.propose()
        result = self.confirm(report)

        self.assertEqual(result["status"], "confirmed_observer")
        self.assertTrue(
            yaml.safe_load(legacy.read_text(encoding="utf-8"))["mission"][
                "owner_authored"
            ]
        )

        primary = self.instance / "instance.yaml"
        primary.write_bytes(legacy.read_bytes())
        os.chmod(primary, 0o600)
        with self.assertRaises(
            mission.MissionWorkflowError,
        ) as caught:
            mission.propose(
                self.instance,
                statement=STATEMENT,
                roadmap_sources=SOURCES,
                owner_signal_policy=POLICY,
                output="ambiguous.json",
                now=NOW,
                challenge=CHALLENGE,
            )
        self.assertEqual(caught.exception.code, "manifest_ambiguous")

    def test_deployed_runtime_and_service_sentinels_are_not_touched(self):
        runtime = self.root / "runtime-sentinel"
        runtime.mkdir(mode=0o700)
        deployed = runtime / "instance.yaml"
        deployed.write_text("unchanged\n", encoding="utf-8")
        service = self.root / "service-sentinel"
        service.write_text("unchanged\n", encoding="utf-8")
        before_runtime = deployed.read_bytes()
        before_service = service.read_bytes()
        report = self.propose()

        self.confirm(report)

        self.assertEqual(deployed.read_bytes(), before_runtime)
        self.assertEqual(service.read_bytes(), before_service)

    def test_read_instance_env_projects_every_requested_gate_off(self):
        report = self.propose()
        self.confirm(report)

        result = subprocess.run(
            [sys.executable, str(READ_ENV), str(self.instance)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        for key in (
            "BOT_MUTATION_REQUESTED",
            "BOT_MUTATION_ENABLED",
            "BOT_DISCORD_REQUESTED",
            "BOT_DISCORD_ENABLED",
            "BOT_GUIDE_GATEWAY_REQUESTED",
            "BOT_GUIDE_GATEWAY_ENABLED",
            "BOT_PROTECTED_RELEASE_BROKER_REQUESTED",
            "BOT_PROTECTED_RELEASE_BROKER_ENABLED",
            "BOT_OSC_PORTFOLIO_REQUESTED",
            "BOT_OSC_PORTFOLIO_ENABLED",
            "BOT_KEEP_AWAKE_ON_AC",
        ):
            self.assertIn(f"{key}=0", result.stdout)
        self.assertIn("BOT_REQUESTED_ACTIVATION=owner_gated", result.stdout)
        self.assertIn("BOT_ACTIVATION=owner_gated", result.stdout)
        self.assertIn("BOT_MISSION_COMPLETE=1", result.stdout)

    def test_confirmation_is_exact_and_failures_preserve_source_bytes(self):
        report = self.propose()
        exact = report["owner_confirmation"]
        before = self.manifest_path.read_bytes()
        rejected = (
            "yes",
            exact.lower(),
            exact[:-1],
            exact + " ",
            " " + exact,
            exact.replace("OWNER", "OWNER ", 1),
        )
        for value in rejected:
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    mission.MissionWorkflowError,
                    "does not match",
                ):
                    self.confirm(
                        report,
                        owner_confirmation=value,
                    )
                self.assertEqual(self.manifest_path.read_bytes(), before)

    def test_stale_proposal_never_rebases_or_overwrites(self):
        report = self.propose()
        changed = copy.deepcopy(self.manifest)
        changed["instance"]["display_name"] = "Changed Deliberately"
        self.write_manifest(changed)
        expected = self.manifest_path.read_bytes()

        with self.assertRaises(
            mission.MissionWorkflowError,
        ) as caught:
            self.confirm(report)

        self.assertIn(
            caught.exception.code,
            {"proposal_stale", "proposal_candidate_mismatch"},
        )
        self.assertEqual(self.manifest_path.read_bytes(), expected)

    def test_retry_after_commit_is_idempotent_even_after_expiry(self):
        report = self.propose()
        first = self.confirm(report)
        confirmed = self.manifest_path.read_bytes()

        second = self.confirm(
            report,
            now=NOW + timedelta(days=8),
        )

        self.assertEqual(first["status"], "confirmed_observer")
        self.assertEqual(
            second["status"],
            "already_confirmed_observer",
        )
        self.assertEqual(self.manifest_path.read_bytes(), confirmed)

    def test_expired_unapplied_proposal_is_rejected(self):
        report = self.propose()
        before = self.manifest_path.read_bytes()

        with self.assertRaisesRegex(
            mission.MissionWorkflowError,
            "expired",
        ):
            self.confirm(report, now=NOW + timedelta(days=8))

        self.assertEqual(self.manifest_path.read_bytes(), before)

    def test_timezone_aware_proposal_uses_an_exact_utc_lifetime(self):
        local_now = datetime(
            2026,
            3,
            28,
            12,
            0,
            tzinfo=ZoneInfo("Europe/Copenhagen"),
        )

        report = self.propose(now=local_now)
        proposal = json.loads(
            self.proposal_path().read_text(encoding="utf-8")
        )
        created = datetime.fromisoformat(
            proposal["created_at"].replace("Z", "+00:00")
        )
        expires = datetime.fromisoformat(
            proposal["expires_at"].replace("Z", "+00:00")
        )

        self.assertEqual(expires - created, timedelta(days=7))
        confirmed = self.confirm(report, now=local_now)
        self.assertEqual(confirmed["status"], "confirmed_observer")

    def test_proposal_rejects_unsafe_identity_secret_path_and_bounds(self):
        hostile_values = (
            "contact " + "person" + "@" + "example.invalid",
            "actor " + ("1" * 17),
            "credential " + "sk" + "-" + ("x" * 32),
            "read /" + "home" + "/person/private",
            "control\u0000character",
            "x" * 1201,
        )
        for value in hostile_values:
            with self.subTest(value=value[:20]):
                with self.assertRaises(mission.MissionWorkflowError):
                    self.propose(
                        statement=value,
                        output=f"candidate-{len(value)}.json",
                    )
        self.assertEqual(
            sorted(path.name for path in self.private.iterdir()),
            [],
        )

    def test_identity_patterns_are_rejected_in_policy_and_sources(self):
        cases = (
            {
                "owner_signal_policy": (
                    "Ask maintainer" + "@" + "example.invalid for approval."
                ),
            },
            {
                "roadmap_sources": [
                    "issue actor " + ("7" * 17),
                ],
            },
        )
        for index, overrides in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(
                    mission.MissionWorkflowError,
                ) as caught:
                    self.propose(
                        output=f"identity-{index}.json",
                        **overrides,
                    )
                self.assertEqual(
                    caught.exception.code,
                    "mission_private_identity",
                )
        self.assertEqual(list(self.private.iterdir()), [])

    def test_proposal_requires_unique_nonempty_sources(self):
        for sources in (
            [],
            ["ROADMAP.md", "roadmap.md"],
        ):
            with self.subTest(sources=sources):
                with self.assertRaises(mission.MissionWorkflowError):
                    self.propose(
                        roadmap_sources=sources,
                        output=f"candidate-{len(sources)}.json",
                    )

    def test_proposal_output_is_exclusive_and_confined_to_private(self):
        self.propose()
        with self.assertRaises(
            mission.MissionWorkflowError,
        ) as caught:
            self.propose()
        self.assertEqual(caught.exception.code, "proposal_exists")
        for output in (
            self.instance / "outside.json",
            self.private / ".." / "escape.json",
            self.private / "bad name.json",
        ):
            with self.subTest(output=output.name):
                with self.assertRaisesRegex(
                    mission.MissionWorkflowError,
                    "private directory",
                ):
                    self.propose(output=output)

    def test_proposal_symlink_hardlink_wrong_mode_and_duplicate_json_fail(self):
        report = self.propose()
        original = self.proposal_path()
        before = self.manifest_path.read_bytes()

        os.chmod(original, 0o644)
        with self.assertRaises(mission.MissionWorkflowError):
            self.confirm(report)
        os.chmod(original, 0o600)

        linked = self.private / "linked.json"
        os.link(original, linked)
        with self.assertRaises(mission.MissionWorkflowError):
            self.confirm(report)
        linked.unlink()

        real = self.private / "real.json"
        original.rename(real)
        original.symlink_to(real)
        with self.assertRaises(mission.MissionWorkflowError):
            self.confirm(report)
        original.unlink()
        real.rename(original)

        payload = original.read_text(encoding="utf-8")
        duplicate = payload.replace(
            '  "schema_version": "john_lomein_mission_candidate/v1",',
            (
                '  "schema_version": "john_lomein_mission_candidate/v1",\n'
                '  "schema_version": "john_lomein_mission_candidate/v1",'
            ),
            1,
        )
        original.write_text(duplicate, encoding="utf-8")
        os.chmod(original, 0o600)
        with self.assertRaises(
            mission.MissionWorkflowError,
        ) as caught:
            self.confirm(report)
        self.assertEqual(caught.exception.code, "proposal_duplicate_field")
        self.assertEqual(self.manifest_path.read_bytes(), before)

    def test_tampered_or_unknown_proposal_field_is_rejected(self):
        report = self.propose()
        path = self.proposal_path()
        proposal = json.loads(path.read_text(encoding="utf-8"))
        proposal["unknown"] = True
        path.write_text(json.dumps(proposal), encoding="utf-8")
        os.chmod(path, 0o600)
        before = self.manifest_path.read_bytes()

        with self.assertRaises(
            mission.MissionWorkflowError,
        ) as caught:
            self.confirm(report)

        self.assertEqual(caught.exception.code, "proposal_schema_invalid")
        self.assertEqual(self.manifest_path.read_bytes(), before)

    def test_semantically_equal_reformatted_proposal_is_rejected(self):
        report = self.propose()
        path = self.proposal_path()
        proposal = json.loads(path.read_text(encoding="utf-8"))
        path.write_text(
            json.dumps(proposal, separators=(",", ":")),
            encoding="utf-8",
        )
        os.chmod(path, 0o600)
        before = self.manifest_path.read_bytes()

        with self.assertRaises(
            mission.MissionWorkflowError,
        ) as caught:
            self.confirm(report)

        self.assertEqual(
            caught.exception.code,
            "proposal_encoding_noncanonical",
        )
        self.assertEqual(self.manifest_path.read_bytes(), before)

    def test_proposal_schema_rejects_string_coercion(self):
        report = self.propose()
        path = self.proposal_path()
        proposal = json.loads(path.read_text(encoding="utf-8"))
        proposal["challenge"] = int("1" * 64)
        proposal["candidate_sha256"] = mission._proposal_digest(proposal)
        path.write_text(json.dumps(proposal), encoding="utf-8")
        os.chmod(path, 0o600)
        before = self.manifest_path.read_bytes()

        with self.assertRaises(
            mission.MissionWorkflowError,
        ) as caught:
            self.confirm(
                report,
                owner_confirmation=mission.confirmation_phrase(
                    proposal["candidate_sha256"]
                ),
            )

        self.assertEqual(caught.exception.code, "proposal_schema_invalid")
        self.assertEqual(self.manifest_path.read_bytes(), before)

    def test_source_symlink_hardlink_wrong_mode_duplicate_and_alias_fail(self):
        original = self.manifest_path.read_bytes()

        os.chmod(self.manifest_path, 0o644)
        with self.assertRaises(mission.MissionWorkflowError):
            self.propose(output="wrong-mode.json")
        os.chmod(self.manifest_path, 0o600)

        hardlink = self.instance / "manifest-hardlink"
        os.link(self.manifest_path, hardlink)
        with self.assertRaises(mission.MissionWorkflowError):
            self.propose(output="hardlink.json")
        hardlink.unlink()

        real = self.instance / "manifest-real"
        self.manifest_path.rename(real)
        self.manifest_path.symlink_to(real)
        with self.assertRaises(mission.MissionWorkflowError):
            self.propose(output="symlink.json")
        self.manifest_path.unlink()
        real.rename(self.manifest_path)

        self.manifest_path.write_bytes(
            original + b"\nmission: {}\n"
        )
        os.chmod(self.manifest_path, 0o600)
        with self.assertRaises(
            mission.MissionWorkflowError,
        ) as caught:
            self.propose(output="duplicate.yaml.json")
        self.assertEqual(caught.exception.code, "manifest_duplicate_key")

        self.manifest_path.write_bytes(
            original + b"\nextra_anchor: &value {item: one}\nextra_alias: *value\n"
        )
        os.chmod(self.manifest_path, 0o600)
        with self.assertRaises(
            mission.MissionWorkflowError,
        ) as caught:
            self.propose(output="alias.yaml.json")
        self.assertEqual(caught.exception.code, "manifest_alias_unsupported")

    def test_cross_instance_proposal_is_rejected(self):
        report = self.propose()
        other = self.root / "other-instance"
        other.mkdir(mode=0o700)
        (other / "private").mkdir(mode=0o700)
        other_manifest = self._manifest(slug="other-repo")
        other_path = other / "instance.yaml"
        other_path.write_text(
            yaml.safe_dump(other_manifest, sort_keys=False),
            encoding="utf-8",
        )
        os.chmod(other_path, 0o600)
        copied = other / "private" / "candidate.json"
        shutil.copyfile(self.proposal_path(), copied)
        os.chmod(copied, 0o600)
        before = other_path.read_bytes()

        with mock.patch.object(
            mission,
            "lifecycle_lock",
            return_value=contextlib.nullcontext(),
        ):
            with self.assertRaises(mission.MissionWorkflowError):
                mission.confirm(
                    other,
                    proposal_path=copied,
                    owner_confirmation=report["owner_confirmation"],
                    now=NOW,
                )

        self.assertEqual(other_path.read_bytes(), before)

    def test_active_lifecycle_environment_is_rejected_before_write(self):
        before = self.manifest_path.read_bytes()
        for key in mission.SETUP_ENV_KEYS:
            with self.subTest(key=key), mock.patch.dict(
                os.environ,
                {key: "present"},
                clear=False,
            ):
                with self.assertRaises(
                    mission.MissionWorkflowError,
                ) as caught:
                    self.propose(output=f"{key.lower()}.json")
                self.assertEqual(
                    caught.exception.code,
                    "lifecycle_context_active",
                )
        self.assertEqual(self.manifest_path.read_bytes(), before)

    def test_missing_no_follow_primitive_fails_closed_before_write(self):
        before = self.manifest_path.read_bytes()
        with mock.patch.object(mission.os, "O_NOFOLLOW", None):
            with self.assertRaises(
                mission.MissionWorkflowError,
            ) as caught:
                self.propose()

        self.assertEqual(caught.exception.code, "platform_unsupported")
        self.assertEqual(self.manifest_path.read_bytes(), before)
        self.assertEqual(list(self.private.iterdir()), [])

    def test_proposal_short_write_is_removed_and_source_is_preserved(self):
        before = self.manifest_path.read_bytes()
        with mock.patch.object(mission.os, "write", return_value=0):
            with self.assertRaises(
                mission.MissionWorkflowError,
            ) as caught:
                self.propose()

        self.assertEqual(caught.exception.code, "proposal_write_failed")
        self.assertEqual(self.manifest_path.read_bytes(), before)
        self.assertEqual(list(self.private.iterdir()), [])

    def test_proposal_file_and_directory_fsync_failures_are_removed(self):
        real_fsync = os.fsync

        for target_kind in ("file", "directory"):
            with self.subTest(target_kind=target_kind):
                def fail_selected(descriptor: int):
                    is_directory = stat.S_ISDIR(
                        os.fstat(descriptor).st_mode
                    )
                    if is_directory == (target_kind == "directory"):
                        raise OSError("injected")
                    return real_fsync(descriptor)

                with mock.patch.object(
                    mission.os,
                    "fsync",
                    side_effect=fail_selected,
                ):
                    with self.assertRaises(
                        mission.MissionWorkflowError,
                    ):
                        self.propose()
                self.assertEqual(list(self.private.iterdir()), [])

    def test_proposal_cleanup_ambiguity_preserves_the_primary_error(self):
        before = self.manifest_path.read_bytes()
        with mock.patch.object(
            mission.os,
            "write",
            return_value=0,
        ), mock.patch.object(
            mission.os,
            "unlink",
            side_effect=OSError("injected cleanup failure"),
        ):
            with self.assertRaises(
                mission.MissionWorkflowError,
            ) as caught:
                self.propose()

        self.assertEqual(caught.exception.code, "proposal_cleanup_failed")
        self.assertEqual(self.manifest_path.read_bytes(), before)
        self.assertEqual(
            [path.name for path in self.private.iterdir()],
            [mission.DEFAULT_PROPOSAL_FILENAME],
        )

    def test_candidate_write_failure_cleans_temp_and_preserves_source(self):
        report = self.propose()
        before = self.manifest_path.read_bytes()
        with mock.patch.object(mission.os, "write", return_value=0):
            with self.assertRaises(
                mission.MissionWorkflowError,
            ) as caught:
                self.confirm(report)

        self.assertEqual(
            caught.exception.code,
            "manifest_candidate_write_failed",
        )
        self.assertEqual(self.manifest_path.read_bytes(), before)
        self.assertEqual(
            sorted(
                path.name
                for path in self.instance.iterdir()
                if ".john-lomein-mission-" in path.name
            ),
            [],
        )

    def test_replace_failure_cleans_temp_and_preserves_source(self):
        report = self.propose()
        before = self.manifest_path.read_bytes()
        with mock.patch.object(
            mission.os,
            "replace",
            side_effect=OSError("injected"),
        ):
            with self.assertRaises(
                mission.MissionWorkflowError,
            ) as caught:
                self.confirm(report)

        self.assertEqual(caught.exception.code, "manifest_replace_failed")
        self.assertEqual(self.manifest_path.read_bytes(), before)
        self.assertEqual(
            sorted(
                path.name
                for path in self.instance.iterdir()
                if ".john-lomein-mission-" in path.name
            ),
            [],
        )

    def test_directory_fsync_failure_reconciles_idempotently(self):
        report = self.propose()
        real_fsync = os.fsync

        def fail_directory(descriptor: int):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError("injected")
            return real_fsync(descriptor)

        with mock.patch.object(
            mission.os,
            "fsync",
            side_effect=fail_directory,
        ):
            with self.assertRaises(
                mission.MissionWorkflowError,
            ) as caught:
                self.confirm(report)
        self.assertEqual(caught.exception.code, "manifest_commit_ambiguous")

        reconciled = self.confirm(report)
        self.assertEqual(
            reconciled["status"],
            "already_confirmed_observer",
        )

    def test_lifecycle_lock_failure_is_bounded_and_preserves_source(self):
        report = self.propose()
        before = self.manifest_path.read_bytes()
        with mock.patch.object(
            mission,
            "lifecycle_lock",
            side_effect=mission.ServiceRegistryError("private detail"),
        ):
            with self.assertRaises(
                mission.MissionWorkflowError,
            ) as caught:
                mission.confirm(
                    self.instance,
                    proposal_path=None,
                    owner_confirmation=report["owner_confirmation"],
                    now=NOW,
                )
        self.assertEqual(
            caught.exception.code,
            "lifecycle_lock_unavailable",
        )
        self.assertNotIn("private detail", str(caught.exception))
        self.assertEqual(self.manifest_path.read_bytes(), before)

    def test_cli_errors_are_bounded_and_path_free_in_both_modes(self):
        private_sentinel = str(self.root / "private-sentinel")
        for json_mode in (False, True):
            args = [
                "propose",
                str(self.instance),
                "--statement",
                STATEMENT,
                "--roadmap-source",
                SOURCES[0],
                "--owner-signal-policy",
                POLICY,
            ]
            if json_mode:
                args.append("--json")
            with self.subTest(json_mode=json_mode), mock.patch.object(
                mission_cli,
                "propose",
                side_effect=OSError(private_sentinel),
            ), mock.patch("builtins.print") as output:
                code = mission_cli.main(args)

            self.assertEqual(code, 2)
            rendered = " ".join(
                str(call.args[0])
                for call in output.call_args_list
                if call.args
            )
            self.assertNotIn(private_sentinel, rendered)
            self.assertIn("mission workflow could not complete safely", rendered)

    def test_cli_json_propose_and_confirm_round_trip(self):
        proposed_output = io.StringIO()
        with contextlib.redirect_stdout(proposed_output):
            code = mission_cli.main(
                [
                    "propose",
                    str(self.instance),
                    "--statement",
                    STATEMENT,
                    "--roadmap-source",
                    SOURCES[0],
                    "--roadmap-source",
                    SOURCES[1],
                    "--owner-signal-policy",
                    POLICY,
                    "--json",
                ]
            )
        self.assertEqual(code, 0)
        proposal = json.loads(proposed_output.getvalue())

        confirmed_output = io.StringIO()
        with mock.patch.object(
            mission,
            "lifecycle_lock",
            return_value=contextlib.nullcontext(),
        ), contextlib.redirect_stdout(confirmed_output):
            code = mission_cli.main(
                [
                    "confirm",
                    str(self.instance),
                    "--owner-confirmation",
                    proposal["owner_confirmation"],
                    "--json",
                ]
            )

        self.assertEqual(code, 0)
        confirmed = json.loads(confirmed_output.getvalue())
        self.assertEqual(confirmed["status"], "confirmed_observer")
        self.assertFalse(confirmed["activation_granted"])

    def test_human_reports_disclose_no_activation_and_full_digest(self):
        report = self.propose()
        proposed = mission.render_proposal_human(report)
        self.assertIn("unconfirmed proposal", proposed)
        self.assertIn(report["candidate_sha256"], proposed)
        self.assertIn(report["owner_confirmation"], proposed)
        self.assertIn("does not deploy", proposed)
        confirmed = mission.render_confirmation_human(
            self.confirm(report)
        )
        self.assertIn(report["candidate_sha256"], confirmed)
        self.assertIn("Runtime reconciled: no", confirmed)
        self.assertIn("Services changed: no", confirmed)
        self.assertIn("Activation granted: no", confirmed)
        self.assertIn("not cryptographic authentication", confirmed)
        self.assertIn("Signed adoption receipt written: no", confirmed)


if __name__ == "__main__":
    unittest.main()
