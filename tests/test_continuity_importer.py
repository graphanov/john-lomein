#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import john_lomein_continuity as continuity  # noqa: E402
import john_lomein_continuity_importer as importer  # noqa: E402
import john_lomein_continuity_protocol as protocol  # noqa: E402


NOW = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)
LEDGER_ID = "jlcl-000000000000000000000001"
INSTANCE_ID = "john-production-1"
REPOSITORY = "owner/repo"
KEY_ID = "owner-continuity-2026-01"
POLICY_ID = "owner-private-memory-v1"
WRITE_ID = "jlcw-00000000000000000000000000000001"


def raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


class ContinuityImporterFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="john-continuity-importer-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.runtime = Path(self.temporary.name).resolve() / "runtime"
        (self.runtime / "state").mkdir(parents=True, mode=0o700)
        os.chmod(self.runtime, 0o700)
        os.chmod(self.runtime / "state", 0o700)
        self.store = continuity.continuity_root(self.runtime)
        self.head = continuity.initialize_store(
            self.store,
            ledger_id=LEDGER_ID,
            now=NOW - timedelta(minutes=1),
        )
        self.private = Ed25519PrivateKey.generate()
        self.public = raw_public_key(self.private)
        self.authority = {
            "class": "owner",
            "source_kind": "owner",
            "source_trust": "owner_asserted",
            "source_actor": "owner-gateway",
        }
        self.policy = self.make_policy()
        self.config = self.make_config()
        self.install_material()

    def make_policy(
        self,
        *,
        state: str = "active",
        operations: list[str] | None = None,
        kinds: list[str] | None = None,
    ) -> dict:
        return {
            "schema_version": protocol.KEY_POLICY_SCHEMA,
            "policy_id": POLICY_ID,
            "key_id": KEY_ID,
            "algorithm": protocol.SIGNATURE_ALGORITHM,
            "public_key_sha256": hashlib.sha256(self.public).hexdigest(),
            "state": state,
            "valid_from": "2026-07-18T00:00:00Z",
            "valid_until": "2026-07-21T00:00:00Z",
            "authority": copy.deepcopy(self.authority),
            "permissions": {
                "operations": (
                    ["put", "suppress"] if operations is None else operations
                ),
                "entry_kinds": (
                    ["user_correction", "user_preference"]
                    if kinds is None
                    else kinds
                ),
                "source_commitment_kinds": ["owner_discord"],
                "privacy": ["private", "public"],
                "visible_to_roles": [
                    "maintainer",
                    "forge",
                    "guide",
                    "overwatch",
                    "learning_steward",
                ],
            },
        }

    def make_config(
        self,
        *,
        enabled: bool = True,
        policy: dict | None = None,
    ) -> dict:
        return {
            "schema_version": protocol.CONFIG_SCHEMA,
            "enabled": enabled,
            "instance_id": INSTANCE_ID,
            "repository": REPOSITORY,
            "ledger_id": LEDGER_ID,
            "maximum_ttl_seconds": 300,
            "maximum_clock_skew_seconds": 10,
            "key_policies": [copy.deepcopy(policy or self.policy)],
        }

    def install_material(self, *, config: dict | None = None) -> None:
        paths = importer.runtime_paths(self.runtime)
        selected = protocol.normalize_config(config or self.config)
        paths.config.write_bytes(protocol.canonical_json(selected))
        os.chmod(paths.config, 0o600)
        paths.public_keys.mkdir(mode=0o700, exist_ok=True)
        os.chmod(paths.public_keys, 0o700)
        for old in paths.public_keys.iterdir():
            old.unlink()
        key_path = paths.public_keys / importer.public_key_filename(KEY_ID)
        key_path.write_bytes(self.public)
        os.chmod(key_path, 0o600)

    def put_body(
        self,
        *,
        expected_head: dict | None = None,
        write_id: str = WRITE_ID,
        issued_at: datetime = NOW,
        summary: str = "Keep the protected boundary explicit.",
        kind: str = "user_correction",
    ) -> dict:
        payload = (
            {"correction_kind": "requirement"}
            if kind == "user_correction"
            else {"preference": "avoid"}
        )
        return {
            "schema_version": protocol.EFFECT_SCHEMA,
            "instance_id": INSTANCE_ID,
            "repository": REPOSITORY,
            "ledger_id": LEDGER_ID,
            "expected_head": copy.deepcopy(expected_head or self.head),
            "policy_id": self.policy["policy_id"],
            "policy_sha256": protocol.policy_authorization_sha256(
                self.policy
            ),
            "write_id": write_id,
            "issued_at": continuity.utc_text(issued_at),
            "expires_at": continuity.utc_text(
                issued_at + timedelta(minutes=5)
            ),
            "authority": copy.deepcopy(self.authority),
            "operation": "put",
            "scope": {
                "privacy": "private",
                "visible_to_roles": ["maintainer"],
                "repository": REPOSITORY,
            },
            "put": {
                "kind": kind,
                "subject": "repository-requirement",
                "summary": summary,
                "payload": payload,
                "memory_expires_at": continuity.utc_text(
                    issued_at + timedelta(days=30)
                ),
                "supersedes_entry_id": None,
            },
            "suppression": None,
        }

    def suppression_body(
        self,
        target: dict,
        *,
        expected_head: dict,
        write_id: str = "jlcw-00000000000000000000000000000002",
        issued_at: datetime = NOW + timedelta(minutes=1),
    ) -> dict:
        return {
            "schema_version": protocol.EFFECT_SCHEMA,
            "instance_id": INSTANCE_ID,
            "repository": REPOSITORY,
            "ledger_id": LEDGER_ID,
            "expected_head": copy.deepcopy(expected_head),
            "policy_id": self.policy["policy_id"],
            "policy_sha256": protocol.policy_authorization_sha256(
                self.policy
            ),
            "write_id": write_id,
            "issued_at": continuity.utc_text(issued_at),
            "expires_at": continuity.utc_text(
                issued_at + timedelta(minutes=5)
            ),
            "authority": copy.deepcopy(self.authority),
            "operation": "suppress",
            "scope": copy.deepcopy(target["scope"]),
            "put": None,
            "suppression": {
                "target_entry_id": target["entry_id"],
                "target_entry_sha256": target["entry_sha256"],
                "reason": "privacy_request",
            },
        }

    def seal(
        self,
        body: dict,
        *,
        commitment_digest: str | None = None,
    ) -> bytes:
        commitment = protocol.build_source_commitment(
            effect=body,
            kind="owner_discord",
            commitment_sha256=(
                commitment_digest
                or protocol.salted_source_commitment_sha256(
                    kind="owner_discord",
                    effect_binding_sha256=protocol.effect_binding_sha256(body),
                    source_event_sha256=hashlib.sha256(
                        b"private-event"
                    ).hexdigest(),
                    salt=b"s" * 32,
                )
            ),
        )
        unsigned = protocol.prepare_unsigned_envelope(
            key_id=KEY_ID,
            effect={**copy.deepcopy(body), "source_commitment": commitment},
        )
        signature = self.private.sign(protocol.signing_bytes(unsigned))
        envelope = {
            **unsigned,
            "signature": base64.urlsafe_b64encode(signature)
            .decode("ascii")
            .rstrip("="),
        }
        return protocol.canonical_json(envelope)

    def admit_put(
        self,
        *,
        body: dict | None = None,
        now: datetime = NOW,
    ) -> tuple[dict, dict, bytes]:
        selected = body or self.put_body()
        raw = self.seal(selected)
        result = importer.admit_envelope(self.runtime, raw, now=now)
        entries, head = continuity.verify_store(self.store)
        return result, entries[-1], raw

    def ordinary_request(self) -> dict:
        return {
            "schema_version": continuity.WRITE_SCHEMA,
            "entry_id": None,
            "kind": "decision",
            "subject": "ordinary",
            "summary": "An ordinary automation decision.",
            "payload": {"disposition": "accepted"},
            "source": {
                "kind": "automation",
                "trust": "product_observed",
                "actor": "maintainer",
                "locator": "automation:ordinary",
                "sha256": "a" * 64,
            },
            "scope": {
                "privacy": "private",
                "visible_to_roles": ["maintainer"],
                "repository": REPOSITORY,
            },
            "expires_at": None,
            "supersedes_entry_id": None,
        }


class ContinuityImporterTest(ContinuityImporterFixture):
    def test_missing_config_is_disabled_without_creating_import_state(self) -> None:
        paths = importer.runtime_paths(self.runtime)
        paths.config.unlink()
        for child in paths.public_keys.iterdir():
            child.unlink()
        paths.public_keys.rmdir()

        status = importer.status(self.runtime)

        self.assertFalse(status["configured"])
        self.assertFalse(status["enabled"])
        self.assertFalse(paths.journal.exists())
        self.assertFalse(paths.journal_head.exists())
        with self.assertRaises(importer.ContinuityImporterError) as caught:
            importer.admit_envelope(
                self.runtime,
                self.seal(self.put_body()),
                now=NOW,
            )
        self.assertEqual(caught.exception.code, "configuration_missing")

    def test_projection_inspection_matches_runtime_without_recovery(self) -> None:
        paths = importer.runtime_paths(self.runtime)
        initial = importer.inspect_projection_state(self.runtime)
        self.assertTrue(initial["configured"])
        self.assertTrue(initial["enabled"])
        self.assertFalse(initial["import_state_initialized"])
        self.assertEqual(initial["continuity_sequence"], 0)
        self.assertEqual(initial["effective_entry_count"], 0)

        self.admit_put()
        projected = importer.inspect_projection_state(self.runtime)
        self.assertEqual(projected["continuity_sequence"], 1)
        self.assertEqual(projected["effective_entry_count"], 1)
        self.assertEqual(projected["import_sequence"], 1)

        paths.config.unlink()
        with self.assertRaises(importer.ContinuityImporterError) as caught:
            importer.inspect_projection_state(self.runtime)
        self.assertEqual(caught.exception.code, "configuration_missing")

    def test_unconfigured_projection_inspection_does_not_create_state(self) -> None:
        paths = importer.runtime_paths(self.runtime)
        paths.config.unlink()
        for child in paths.public_keys.iterdir():
            child.unlink()
        paths.public_keys.rmdir()
        before = sorted(path.name for path in self.store.iterdir())

        inspected = importer.inspect_projection_state(self.runtime)

        self.assertFalse(inspected["configured"])
        self.assertFalse(inspected["enabled"])
        self.assertEqual(inspected["effective_entry_count"], 0)
        self.assertEqual(
            sorted(path.name for path in self.store.iterdir()),
            before,
        )

    def test_put_is_deterministic_private_and_exactly_replay_safe(self) -> None:
        result, entry, raw = self.admit_put()
        paths = importer.runtime_paths(self.runtime)

        self.assertEqual(result["disposition"], "committed")
        self.assertEqual(
            entry["entry_id"],
            protocol.entry_id_for_write_id(WRITE_ID),
        )
        self.assertEqual(entry["recorded_at"], continuity.utc_text(NOW))
        self.assertEqual(entry["source"]["kind"], "owner")
        self.assertEqual(
            importer.admit_envelope(self.runtime, raw, now=NOW)[
                "disposition"
            ],
            "replayed",
        )
        entries, _ = continuity.verify_store(self.store)
        self.assertEqual(len(entries), 1)
        self.assertEqual(
            stat_mode(paths.journal),
            0o600,
        )
        self.assertEqual(stat_mode(paths.journal_head), 0o600)
        self.assertEqual(stat_mode(paths.public_keys), 0o700)
        self.assertLessEqual(
            max(len(line) for line in paths.journal.read_bytes().splitlines(True)),
            protocol.MAX_LEDGER_LINE_BYTES,
        )

    def test_maximum_legal_envelope_fits_record_and_transaction_budgets(
        self,
    ) -> None:
        body = self.put_body(summary="m" * continuity.MAX_SUMMARY_BYTES)
        body["put"]["subject"] = "s" * 192
        body["scope"] = {
            "privacy": "public",
            "visible_to_roles": list(continuity.OPERATIONAL_ROLES),
            "repository": REPOSITORY,
        }
        raw = self.seal(body)
        observed: dict[str, int] = {}
        paths = importer.runtime_paths(self.runtime)

        def capture(stage: str) -> None:
            if stage == "intent_fsynced":
                observed["transaction"] = paths.transaction.stat().st_size

        with mock.patch.object(
            importer,
            "_transaction_checkpoint",
            side_effect=capture,
        ):
            importer.admit_envelope(self.runtime, raw, now=NOW)

        self.assertLessEqual(len(raw), protocol.MAX_ENVELOPE_BYTES)
        self.assertLessEqual(
            observed["transaction"],
            continuity.MAX_TRANSACTION_BYTES,
        )
        self.assertLessEqual(
            max(len(line) for line in paths.journal.read_bytes().splitlines(True)),
            protocol.MAX_LEDGER_LINE_BYTES,
        )

    def test_ordinary_append_authority_remains_closed(self) -> None:
        write = protocol.verify_for_new_admission(
            self.seal(self.put_body()),
            config=self.config,
            public_keys={KEY_ID: self.public},
            now=NOW,
        )["continuity_write"]
        with self.assertRaises(continuity.ContinuityError) as caught:
            continuity.append_entry(self.store, write, now=NOW)
        self.assertEqual(caught.exception.code, "authority_required")

    def test_disabled_config_and_stale_head_do_not_mutate_state(self) -> None:
        disabled = self.make_config(enabled=False)
        self.install_material(config=disabled)
        raw = self.seal(self.put_body())
        before = continuity.verify_store(self.store)
        with self.assertRaises(protocol.ContinuityProtocolError) as caught:
            importer.admit_envelope(self.runtime, raw, now=NOW)
        self.assertEqual(caught.exception.code, "importer_disabled")
        self.assertEqual(continuity.verify_store(self.store), before)
        paths = importer.runtime_paths(self.runtime)
        self.assertFalse(paths.journal.exists())
        self.assertFalse(paths.journal_head.exists())

        self.install_material()
        stale = copy.deepcopy(self.head)
        stale["sequence"] = 1
        stale["head_sha256"] = continuity.sha256_json(
            {key: value for key, value in stale.items() if key != "head_sha256"}
        )
        with self.assertRaises(importer.ContinuityImporterError) as caught:
            importer.admit_envelope(
                self.runtime,
                self.seal(self.put_body(expected_head=stale)),
                now=NOW,
            )
        self.assertEqual(caught.exception.code, "expected_head_mismatch")
        self.assertEqual(continuity.verify_store(self.store), before)
        self.assertFalse(paths.journal.exists())
        self.assertFalse(paths.journal_head.exists())

    def test_logical_suppression_creates_tombstone_without_rewriting_ledger(
        self,
    ) -> None:
        _, entry, _ = self.admit_put()
        capsule_before = continuity.build_runtime_capsule(
            self.runtime,
            role="maintainer",
            profile="john-lomein-maintainer",
            platform="cli",
            repository=REPOSITORY,
            persona={
                "version": "john-lomein.persona.v1",
                "sha256": "a" * 64,
            },
            now=NOW,
        )
        self.assertEqual(
            [record["entry_id"] for record in capsule_before["records"]],
            [entry["entry_id"]],
        )
        entries_before, head = continuity.verify_store(self.store)
        ledger_before = (
            self.store / continuity.LEDGER_FILENAME
        ).read_bytes()
        body = self.suppression_body(entry, expected_head=head)
        raw = self.seal(body)

        result = importer.admit_envelope(
            self.runtime,
            raw,
            now=NOW + timedelta(minutes=1),
        )

        self.assertEqual(result["operation"], "suppress")
        self.assertEqual(
            (self.store / continuity.LEDGER_FILENAME).read_bytes(),
            ledger_before,
        )
        entries_after, head_after = continuity.verify_store(self.store)
        self.assertEqual(entries_after, entries_before)
        self.assertEqual(head_after, head)
        verified = importer.verify_runtime(self.runtime)
        self.assertEqual(verified["suppressed_entry_count"], 1)
        self.assertEqual(verified["effective_entry_count"], 0)
        capsule_after = continuity.build_runtime_capsule(
            self.runtime,
            role="maintainer",
            profile="john-lomein-maintainer",
            platform="cli",
            repository=REPOSITORY,
            persona={
                "version": "john-lomein.persona.v1",
                "sha256": "a" * 64,
            },
            now=NOW + timedelta(minutes=1),
        )
        self.assertEqual(capsule_after["records"], [])
        self.assertNotIn(
            entry["summary"],
            continuity.render_capsule_context(capsule_after),
        )
        self.assertEqual(
            importer.admit_envelope(
                self.runtime,
                raw,
                now=NOW + timedelta(minutes=1),
            )["disposition"],
            "replayed",
        )

    def test_suppression_requires_exact_existing_hash_scope_and_single_tombstone(
        self,
    ) -> None:
        _, entry, _ = self.admit_put()
        _, head = continuity.verify_store(self.store)
        wrong = self.suppression_body(entry, expected_head=head)
        wrong["suppression"]["target_entry_sha256"] = "9" * 64
        with self.assertRaises(importer.ContinuityImporterError) as caught:
            importer.admit_envelope(
                self.runtime,
                self.seal(wrong),
                now=NOW + timedelta(minutes=1),
            )
        self.assertEqual(caught.exception.code, "target_mismatch")

        first = self.suppression_body(entry, expected_head=head)
        importer.admit_envelope(
            self.runtime,
            self.seal(first),
            now=NOW + timedelta(minutes=1),
        )
        second = self.suppression_body(
            entry,
            expected_head=head,
            write_id="jlcw-00000000000000000000000000000003",
            issued_at=NOW + timedelta(minutes=2),
        )
        with self.assertRaises(importer.ContinuityImporterError) as caught:
            importer.admit_envelope(
                self.runtime,
                self.seal(second),
                now=NOW + timedelta(minutes=2),
            )
        self.assertEqual(caught.exception.code, "target_suppressed")

    def test_suppressing_a_superseder_does_not_resurrect_its_target(self) -> None:
        first_id = "jlce-000000000000000000000001"
        second_id = "jlce-000000000000000000000002"
        entries = [
            {"entry_id": first_id, "supersedes_entry_id": None},
            {"entry_id": second_id, "supersedes_entry_id": first_id},
        ]
        records = [
            {
                "operation": "suppress",
                "result": {"target_entry_id": second_id},
            }
        ]

        self.assertEqual(importer.effective_entries(entries, records), [])

    def test_same_write_id_with_different_envelope_is_a_conflict(self) -> None:
        self.admit_put()
        _, head = continuity.verify_store(self.store)
        changed = self.put_body(
            expected_head=head,
            summary="A different signed statement.",
        )
        with self.assertRaises(importer.ContinuityImporterError) as caught:
            importer.admit_envelope(
                self.runtime,
                self.seal(changed),
                now=NOW,
            )
        self.assertEqual(caught.exception.code, "replay_conflict")

    def test_competing_same_head_puts_serialize_and_only_one_commits(self) -> None:
        first = self.seal(self.put_body())
        second = self.seal(
            self.put_body(
                write_id="jlcw-00000000000000000000000000000002",
                summary="A competing exact-head write.",
            )
        )

        def attempt(raw: bytes) -> str:
            try:
                return importer.admit_envelope(
                    self.runtime,
                    raw,
                    now=NOW,
                )["disposition"]
            except importer.ContinuityImporterError as exc:
                return exc.code

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(attempt, (first, second)))

        self.assertCountEqual(
            outcomes,
            ["committed", "expected_head_mismatch"],
        )
        self.assertEqual(len(continuity.verify_store(self.store)[0]), 1)
        self.assertEqual(importer.verify_runtime(self.runtime)["import_sequence"], 1)

    def test_interrupted_put_is_exactly_recovered_at_every_boundary(self) -> None:
        stages = (
            "intent_fsynced",
            "continuity_ledger_fsynced",
            "continuity_head_fsynced",
            "import_journal_fsynced",
            "import_head_fsynced",
            "transaction_cleared",
        )
        for stage in stages:
            with self.subTest(stage=stage):
                fixture = self._fresh_fixture()
                raw = fixture.seal(fixture.put_body())

                def crash(observed: str) -> None:
                    if observed == stage:
                        raise RuntimeError("simulated crash")

                with mock.patch.object(
                    importer,
                    "_transaction_checkpoint",
                    side_effect=crash,
                ):
                    with self.assertRaises(RuntimeError):
                        importer.admit_envelope(
                            fixture.runtime,
                            raw,
                            now=NOW,
                        )
                recovery = importer.recover_runtime(fixture.runtime)
                entries, _ = continuity.verify_store(fixture.store)
                if stage == "intent_fsynced":
                    self.assertEqual(
                        recovery["disposition"],
                        "abandoned_unstarted_intent",
                    )
                    self.assertEqual(entries, [])
                    committed = importer.admit_envelope(
                        fixture.runtime,
                        raw,
                        now=NOW,
                    )
                    self.assertEqual(committed["disposition"], "committed")
                else:
                    self.assertEqual(len(entries), 1)
                    replay = importer.admit_envelope(
                        fixture.runtime,
                        raw,
                        now=NOW,
                    )
                    self.assertEqual(replay["disposition"], "replayed")
                self.assertFalse(
                    (
                        fixture.store / continuity.TRANSACTION_FILENAME
                    ).exists()
                )
                fixture.temporary.cleanup()

    def test_recovery_rejects_noncanonical_pending_transaction(self) -> None:
        raw = self.seal(self.put_body())

        def crash(stage: str) -> None:
            if stage == "intent_fsynced":
                raise RuntimeError("simulated crash")

        with mock.patch.object(
            importer,
            "_transaction_checkpoint",
            side_effect=crash,
        ):
            with self.assertRaises(RuntimeError):
                importer.admit_envelope(self.runtime, raw, now=NOW)
        path = importer.runtime_paths(self.runtime).transaction
        canonical = path.read_bytes()
        path.write_bytes(canonical[:-1] + b" \n")
        os.chmod(path, 0o600)

        with self.assertRaises(importer.ContinuityImporterError):
            importer.recover_runtime(self.runtime)
        self.assertTrue(path.exists())
        with self.assertRaises(continuity.ContinuityError):
            continuity.verify_store(self.store)

    def test_first_use_empty_journal_crash_has_one_safe_repair(self) -> None:
        raw = self.seal(self.put_body())

        def crash(stage: str) -> None:
            if stage == "empty_journal_fsynced":
                raise RuntimeError("simulated crash")

        with mock.patch.object(
            importer,
            "_initialization_checkpoint",
            side_effect=crash,
        ):
            with self.assertRaises(RuntimeError):
                importer.admit_envelope(self.runtime, raw, now=NOW)
        paths = importer.runtime_paths(self.runtime)
        self.assertEqual(paths.journal.read_bytes(), b"")
        self.assertFalse(paths.journal_head.exists())
        self.assertFalse(paths.transaction.exists())

        repaired = importer.recover_runtime(self.runtime)

        self.assertEqual(
            repaired["disposition"],
            "repaired_empty_import_state",
        )
        self.assertTrue(paths.journal_head.exists())
        committed = importer.admit_envelope(self.runtime, raw, now=NOW)
        self.assertEqual(committed["disposition"], "committed")

    def test_historical_put_must_immediately_follow_its_signed_head(self) -> None:
        self.admit_put()
        _, first_head = continuity.verify_store(self.store)
        second_write_id = "jlcw-00000000000000000000000000000002"
        second_body = self.put_body(
            expected_head=first_head,
            write_id=second_write_id,
            issued_at=NOW + timedelta(minutes=1),
            summary="The valid second signed write.",
        )
        importer.admit_envelope(
            self.runtime,
            self.seal(second_body),
            now=NOW + timedelta(minutes=1),
        )
        paths = importer.runtime_paths(self.runtime)
        lines = paths.journal.read_bytes().splitlines(keepends=True)
        second_record = json.loads(lines[1])
        opaque_commitment = second_record["envelope"]["effect"][
            "source_commitment"
        ]["commitment_sha256"]
        hostile_body = self.put_body(
            expected_head=self.head,
            write_id=second_write_id,
            issued_at=NOW + timedelta(minutes=1),
            summary="The valid second signed write.",
        )
        hostile_envelope = protocol.parse_envelope(
            self.seal(
                hostile_body,
                commitment_digest=opaque_commitment,
            )
        )
        second_record["envelope"] = hostile_envelope
        second_record["envelope_sha256"] = protocol.envelope_sha256(
            hostile_envelope
        )
        record_base = dict(second_record)
        record_base.pop("record_sha256")
        second_record["record_sha256"] = continuity.sha256_json(record_base)
        hostile_line = continuity.canonical_json(second_record) + b"\n"
        hostile_journal = lines[0] + hostile_line
        paths.journal.write_bytes(hostile_journal)
        os.chmod(paths.journal, 0o600)
        import_head = json.loads(paths.journal_head.read_bytes())
        import_head["head_record_sha256"] = second_record["record_sha256"]
        import_head["journal_size_bytes"] = len(hostile_journal)
        head_base = dict(import_head)
        head_base.pop("head_sha256")
        import_head["head_sha256"] = continuity.sha256_json(head_base)
        paths.journal_head.write_bytes(
            continuity.canonical_json(import_head) + b"\n"
        )
        os.chmod(paths.journal_head, 0o600)

        with self.assertRaises(importer.ContinuityImporterError):
            importer.verify_runtime(self.runtime)

    def test_import_intent_blocks_ordinary_writers_until_recovery(self) -> None:
        raw = self.seal(self.put_body())

        def crash(stage: str) -> None:
            if stage == "intent_fsynced":
                raise RuntimeError("simulated crash")

        with mock.patch.object(
            importer,
            "_transaction_checkpoint",
            side_effect=crash,
        ):
            with self.assertRaises(RuntimeError):
                importer.admit_envelope(self.runtime, raw, now=NOW)
        ordinary = self.ordinary_request()
        with self.assertRaises(continuity.ContinuityError):
            continuity.append_entry(self.store, ordinary, now=NOW)
        importer.recover_runtime(self.runtime)
        appended = continuity.append_entry(self.store, ordinary, now=NOW)
        self.assertEqual(appended["kind"], "decision")

    def test_recovery_reports_ordinary_transaction_neutrally(self) -> None:
        def crash(stage: str) -> None:
            if stage == "head_fsynced":
                raise RuntimeError("simulated crash")

        with mock.patch.object(
            continuity,
            "_transaction_checkpoint",
            side_effect=crash,
        ):
            with self.assertRaises(RuntimeError):
                continuity.append_entry(
                    self.store,
                    self.ordinary_request(),
                    now=NOW,
                )

        recovered = importer.recover_runtime(self.runtime)

        self.assertEqual(
            recovered["disposition"],
            "ordinary_transaction_reconciled",
        )
        self.assertEqual(len(continuity.verify_store(self.store)[0]), 1)

    def test_interrupted_suppression_recovers_only_an_exact_tombstone(
        self,
    ) -> None:
        stages = (
            "intent_fsynced",
            "import_journal_fsynced",
            "import_head_fsynced",
            "transaction_cleared",
        )
        for stage in stages:
            with self.subTest(stage=stage):
                fixture = self._fresh_fixture()
                _, entry, _ = fixture.admit_put()
                entries_before, head = continuity.verify_store(fixture.store)
                raw = fixture.seal(
                    fixture.suppression_body(entry, expected_head=head)
                )

                def crash(observed: str) -> None:
                    if observed == stage:
                        raise RuntimeError("simulated crash")

                with mock.patch.object(
                    importer,
                    "_transaction_checkpoint",
                    side_effect=crash,
                ):
                    with self.assertRaises(RuntimeError):
                        importer.admit_envelope(
                            fixture.runtime,
                            raw,
                            now=NOW + timedelta(minutes=1),
                        )
                importer.recover_runtime(fixture.runtime)
                entries_after, head_after = continuity.verify_store(
                    fixture.store
                )
                self.assertEqual(entries_after, entries_before)
                self.assertEqual(head_after, head)
                verified = importer.verify_runtime(fixture.runtime)
                expected_suppressed = 0 if stage == "intent_fsynced" else 1
                self.assertEqual(
                    verified["suppressed_entry_count"],
                    expected_suppressed,
                )
                fixture.temporary.cleanup()

    def test_retirement_preserves_replay_but_revocation_fails_closed(self) -> None:
        _, _, raw = self.admit_put()
        retired_policy = self.make_policy(state="retired")
        self.install_material(
            config=self.make_config(policy=retired_policy)
        )
        replay = importer.admit_envelope(self.runtime, raw, now=NOW)
        self.assertEqual(replay["disposition"], "replayed")
        importer.verify_runtime(self.runtime)

        revoked_policy = self.make_policy(state="revoked")
        self.install_material(
            config=self.make_config(policy=revoked_policy)
        )
        with self.assertRaises(importer.ContinuityImporterError):
            importer.verify_runtime(self.runtime)

    def test_modes_extra_keys_tamper_and_noncanonical_inputs_fail_closed(
        self,
    ) -> None:
        paths = importer.runtime_paths(self.runtime)
        extra = paths.public_keys / "private.key"
        extra.write_bytes(b"x" * 32)
        os.chmod(extra, 0o600)
        with self.assertRaises(importer.ContinuityImporterError) as caught:
            importer.admit_envelope(
                self.runtime,
                self.seal(self.put_body()),
                now=NOW,
            )
        self.assertEqual(caught.exception.code, "key_material_invalid")
        extra.unlink()

        os.chmod(paths.config, 0o644)
        with self.assertRaises(importer.ContinuityImporterError) as caught:
            importer.status(self.runtime)
        self.assertEqual(caught.exception.code, "state_unsafe")
        os.chmod(paths.config, 0o600)

        raw = self.seal(self.put_body())
        with self.assertRaises(protocol.ContinuityProtocolError) as caught:
            importer.admit_envelope(
                self.runtime,
                json.dumps(json.loads(raw)).encode("utf-8"),
                now=NOW,
            )
        self.assertEqual(caught.exception.code, "noncanonical_json")

        self.admit_put()
        journal = paths.journal.read_bytes()
        paths.journal.write_bytes(
            journal.replace(b'"operation":"put"', b'"operation":"bad"')
        )
        os.chmod(paths.journal, 0o600)
        with self.assertRaises(importer.ContinuityImporterError):
            importer.verify_runtime(self.runtime)

    def test_inspection_and_cli_are_bounded_and_redact_memory_content(
        self,
    ) -> None:
        secret_summary = "PRIVATE-CONTINUITY-CONTENT-MUST-NOT-PRINT"
        self.admit_put(body=self.put_body(summary=secret_summary))
        inspected = importer.inspect_runtime(self.runtime)
        raw = continuity.canonical_json(inspected)
        self.assertNotIn(secret_summary.encode(), raw)
        self.assertTrue(inspected["redacted"])
        self.assertLess(len(raw), importer.MAX_OUTPUT_BYTES)

        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "john_lomein_continuity_importer.py"),
                "--runtime-home",
                str(self.runtime),
                "inspect",
                "--limit",
                "1",
            ],
            check=False,
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertNotIn(secret_summary.encode(), completed.stdout)
        output = json.loads(completed.stdout)
        self.assertEqual(
            output["schema_version"],
            importer.IMPORT_INSPECTION_SCHEMA,
        )

    def test_source_has_no_network_signing_or_private_key_surface(self) -> None:
        source = (
            SCRIPTS / "john_lomein_continuity_importer.py"
        ).read_text(encoding="utf-8")
        forbidden = (
            "Ed25519PrivateKey",
            "private_bytes(",
            "requests.",
            "urllib.",
            "http.client",
            "socket.",
            "subprocess.",
            "os.environ",
        )
        for marker in forbidden:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, source)
        parser_help = importer.build_parser().format_help()
        self.assertNotIn("--config", parser_help)
        self.assertNotIn("--public-key", parser_help)

    def _fresh_fixture(self) -> "ContinuityImporterFixture":
        fixture = ContinuityImporterFixture(methodName="runTest")
        fixture.setUp()
        return fixture


def stat_mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


if __name__ == "__main__":
    unittest.main()
