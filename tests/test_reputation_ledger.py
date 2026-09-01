#!/usr/bin/env python3
from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "john-lomein-reputation.py"
spec = importlib.util.spec_from_file_location(
    "john_lomein_reputation", SCRIPT
)
assert spec and spec.loader
reputation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reputation)

NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
OBSERVER_ID = "observer-main"


def payload(
    *,
    sequence: int,
    previous: str,
    event_id: str,
    delivery_id: str,
    outcome: str,
    observed_at: str,
    visibility: str = "public",
    duration_seconds: int | None = None,
    repo: str = "acme/widget",
    source_kind: str = "github_app",
    occurrence_id: str | None = None,
    subject_kind: str = "pull_request",
    subject_id: str = "PR_node_17",
) -> dict:
    subject = {
        "id": subject_id,
        "kind": subject_kind,
        "repo": repo,
        "visibility": visibility,
    }
    if subject_kind in {"pull_request", "review"}:
        subject["number"] = 17
        subject["head_sha"] = "a" * 40
    value = {
        "schema_version": reputation.EVENT_SCHEMA,
        "ledger_id": "public-main",
        "sequence": sequence,
        "previous_event_sha256": previous,
        "event_id": event_id,
        "claim_id": "",
        "observed_at": observed_at,
        "actor": "john-lomein",
        "persona_version": "john-lomein.persona.v1",
        "source": {
            "observer_id": OBSERVER_ID,
            "kind": source_kind,
            "delivery_id": delivery_id,
            "occurrence_id": occurrence_id or f"occurrence-{event_id}",
        },
        "subject": subject,
        "outcome": {"kind": outcome},
    }
    if duration_seconds is not None:
        value["outcome"]["duration_seconds"] = duration_seconds
    value["claim_id"] = reputation.claim_id_for_event(value)
    return value


def observer_policy(
    fingerprint: str,
    *,
    source_kinds: list[str] | None = None,
    outcomes: list[str] | None = None,
    repositories: list[str] | None = None,
    public_repositories: list[str] | None = None,
) -> dict:
    return {
        "schema_version": reputation.OBSERVER_POLICY_SCHEMA,
        "observer_id": OBSERVER_ID,
        "public_key_sha256": fingerprint,
        "allowed_source_kinds": sorted(source_kinds or ["github_app"]),
        "allowed_outcomes": sorted(
            outcomes or reputation.SOURCE_OUTCOMES["github_app"]
        ),
        "allowed_repositories": sorted(
            repositories or ["acme/private-widget", "acme/widget"]
        ),
        "public_repository_allowlist": sorted(
            public_repositories
            if public_repositories is not None
            else ["acme/widget"]
        ),
    }


class ReputationLedgerTest(unittest.TestCase):
    def make_key(self, directory: Path) -> tuple[Path, Path, str]:
        openssl = shutil.which("openssl")
        if not openssl:
            self.skipTest("openssl unavailable")
        private = directory / "private.pem"
        public = directory / "public.pem"
        generated = subprocess.run(
            [
                openssl,
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(private),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(generated.returncode, 0, generated.stderr)
        exported = subprocess.run(
            [
                openssl,
                "pkey",
                "-in",
                str(private),
                "-pubout",
                "-out",
                str(public),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(exported.returncode, 0, exported.stderr)
        os.chmod(public, 0o400)
        fingerprint = hashlib.sha256(public.read_bytes()).hexdigest()
        return private, public, fingerprint

    def sign(self, private: Path, value: dict) -> str:
        openssl = shutil.which("openssl")
        assert openssl
        with tempfile.TemporaryDirectory() as tmp:
            body = Path(tmp) / "body.json"
            signature = Path(tmp) / "body.sig"
            body.write_bytes(reputation.canonical_json(value))
            signed = subprocess.run(
                [
                    openssl,
                    "dgst",
                    "-sha256",
                    "-sign",
                    str(private),
                    "-out",
                    str(signature),
                    str(body),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(signed.returncode, 0, signed.stderr)
            return base64.b64encode(signature.read_bytes()).decode("ascii")

    def write_ledger(
        self,
        path: Path,
        private: Path,
        values: list[dict],
    ) -> None:
        lines = []
        for value in values:
            lines.append(
                json.dumps(
                    {
                        "schema_version": reputation.ENVELOPE_SCHEMA,
                        "payload": value,
                        "signature": self.sign(private, value),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def write_policy(self, path: Path, value: dict) -> None:
        path.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        os.chmod(path, 0o400)

    def load_with_mocked_signatures(
        self,
        root: Path,
        values: list[dict],
        *,
        policy_overrides: dict | None = None,
    ) -> reputation.VerifiedLedger:
        public = root / "public.pem"
        public.write_text(
            "-----BEGIN PUBLIC KEY-----\nAA==\n"
            "-----END PUBLIC KEY-----\n",
            encoding="utf-8",
        )
        os.chmod(public, 0o400)
        fingerprint = hashlib.sha256(public.read_bytes()).hexdigest()
        ledger = root / "ledger.jsonl"
        ledger.write_text(
            "\n".join(
                json.dumps(
                    {
                        "schema_version": reputation.ENVELOPE_SCHEMA,
                        "payload": item,
                        "signature": "eA==",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                for item in values
            )
            + "\n",
            encoding="utf-8",
        )
        policy = observer_policy(fingerprint)
        if policy_overrides:
            policy.update(policy_overrides)
        with mock.patch.object(
            reputation, "verify_signature", return_value=None
        ):
            return reputation.load_signed_ledger(
                ledger,
                public_key=public,
                observer_policy=policy,
                now=NOW,
            )

    def test_signed_chain_builds_public_safe_fresh_outcome_metrics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, public, fingerprint = self.make_key(root)
            first = payload(
                sequence=1,
                previous=reputation.ZERO_HASH,
                event_id="event-1",
                delivery_id="delivery-1",
                outcome="pr_merged",
                observed_at="2026-07-16T09:00:00Z",
            )
            second = payload(
                sequence=2,
                previous=reputation.sha256_json(first),
                event_id="event-2",
                delivery_id="delivery-2",
                outcome="repair_completed",
                observed_at="2026-07-16T10:00:00Z",
                visibility="private",
                repo="acme/private-widget",
                subject_id="PR_private_17",
                duration_seconds=900,
            )
            ledger_path = root / "ledger.jsonl"
            self.write_ledger(ledger_path, private, [first, second])

            ledger = reputation.load_signed_ledger(
                ledger_path,
                public_key=public,
                observer_policy=observer_policy(fingerprint),
                now=NOW,
            )
            report = reputation.build_report(ledger, now=NOW)

            self.assertTrue(reputation.verify_report(report))
            self.assertEqual(report["summary"]["status"], "externally_attested")
            self.assertEqual(report["summary"]["signed_events"], 2)
            self.assertEqual(
                report["summary"]["public_repositories"],
                ["acme/widget"],
            )
            self.assertEqual(report["summary"]["private_repository_count"], 1)
            self.assertEqual(report["metrics"]["shipped_prs"], 1)
            self.assertEqual(report["metrics"]["repairs_completed"], 1)
            self.assertEqual(report["metrics"]["mean_repair_seconds"], 900.0)
            self.assertEqual(report["evidence"]["freshness"], "current")
            self.assertTrue(
                report["evidence"]["current_capability_evidence"]
            )
            serialized = json.dumps(report, sort_keys=True)
            self.assertNotIn("acme/private-widget", serialized)
            self.assertNotIn('"signature":', serialized)

    def test_bad_signature_writable_or_symlinked_key_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, public, fingerprint = self.make_key(root)
            event = payload(
                sequence=1,
                previous=reputation.ZERO_HASH,
                event_id="event-1",
                delivery_id="delivery-1",
                outcome="pr_merged",
                observed_at="2026-07-16T09:00:00Z",
            )
            ledger = root / "ledger.jsonl"
            self.write_ledger(ledger, private, [event])
            content = json.loads(ledger.read_text(encoding="utf-8"))
            content["signature"] = base64.b64encode(b"forged").decode("ascii")
            ledger.write_text(
                json.dumps(content, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                reputation.ReputationError,
                "signature verification failed",
            ):
                reputation.load_signed_ledger(
                    ledger,
                    public_key=public,
                    observer_policy=observer_policy(fingerprint),
                    now=NOW,
                )

            os.chmod(public, 0o600)
            with self.assertRaisesRegex(
                reputation.ReputationError,
                "must not be writable",
            ):
                reputation.load_signed_ledger(
                    ledger,
                    public_key=public,
                    observer_policy=observer_policy(fingerprint),
                    now=NOW,
                )
            os.chmod(public, 0o400)
            target = root / "real-public.pem"
            public.rename(target)
            public.symlink_to(target)
            with self.assertRaisesRegex(
                reputation.ReputationError,
                "public key is unreadable",
            ):
                reputation.load_signed_ledger(
                    ledger,
                    public_key=public,
                    observer_policy=observer_policy(fingerprint),
                    now=NOW,
                )

    def test_chain_delivery_claim_occurrence_and_visibility_are_unique(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = payload(
                sequence=1,
                previous=reputation.ZERO_HASH,
                event_id="event-1",
                delivery_id="delivery-1",
                outcome="pr_merged",
                observed_at="2026-07-16T09:00:00Z",
            )
            bad_chain = payload(
                sequence=2,
                previous="b" * 64,
                event_id="event-2",
                delivery_id="delivery-2",
                outcome="rollback",
                observed_at="2026-07-16T10:00:00Z",
                subject_id="PR_node_18",
            )
            with self.assertRaisesRegex(
                reputation.ReputationError, "hash chain"
            ):
                self.load_with_mocked_signatures(root, [first, bad_chain])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            duplicate_claim = payload(
                sequence=2,
                previous=reputation.sha256_json(first),
                event_id="event-2",
                delivery_id="delivery-2",
                occurrence_id="occurrence-2",
                outcome="pr_merged",
                observed_at="2026-07-16T10:00:00Z",
            )
            self.assertEqual(first["claim_id"], duplicate_claim["claim_id"])
            with self.assertRaisesRegex(
                reputation.ReputationError, "duplicate semantic claim"
            ):
                self.load_with_mocked_signatures(
                    root, [first, duplicate_claim]
                )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            visibility_flip = payload(
                sequence=2,
                previous=reputation.sha256_json(first),
                event_id="event-3",
                delivery_id="delivery-3",
                outcome="repair_completed",
                observed_at="2026-07-16T10:00:00Z",
                visibility="private",
                subject_id="PR_node_18",
                duration_seconds=60,
            )
            with self.assertRaisesRegex(
                reputation.ReputationError, "visibility changed"
            ):
                self.load_with_mocked_signatures(
                    root, [first, visibility_flip]
                )

    def test_observer_policy_and_source_outcome_compatibility_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event = payload(
                sequence=1,
                previous=reputation.ZERO_HASH,
                event_id="event-1",
                delivery_id="delivery-1",
                outcome="pr_merged",
                observed_at="2026-07-16T09:00:00Z",
            )
            with self.assertRaisesRegex(
                reputation.ReputationError, "repository is not authorized"
            ):
                self.load_with_mocked_signatures(
                    root,
                    [event],
                    policy_overrides={
                        "allowed_repositories": ["acme/elsewhere"],
                        "public_repository_allowlist": [],
                    },
                )

        incompatible = payload(
            sequence=1,
            previous=reputation.ZERO_HASH,
            event_id="event-2",
            delivery_id="delivery-2",
            outcome="pr_merged",
            observed_at="2026-07-16T09:00:00Z",
            source_kind="independent_evaluator",
        )
        with self.assertRaisesRegex(
            reputation.ReputationError, "incompatible with source kind"
        ):
            reputation._normalize_payload(incompatible, index=1)

    def test_future_events_fail_and_old_history_is_marked_historical(self):
        future = payload(
            sequence=1,
            previous=reputation.ZERO_HASH,
            event_id="future",
            delivery_id="future",
            outcome="pr_merged",
            observed_at=reputation.datetime.strftime(
                NOW + timedelta(seconds=reputation.MAX_CLOCK_SKEW_SECONDS + 1),
                "%Y-%m-%dT%H:%M:%SZ",
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(
                reputation.ReputationError, "timestamp is in the future"
            ):
                self.load_with_mocked_signatures(Path(tmp), [future])

        old = payload(
            sequence=1,
            previous=reputation.ZERO_HASH,
            event_id="old",
            delivery_id="old",
            outcome="pr_merged",
            observed_at="2020-01-01T00:00:00Z",
        )
        with tempfile.TemporaryDirectory() as tmp:
            ledger = self.load_with_mocked_signatures(Path(tmp), [old])
            report = reputation.build_report(ledger, now=NOW)
        self.assertEqual(report["evidence"]["freshness"], "historical")
        self.assertFalse(report["evidence"]["current_capability_evidence"])
        self.assertIn("not", report["interpretation"].lower())
        self.assertTrue(reputation.verify_report(report))

    def test_report_authenticity_requires_ledger_reproduction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, public, fingerprint = self.make_key(root)
            event = payload(
                sequence=1,
                previous=reputation.ZERO_HASH,
                event_id="event-1",
                delivery_id="delivery-1",
                outcome="pr_merged",
                observed_at="2026-07-16T09:00:00Z",
            )
            ledger_path = root / "ledger.jsonl"
            self.write_ledger(ledger_path, private, [event])
            policy = observer_policy(fingerprint)
            policy_path = root / "policy.json"
            self.write_policy(policy_path, policy)
            ledger = reputation.load_signed_ledger(
                ledger_path,
                public_key=public,
                observer_policy=policy,
                now=NOW,
            )
            report = reputation.build_report(ledger, now=NOW)
            report_path = root / "report.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = reputation.main(
                    [
                        "verify",
                        "--report",
                        str(report_path),
                        "--ledger",
                        str(ledger_path),
                        "--public-key",
                        str(public),
                        "--observer-policy",
                        str(policy_path),
                    ]
                )
            self.assertEqual(result, 0)
            self.assertTrue(json.loads(output.getvalue())["valid"])

            forged = json.loads(json.dumps(report))
            forged["metrics"]["shipped_prs"] = 9_999
            forged["report_digest"] = reputation.sha256_json(
                {
                    key: value
                    for key, value in forged.items()
                    if key != "report_digest"
                }
            )
            report_path.write_text(json.dumps(forged), encoding="utf-8")
            self.assertTrue(reputation.verify_report(forged))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = reputation.main(
                    [
                        "verify",
                        "--report",
                        str(report_path),
                        "--ledger",
                        str(ledger_path),
                        "--public-key",
                        str(public),
                        "--observer-policy",
                        str(policy_path),
                    ]
                )
            self.assertEqual(result, 1)
            verification = json.loads(output.getvalue())
            self.assertTrue(verification["digest_valid"])
            self.assertFalse(verification["source_reproducible"])
            self.assertFalse(verification["valid"])

            arbitrary = {
                "schema_version": "attacker.fake.v1",
                "metrics": {"shipped_prs": 999_999},
            }
            arbitrary["report_digest"] = reputation.sha256_json(arbitrary)
            self.assertFalse(reputation.verify_report(arbitrary))

    def test_key_and_ledger_bytes_are_stable_after_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = payload(
                sequence=1,
                previous=reputation.ZERO_HASH,
                event_id="event-1",
                delivery_id="delivery-1",
                outcome="pr_merged",
                observed_at="2026-07-16T09:00:00Z",
            )
            second = payload(
                sequence=2,
                previous=reputation.sha256_json(first),
                event_id="event-2",
                delivery_id="delivery-2",
                outcome="rollback",
                observed_at="2026-07-16T10:00:00Z",
                subject_id="PR_node_18",
            )
            public = root / "public.pem"
            original_key = (
                b"-----BEGIN PUBLIC KEY-----\nAA==\n"
                b"-----END PUBLIC KEY-----\n"
            )
            public.write_bytes(original_key)
            os.chmod(public, 0o400)
            fingerprint = hashlib.sha256(original_key).hexdigest()
            ledger_path = root / "ledger.jsonl"
            ledger_path.write_text(
                "\n".join(
                    json.dumps(
                        {
                            "schema_version": reputation.ENVELOPE_SCHEMA,
                            "payload": item,
                            "signature": "eA==",
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    for item in (first, second)
                )
                + "\n",
                encoding="utf-8",
            )
            seen_keys: list[bytes] = []

            def replace_sources(key_bytes, _payload, _signature):
                seen_keys.append(key_bytes)
                public.unlink(missing_ok=True)
                public.write_bytes(b"attacker replacement")
                ledger_path.write_text("", encoding="utf-8")

            with mock.patch.object(
                reputation,
                "verify_signature",
                side_effect=replace_sources,
            ):
                ledger = reputation.load_signed_ledger(
                    ledger_path,
                    public_key=public,
                    observer_policy=observer_policy(fingerprint),
                    now=NOW,
                )
            self.assertEqual(len(ledger), 2)
            self.assertEqual(seen_keys, [original_key, original_key])


if __name__ == "__main__":
    unittest.main()
