from __future__ import annotations

import importlib.util
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "john_lomein_owner_override.py"


def load_contract():
    spec = importlib.util.spec_from_file_location("john_lomein_owner_override", SCRIPT)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def key_pair() -> tuple[bytes, bytes]:
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def source_event() -> dict[str, str]:
    return {
        "platform": "discord",
        "application_id": "1" * 17,
        "guild_id": "2" * 17,
        "channel_id": "3" * 17,
        "message_id": "4" * 17,
        "actor_id": "5" * 17,
        "actor_login": "RepoOwner",
        "observed_at": "2026-09-01T00:00:00Z",
    }


def build_envelope(contract, private_pem: bytes, public_pem: bytes) -> dict:
    now = datetime(2026, 9, 1, tzinfo=timezone.utc)
    return contract.build_signed_owner_override(
        instance_slug="sample-project",
        repository="repoowner/sample-project",
        issue=125,
        intent="compatibility_requirement",
        directive="Make this feature retroactively compatible with release 125y71.",
        source_event=source_event(),
        private_key_pem=private_pem,
        public_key_pem=public_pem,
        key_id="owner-override-2026-01",
        now=now,
        ttl_seconds=600,
        random_bytes=lambda size: b"o" * size,
    )


def test_signed_owner_override_round_trip_is_exact_and_non_authorizing():
    contract = load_contract()
    private_pem, public_pem = key_pair()
    envelope = build_envelope(contract, private_pem, public_pem)

    verified = contract.verify_owner_override(
        envelope,
        public_key_pem=public_pem,
        expected_key_id="owner-override-2026-01",
        expected_instance_slug="sample-project",
        expected_repository="repoowner/sample-project",
        expected_issue=125,
        now=datetime(2026, 9, 1, 0, 5, tzinfo=timezone.utc),
    )

    assert verified["directive"] == "Make this feature retroactively compatible with release 125y71."
    assert verified["directive_sha256"] == contract.sha256_text(verified["directive"])
    assert verified["source_event_sha256"] == contract.sha256_json(verified["source"])
    assert verified["authority"] == {
        "can_mark_ready": False,
        "can_authorize_coding": False,
        "can_merge": False,
        "can_release": False,
        "can_publish": False,
    }
    assert verified["envelope_sha256"] == contract.sha256_json(envelope)


def test_tampering_expiry_scope_and_unknown_fields_fail_closed():
    contract = load_contract()
    private_pem, public_pem = key_pair()
    envelope = build_envelope(contract, private_pem, public_pem)

    tampered = json.loads(json.dumps(envelope))
    tampered["payload"]["directive"] = "Publish now."
    with pytest.raises(contract.OwnerOverrideError, match="signature"):
        contract.verify_owner_override(
            tampered,
            public_key_pem=public_pem,
            expected_key_id="owner-override-2026-01",
            expected_instance_slug="sample-project",
            expected_repository="repoowner/sample-project",
            expected_issue=125,
            now=datetime(2026, 9, 1, 0, 5, tzinfo=timezone.utc),
        )

    with pytest.raises(contract.OwnerOverrideError, match="expired"):
        contract.verify_owner_override(
            envelope,
            public_key_pem=public_pem,
            expected_key_id="owner-override-2026-01",
            expected_instance_slug="sample-project",
            expected_repository="repoowner/sample-project",
            expected_issue=125,
            now=datetime(2026, 9, 1, 0, 11, tzinfo=timezone.utc),
        )

    for field, value, expected in (
        ("expected_repository", "other/repo", "repository"),
        ("expected_issue", 126, "issue"),
        ("expected_instance_slug", "other", "instance"),
    ):
        kwargs = {
            "expected_repository": "repoowner/sample-project",
            "expected_issue": 125,
            "expected_instance_slug": "sample-project",
        }
        kwargs[field] = value
        with pytest.raises(contract.OwnerOverrideError, match=expected):
            contract.verify_owner_override(
                envelope,
                public_key_pem=public_pem,
                expected_key_id="owner-override-2026-01",
                now=datetime(2026, 9, 1, 0, 5, tzinfo=timezone.utc),
                **kwargs,
            )

    unknown = json.loads(json.dumps(envelope))
    unknown["payload"]["can_merge"] = True
    with pytest.raises(contract.OwnerOverrideError, match="unknown"):
        contract.verify_owner_override(
            unknown,
            public_key_pem=public_pem,
            expected_key_id="owner-override-2026-01",
            expected_instance_slug="sample-project",
            expected_repository="repoowner/sample-project",
            expected_issue=125,
            now=datetime(2026, 9, 1, 0, 5, tzinfo=timezone.utc),
        )


def test_only_narrow_acceptance_intents_are_supported():
    contract = load_contract()
    private_pem, public_pem = key_pair()
    with pytest.raises(contract.OwnerOverrideError, match="intent"):
        contract.build_signed_owner_override(
            instance_slug="sample-project",
            repository="repoowner/sample-project",
            issue=125,
            intent="merge",
            directive="Merge it.",
            source_event=source_event(),
            private_key_pem=private_pem,
            public_key_pem=public_pem,
            key_id="owner-override-2026-01",
            now=datetime(2026, 9, 1, tzinfo=timezone.utc),
            ttl_seconds=600,
        )


def test_source_event_requires_discord_identity_and_current_observation():
    contract = load_contract()
    private_pem, public_pem = key_pair()
    bad = source_event()
    bad["actor_id"] = "RepoOwner"
    with pytest.raises(contract.OwnerOverrideError, match="actor_id"):
        contract.build_signed_owner_override(
            instance_slug="sample-project",
            repository="repoowner/sample-project",
            issue=125,
            intent="add_constraint",
            directive="Preserve backwards compatibility.",
            source_event=bad,
            private_key_pem=private_pem,
            public_key_pem=public_pem,
            key_id="owner-override-2026-01",
            now=datetime(2026, 9, 1, tzinfo=timezone.utc),
            ttl_seconds=600,
        )


def test_inbox_loader_returns_only_sanitized_exact_issue_evidence(tmp_path):
    contract = load_contract()
    private_pem, public_pem = key_pair()
    envelope = build_envelope(contract, private_pem, public_pem)
    inbox = tmp_path / "owner-overrides"
    inbox.mkdir(mode=0o700)
    public_key = tmp_path / "owner-override.public.pem"
    public_key.write_bytes(public_pem)
    public_key.chmod(0o600)
    path = inbox / f"issue-125-{'4' * 17}.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    path.chmod(0o600)

    evidence = contract.load_verified_owner_overrides(
        inbox=inbox,
        public_key_path=public_key,
        expected_public_key_sha256=hashlib.sha256(public_pem).hexdigest(),
        expected_key_id="owner-override-2026-01",
        expected_instance_slug="sample-project",
        expected_repository="repoowner/sample-project",
        expected_issue=125,
        expected_owner_logins={"repoowner"},
        expected_owner_actor_ids={"5" * 17},
        now=datetime(2026, 9, 1, 0, 5, tzinfo=timezone.utc),
    )

    assert len(evidence) == 1
    assert evidence[0]["schema_version"] == contract.PROMPT_EVIDENCE_SCHEMA
    assert evidence[0]["actor_login"] == "RepoOwner"
    assert evidence[0]["directive"].startswith("Make this feature")
    serialized = json.dumps(evidence)
    assert "5" * 17 not in serialized
    assert "4" * 17 not in serialized
    assert "channel_id" not in serialized
    assert not path.exists()
    assert len(list((inbox.parent / "consumed").glob("*.json"))) == 1
    replay = inbox / f"issue-125-replay-{'4' * 17}.json"
    replay.write_text(json.dumps(envelope), encoding="utf-8")
    replay.chmod(0o600)
    second = contract.load_verified_owner_overrides(
        inbox=inbox, public_key_path=public_key,
        expected_public_key_sha256=hashlib.sha256(public_pem).hexdigest(), expected_key_id="owner-override-2026-01",
        expected_instance_slug="sample-project", expected_repository="repoowner/sample-project", expected_issue=125,
        expected_owner_logins={"repoowner"}, expected_owner_actor_ids={"5" * 17}, now=datetime(2026, 9, 1, 0, 5, tzinfo=timezone.utc),
    )
    assert second == []
    replacement = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key.write_bytes(replacement)
    with pytest.raises(contract.OwnerOverrideError, match="digest"):
        contract.load_verified_owner_overrides(
            inbox=inbox, public_key_path=public_key,
            expected_public_key_sha256=hashlib.sha256(public_pem).hexdigest(),
            expected_key_id="owner-override-2026-01",
            expected_instance_slug="sample-project", expected_repository="repoowner/sample-project",
            expected_issue=125, expected_owner_logins={"repoowner"}, expected_owner_actor_ids={"5" * 17},
            now=datetime(2026, 9, 1, 0, 5, tzinfo=timezone.utc),
        )


def test_inbox_loader_fails_closed_on_invalid_matching_file_or_actor(tmp_path):
    contract = load_contract()
    private_pem, public_pem = key_pair()
    envelope = build_envelope(contract, private_pem, public_pem)
    inbox = tmp_path / "owner-overrides"
    inbox.mkdir(mode=0o700)
    public_key = tmp_path / "owner-override.public.pem"
    public_key.write_bytes(public_pem)
    public_key.chmod(0o600)
    path = inbox / "issue-125-invalid.json"
    path.write_text("{}", encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(contract.OwnerOverrideError, match="inbox"):
        contract.load_verified_owner_overrides(
            inbox=inbox,
            public_key_path=public_key,
            expected_public_key_sha256=hashlib.sha256(public_pem).hexdigest(),
            expected_key_id="owner-override-2026-01",
            expected_instance_slug="sample-project",
            expected_repository="repoowner/sample-project",
            expected_issue=125,
            expected_owner_logins={"repoowner"},
            expected_owner_actor_ids={"5" * 17},
            now=datetime(2026, 9, 1, 0, 5, tzinfo=timezone.utc),
        )

    path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(contract.OwnerOverrideError, match="actor"):
        contract.load_verified_owner_overrides(
            inbox=inbox,
            public_key_path=public_key,
            expected_public_key_sha256=hashlib.sha256(public_pem).hexdigest(),
            expected_key_id="owner-override-2026-01",
            expected_instance_slug="sample-project",
            expected_repository="repoowner/sample-project",
            expected_issue=125,
            expected_owner_logins={"someone-else"},
            expected_owner_actor_ids={"5" * 17},
            now=datetime(2026, 9, 1, 0, 5, tzinfo=timezone.utc),
        )


def test_owner_override_assets_are_deployed_and_default_inactive():
    deploy = (ROOT / "scripts" / "deploy-instance.sh").read_text(encoding="utf-8")
    doctor = (ROOT / "scripts" / "doctor-instance.py").read_text(encoding="utf-8")
    template = (ROOT / "templates" / "instance.yaml.example").read_text(
        encoding="utf-8"
    )
    assert "john_lomein_owner_override.py" in deploy
    assert "BOT_OWNER_OVERRIDE_ENABLED" in deploy
    assert "private/owner-overrides" in deploy
    assert "state/owner-overrides" not in deploy
    assert "john_lomein_owner_override.py" in doctor
    assert "john-lomein.owner-override-policy.v1" in template
    assert "enabled: false" in template
    assert "authority: acceptance_constraints_only" in template
