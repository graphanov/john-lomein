#!/usr/bin/env python3
"""Signed, least-authority owner directives for Forge design input.

This module is a wire contract, not a Discord client. A separately protected
owner gateway must authenticate and fetch the exact Discord event before it may
call ``build_signed_owner_override``. Forge holds only the public key.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Callable, Mapping, Set
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PAYLOAD_SCHEMA = "john-lomein.owner-override.v1"
ENVELOPE_SCHEMA = "john-lomein.owner-override-envelope.v1"
SOURCE_SCHEMA = "john-lomein.discord-owner-override-source.v1"
PROMPT_EVIDENCE_SCHEMA = "john-lomein.owner-override-prompt-evidence.v1"
ALGORITHM = "ed25519"
MAX_DIRECTIVE_CHARS = 4000
MAX_TTL_SECONDS = 900
MAX_CLOCK_SKEW_SECONDS = 60
MAX_SOURCE_AGE_SECONDS = 900
ALLOWED_INTENTS = frozenset(
    {
        "add_constraint",
        "narrow_scope",
        "replace_acceptance_criteria",
        "compatibility_requirement",
    }
)
AUTHORITY = {
    "can_mark_ready": False,
    "can_authorize_coding": False,
    "can_merge": False,
    "can_release": False,
    "can_publish": False,
}

SLUG_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62})\Z")
REPO_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
LOGIN_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\Z")
SNOWFLAKE_RE = re.compile(r"[0-9]{17,20}\Z")
KEY_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
NONCE_RE = re.compile(r"[0-9a-f]{64}\Z")


class OwnerOverrideError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise OwnerOverrideError("owner override is not canonical JSON") from exc


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def _mapping(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise OwnerOverrideError(f"{field} must be a mapping")
    return dict(value)


def _strict_keys(
    value: Mapping[str, Any],
    *,
    field: str,
    required: set[str],
) -> None:
    keys = set(value)
    missing = sorted(required - keys)
    unknown = sorted(keys - required)
    if missing:
        raise OwnerOverrideError(f"{field} missing fields: {', '.join(missing)}")
    if unknown:
        raise OwnerOverrideError(f"{field} has unknown fields: {', '.join(unknown)}")


def _timestamp(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise OwnerOverrideError(f"{field} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise OwnerOverrideError(f"{field} must be an RFC3339 UTC timestamp") from exc
    if parsed.tzinfo is None:
        raise OwnerOverrideError(f"{field} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    current = value.astimezone(timezone.utc).replace(microsecond=0)
    return current.isoformat().replace("+00:00", "Z")


def _public_key(public_key_pem: bytes) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise OwnerOverrideError("owner override public key is invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise OwnerOverrideError("owner override public key is not Ed25519")
    return key


def _private_key(private_key_pem: bytes) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise OwnerOverrideError("owner override private key is invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise OwnerOverrideError("owner override private key is not Ed25519")
    return key


def public_key_sha256(public_key_pem: bytes) -> str:
    key = _public_key(public_key_pem)
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sha256_bytes(raw)


def _normalize_source(value: Any) -> dict[str, str]:
    source = _mapping(value, field="owner override source")
    required = {
        "schema_version",
        "platform",
        "application_id",
        "guild_id",
        "channel_id",
        "message_id",
        "actor_id",
        "actor_login",
        "observed_at",
    }
    _strict_keys(source, field="owner override source", required=required)
    if source.get("schema_version") != SOURCE_SCHEMA:
        raise OwnerOverrideError("owner override source schema is unsupported")
    if source.get("platform") != "discord":
        raise OwnerOverrideError("owner override source platform must be discord")
    normalized: dict[str, str] = {
        "schema_version": SOURCE_SCHEMA,
        "platform": "discord",
    }
    for field in ("application_id", "guild_id", "channel_id", "message_id", "actor_id"):
        text = str(source.get(field) or "")
        if not SNOWFLAKE_RE.fullmatch(text):
            raise OwnerOverrideError(f"owner override source {field} is invalid")
        normalized[field] = text
    login = str(source.get("actor_login") or "")
    if not LOGIN_RE.fullmatch(login):
        raise OwnerOverrideError("owner override source actor_login is invalid")
    normalized["actor_login"] = login
    observed = _timestamp(source.get("observed_at"), field="owner override source observed_at")
    normalized["observed_at"] = _format_timestamp(observed)
    return normalized


def _normalize_payload(value: Any, *, verify_digests: bool) -> dict[str, Any]:
    payload = _mapping(value, field="owner override payload")
    required = {
        "schema_version",
        "instance_slug",
        "repository",
        "issue",
        "intent",
        "directive",
        "directive_sha256",
        "source",
        "source_event_sha256",
        "issued_at",
        "expires_at",
        "nonce",
        "authority",
    }
    _strict_keys(payload, field="owner override payload", required=required)
    if payload.get("schema_version") != PAYLOAD_SCHEMA:
        raise OwnerOverrideError("owner override payload schema is unsupported")

    instance_slug = str(payload.get("instance_slug") or "")
    repository = str(payload.get("repository") or "")
    if not SLUG_RE.fullmatch(instance_slug):
        raise OwnerOverrideError("owner override instance is invalid")
    if not REPO_RE.fullmatch(repository):
        raise OwnerOverrideError("owner override repository is invalid")
    issue = payload.get("issue")
    if type(issue) is not int or issue < 1:
        raise OwnerOverrideError("owner override issue is invalid")
    intent = str(payload.get("intent") or "")
    if intent not in ALLOWED_INTENTS:
        raise OwnerOverrideError("owner override intent is unsupported")
    directive = payload.get("directive")
    if not isinstance(directive, str) or not directive.strip():
        raise OwnerOverrideError("owner override directive is empty")
    directive = directive.strip()
    if len(directive) > MAX_DIRECTIVE_CHARS or "\x00" in directive:
        raise OwnerOverrideError("owner override directive is invalid")

    directive_digest = str(payload.get("directive_sha256") or "")
    source_digest = str(payload.get("source_event_sha256") or "")
    if not DIGEST_RE.fullmatch(directive_digest):
        raise OwnerOverrideError("owner override directive digest is invalid")
    if not DIGEST_RE.fullmatch(source_digest):
        raise OwnerOverrideError("owner override source digest is invalid")
    source = _normalize_source(payload.get("source"))
    issued_at = _timestamp(payload.get("issued_at"), field="owner override issued_at")
    expires_at = _timestamp(payload.get("expires_at"), field="owner override expires_at")
    if expires_at <= issued_at or (expires_at - issued_at).total_seconds() > MAX_TTL_SECONDS:
        raise OwnerOverrideError("owner override validity window is invalid")
    nonce = str(payload.get("nonce") or "")
    if not NONCE_RE.fullmatch(nonce):
        raise OwnerOverrideError("owner override nonce is invalid")
    authority = _mapping(payload.get("authority"), field="owner override authority")
    _strict_keys(authority, field="owner override authority", required=set(AUTHORITY))
    if authority != AUTHORITY:
        raise OwnerOverrideError("owner override cannot grant readiness or execution authority")
    if verify_digests:
        if directive_digest != sha256_text(directive):
            raise OwnerOverrideError("owner override directive digest does not match")
        if source_digest != sha256_json(source):
            raise OwnerOverrideError("owner override source digest does not match")

    return {
        "schema_version": PAYLOAD_SCHEMA,
        "instance_slug": instance_slug,
        "repository": repository,
        "issue": issue,
        "intent": intent,
        "directive": directive,
        "directive_sha256": directive_digest,
        "source": source,
        "source_event_sha256": source_digest,
        "issued_at": _format_timestamp(issued_at),
        "expires_at": _format_timestamp(expires_at),
        "nonce": nonce,
        "authority": dict(AUTHORITY),
    }


def _normalize_signer(value: Any) -> dict[str, str]:
    signer = _mapping(value, field="owner override signer")
    _strict_keys(
        signer,
        field="owner override signer",
        required={"algorithm", "key_id", "public_key_sha256"},
    )
    if signer.get("algorithm") != ALGORITHM:
        raise OwnerOverrideError("owner override signature algorithm is unsupported")
    key_id = str(signer.get("key_id") or "")
    fingerprint = str(signer.get("public_key_sha256") or "")
    if not KEY_ID_RE.fullmatch(key_id):
        raise OwnerOverrideError("owner override key ID is invalid")
    if not DIGEST_RE.fullmatch(fingerprint):
        raise OwnerOverrideError("owner override public-key fingerprint is invalid")
    return {
        "algorithm": ALGORITHM,
        "key_id": key_id,
        "public_key_sha256": fingerprint,
    }


def _signature_bytes(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise OwnerOverrideError("owner override signature is invalid")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise OwnerOverrideError("owner override signature is invalid") from exc
    if len(raw) != 64:
        raise OwnerOverrideError("owner override signature is invalid")
    return raw


def _unsigned(envelope_schema: str, payload: Mapping[str, Any], signer: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": envelope_schema,
        "payload": dict(payload),
        "signer": dict(signer),
    }


def build_signed_owner_override(
    *,
    instance_slug: str,
    repository: str,
    issue: int,
    intent: str,
    directive: str,
    source_event: Any,
    private_key_pem: bytes,
    public_key_pem: bytes,
    key_id: str,
    now: datetime,
    ttl_seconds: int,
    random_bytes: Callable[[int], bytes] = secrets.token_bytes,
) -> dict[str, Any]:
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise OwnerOverrideError("owner override TTL is invalid")
    current = now.astimezone(timezone.utc).replace(microsecond=0)
    source_input = _mapping(source_event, field="owner override source")
    source_input.setdefault("schema_version", SOURCE_SCHEMA)
    source = _normalize_source(source_input)
    observed = _timestamp(source["observed_at"], field="owner override source observed_at")
    if observed > current + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        raise OwnerOverrideError("owner override source observation is in the future")
    if current - observed > timedelta(seconds=MAX_SOURCE_AGE_SECONDS):
        raise OwnerOverrideError("owner override source observation is stale")
    directive_text = str(directive or "").strip()
    source_digest = sha256_json(source)
    directive_digest = sha256_text(directive_text)
    salt = random_bytes(32)
    if not isinstance(salt, bytes) or len(salt) != 32:
        raise OwnerOverrideError("owner override nonce source is invalid")
    nonce = sha256_json(
        {
            "salt": base64.urlsafe_b64encode(salt).decode("ascii").rstrip("="),
            "source_event_sha256": source_digest,
            "directive_sha256": directive_digest,
            "repository": repository,
            "issue": issue,
        }
    ).removeprefix("sha256:")
    payload = _normalize_payload(
        {
            "schema_version": PAYLOAD_SCHEMA,
            "instance_slug": instance_slug,
            "repository": repository,
            "issue": issue,
            "intent": intent,
            "directive": directive_text,
            "directive_sha256": directive_digest,
            "source": source,
            "source_event_sha256": source_digest,
            "issued_at": _format_timestamp(current),
            "expires_at": _format_timestamp(current + timedelta(seconds=ttl_seconds)),
            "nonce": nonce,
            "authority": dict(AUTHORITY),
        },
        verify_digests=True,
    )
    private_key = _private_key(private_key_pem)
    public_key = _public_key(public_key_pem)
    expected_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    actual_raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if expected_raw != actual_raw:
        raise OwnerOverrideError("owner override key pair does not match")
    signer = _normalize_signer(
        {
            "algorithm": ALGORITHM,
            "key_id": key_id,
            "public_key_sha256": public_key_sha256(public_key_pem),
        }
    )
    unsigned = _unsigned(ENVELOPE_SCHEMA, payload, signer)
    signature = private_key.sign(canonical_json(unsigned))
    return {
        **unsigned,
        "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }


def verify_owner_override(
    envelope: Any,
    *,
    public_key_pem: bytes,
    expected_key_id: str,
    expected_instance_slug: str,
    expected_repository: str,
    expected_issue: int,
    expected_owner_logins: Set[str] | None = None,
    expected_owner_actor_ids: Set[str] | None = None,
    now: datetime,
) -> dict[str, Any]:
    raw = _mapping(envelope, field="owner override envelope")
    _strict_keys(
        raw,
        field="owner override envelope",
        required={"schema_version", "payload", "signer", "signature"},
    )
    if raw.get("schema_version") != ENVELOPE_SCHEMA:
        raise OwnerOverrideError("owner override envelope schema is unsupported")
    payload = _normalize_payload(raw.get("payload"), verify_digests=False)
    signer = _normalize_signer(raw.get("signer"))
    signature = _signature_bytes(raw.get("signature"))
    public_key = _public_key(public_key_pem)
    fingerprint = public_key_sha256(public_key_pem)
    if signer["key_id"] != expected_key_id:
        raise OwnerOverrideError("owner override key ID does not match")
    if signer["public_key_sha256"] != fingerprint:
        raise OwnerOverrideError("owner override public-key fingerprint does not match")
    unsigned = _unsigned(ENVELOPE_SCHEMA, payload, signer)
    try:
        public_key.verify(signature, canonical_json(unsigned))
    except InvalidSignature as exc:
        raise OwnerOverrideError("owner override signature is invalid") from exc
    payload = _normalize_payload(payload, verify_digests=True)

    if payload["instance_slug"] != expected_instance_slug:
        raise OwnerOverrideError("owner override instance does not match")
    if payload["repository"].casefold() != expected_repository.casefold():
        raise OwnerOverrideError("owner override repository does not match")
    if payload["issue"] != expected_issue:
        raise OwnerOverrideError("owner override issue does not match")
    if expected_owner_logins is not None:
        allowed = {str(item).casefold() for item in expected_owner_logins}
        if payload["source"]["actor_login"].casefold() not in allowed:
            raise OwnerOverrideError("owner override actor is not configured")
    if expected_owner_actor_ids is not None:
        allowed_actor_ids = {
            str(item).strip() for item in expected_owner_actor_ids if str(item).strip()
        }
        if payload["source"]["actor_id"] not in allowed_actor_ids:
            raise OwnerOverrideError("owner override actor_id is not configured")

    current = now.astimezone(timezone.utc)
    issued = _timestamp(payload["issued_at"], field="owner override issued_at")
    expires = _timestamp(payload["expires_at"], field="owner override expires_at")
    observed = _timestamp(
        payload["source"]["observed_at"],
        field="owner override source observed_at",
    )
    if issued > current + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        raise OwnerOverrideError("owner override was issued in the future")
    if current > expires:
        raise OwnerOverrideError("owner override has expired")
    if observed > issued + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        raise OwnerOverrideError("owner override source observation is after issuance")
    if issued - observed > timedelta(seconds=MAX_SOURCE_AGE_SECONDS):
        raise OwnerOverrideError("owner override source observation is stale")

    return {**payload, "envelope_sha256": sha256_json(raw)}


def _safe_read_bytes(path: Path, *, maximum: int) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise OwnerOverrideError(f"owner override file is unavailable: {path.name}") from exc
    if not stat.S_ISREG(before.st_mode) or path.is_symlink():
        raise OwnerOverrideError(f"owner override file is unsafe: {path.name}")
    if before.st_uid != os.getuid() or before.st_mode & 0o022:
        raise OwnerOverrideError(f"owner override file permissions are unsafe: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OwnerOverrideError(f"owner override file is unavailable: {path.name}") from exc
    try:
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise OwnerOverrideError(f"owner override file changed during read: {path.name}")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(data) > maximum:
        raise OwnerOverrideError(f"owner override file is too large: {path.name}")
    return data


def _safe_inbox(path: Path) -> None:
    try:
        details = path.lstat()
    except OSError as exc:
        raise OwnerOverrideError("owner override inbox is unavailable") from exc
    if not stat.S_ISDIR(details.st_mode) or path.is_symlink():
        raise OwnerOverrideError("owner override inbox is unsafe")
    if details.st_uid != os.getuid() or details.st_mode & 0o022:
        raise OwnerOverrideError("owner override inbox permissions are unsafe")


def _archive_owner_override(inbox_path: Path, entry: Path, bucket: str, envelope_sha256: str) -> None:
    archive = inbox_path.parent / bucket
    archive.mkdir(mode=0o700, exist_ok=True)
    _safe_inbox(archive)
    target = archive / f"{envelope_sha256.removeprefix('sha256:')}.json"
    if target.exists():
        raise OwnerOverrideError("owner override archive collision")
    os.replace(entry, target)
    os.chmod(target, 0o600)


def _consumed_owner_override_index(root: Path) -> tuple[set[str], dict[str, str]]:
    if not root.exists():
        return set(), {}
    _safe_inbox(root)
    entries = sorted(root.iterdir())
    if any(path.is_dir() or path.suffix != ".json" for path in entries):
        raise OwnerOverrideError("owner override consumed archive contains an unsupported entry")
    files = entries
    if len(files) > 1000:
        raise OwnerOverrideError("owner override consumed archive is too large")
    digests: set[str] = set()
    nonces: dict[str, str] = {}
    for path in files:
        envelope = json.loads(_safe_read_bytes(path, maximum=65536).decode("utf-8"))
        digest = sha256_json(envelope)
        if path.name != digest.removeprefix("sha256:") + ".json":
            raise OwnerOverrideError("owner override consumed archive digest mismatch")
        nonce = str((envelope.get("payload") or {}).get("nonce") or "")
        if re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
            raise OwnerOverrideError("owner override consumed archive nonce is invalid")
        if nonce in nonces and nonces[nonce] != digest:
            raise OwnerOverrideError("owner override consumed archive reuses a nonce")
        digests.add(digest)
        nonces[nonce] = digest
    return digests, nonces


def _load_verified_owner_overrides_unlocked(
    *,
    inbox: Path | str,
    public_key_path: Path | str,
    expected_key_id: str,
    expected_public_key_sha256: str,
    expected_instance_slug: str,
    expected_repository: str,
    expected_issue: int,
    expected_owner_logins: Set[str],
    expected_owner_actor_ids: Set[str],
    now: datetime,
    maximum_files: int = 20,
) -> list[dict[str, Any]]:
    """Load exact-issue envelopes and return prompt-safe signed evidence."""

    if type(maximum_files) is not int or not 1 <= maximum_files <= 100:
        raise OwnerOverrideError("owner override inbox file limit is invalid")
    inbox_path = Path(inbox)
    key_path = Path(public_key_path)
    _safe_inbox(inbox_path)
    public_key_pem = _safe_read_bytes(key_path, maximum=16384)
    observed_key_sha256 = hashlib.sha256(public_key_pem).hexdigest()
    if re.fullmatch(r"[0-9a-f]{64}", expected_public_key_sha256) is None or observed_key_sha256 != expected_public_key_sha256:
        raise OwnerOverrideError("owner override public key digest does not match policy")
    pattern = re.compile(rf"issue-{int(expected_issue)}-[A-Za-z0-9._-]{{1,128}}\.json\Z")
    candidates = sorted(
        (entry for entry in inbox_path.iterdir() if pattern.fullmatch(entry.name)),
        key=lambda entry: entry.name,
    )
    if len(candidates) > maximum_files:
        raise OwnerOverrideError("owner override inbox has too many matching files")

    consumed_digests, consumed_nonces = _consumed_owner_override_index(inbox_path.parent / "consumed")
    verified: list[dict[str, Any]] = []
    seen_envelopes: set[str] = set(consumed_digests)
    seen_nonces: dict[str, str] = dict(consumed_nonces)
    for path in candidates:
        try:
            raw = _safe_read_bytes(path, maximum=65536)
            envelope = json.loads(raw.decode("utf-8"))
        except (OwnerOverrideError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OwnerOverrideError(f"owner override inbox file is invalid: {path.name}: {exc}") from exc
        try:
            item = verify_owner_override(envelope, public_key_pem=public_key_pem, expected_key_id=expected_key_id, expected_instance_slug=expected_instance_slug, expected_repository=expected_repository, expected_issue=expected_issue, expected_owner_logins=expected_owner_logins, expected_owner_actor_ids=expected_owner_actor_ids, now=now)
        except OwnerOverrideError as exc:
            if str(exc) == "owner override has expired":
                _archive_owner_override(inbox_path, path, "expired", sha256_json(envelope))
                continue
            raise OwnerOverrideError(f"owner override inbox file is invalid: {path.name}: {exc}") from exc
        envelope_digest = str(item["envelope_sha256"])
        nonce = str(item["nonce"])
        if envelope_digest in seen_envelopes:
            path.unlink()
            continue
        if nonce in seen_nonces and seen_nonces[nonce] != envelope_digest:
            raise OwnerOverrideError("owner override inbox reuses a nonce")
        seen_envelopes.add(envelope_digest)
        seen_nonces[nonce] = envelope_digest
        verified.append(
            {
                "schema_version": PROMPT_EVIDENCE_SCHEMA,
                "intent": item["intent"],
                "directive": item["directive"],
                "directive_sha256": item["directive_sha256"],
                "actor_login": item["source"]["actor_login"],
                "issued_at": item["issued_at"],
                "expires_at": item["expires_at"],
                "envelope_sha256": envelope_digest,
                "authority": dict(AUTHORITY),
            }
        )
        _archive_owner_override(inbox_path, path, "consumed", envelope_digest)
    verified.sort(key=lambda item: (str(item["issued_at"]), str(item["envelope_sha256"])))
    return verified

def load_verified_owner_overrides(
    *,
    inbox: Path | str,
    public_key_path: Path | str,
    expected_key_id: str,
    expected_public_key_sha256: str,
    expected_instance_slug: str,
    expected_repository: str,
    expected_issue: int,
    expected_owner_logins: Set[str],
    expected_owner_actor_ids: Set[str],
    now: datetime,
    maximum_files: int = 20,
) -> list[dict[str, Any]]:
    inbox_path = Path(inbox)
    lock_path = inbox_path.parent / ".owner-override-consumption.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o022:
        os.close(descriptor)
        raise OwnerOverrideError("owner override consumption lock is unsafe")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return _load_verified_owner_overrides_unlocked(
            inbox=inbox_path,
            public_key_path=public_key_path,
            expected_key_id=expected_key_id,
            expected_public_key_sha256=expected_public_key_sha256,
            expected_instance_slug=expected_instance_slug,
            expected_repository=expected_repository,
            expected_issue=expected_issue,
            expected_owner_logins=expected_owner_logins,
            expected_owner_actor_ids=expected_owner_actor_ids,
            now=now,
            maximum_files=maximum_files,
        )
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
