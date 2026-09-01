#!/usr/bin/env python3
"""Mint narrowly scoped release-owner assertions from authenticated Discord events.

The signer is deliberately separate from both the Hermes/model runtime and the
credential-bearing release broker:

* the runtime may prepare a release bundle, but cannot read the signing key;
* the owner gateway authenticates the Discord actor and channel before signing;
* the broker independently validates the resulting assertion and live GitHub
  state before it can merge anything.

The current owner-assertion v2 wire shape does not expose Discord metadata.
Instead, its 256-bit nonce is a salted cryptographic commitment to the complete
normalized source event, bundle digest, and approval-text digest.  The signer
persists that salt and source event in an idempotent, mode-0600 audit record, so
the signed nonce can later be proven to originate from the exact event without
expanding the broker protocol or leaking gateway metadata into runtime files.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from release_broker import john_lomein_release_broker_protocol as protocol


CONFIG_SCHEMA = "john-lomein.release-owner-signer-config.v1"
EVENT_SCHEMA = "john-lomein.discord-owner-release-approval-event.v1"
COMMITMENT_SCHEMA = "john-lomein.release-owner-source-commitment.v1"
RECORD_SCHEMA = "john-lomein.release-owner-signing-record.v1"
SELF_CHECK_SCHEMA = "john-lomein.release-owner-gateway-self-check.v1"
PLATFORM = "discord"

MAX_CONFIG_BYTES = 256 * 1024
MAX_EVENT_BYTES = 64 * 1024
MAX_BUNDLE_BYTES = 2 * 1024 * 1024
MAX_KEY_BYTES = 64 * 1024
MAX_APPROVAL_BYTES = protocol.MAX_APPROVAL_TEXT_BYTES
MAX_RECORD_BYTES = 4 * 1024 * 1024
MIN_ASSERTION_TTL_SECONDS = 60
MAX_ASSERTION_TTL_SECONDS = 15 * 60
MIN_EVENT_AGE_SECONDS = 1
MAX_EVENT_AGE_SECONDS = 15 * 60
MAX_OBSERVATION_DELAY_SECONDS = 120
MAX_CLOCK_SKEW_SECONDS = 30
MIN_BUNDLE_REMAINING_SECONDS = 60
DISCORD_EPOCH_MS = 1_420_070_400_000

SNOWFLAKE_RE = re.compile(r"^[0-9]{17,20}$")
SIGNER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,127}$")
EVENT_ID_RE = re.compile(r"^jlroe-[0-9a-f]{24}$")
RECORD_ID_RE = re.compile(r"^jlros-[0-9a-f]{24}$")
SALT_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


class ReleaseOwnerSignerError(ValueError):
    """A fail-closed signer configuration, event, key, or persistence error."""


def _mapping(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseOwnerSignerError(f"{field} must be an object")
    return value


def _strict_keys(
    value: dict[str, Any],
    *,
    field: str,
    required: set[str],
) -> None:
    if set(value) != required:
        raise ReleaseOwnerSignerError(
            f"{field} fields do not match the required schema"
        )


def _positive_int(value: Any, *, field: str, maximum: int = 2**31 - 1) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
        or value > maximum
    ):
        raise ReleaseOwnerSignerError(f"{field} is invalid")
    return value


def _uid(value: Any, *, field: str) -> int:
    return _positive_int(value, field=field)


def _gid(value: Any, *, field: str) -> int:
    return _positive_int(value, field=field)


def _bounded_int(
    value: Any,
    *,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise ReleaseOwnerSignerError(f"{field} is outside the allowed range")
    return value


def _absolute_path(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ReleaseOwnerSignerError(f"{field} must be an absolute path")
    path = Path(value)
    if (
        not path.is_absolute()
        or ".." in path.parts
        or "." in path.parts
        or value != str(path)
    ):
        raise ReleaseOwnerSignerError(f"{field} must be normalized")
    return value


def _utc(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise ReleaseOwnerSignerError(f"{field} must be a UTC timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ReleaseOwnerSignerError(
            f"{field} must be a canonical UTC timestamp"
        ) from exc


def _now(value: datetime | None) -> datetime:
    current = datetime.now(timezone.utc) if value is None else value
    if not isinstance(current, datetime) or current.tzinfo is None:
        raise ReleaseOwnerSignerError("clock value must be timezone-aware")
    return current.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _snowflake(value: Any, *, field: str) -> str:
    text = str(value or "")
    if not SNOWFLAKE_RE.fullmatch(text):
        raise ReleaseOwnerSignerError(f"{field} must be a Discord snowflake")
    return text


def _snowflake_timestamp(value: str) -> datetime:
    raw = int(value)
    milliseconds = (raw >> 22) + DISCORD_EPOCH_MS
    return datetime.fromtimestamp(milliseconds / 1000, tz=timezone.utc)


def _safe_text(value: Any, *, field: str, maximum_bytes: int) -> str:
    if not isinstance(value, str) or not value:
        raise ReleaseOwnerSignerError(f"{field} is invalid")
    try:
        raw = value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ReleaseOwnerSignerError(f"{field} is invalid Unicode") from exc
    if len(raw) > maximum_bytes or "\x00" in value:
        raise ReleaseOwnerSignerError(f"{field} exceeds its safety limits")
    if any(ord(character) < 0x20 for character in value):
        raise ReleaseOwnerSignerError(f"{field} contains control characters")
    return value


def _digest(value: Any, *, field: str) -> str:
    text = str(value or "")
    if not protocol.SHA256_RE.fullmatch(text):
        raise ReleaseOwnerSignerError(f"{field} must be a SHA-256 digest")
    return text


def _fingerprint(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _owner_actor_map(config: dict[str, Any]) -> dict[str, str]:
    return {
        actor["user_id"]: actor["actor_login"]
        for actor in config["discord"]["owner_actors"]
    }


def normalize_signer_config(raw: Any) -> dict[str, Any]:
    config = _mapping(raw, field="release owner signer config")
    _strict_keys(
        config,
        field="release owner signer config",
        required={
            "schema_version",
            "enabled",
            "signer_id",
            "signer_uid",
            "signer_gid",
            "runtime_uid",
            "issuer",
            "key_id",
            "private_key_path",
            "public_key_path",
            "public_key_sha256",
            "state_directory",
            "assertion_ttl_seconds",
            "maximum_event_age_seconds",
            "maximum_observation_delay_seconds",
            "maximum_clock_skew_seconds",
            "instance",
            "discord",
        },
    )
    if config.get("schema_version") != CONFIG_SCHEMA:
        raise ReleaseOwnerSignerError("release owner signer schema is unsupported")
    if type(config.get("enabled")) is not bool:
        raise ReleaseOwnerSignerError("release owner signer enabled must be boolean")
    signer_id = str(config.get("signer_id") or "")
    issuer = str(config.get("issuer") or "")
    key_id = str(config.get("key_id") or "")
    if not SIGNER_ID_RE.fullmatch(signer_id):
        raise ReleaseOwnerSignerError("release owner signer ID is invalid")
    if not protocol.TOKEN_RE.fullmatch(issuer):
        raise ReleaseOwnerSignerError("release owner signer issuer is invalid")
    if not protocol.KEY_ID_RE.fullmatch(key_id):
        raise ReleaseOwnerSignerError("release owner signer key ID is invalid")
    signer_uid = _uid(config.get("signer_uid"), field="release signer UID")
    signer_gid = _gid(config.get("signer_gid"), field="release signer GID")
    runtime_uid = _uid(config.get("runtime_uid"), field="Hermes runtime UID")
    if signer_uid == runtime_uid:
        raise ReleaseOwnerSignerError(
            "release signer and Hermes runtime must use distinct UIDs"
        )
    private_path = _absolute_path(
        config.get("private_key_path"), field="release signer private-key path"
    )
    public_path = _absolute_path(
        config.get("public_key_path"), field="release signer public-key path"
    )
    if private_path == public_path:
        raise ReleaseOwnerSignerError("release signer key paths must be distinct")
    public_fingerprint = _digest(
        config.get("public_key_sha256"),
        field="release signer public-key fingerprint",
    )
    state_directory = _absolute_path(
        config.get("state_directory"), field="release signer state directory"
    )
    assertion_ttl = _bounded_int(
        config.get("assertion_ttl_seconds"),
        field="release assertion TTL",
        minimum=MIN_ASSERTION_TTL_SECONDS,
        maximum=MAX_ASSERTION_TTL_SECONDS,
    )
    maximum_event_age = _bounded_int(
        config.get("maximum_event_age_seconds"),
        field="release approval event age",
        minimum=MIN_EVENT_AGE_SECONDS,
        maximum=MAX_EVENT_AGE_SECONDS,
    )
    maximum_observation_delay = _bounded_int(
        config.get("maximum_observation_delay_seconds"),
        field="release approval observation delay",
        minimum=0,
        maximum=MAX_OBSERVATION_DELAY_SECONDS,
    )
    maximum_clock_skew = _bounded_int(
        config.get("maximum_clock_skew_seconds"),
        field="release approval clock skew",
        minimum=0,
        maximum=MAX_CLOCK_SKEW_SECONDS,
    )

    instance = _mapping(config.get("instance"), field="release signer instance")
    _strict_keys(
        instance,
        field="release signer instance",
        required={"slug", "repository"},
    )
    slug = str(instance.get("slug") or "")
    if not protocol.INSTANCE_SLUG_RE.fullmatch(slug):
        raise ReleaseOwnerSignerError("release signer instance slug is invalid")
    repository = _mapping(
        instance.get("repository"), field="release signer repository"
    )
    _strict_keys(
        repository,
        field="release signer repository",
        required={"id", "full_name", "default_branch"},
    )
    repository_id = _positive_int(
        repository.get("id"),
        field="release signer repository ID",
        maximum=protocol.MAX_SAFE_JSON_INTEGER,
    )
    full_name = str(repository.get("full_name") or "")
    default_branch = str(repository.get("default_branch") or "")
    if not protocol.REPOSITORY_RE.fullmatch(full_name):
        raise ReleaseOwnerSignerError("release signer repository name is invalid")
    if not protocol.BRANCH_RE.fullmatch(default_branch):
        raise ReleaseOwnerSignerError("release signer default branch is invalid")

    discord = _mapping(config.get("discord"), field="release signer Discord policy")
    _strict_keys(
        discord,
        field="release signer Discord policy",
        required={
            "application_id",
            "guild_id",
            "approval_channel_ids",
            "owner_actors",
        },
    )
    application_id = _snowflake(
        discord.get("application_id"), field="Discord application ID"
    )
    guild_id = _snowflake(discord.get("guild_id"), field="Discord guild ID")
    channels_raw = discord.get("approval_channel_ids")
    if not isinstance(channels_raw, list) or not channels_raw:
        raise ReleaseOwnerSignerError("Discord approval channels are invalid")
    channels = [
        _snowflake(value, field="Discord approval channel ID")
        for value in channels_raw
    ]
    if channels != sorted(channels) or len(channels) != len(set(channels)):
        raise ReleaseOwnerSignerError(
            "Discord approval channels must be sorted and unique"
        )
    actors_raw = discord.get("owner_actors")
    if not isinstance(actors_raw, list) or not actors_raw:
        raise ReleaseOwnerSignerError("Discord owner actors are invalid")
    actors: list[dict[str, str]] = []
    for raw_actor in actors_raw:
        actor = _mapping(raw_actor, field="Discord owner actor")
        _strict_keys(
            actor,
            field="Discord owner actor",
            required={"user_id", "actor_login"},
        )
        user_id = _snowflake(actor.get("user_id"), field="Discord owner user ID")
        actor_login = str(actor.get("actor_login") or "")
        if not protocol.LOGIN_RE.fullmatch(actor_login):
            raise ReleaseOwnerSignerError("Discord owner actor login is invalid")
        actors.append({"user_id": user_id, "actor_login": actor_login})
    if actors != sorted(actors, key=lambda value: value["user_id"]):
        raise ReleaseOwnerSignerError("Discord owner actors must be sorted")
    if len({actor["user_id"] for actor in actors}) != len(actors):
        raise ReleaseOwnerSignerError("Discord owner actor IDs must be unique")

    return {
        "schema_version": CONFIG_SCHEMA,
        "enabled": config["enabled"],
        "signer_id": signer_id,
        "signer_uid": signer_uid,
        "signer_gid": signer_gid,
        "runtime_uid": runtime_uid,
        "issuer": issuer,
        "key_id": key_id,
        "private_key_path": private_path,
        "public_key_path": public_path,
        "public_key_sha256": public_fingerprint,
        "state_directory": state_directory,
        "assertion_ttl_seconds": assertion_ttl,
        "maximum_event_age_seconds": maximum_event_age,
        "maximum_observation_delay_seconds": maximum_observation_delay,
        "maximum_clock_skew_seconds": maximum_clock_skew,
        "instance": {
            "slug": slug,
            "repository": {
                "id": repository_id,
                "full_name": full_name,
                "default_branch": default_branch,
            },
        },
        "discord": {
            "application_id": application_id,
            "guild_id": guild_id,
            "approval_channel_ids": channels,
            "owner_actors": actors,
        },
    }


def assert_process_identity(
    config: Any,
    *,
    process_uid: int | None = None,
    process_gid: int | None = None,
) -> dict[str, Any]:
    normalized = normalize_signer_config(config)
    uid = os.geteuid() if process_uid is None else process_uid
    gid = os.getegid() if process_gid is None else process_gid
    if uid != normalized["signer_uid"]:
        raise ReleaseOwnerSignerError("release signer process UID does not match")
    if gid != normalized["signer_gid"]:
        raise ReleaseOwnerSignerError("release signer process GID does not match")
    if uid == normalized["runtime_uid"]:
        raise ReleaseOwnerSignerError("Hermes runtime may not act as release signer")
    return normalized


def normalize_discord_event(
    raw: Any,
    config: Any,
    *,
    now: datetime | None = None,
    allow_stale: bool = False,
) -> dict[str, Any]:
    normalized_config = normalize_signer_config(config)
    event = _mapping(raw, field="Discord owner approval event")
    _strict_keys(
        event,
        field="Discord owner approval event",
        required={
            "schema_version",
            "platform",
            "application_id",
            "guild_id",
            "channel_id",
            "message_id",
            "actor_user_id",
            "actor_is_bot",
            "created_at",
            "observed_at",
            "text",
        },
    )
    if event.get("schema_version") != EVENT_SCHEMA:
        raise ReleaseOwnerSignerError("Discord approval event schema is unsupported")
    if event.get("platform") != PLATFORM:
        raise ReleaseOwnerSignerError("release owner event must come from Discord")
    application_id = _snowflake(
        event.get("application_id"), field="Discord event application ID"
    )
    guild_id = _snowflake(event.get("guild_id"), field="Discord event guild ID")
    channel_id = _snowflake(
        event.get("channel_id"), field="Discord event channel ID"
    )
    message_id = _snowflake(
        event.get("message_id"), field="Discord event message ID"
    )
    actor_user_id = _snowflake(
        event.get("actor_user_id"), field="Discord event actor ID"
    )
    if type(event.get("actor_is_bot")) is not bool:
        raise ReleaseOwnerSignerError("Discord event actor bot flag is invalid")
    if event["actor_is_bot"]:
        raise ReleaseOwnerSignerError("Discord bot actors may not approve releases")
    if application_id != normalized_config["discord"]["application_id"]:
        raise ReleaseOwnerSignerError("Discord event application does not match")
    if guild_id != normalized_config["discord"]["guild_id"]:
        raise ReleaseOwnerSignerError("Discord event guild does not match")
    if channel_id not in normalized_config["discord"]["approval_channel_ids"]:
        raise ReleaseOwnerSignerError("Discord event channel is not authorized")
    if actor_user_id not in _owner_actor_map(normalized_config):
        raise ReleaseOwnerSignerError("Discord event actor is not an authorized owner")
    created = _utc(event.get("created_at"), field="Discord event created_at")
    observed = _utc(event.get("observed_at"), field="Discord event observed_at")
    current = _now(now)
    skew = timedelta(
        seconds=normalized_config["maximum_clock_skew_seconds"]
    )
    if created > current + skew or observed > current + skew:
        raise ReleaseOwnerSignerError("Discord approval event is from the future")
    if observed + skew < created:
        raise ReleaseOwnerSignerError("Discord approval event observation predates it")
    if (
        observed - created
    ).total_seconds() > normalized_config["maximum_observation_delay_seconds"]:
        raise ReleaseOwnerSignerError("Discord approval observation was too late")
    if (
        not allow_stale
        and (current - created).total_seconds()
        > normalized_config["maximum_event_age_seconds"]
    ):
        raise ReleaseOwnerSignerError("Discord approval event is stale")
    snowflake_created = _snowflake_timestamp(message_id)
    if abs((snowflake_created - created).total_seconds()) > 1:
        raise ReleaseOwnerSignerError(
            "Discord message timestamp does not match its snowflake"
        )
    text = _safe_text(
        event.get("text"),
        field="Discord release approval text",
        maximum_bytes=MAX_APPROVAL_BYTES,
    )
    return {
        "schema_version": EVENT_SCHEMA,
        "platform": PLATFORM,
        "application_id": application_id,
        "guild_id": guild_id,
        "channel_id": channel_id,
        "message_id": message_id,
        "actor_user_id": actor_user_id,
        "actor_is_bot": False,
        "created_at": _utc_text(created),
        "observed_at": _utc_text(observed),
        "text": text,
    }


def expected_release_approval_text(bundle: Any) -> str:
    normalized = protocol.normalize_release_bundle(bundle)
    return (
        f"APPROVE JOHN-LOMEIN BUNDLE {normalized['bundle_id']} "
        f"DIGEST {normalized['bundle_digest']}: squash-merge the listed PR "
        "with the protected release broker; DO NOT publish. Post-merge "
        "repository verification and any publication require separate gates."
    )


def source_event_id(event: Any) -> str:
    normalized = _mapping(event, field="Discord owner approval event")
    identity = {
        "platform": normalized.get("platform"),
        "application_id": normalized.get("application_id"),
        "guild_id": normalized.get("guild_id"),
        "channel_id": normalized.get("channel_id"),
        "message_id": normalized.get("message_id"),
    }
    return "jlroe-" + protocol.sha256_json(identity).removeprefix("sha256:")[:24]


def _decode_salt(value: str) -> bytes:
    if not SALT_RE.fullmatch(value):
        raise ReleaseOwnerSignerError("release source commitment salt is invalid")
    try:
        raw = base64.urlsafe_b64decode(value + "=")
    except (TypeError, ValueError) as exc:
        raise ReleaseOwnerSignerError(
            "release source commitment salt is invalid"
        ) from exc
    if len(raw) != 32:
        raise ReleaseOwnerSignerError("release source commitment salt is invalid")
    return raw


def _commitment(
    *,
    salt: bytes,
    source_event_sha256: str,
    bundle_id: str,
    bundle_digest: str,
    approval_text_sha256: str,
) -> dict[str, str]:
    if not isinstance(salt, bytes) or len(salt) != 32:
        raise ReleaseOwnerSignerError("release source commitment needs 256 random bits")
    salt_text = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    body = {
        "schema_version": COMMITMENT_SCHEMA,
        "salt": salt_text,
        "source_event_sha256": source_event_sha256,
        "bundle_id": bundle_id,
        "bundle_digest": bundle_digest,
        "approval_text_sha256": approval_text_sha256,
    }
    return {
        **body,
        "nonce": protocol.sha256_json(body).removeprefix("sha256:"),
    }


def _load_key_pair(
    private_key_bytes: bytes,
    public_key_bytes: bytes,
    *,
    expected_public_key_sha256: str,
) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    if _fingerprint(public_key_bytes) != expected_public_key_sha256:
        raise ReleaseOwnerSignerError(
            "release signer public-key fingerprint does not match"
        )
    try:
        private_key = serialization.load_pem_private_key(
            private_key_bytes, password=None
        )
        public_key = serialization.load_pem_public_key(public_key_bytes)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ReleaseOwnerSignerError("release signer key material is invalid") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ReleaseOwnerSignerError("release signer private key is not Ed25519")
    if not isinstance(public_key, Ed25519PublicKey):
        raise ReleaseOwnerSignerError("release signer public key is not Ed25519")
    expected_public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    actual_public = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if expected_public != actual_public:
        raise ReleaseOwnerSignerError("release signer key pair does not match")
    return private_key, public_key


def build_signing_record(
    *,
    config: Any,
    bundle: Any,
    approval_text: str,
    source_event: Any,
    private_key_bytes: bytes,
    public_key_bytes: bytes,
    now: datetime | None = None,
    random_bytes: Callable[[int], bytes] = secrets.token_bytes,
) -> dict[str, Any]:
    normalized_config = normalize_signer_config(config)
    if not normalized_config["enabled"]:
        raise ReleaseOwnerSignerError("release owner signer is disabled")
    current = _now(now)
    normalized_bundle = protocol.normalize_release_bundle(bundle)
    if len(normalized_bundle["ordered_prs"]) != 1:
        raise ReleaseOwnerSignerError(
            "protected release v1 accepts exactly one PR per owner assertion"
        )
    expected_approval = expected_release_approval_text(normalized_bundle)
    if approval_text != expected_approval:
        raise ReleaseOwnerSignerError(
            "release approval text does not exactly match the bundle"
        )
    normalized_event = normalize_discord_event(
        source_event, normalized_config, now=current
    )
    if normalized_event["text"] != approval_text:
        raise ReleaseOwnerSignerError(
            "Discord event text does not exactly match the release approval"
        )
    if normalized_bundle["instance_slug"] != normalized_config["instance"]["slug"]:
        raise ReleaseOwnerSignerError("release bundle instance does not match signer")
    if (
        normalized_bundle["repository"]
        != normalized_config["instance"]["repository"]
    ):
        raise ReleaseOwnerSignerError("release bundle repository does not match signer")
    bundle_created = _utc(
        normalized_bundle["created_at"], field="release bundle created_at"
    )
    bundle_expires = _utc(
        normalized_bundle["expires_at"], field="release bundle expires_at"
    )
    event_created = _utc(
        normalized_event["created_at"], field="Discord event created_at"
    )
    if event_created < bundle_created:
        raise ReleaseOwnerSignerError("Discord approval predates the release bundle")
    if (
        bundle_expires - current
    ).total_seconds() < MIN_BUNDLE_REMAINING_SECONDS:
        raise ReleaseOwnerSignerError(
            "release bundle has insufficient lifetime remaining"
        )
    issued = current
    expires = min(
        issued + timedelta(seconds=normalized_config["assertion_ttl_seconds"]),
        bundle_expires,
    )
    if (expires - issued).total_seconds() < MIN_ASSERTION_TTL_SECONDS:
        raise ReleaseOwnerSignerError(
            "release assertion would have insufficient lifetime"
        )
    approval_digest = protocol.sha256_text(approval_text)
    source_digest = protocol.sha256_json(normalized_event)
    try:
        salt = random_bytes(32)
    except Exception as exc:
        raise ReleaseOwnerSignerError(
            "release source commitment randomness failed"
        ) from exc
    commitment = _commitment(
        salt=salt,
        source_event_sha256=source_digest,
        bundle_id=normalized_bundle["bundle_id"],
        bundle_digest=normalized_bundle["bundle_digest"],
        approval_text_sha256=approval_digest,
    )
    actor_login = _owner_actor_map(normalized_config)[
        normalized_event["actor_user_id"]
    ]
    payload = {
        "schema_version": protocol.OWNER_ASSERTION_SCHEMA,
        "purpose": "release_merge",
        "issuer": normalized_config["issuer"],
        "actor_id": normalized_event["actor_user_id"],
        "actor_login": actor_login,
        "tier": "owner",
        "issued_at": _utc_text(issued),
        "expires_at": _utc_text(expires),
        "nonce": commitment["nonce"],
        "instance_slug": normalized_bundle["instance_slug"],
        "repository_id": normalized_bundle["repository"]["id"],
        "repository_full_name": normalized_bundle["repository"]["full_name"],
        "bundle_id": normalized_bundle["bundle_id"],
        "bundle_digest": normalized_bundle["bundle_digest"],
        "approval_text_sha256": approval_digest,
        "action": protocol.RELEASE_ACTION,
        "merge_method": protocol.MERGE_METHOD,
        "publish": False,
        "ordered_prs_digest": protocol.ordered_prs_digest(normalized_bundle),
        "changed_paths_digest": protocol.changed_paths_digest(normalized_bundle),
        "risk_class": protocol.aggregate_risk_class(normalized_bundle),
    }
    private_key, _ = _load_key_pair(
        private_key_bytes,
        public_key_bytes,
        expected_public_key_sha256=normalized_config["public_key_sha256"],
    )
    signature = private_key.sign(protocol.canonical_json(payload))
    assertion = {
        "schema_version": protocol.SIGNED_ENVELOPE_SCHEMA,
        "algorithm": protocol.SIGNATURE_ALGORITHM,
        "key_id": normalized_config["key_id"],
        "payload": payload,
        "signature": base64.urlsafe_b64encode(signature)
        .decode("ascii")
        .rstrip("="),
    }
    try:
        protocol.verify_owner_assertion_signature(
            assertion,
            public_key=public_key_bytes,
            expected_public_key_sha256=normalized_config["public_key_sha256"],
            expected_key_id=normalized_config["key_id"],
            expected_issuer=normalized_config["issuer"],
            allowed_actor_ids={normalized_event["actor_user_id"]},
            now=current,
            maximum_ttl_seconds=normalized_config["assertion_ttl_seconds"],
            maximum_clock_skew_seconds=normalized_config[
                "maximum_clock_skew_seconds"
            ],
        )
    except protocol.ReleaseBrokerProtocolError as exc:
        raise ReleaseOwnerSignerError(
            f"release owner assertion self-verification failed: {exc}"
        ) from exc
    assertion_digest = protocol.owner_assertion_digest(assertion)
    event_id = source_event_id(normalized_event)
    record_id = "jlros-" + assertion_digest.removeprefix("sha256:")[:24]
    return {
        "schema_version": RECORD_SCHEMA,
        "record_id": record_id,
        "event_id": event_id,
        "signer_id": normalized_config["signer_id"],
        "signer_config_sha256": protocol.sha256_json(normalized_config),
        "created_at": _utc_text(current),
        "source_event": normalized_event,
        "source_event_sha256": source_digest,
        "source_commitment": commitment,
        "bundle": normalized_bundle,
        "approval_text": approval_text,
        "approval_text_sha256": approval_digest,
        "owner_assertion": assertion,
        "owner_assertion_sha256": assertion_digest,
    }


def verify_signing_record(
    raw: Any,
    *,
    config: Any,
    public_key_bytes: bytes,
    now: datetime | None = None,
    allow_expired_assertion: bool = True,
) -> dict[str, Any]:
    normalized_config = normalize_signer_config(config)
    record = _mapping(raw, field="release owner signing record")
    _strict_keys(
        record,
        field="release owner signing record",
        required={
            "schema_version",
            "record_id",
            "event_id",
            "signer_id",
            "signer_config_sha256",
            "created_at",
            "source_event",
            "source_event_sha256",
            "source_commitment",
            "bundle",
            "approval_text",
            "approval_text_sha256",
            "owner_assertion",
            "owner_assertion_sha256",
        },
    )
    if record.get("schema_version") != RECORD_SCHEMA:
        raise ReleaseOwnerSignerError("release owner signing record is unsupported")
    record_id = str(record.get("record_id") or "")
    event_id = str(record.get("event_id") or "")
    if not RECORD_ID_RE.fullmatch(record_id):
        raise ReleaseOwnerSignerError("release owner signing record ID is invalid")
    if not EVENT_ID_RE.fullmatch(event_id):
        raise ReleaseOwnerSignerError("release owner source event ID is invalid")
    if record.get("signer_id") != normalized_config["signer_id"]:
        raise ReleaseOwnerSignerError("release owner signing record signer differs")
    expected_config_digest = protocol.sha256_json(normalized_config)
    if record.get("signer_config_sha256") != expected_config_digest:
        raise ReleaseOwnerSignerError("release owner signer config digest differs")
    current = _now(now)
    normalized_event = normalize_discord_event(
        record.get("source_event"),
        normalized_config,
        now=current,
        allow_stale=True,
    )
    source_digest = protocol.sha256_json(normalized_event)
    if record.get("source_event_sha256") != source_digest:
        raise ReleaseOwnerSignerError("release source event digest differs")
    if event_id != source_event_id(normalized_event):
        raise ReleaseOwnerSignerError("release source event ID differs")
    normalized_bundle = protocol.normalize_release_bundle(record.get("bundle"))
    approval_text = _safe_text(
        record.get("approval_text"),
        field="release approval text",
        maximum_bytes=MAX_APPROVAL_BYTES,
    )
    if approval_text != expected_release_approval_text(normalized_bundle):
        raise ReleaseOwnerSignerError("recorded release approval text differs")
    if normalized_event["text"] != approval_text:
        raise ReleaseOwnerSignerError("recorded source event text differs")
    approval_digest = protocol.sha256_text(approval_text)
    if record.get("approval_text_sha256") != approval_digest:
        raise ReleaseOwnerSignerError("recorded approval digest differs")
    commitment = _mapping(
        record.get("source_commitment"),
        field="release source commitment",
    )
    _strict_keys(
        commitment,
        field="release source commitment",
        required={
            "schema_version",
            "salt",
            "source_event_sha256",
            "bundle_id",
            "bundle_digest",
            "approval_text_sha256",
            "nonce",
        },
    )
    if commitment.get("schema_version") != COMMITMENT_SCHEMA:
        raise ReleaseOwnerSignerError("release source commitment is unsupported")
    salt = _decode_salt(str(commitment.get("salt") or ""))
    expected_commitment = _commitment(
        salt=salt,
        source_event_sha256=source_digest,
        bundle_id=normalized_bundle["bundle_id"],
        bundle_digest=normalized_bundle["bundle_digest"],
        approval_text_sha256=approval_digest,
    )
    if commitment != expected_commitment:
        raise ReleaseOwnerSignerError("release source commitment differs")
    assertion = record.get("owner_assertion")
    try:
        normalized_assertion = protocol.verify_owner_assertion_signature(
            assertion,
            public_key=public_key_bytes,
            expected_public_key_sha256=normalized_config["public_key_sha256"],
            expected_key_id=normalized_config["key_id"],
            expected_issuer=normalized_config["issuer"],
            allowed_actor_ids=set(_owner_actor_map(normalized_config)),
            now=current,
            allow_expired=allow_expired_assertion,
            maximum_ttl_seconds=normalized_config["assertion_ttl_seconds"],
            maximum_clock_skew_seconds=normalized_config[
                "maximum_clock_skew_seconds"
            ],
        )
    except protocol.ReleaseBrokerProtocolError as exc:
        raise ReleaseOwnerSignerError(
            f"recorded release assertion is invalid: {exc}"
        ) from exc
    assertion_digest = protocol.owner_assertion_digest(normalized_assertion)
    if record.get("owner_assertion_sha256") != assertion_digest:
        raise ReleaseOwnerSignerError("recorded owner assertion digest differs")
    if record_id != "jlros-" + assertion_digest.removeprefix("sha256:")[:24]:
        raise ReleaseOwnerSignerError("release owner signing record ID differs")
    payload = normalized_assertion["payload"]
    actor_login = _owner_actor_map(normalized_config)[
        normalized_event["actor_user_id"]
    ]
    expected_bindings = {
        "issuer": normalized_config["issuer"],
        "actor_id": normalized_event["actor_user_id"],
        "actor_login": actor_login,
        "nonce": commitment["nonce"],
        "instance_slug": normalized_bundle["instance_slug"],
        "repository_id": normalized_bundle["repository"]["id"],
        "repository_full_name": normalized_bundle["repository"]["full_name"],
        "bundle_id": normalized_bundle["bundle_id"],
        "bundle_digest": normalized_bundle["bundle_digest"],
        "approval_text_sha256": approval_digest,
        "ordered_prs_digest": protocol.ordered_prs_digest(normalized_bundle),
        "changed_paths_digest": protocol.changed_paths_digest(normalized_bundle),
        "risk_class": protocol.aggregate_risk_class(normalized_bundle),
    }
    for field, expected in expected_bindings.items():
        if payload.get(field) != expected:
            raise ReleaseOwnerSignerError(
                f"recorded owner assertion {field} binding differs"
            )
    created = _utc(record.get("created_at"), field="signing record created_at")
    if payload["issued_at"] != _utc_text(created):
        raise ReleaseOwnerSignerError("signing record timestamp differs")
    return {
        "schema_version": RECORD_SCHEMA,
        "record_id": record_id,
        "event_id": event_id,
        "signer_id": normalized_config["signer_id"],
        "signer_config_sha256": expected_config_digest,
        "created_at": _utc_text(created),
        "source_event": normalized_event,
        "source_event_sha256": source_digest,
        "source_commitment": expected_commitment,
        "bundle": normalized_bundle,
        "approval_text": approval_text,
        "approval_text_sha256": approval_digest,
        "owner_assertion": normalized_assertion,
        "owner_assertion_sha256": assertion_digest,
    }


def _validate_parent_chain(
    path: Path,
    *,
    field: str,
    trusted_root: Path,
    allowed_owner_uids: set[int],
) -> None:
    if not path.is_absolute() or not trusted_root.is_absolute():
        raise ReleaseOwnerSignerError(f"{field} path is unsafe")
    try:
        path.relative_to(trusted_root)
    except ValueError as exc:
        raise ReleaseOwnerSignerError(f"{field} escapes its trusted root") from exc
    current = path
    while True:
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise ReleaseOwnerSignerError(f"{field} parent is unreadable") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ReleaseOwnerSignerError(f"{field} parent is unsafe")
        if info.st_uid not in allowed_owner_uids:
            raise ReleaseOwnerSignerError(f"{field} parent owner is untrusted")
        if info.st_mode & 0o022:
            raise ReleaseOwnerSignerError(f"{field} parent is writable")
        if current == trusted_root:
            return
        current = current.parent


def read_secure_file(
    path: Path,
    *,
    field: str,
    maximum_bytes: int,
    expected_owner_uid: int,
    expected_group_gid: int,
    exact_mode: int,
    trusted_root: Path,
) -> bytes:
    if not path.is_absolute() or ".." in path.parts:
        raise ReleaseOwnerSignerError(f"{field} path is unsafe")
    _validate_parent_chain(
        path.parent,
        field=field,
        trusted_root=trusted_root,
        allowed_owner_uids={0, expected_owner_uid},
    )
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ReleaseOwnerSignerError(f"{field} is unreadable") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ReleaseOwnerSignerError(f"{field} must be a regular file")
        if before.st_uid != expected_owner_uid:
            raise ReleaseOwnerSignerError(f"{field} owner does not match")
        if before.st_gid != expected_group_gid:
            raise ReleaseOwnerSignerError(f"{field} group does not match")
        if stat.S_IMODE(before.st_mode) != exact_mode:
            raise ReleaseOwnerSignerError(f"{field} mode does not match")
        if before.st_nlink != 1:
            raise ReleaseOwnerSignerError(f"{field} must not have hard links")
        if before.st_size < 1 or before.st_size > maximum_bytes:
            raise ReleaseOwnerSignerError(f"{field} size is invalid")
        raw = bytearray()
        while len(raw) <= maximum_bytes:
            chunk = os.read(
                fd, min(16 * 1024, maximum_bytes + 1 - len(raw))
            )
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(fd)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ReleaseOwnerSignerError(f"{field} changed while being read")
        if not raw or len(raw) > maximum_bytes:
            raise ReleaseOwnerSignerError(f"{field} size is invalid")
        return bytes(raw)
    except ReleaseOwnerSignerError:
        raise
    except OSError as exc:
        raise ReleaseOwnerSignerError(f"{field} is unreadable") from exc
    finally:
        os.close(fd)


def load_config(
    path: Path,
    *,
    expected_owner_uid: int = 0,
    expected_group_gid: int | None = None,
    trusted_root: Path = Path("/"),
) -> dict[str, Any]:
    group_gid = os.getegid() if expected_group_gid is None else expected_group_gid
    raw = read_secure_file(
        path,
        field="release owner signer config",
        maximum_bytes=MAX_CONFIG_BYTES,
        expected_owner_uid=expected_owner_uid,
        expected_group_gid=group_gid,
        exact_mode=0o440,
        trusted_root=trusted_root,
    )
    try:
        parsed = protocol.parse_json_bytes(
            raw,
            field="release owner signer config",
            maximum_bytes=MAX_CONFIG_BYTES,
        )
    except protocol.ReleaseBrokerProtocolError as exc:
        raise ReleaseOwnerSignerError(str(exc)) from exc
    return normalize_signer_config(parsed)


def load_configured_key_pair(
    config: Any,
    *,
    expected_key_owner_uid: int = 0,
    trusted_root: Path = Path("/"),
) -> tuple[bytes, bytes]:
    normalized = normalize_signer_config(config)
    private_bytes = read_secure_file(
        Path(normalized["private_key_path"]),
        field="release owner signer private key",
        maximum_bytes=MAX_KEY_BYTES,
        expected_owner_uid=expected_key_owner_uid,
        expected_group_gid=normalized["signer_gid"],
        exact_mode=0o640,
        trusted_root=trusted_root,
    )
    public_bytes = read_secure_file(
        Path(normalized["public_key_path"]),
        field="release owner signer public key",
        maximum_bytes=MAX_KEY_BYTES,
        expected_owner_uid=expected_key_owner_uid,
        expected_group_gid=normalized["signer_gid"],
        exact_mode=0o440,
        trusted_root=trusted_root,
    )
    _load_key_pair(
        private_bytes,
        public_bytes,
        expected_public_key_sha256=normalized["public_key_sha256"],
    )
    return private_bytes, public_bytes


def _directory_fd(path: Path, *, config: dict[str, Any]) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ReleaseOwnerSignerError("release signer state directory is unsafe") from exc
    info = os.fstat(fd)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != config["signer_uid"]
        or info.st_gid != config["signer_gid"]
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        os.close(fd)
        raise ReleaseOwnerSignerError("release signer state directory is unsafe")
    return fd


def _records_fd(state_fd: int, *, config: dict[str, Any]) -> int:
    try:
        os.mkdir("records", mode=0o700, dir_fd=state_fd)
        os.fsync(state_fd)
    except FileExistsError:
        pass
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open("records", flags, dir_fd=state_fd)
    except OSError as exc:
        raise ReleaseOwnerSignerError("release signer records directory is unsafe") from exc
    info = os.fstat(fd)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != config["signer_uid"]
        or info.st_gid != config["signer_gid"]
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        os.close(fd)
        raise ReleaseOwnerSignerError("release signer records directory is unsafe")
    return fd


def _read_record_at(records_fd: int, name: str) -> dict[str, Any]:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(name, flags, dir_fd=records_fd)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ReleaseOwnerSignerError("release signing record is unreadable") from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size < 1
            or info.st_size > MAX_RECORD_BYTES
        ):
            raise ReleaseOwnerSignerError("release signing record is unsafe")
        raw = bytearray()
        while len(raw) <= MAX_RECORD_BYTES:
            chunk = os.read(
                fd, min(64 * 1024, MAX_RECORD_BYTES + 1 - len(raw))
            )
            if not chunk:
                break
            raw.extend(chunk)
        try:
            return protocol.parse_json_bytes(
                bytes(raw),
                field="release signing record",
                maximum_bytes=MAX_RECORD_BYTES,
            )
        except protocol.ReleaseBrokerProtocolError as exc:
            raise ReleaseOwnerSignerError(str(exc)) from exc
    finally:
        os.close(fd)


def _logical_request_digest(record: dict[str, Any]) -> str:
    return protocol.sha256_json(
        {
            "signer_config_sha256": record.get("signer_config_sha256"),
            "source_event": record.get("source_event"),
            "bundle": record.get("bundle"),
            "approval_text_sha256": record.get("approval_text_sha256"),
        }
    )


def persist_signing_record(
    config: Any,
    record: Any,
    *,
    public_key_bytes: bytes,
    now: datetime | None = None,
) -> tuple[dict[str, Any], Path]:
    normalized_config = normalize_signer_config(config)
    normalized_record = verify_signing_record(
        record,
        config=normalized_config,
        public_key_bytes=public_key_bytes,
        now=now,
    )
    event_id = normalized_record["event_id"]
    filename = f"{event_id}.json"
    state_path = Path(normalized_config["state_directory"])
    state_fd = _directory_fd(state_path, config=normalized_config)
    records_fd = -1
    temp_name = f".{event_id}.{secrets.token_hex(16)}.tmp"
    try:
        records_fd = _records_fd(state_fd, config=normalized_config)
        try:
            existing = _read_record_at(records_fd, filename)
        except FileNotFoundError:
            pass
        else:
            verified = verify_signing_record(
                existing,
                config=normalized_config,
                public_key_bytes=public_key_bytes,
                now=now,
            )
            if _logical_request_digest(verified) != _logical_request_digest(
                normalized_record
            ):
                raise ReleaseOwnerSignerError(
                    "Discord source event is already bound to a different request"
                )
            return verified, state_path / "records" / filename
        encoded = protocol.canonical_json(normalized_record) + b"\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        temp_fd = os.open(temp_name, flags, 0o600, dir_fd=records_fd)
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(temp_fd, view)
                if written <= 0:
                    raise ReleaseOwnerSignerError(
                        "release signing record write failed"
                    )
                view = view[written:]
            os.fsync(temp_fd)
        finally:
            os.close(temp_fd)
        try:
            os.link(
                temp_name,
                filename,
                src_dir_fd=records_fd,
                dst_dir_fd=records_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            existing = _read_record_at(records_fd, filename)
            verified = verify_signing_record(
                existing,
                config=normalized_config,
                public_key_bytes=public_key_bytes,
                now=now,
            )
            if _logical_request_digest(verified) != _logical_request_digest(
                normalized_record
            ):
                raise ReleaseOwnerSignerError(
                    "Discord source event is already bound to a different request"
                )
            return verified, state_path / "records" / filename
        finally:
            try:
                os.unlink(temp_name, dir_fd=records_fd)
            except FileNotFoundError:
                pass
        os.fsync(records_fd)
        return normalized_record, state_path / "records" / filename
    finally:
        if records_fd >= 0:
            os.close(records_fd)
        os.close(state_fd)


def mint_and_persist(
    *,
    config: Any,
    bundle: Any,
    approval_text: str,
    source_event: Any,
    now: datetime | None = None,
    process_uid: int | None = None,
    process_gid: int | None = None,
    expected_key_owner_uid: int = 0,
    trusted_key_root: Path = Path("/"),
    random_bytes: Callable[[int], bytes] = secrets.token_bytes,
) -> tuple[dict[str, Any], Path]:
    normalized_config = assert_process_identity(
        config,
        process_uid=process_uid,
        process_gid=process_gid,
    )
    private_bytes, public_bytes = load_configured_key_pair(
        normalized_config,
        expected_key_owner_uid=expected_key_owner_uid,
        trusted_root=trusted_key_root,
    )
    record = build_signing_record(
        config=normalized_config,
        bundle=bundle,
        approval_text=approval_text,
        source_event=source_event,
        private_key_bytes=private_bytes,
        public_key_bytes=public_bytes,
        now=now,
        random_bytes=random_bytes,
    )
    return persist_signing_record(
        normalized_config,
        record,
        public_key_bytes=public_bytes,
        now=now,
    )


def self_check(
    *,
    config: Any,
    discord_source_config: Path,
) -> dict[str, Any]:
    """Validate private signer health without Discord/network or mutation."""
    from owner_gateway import john_lomein_discord_release_source as source

    normalized = assert_process_identity(config)
    load_configured_key_pair(normalized)
    try:
        source_config = source.load_source_config(
            discord_source_config,
            normalized,
        )
        source.load_bot_token(source_config, normalized)
    except source.DiscordReleaseSourceError as exc:
        raise ReleaseOwnerSignerError(str(exc)) from exc
    state_fd = _directory_fd(
        Path(normalized["state_directory"]),
        config=normalized,
    )
    os.close(state_fd)
    return {
        "schema_version": SELF_CHECK_SCHEMA,
        "enabled": (
            normalized["enabled"] and source_config["enabled"]
        ),
        "healthy": True,
    }


def load_untrusted_json(path: Path, *, field: str, maximum_bytes: int) -> Any:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ReleaseOwnerSignerError(f"{field} is unreadable") from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size < 1
            or info.st_size > maximum_bytes
        ):
            raise ReleaseOwnerSignerError(f"{field} is unsafe")
        raw = bytearray()
        while len(raw) <= maximum_bytes:
            chunk = os.read(fd, min(64 * 1024, maximum_bytes + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        try:
            return protocol.parse_json_bytes(
                bytes(raw), field=field, maximum_bytes=maximum_bytes
            )
        except protocol.ReleaseBrokerProtocolError as exc:
            raise ReleaseOwnerSignerError(str(exc)) from exc
    finally:
        os.close(fd)


def load_untrusted_text(path: Path, *, field: str, maximum_bytes: int) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ReleaseOwnerSignerError(f"{field} is unreadable") from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size < 1
            or info.st_size > maximum_bytes
        ):
            raise ReleaseOwnerSignerError(f"{field} is unsafe")
        data = bytearray()
        while len(data) <= maximum_bytes:
            chunk = os.read(fd, min(16 * 1024, maximum_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        try:
            return bytes(data).decode("utf-8", errors="strict").rstrip("\n")
        except UnicodeError as exc:
            raise ReleaseOwnerSignerError(f"{field} is invalid UTF-8") from exc
    finally:
        os.close(fd)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Mint or verify protected release-owner assertions."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    mint = subparsers.add_parser("mint")
    mint.add_argument("--config", type=Path, required=True)
    mint.add_argument("--discord-source-config", type=Path, required=True)
    mint.add_argument("--bundle", type=Path, required=True)
    mint.add_argument("--channel-id", required=True)
    mint.add_argument("--message-id", required=True)
    check = subparsers.add_parser("self-check")
    check.add_argument("--config", type=Path, required=True)
    check.add_argument(
        "--discord-source-config",
        type=Path,
        required=True,
    )
    verify = subparsers.add_parser("verify-record")
    verify.add_argument("--config", type=Path, required=True)
    verify.add_argument("--record", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "self-check":
            print(
                json.dumps(
                    self_check(
                        config=config,
                        discord_source_config=args.discord_source_config,
                    ),
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 0
        if args.command == "mint":
            from owner_gateway import john_lomein_discord_release_source as source

            bundle = load_untrusted_json(
                args.bundle,
                field="release bundle",
                maximum_bytes=MAX_BUNDLE_BYTES,
            )
            normalized_bundle = protocol.normalize_release_bundle(bundle)
            approval = expected_release_approval_text(normalized_bundle)
            assert_process_identity(config)
            source_config = source.load_source_config(
                args.discord_source_config,
                config,
            )
            bot_token = source.load_bot_token(source_config, config)
            event = source.fetch_normalized_event(
                signer_config=config,
                source_config=source_config,
                channel_id=args.channel_id,
                message_id=args.message_id,
                bot_token=bot_token,
            )
            record, _ = mint_and_persist(
                config=config,
                bundle=normalized_bundle,
                approval_text=approval,
                source_event=event,
            )
            print(
                json.dumps(
                    {
                        "ok": True,
                        "record_id": record["record_id"],
                        "event_id": record["event_id"],
                        "bundle_id": record["bundle"]["bundle_id"],
                        "owner_assertion_sha256": record[
                            "owner_assertion_sha256"
                        ],
                        "owner_assertion": record["owner_assertion"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 0
        _, public_bytes = load_configured_key_pair(config)
        record = load_untrusted_json(
            args.record,
            field="release owner signing record",
            maximum_bytes=MAX_RECORD_BYTES,
        )
        verified = verify_signing_record(
            record,
            config=config,
            public_key_bytes=public_bytes,
        )
        print(
            json.dumps(
                {
                    "ok": True,
                    "record_id": verified["record_id"],
                    "event_id": verified["event_id"],
                    "bundle_id": verified["bundle"]["bundle_id"],
                    "owner_assertion_sha256": verified[
                        "owner_assertion_sha256"
                    ],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except (
        ReleaseOwnerSignerError,
        protocol.ReleaseBrokerProtocolError,
    ) as exc:
        print(f"release owner signer refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
