#!/usr/bin/env python3
"""Crash-safe durable state for the protected release broker.

This module owns no GitHub credentials, network access, or receipt signing
key.  It is the durable authorization/effect boundary between a validated
release packet and a future credential-bearing service:

* exact-packet idempotency and semantic-alias rejection;
* atomic owner-assertion nonce consumption;
* one active bundle per repository;
* ordered step and charged mutation-attempt state;
* recovery evidence for ambiguous/crashed attempts;
* append-only terminal receipt-chain metadata;
* durable request, assertion, bundle, attempt, and merge budgets; and
* repository-scoped immediate and threshold circuit breakers.

The caller must validate the packet signature and root-owned policy before
calling :meth:`ReleaseBrokerStore.reserve`.  The store nevertheless
re-canonicalizes the normalized packet and independently checks all identity
and digest fields that it persists.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import unicodedata
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Literal
from urllib.parse import quote


SCHEMA_VERSION = 1
PACKET_SCHEMA = "john-lomein.protected-release-merge-packet.v1"
BUNDLE_SCHEMA = "john-lomein.release-bundle.v6"
OWNER_ASSERTION_SCHEMA = "john-lomein.owner-assertion.v2"
PACKET_AUTHORITY = "request_only_no_execution_authority"
RELEASE_ACTION = "merge_release_bundle"
MERGE_METHOD = "squash"
BUNDLE_SEMANTIC_SCHEMA = "john-lomein.release-broker-semantic.v1"
RECEIPT_CHAIN_SCHEMA = "john-lomein.release-receipt-chain-entry.v1"

ZERO_DIGEST = "sha256:" + ("0" * 64)
REQUEST_WINDOW_SECONDS = 60 * 60
MAX_CLOCK_SKEW_SECONDS = 300
MAX_PACKET_BYTES = 2 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991
MAX_ATTEMPTS_PER_STEP = 2

PACKET_ID_RE = re.compile(r"^jlrp-[0-9a-f]{24}$")
BUNDLE_ID_RE = re.compile(r"^jlb-[0-9a-f]{24}$")
BUNDLE_KEY_RE = re.compile(r"^jlrb-[0-9a-f]{32}$")
ATTEMPT_ID_RE = re.compile(r"^jlra-[A-Za-z0-9._:@+~-]{1,120}$")
RECOVERY_ID_RE = re.compile(r"^jlrr-[A-Za-z0-9._:@+~-]{1,120}$")
INSTANCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
REPOSITORY_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)
KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$")
NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,255}$")
MERGE_ACTOR_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._:@/+~-]{0,250}(?:\[bot\])?)?$"
)
OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

ACTIVE_BUNDLE_STATES = frozenset({"reserved", "executing"})
TERMINAL_BUNDLE_STATES = frozenset(
    {"succeeded", "rejected", "partial", "indeterminate"}
)
STEP_STATES = frozenset(
    {
        "pending",
        "mutation_pending",
        "confirmed",
        "rejected",
        "indeterminate",
    }
)
ATTEMPT_STATES = frozenset(
    {"pending", "confirmed", "absent", "indeterminate"}
)

ReservationDisposition = Literal[
    "new_bundle",
    "exact_pending",
    "exact_terminal_replay",
]
MutationDisposition = Literal[
    "charged",
    "already_charged",
    "step_confirmed",
    "terminal_replay",
]


class ReleaseBrokerStoreError(RuntimeError):
    """Base class for fail-closed release-store failures."""


class UnsafeStoreError(ReleaseBrokerStoreError):
    """The SQLite path, owner, permissions, or durability mode is unsafe."""


class StoreCorruptionError(ReleaseBrokerStoreError):
    """Persisted data no longer matches its canonical durable identity."""


class StoreBindingError(ReleaseBrokerStoreError):
    """The database is unbound or bound to another trusted configuration."""


class PacketConflictError(ReleaseBrokerStoreError):
    """A packet identifier or request digest was reused inconsistently."""


class NonceReplayError(ReleaseBrokerStoreError):
    """An owner authorization nonce or assertion was already consumed."""


class BundleConflictError(ReleaseBrokerStoreError):
    """A semantic bundle identity conflicts with persisted content."""


class SemanticTerminalReplayError(BundleConflictError):
    """A fresh packet attempted to alias an already-reserved bundle."""


class ActiveBundleError(ReleaseBrokerStoreError):
    """Another non-terminal bundle already owns the repository lease."""


class StateTransitionError(ReleaseBrokerStoreError):
    """A requested bundle, step, attempt, or receipt transition is invalid."""


class PendingRecoveryError(StateTransitionError):
    """A charged attempt must be reconciled before another mutation."""


class CircuitOpenError(ReleaseBrokerStoreError):
    """The repository release circuit is open."""


class BudgetExceeded(ReleaseBrokerStoreError):
    """A durable release budget has no remaining capacity."""

    def __init__(
        self,
        *,
        budget: str,
        limit: int,
        used: int,
        reset_at: datetime,
    ) -> None:
        self.budget = budget
        self.limit = limit
        self.used = used
        self.reset_at = reset_at.astimezone(timezone.utc)
        super().__init__(
            f"{budget} budget exhausted ({used}/{limit}); "
            f"resets at {utc_text(self.reset_at)}"
        )


@dataclass(frozen=True)
class BudgetLimits:
    """Root-owned limits used for every durable reservation."""

    unique_requests_per_hour: int
    owner_assertions_per_hour: int
    bundles_per_day: int
    mutation_attempts_per_day: int
    confirmed_merges_per_day: int
    consecutive_indeterminate_limit: int
    max_prs_per_bundle: int = 1

    def __post_init__(self) -> None:
        for field_name in (
            "unique_requests_per_hour",
            "owner_assertions_per_hour",
            "bundles_per_day",
            "mutation_attempts_per_day",
            "confirmed_merges_per_day",
        ):
            value = getattr(self, field_name)
            if type(value) is not int or value < 0 or value > 1_000_000:
                raise ValueError(
                    f"{field_name} must be an integer between 0 and 1000000"
                )
        threshold = self.consecutive_indeterminate_limit
        if type(threshold) is not int or threshold < 1 or threshold > 1_000_000:
            raise ValueError(
                "consecutive_indeterminate_limit must be between 1 and 1000000"
            )
        maximum = self.max_prs_per_bundle
        if type(maximum) is not int or maximum < 1 or maximum > 50:
            raise ValueError("max_prs_per_bundle must be between 1 and 50")


@dataclass(frozen=True)
class Reservation:
    disposition: ReservationDisposition
    packet_id: str
    bundle_key: str
    bundle_id: str
    bundle_digest: str
    repository_id: int
    state: str
    receipt: dict[str, Any] | None = None
    receipt_packet_id: str | None = None


@dataclass(frozen=True)
class MutationReservation:
    disposition: MutationDisposition
    packet_id: str
    bundle_key: str
    position: int
    attempt_id: str | None
    expected_base_sha: str | None
    charged_at: str | None
    receipt: dict[str, Any] | None = None


@dataclass(frozen=True)
class StepConfirmation:
    disposition: Literal["confirmed", "already_confirmed"]
    bundle_key: str
    position: int
    attempt_id: str
    merge_sha: str
    tree_sha: str


@dataclass(frozen=True)
class RecoveryResult:
    disposition: Literal["recorded", "already_recorded"]
    recovery_id: str
    bundle_key: str
    position: int
    attempt_id: str
    classification: str


@dataclass(frozen=True)
class Terminalization:
    disposition: Literal["terminalized", "receipt_replay"]
    bundle_key: str
    packet_id: str
    outcome: str
    receipt_digest: str
    chain_digest: str
    receipt: dict[str, Any]


@dataclass(frozen=True)
class PendingRecovery:
    bundle_key: str
    packet_id: str
    repository_id: int
    repository_full_name: str
    position: int
    pr_number: int
    head_sha: str
    expected_base_sha: str
    attempt_id: str
    precondition_digest: str
    started_at: str
    attempt_number: int


@dataclass(frozen=True)
class _PacketIdentity:
    packet_id: str
    request_digest: str
    packet_json: str
    packet_json_digest: str
    packet_created_at: int
    packet_expires_at: int
    instance_slug: str
    repository_id: int
    repository_full_name: str
    default_branch: str
    bundle_id: str
    bundle_digest: str
    bundle_json: str
    bundle_json_digest: str
    bundle_expires_at: int
    bundle_key: str
    semantic_json: str
    semantic_digest: str
    initial_base_sha: str
    owner_key_id: str
    owner_nonce: str
    owner_assertion_digest: str
    owner_issuer: str
    owner_actor_id: str
    steps: tuple[dict[str, Any], ...]


def utc_text(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("time must be timezone-aware")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch_text(value: int) -> str:
    return utc_text(datetime.fromtimestamp(value, tz=timezone.utc))


def _now_epoch(value: datetime | None) -> int:
    current = value or datetime.now(timezone.utc)
    if not isinstance(current, datetime) or current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    return int(current.astimezone(timezone.utc).timestamp())


def _parse_utc(value: Any, *, field: str) -> int:
    if not isinstance(value, str):
        raise ReleaseBrokerStoreError(f"{field} must be a UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ReleaseBrokerStoreError(
            f"{field} must be a canonical UTC timestamp"
        ) from exc
    return int(parsed.timestamp())


def _utc_day(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")


def _next_utc_day(epoch: int) -> datetime:
    start = datetime.strptime(_utc_day(epoch), "%Y-%m-%d").replace(
        tzinfo=timezone.utc
    )
    return start + timedelta(days=1)


def _validate_canonical(value: Any, *, field: str, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ReleaseBrokerStoreError(f"{field} exceeds maximum JSON depth")
    if value is None or type(value) is bool:
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > MAX_SAFE_JSON_INTEGER:
            raise ReleaseBrokerStoreError(
                f"{field} integer is outside the canonical range"
            )
        return
    if isinstance(value, float):
        raise ReleaseBrokerStoreError(f"{field} may not contain floats")
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise ReleaseBrokerStoreError(f"{field} is not NFC-normalized")
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ReleaseBrokerStoreError(f"{field} is not valid Unicode") from exc
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ReleaseBrokerStoreError(
                    f"{field} object keys must be strings"
                )
            _validate_canonical(key, field=f"{field} key", depth=depth + 1)
            _validate_canonical(
                item,
                field=f"{field}.{key}",
                depth=depth + 1,
            )
        return
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        for index, item in enumerate(value):
            _validate_canonical(
                item,
                field=f"{field}[{index}]",
                depth=depth + 1,
            )
        return
    raise ReleaseBrokerStoreError(
        f"{field} contains an unsupported canonical JSON type"
    )


def _utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16-be", errors="strict")


def _canonical_text(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, str):
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
    if isinstance(value, Mapping):
        keys = sorted(value, key=_utf16_sort_key)
        return (
            "{"
            + ",".join(
                f"{_canonical_text(key)}:{_canonical_text(value[key])}"
                for key in keys
            )
            + "}"
        )
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        return "[" + ",".join(_canonical_text(item) for item in value) + "]"
    raise ReleaseBrokerStoreError("value is not canonical JSON")


def canonical_json(value: Any) -> str:
    _validate_canonical(value, field="value")
    text = _canonical_text(value)
    if len(text.encode("utf-8")) > MAX_PACKET_BYTES:
        raise ReleaseBrokerStoreError("canonical JSON exceeds its size limit")
    return text


def sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_text(canonical_json(value))


def _decode_canonical_json(text: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(text, str):
        raise StoreCorruptionError(f"{field} is not stored as text")
    try:
        value = json.loads(
            text,
            parse_float=lambda _: (_ for _ in ()).throw(
                StoreCorruptionError(f"{field} contains a float")
            ),
            parse_constant=lambda _: (_ for _ in ()).throw(
                StoreCorruptionError(f"{field} contains a non-finite number")
            ),
        )
    except StoreCorruptionError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise StoreCorruptionError(f"{field} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise StoreCorruptionError(f"{field} is not an object")
    try:
        normalized = canonical_json(value)
    except ReleaseBrokerStoreError as exc:
        raise StoreCorruptionError(f"{field} is not canonical") from exc
    if normalized != text:
        raise StoreCorruptionError(f"{field} is not canonical")
    return value


def _require_digest(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ReleaseBrokerStoreError(f"{field} must be a SHA-256 digest")
    return value


def _require_oid(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not OID_RE.fullmatch(value):
        raise ReleaseBrokerStoreError(f"{field} must be a full Git OID")
    return value


def _require_mapping(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReleaseBrokerStoreError(f"{field} must be an object")
    return dict(value)


def _require_positive_int(value: Any, *, field: str) -> int:
    if type(value) is not int or value <= 0 or value > MAX_SAFE_JSON_INTEGER:
        raise ReleaseBrokerStoreError(f"{field} must be a positive integer")
    return value


def _packet_identity(
    packet: Mapping[str, Any],
    *,
    now_epoch: int,
    enforce_freshness: bool,
) -> _PacketIdentity:
    packet_value = _require_mapping(packet, field="release packet")
    if packet_value.get("schema_version") != PACKET_SCHEMA:
        raise ReleaseBrokerStoreError("release packet schema is unsupported")
    if packet_value.get("authority") != PACKET_AUTHORITY:
        raise ReleaseBrokerStoreError("release packet authority is invalid")
    packet_id = str(packet_value.get("packet_id") or "")
    if not PACKET_ID_RE.fullmatch(packet_id):
        raise ReleaseBrokerStoreError("release packet ID is invalid")
    request_digest = _require_digest(
        packet_value.get("request_digest"),
        field="release packet request digest",
    )
    packet_created_at = _parse_utc(
        packet_value.get("created_at"),
        field="release packet created_at",
    )
    packet_expires_at = _parse_utc(
        packet_value.get("expires_at"),
        field="release packet expires_at",
    )
    if packet_expires_at <= packet_created_at:
        raise ReleaseBrokerStoreError("release packet lifetime is invalid")
    if enforce_freshness:
        if packet_created_at > now_epoch + MAX_CLOCK_SKEW_SECONDS:
            raise ReleaseBrokerStoreError(
                "release packet creation time is in the future"
            )
        if now_epoch >= packet_expires_at:
            raise ReleaseBrokerStoreError("release packet has expired")

    request = _require_mapping(
        packet_value.get("request"), field="release packet request"
    )
    if request.get("action") != RELEASE_ACTION:
        raise ReleaseBrokerStoreError("release action is unsupported")
    if sha256_json(request) != request_digest:
        raise ReleaseBrokerStoreError(
            "release packet request digest does not match"
        )

    normalized_body = {
        "schema_version": PACKET_SCHEMA,
        "created_at": packet_value.get("created_at"),
        "expires_at": packet_value.get("expires_at"),
        "authority": PACKET_AUTHORITY,
        "requested_by": packet_value.get("requested_by"),
        "request": request,
    }
    expected_packet_id = (
        "jlrp-" + sha256_json(normalized_body).removeprefix("sha256:")[:24]
    )
    if packet_id != expected_packet_id:
        raise ReleaseBrokerStoreError("release packet ID does not match")

    bundle = _require_mapping(request.get("bundle"), field="release bundle")
    if bundle.get("schema_version") != BUNDLE_SCHEMA:
        raise ReleaseBrokerStoreError("release bundle schema is unsupported")
    if bundle.get("merge_method") != MERGE_METHOD:
        raise ReleaseBrokerStoreError("release bundle must use squash")
    if bundle.get("publish") is not False:
        raise ReleaseBrokerStoreError("release bundle may not publish")
    actions = _require_mapping(
        bundle.get("actions"), field="release bundle actions"
    )
    if actions != {"merge": True, "publish": False}:
        raise ReleaseBrokerStoreError(
            "release bundle actions must authorize merge only"
        )
    instance_slug = str(bundle.get("instance_slug") or "")
    if not INSTANCE_RE.fullmatch(instance_slug):
        raise ReleaseBrokerStoreError("release instance slug is invalid")
    repository = _require_mapping(
        bundle.get("repository"), field="release repository"
    )
    repository_id = _require_positive_int(
        repository.get("id"), field="release repository ID"
    )
    repository_full_name = str(repository.get("full_name") or "")
    if not REPOSITORY_RE.fullmatch(repository_full_name):
        raise ReleaseBrokerStoreError("release repository name is invalid")
    default_branch = str(repository.get("default_branch") or "")
    if (
        not default_branch
        or len(default_branch.encode("utf-8")) > 200
        or any(character.isspace() for character in default_branch)
    ):
        raise ReleaseBrokerStoreError("release default branch is invalid")
    bundle_id = str(bundle.get("bundle_id") or "")
    if not BUNDLE_ID_RE.fullmatch(bundle_id):
        raise ReleaseBrokerStoreError("release bundle ID is invalid")
    bundle_digest = _require_digest(
        bundle.get("bundle_digest"),
        field="release bundle digest",
    )
    bundle_digest_payload = {
        key: value
        for key, value in bundle.items()
        if key not in {"bundle_id", "bundle_digest"}
    }
    if sha256_json(bundle_digest_payload) != bundle_digest:
        raise ReleaseBrokerStoreError("release bundle digest does not match")
    expected_bundle_id = (
        "jlb-" + bundle_digest.removeprefix("sha256:")[:24]
    )
    if bundle_id != expected_bundle_id:
        raise ReleaseBrokerStoreError("release bundle ID does not match")
    bundle_expires_at = _parse_utc(
        bundle.get("expires_at"), field="release bundle expires_at"
    )
    if packet_expires_at > bundle_expires_at:
        raise ReleaseBrokerStoreError("release packet outlives its bundle")
    if enforce_freshness and now_epoch >= bundle_expires_at:
        raise ReleaseBrokerStoreError("release bundle has expired")
    initial_base_sha = _require_oid(
        bundle.get("initial_base_sha"), field="release initial base"
    )

    raw_steps = bundle.get("ordered_prs")
    if not isinstance(raw_steps, list) or not raw_steps or len(raw_steps) > 50:
        raise ReleaseBrokerStoreError("release ordered PR list is invalid")
    steps: list[dict[str, Any]] = []
    seen_prs: set[int] = set()
    for index, raw_step in enumerate(raw_steps):
        step = _require_mapping(
            raw_step, field=f"release PR at position {index}"
        )
        if step.get("position") != index:
            raise ReleaseBrokerStoreError(
                "release PR positions must be contiguous"
            )
        pr_number = _require_positive_int(
            step.get("number"), field=f"release PR {index} number"
        )
        if pr_number in seen_prs:
            raise ReleaseBrokerStoreError(
                "release PR numbers must be unique"
            )
        seen_prs.add(pr_number)
        head_sha = _require_oid(
            step.get("head_sha"), field=f"release PR {index} head"
        )
        expected_tree_sha = _require_oid(
            step.get("expected_merge_tree_sha"),
            field=f"release PR {index} expected merge tree",
        )
        normalized_step = dict(step)
        normalized_step["position"] = index
        normalized_step["number"] = pr_number
        normalized_step["head_sha"] = head_sha
        normalized_step["expected_merge_tree_sha"] = expected_tree_sha
        step_json = canonical_json(normalized_step)
        steps.append(
            {
                "position": index,
                "pr_number": pr_number,
                "head_sha": head_sha,
                "expected_tree_sha": expected_tree_sha,
                "step_json": step_json,
                "step_digest": sha256_text(step_json),
            }
        )

    assertion = _require_mapping(
        request.get("owner_assertion"), field="owner assertion"
    )
    owner_key_id = str(assertion.get("key_id") or "")
    if not KEY_ID_RE.fullmatch(owner_key_id):
        raise ReleaseBrokerStoreError("owner assertion key ID is invalid")
    payload = _require_mapping(
        assertion.get("payload"), field="owner assertion payload"
    )
    if payload.get("schema_version") != OWNER_ASSERTION_SCHEMA:
        raise ReleaseBrokerStoreError(
            "owner assertion payload schema is unsupported"
        )
    owner_nonce = str(payload.get("nonce") or "")
    if not NONCE_RE.fullmatch(owner_nonce):
        raise ReleaseBrokerStoreError("owner assertion nonce is invalid")
    owner_issuer = str(payload.get("issuer") or "")
    owner_actor_id = str(payload.get("actor_id") or "")
    if not TOKEN_RE.fullmatch(owner_issuer) or not TOKEN_RE.fullmatch(
        owner_actor_id
    ):
        raise ReleaseBrokerStoreError(
            "owner assertion issuer or actor is invalid"
        )
    if (
        payload.get("instance_slug") != instance_slug
        or payload.get("repository_id") != repository_id
        or payload.get("repository_full_name") != repository_full_name
        or payload.get("bundle_id") != bundle_id
        or payload.get("bundle_digest") != bundle_digest
        or payload.get("action") != RELEASE_ACTION
        or payload.get("merge_method") != MERGE_METHOD
        or payload.get("publish") is not False
    ):
        raise ReleaseBrokerStoreError(
            "owner assertion does not bind the release bundle"
        )
    assertion_expires_at = _parse_utc(
        payload.get("expires_at"), field="owner assertion expires_at"
    )
    if enforce_freshness and now_epoch >= assertion_expires_at:
        raise ReleaseBrokerStoreError("owner assertion has expired")
    owner_assertion_digest = sha256_json(assertion)

    bundle_json = canonical_json(bundle)
    bundle_json_digest = sha256_text(bundle_json)
    semantic = {
        "schema_version": BUNDLE_SEMANTIC_SCHEMA,
        "instance_slug": instance_slug,
        "repository_id": repository_id,
        "repository_full_name": repository_full_name,
        "bundle_id": bundle_id,
        "bundle_digest": bundle_digest,
        "initial_base_sha": initial_base_sha,
        "ordered_steps": [
            {
                "position": step["position"],
                "pr_number": step["pr_number"],
                "head_sha": step["head_sha"],
                "expected_tree_sha": step["expected_tree_sha"],
                "step_digest": step["step_digest"],
            }
            for step in steps
        ],
    }
    semantic_json = canonical_json(semantic)
    semantic_digest = sha256_text(semantic_json)
    bundle_key = (
        "jlrb-" + semantic_digest.removeprefix("sha256:")[:32]
    )
    packet_json = canonical_json(packet_value)
    return _PacketIdentity(
        packet_id=packet_id,
        request_digest=request_digest,
        packet_json=packet_json,
        packet_json_digest=sha256_text(packet_json),
        packet_created_at=packet_created_at,
        packet_expires_at=packet_expires_at,
        instance_slug=instance_slug,
        repository_id=repository_id,
        repository_full_name=repository_full_name,
        default_branch=default_branch,
        bundle_id=bundle_id,
        bundle_digest=bundle_digest,
        bundle_json=bundle_json,
        bundle_json_digest=bundle_json_digest,
        bundle_expires_at=bundle_expires_at,
        bundle_key=bundle_key,
        semantic_json=semantic_json,
        semantic_digest=semantic_digest,
        initial_base_sha=initial_base_sha,
        owner_key_id=owner_key_id,
        owner_nonce=owner_nonce,
        owner_assertion_digest=owner_assertion_digest,
        owner_issuer=owner_issuer,
        owner_actor_id=owner_actor_id,
        steps=tuple(steps),
    )


def semantic_bundle_key(
    packet: Mapping[str, Any],
    *,
    now: datetime | None = None,
    allow_expired: bool = False,
) -> str:
    return _packet_identity(
        packet,
        now_epoch=_now_epoch(now),
        enforce_freshness=not allow_expired,
    ).bundle_key


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _file_flags() -> int:
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _open_secure_directory_tree(path: Path) -> tuple[Path, int]:
    try:
        direct_info = os.lstat(path)
    except OSError as exc:
        raise UnsafeStoreError(
            "release broker database directory is unavailable"
        ) from exc
    if stat.S_ISLNK(direct_info.st_mode):
        raise UnsafeStoreError(
            "release broker database directory must not be a symlink"
        )
    try:
        canonical = path.resolve(strict=True)
    except OSError as exc:
        raise UnsafeStoreError(
            "release broker database directory is unavailable"
        ) from exc
    try:
        current_fd = os.open("/", _directory_flags())
    except OSError as exc:
        raise UnsafeStoreError(
            "release broker filesystem root is unsafe"
        ) from exc
    try:
        for component in canonical.parts[1:]:
            try:
                next_fd = os.open(
                    component,
                    _directory_flags(),
                    dir_fd=current_fd,
                )
            except OSError as exc:
                raise UnsafeStoreError(
                    "release broker database path contains an unsafe directory"
                ) from exc
            os.close(current_fd)
            current_fd = next_fd
            info = os.fstat(current_fd)
            if not stat.S_ISDIR(info.st_mode):
                raise UnsafeStoreError(
                    "release broker database path component is not a directory"
                )
            if hasattr(os, "geteuid") and info.st_uid not in {
                0,
                os.geteuid(),
            }:
                raise UnsafeStoreError(
                    "release broker database path has an untrusted owner"
                )
            writable_by_other = bool(info.st_mode & 0o022)
            sticky_root = bool(info.st_mode & stat.S_ISVTX and info.st_uid == 0)
            if writable_by_other and not sticky_root:
                raise UnsafeStoreError(
                    "release broker database path is writable by another identity"
                )
        return canonical, current_fd
    except Exception:
        os.close(current_fd)
        raise


def _require_secure_owner_mode(
    info: os.stat_result,
    *,
    field: str,
    directory: bool,
) -> None:
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode):
        raise UnsafeStoreError(f"{field} has the wrong file type")
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise UnsafeStoreError(f"{field} is not owned by the broker user")
    if info.st_mode & 0o077:
        raise UnsafeStoreError(f"{field} grants group or world permissions")
    if not directory and info.st_nlink != 1:
        raise UnsafeStoreError(f"{field} must not be hard-linked")


_SCHEMA = """
CREATE TABLE IF NOT EXISTS runtime_binding (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL,
    binding_digest TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    bound_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS packets (
    packet_id TEXT PRIMARY KEY,
    request_digest TEXT NOT NULL UNIQUE,
    packet_json TEXT NOT NULL,
    packet_json_digest TEXT NOT NULL,
    instance_slug TEXT NOT NULL,
    repository_id INTEGER NOT NULL CHECK (repository_id > 0),
    repository_full_name TEXT NOT NULL,
    bundle_key TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    bundle_digest TEXT NOT NULL,
    owner_key_id TEXT NOT NULL,
    owner_nonce TEXT NOT NULL,
    owner_assertion_digest TEXT NOT NULL,
    accepted_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS owner_nonces (
    owner_key_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    assertion_digest TEXT NOT NULL UNIQUE,
    packet_id TEXT NOT NULL UNIQUE REFERENCES packets(packet_id),
    instance_slug TEXT NOT NULL,
    repository_id INTEGER NOT NULL CHECK (repository_id > 0),
    issuer TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    consumed_at INTEGER NOT NULL,
    PRIMARY KEY(owner_key_id, nonce)
) STRICT;

CREATE TABLE IF NOT EXISTS bundles (
    bundle_key TEXT PRIMARY KEY,
    semantic_digest TEXT NOT NULL UNIQUE,
    semantic_json TEXT NOT NULL UNIQUE,
    bundle_json TEXT NOT NULL,
    bundle_json_digest TEXT NOT NULL,
    instance_slug TEXT NOT NULL,
    repository_id INTEGER NOT NULL CHECK (repository_id > 0),
    repository_full_name TEXT NOT NULL,
    default_branch TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    bundle_digest TEXT NOT NULL,
    initial_base_sha TEXT NOT NULL,
    step_count INTEGER NOT NULL CHECK (step_count > 0),
    state TEXT NOT NULL CHECK (
        state IN (
            'reserved', 'executing', 'succeeded', 'rejected',
            'partial', 'indeterminate'
        )
    ),
    first_packet_id TEXT NOT NULL REFERENCES packets(packet_id),
    last_packet_id TEXT NOT NULL REFERENCES packets(packet_id),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    terminal_at INTEGER,
    terminal_outcome TEXT,
    terminal_receipt_sequence INTEGER,
    UNIQUE(instance_slug, repository_id, bundle_id),
    UNIQUE(instance_slug, repository_id, bundle_digest),
    CHECK (
        (state IN ('reserved', 'executing')
         AND terminal_at IS NULL
         AND terminal_outcome IS NULL
         AND terminal_receipt_sequence IS NULL)
        OR
        (state IN ('succeeded', 'rejected', 'partial', 'indeterminate')
         AND terminal_at IS NOT NULL
         AND terminal_outcome = state
         AND terminal_receipt_sequence IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS one_active_bundle_per_repository
ON bundles(repository_id)
WHERE state IN ('reserved', 'executing');

CREATE TABLE IF NOT EXISTS bundle_steps (
    bundle_key TEXT NOT NULL REFERENCES bundles(bundle_key),
    position INTEGER NOT NULL CHECK (position >= 0),
    pr_number INTEGER NOT NULL CHECK (pr_number > 0),
    head_sha TEXT NOT NULL,
    step_digest TEXT NOT NULL,
    step_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN (
            'pending', 'mutation_pending', 'confirmed',
            'rejected', 'indeterminate'
        )
    ),
    expected_base_sha TEXT,
    active_attempt_id TEXT,
    merge_sha TEXT,
    parent_sha TEXT,
    tree_sha TEXT,
    merged_by TEXT,
    terminal_detail_json TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    confirmed_at INTEGER,
    PRIMARY KEY(bundle_key, position),
    UNIQUE(bundle_key, pr_number),
    CHECK (
        (state = 'pending'
         AND active_attempt_id IS NULL
         AND merge_sha IS NULL
         AND parent_sha IS NULL
         AND tree_sha IS NULL
         AND merged_by IS NULL
         AND confirmed_at IS NULL)
        OR
        (state = 'mutation_pending'
         AND active_attempt_id IS NOT NULL
         AND expected_base_sha IS NOT NULL
         AND merge_sha IS NULL
         AND parent_sha IS NULL
         AND tree_sha IS NULL
         AND merged_by IS NULL
         AND confirmed_at IS NULL)
        OR
        (state = 'confirmed'
         AND active_attempt_id IS NULL
         AND expected_base_sha IS NOT NULL
         AND merge_sha IS NOT NULL
         AND parent_sha IS NOT NULL
         AND tree_sha IS NOT NULL
         AND merged_by IS NOT NULL
         AND confirmed_at IS NOT NULL)
        OR
        (state IN ('rejected', 'indeterminate')
         AND active_attempt_id IS NULL
         AND confirmed_at IS NULL)
    )
) STRICT;

CREATE TABLE IF NOT EXISTS mutation_attempts (
    attempt_id TEXT PRIMARY KEY,
    bundle_key TEXT NOT NULL,
    position INTEGER NOT NULL,
    packet_id TEXT NOT NULL REFERENCES packets(packet_id),
    attempt_number INTEGER NOT NULL CHECK (attempt_number IN (1, 2)),
    precondition_digest TEXT NOT NULL,
    expected_base_sha TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('pending', 'confirmed', 'absent', 'indeterminate')
    ),
    merge_budget_day TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    terminal_at INTEGER,
    merge_sha TEXT,
    parent_sha TEXT,
    tree_sha TEXT,
    merged_by TEXT,
    terminal_detail_json TEXT,
    FOREIGN KEY(bundle_key, position)
        REFERENCES bundle_steps(bundle_key, position),
    UNIQUE(bundle_key, position, attempt_number),
    CHECK (
        (state = 'pending'
         AND terminal_at IS NULL
         AND merge_sha IS NULL
         AND parent_sha IS NULL
         AND tree_sha IS NULL
         AND merged_by IS NULL)
        OR
        (state = 'confirmed'
         AND terminal_at IS NOT NULL
         AND merge_sha IS NOT NULL
         AND parent_sha IS NOT NULL
         AND tree_sha IS NOT NULL
         AND merged_by IS NOT NULL)
        OR
        (state IN ('absent', 'indeterminate')
         AND terminal_at IS NOT NULL)
    )
) STRICT;

CREATE TABLE IF NOT EXISTS recovery_records (
    recovery_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    recovery_id TEXT NOT NULL UNIQUE,
    attempt_id TEXT NOT NULL REFERENCES mutation_attempts(attempt_id),
    bundle_key TEXT NOT NULL,
    position INTEGER NOT NULL,
    classification TEXT NOT NULL CHECK (
        classification IN ('confirmed', 'absent', 'indeterminate')
    ),
    evidence_digest TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    recorded_at INTEGER NOT NULL
) STRICT;

CREATE TRIGGER IF NOT EXISTS recovery_records_no_update
BEFORE UPDATE ON recovery_records
BEGIN
    SELECT RAISE(ABORT, 'recovery records are append-only');
END;

CREATE TRIGGER IF NOT EXISTS recovery_records_no_delete
BEFORE DELETE ON recovery_records
BEGIN
    SELECT RAISE(ABORT, 'recovery records are append-only');
END;

CREATE TABLE IF NOT EXISTS budget_events (
    event_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK (
        kind IN (
            'unique_request', 'owner_assertion', 'bundle',
            'mutation_attempt', 'confirmed_merge'
        )
    ),
    instance_slug TEXT NOT NULL,
    repository_id INTEGER NOT NULL CHECK (repository_id > 0),
    occurred_at INTEGER NOT NULL,
    utc_day TEXT NOT NULL,
    packet_id TEXT REFERENCES packets(packet_id),
    bundle_key TEXT,
    position INTEGER,
    attempt_id TEXT,
    detail_json TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS budget_hourly
ON budget_events(instance_slug, kind, occurred_at);

CREATE INDEX IF NOT EXISTS budget_daily
ON budget_events(instance_slug, kind, utc_day);

CREATE TRIGGER IF NOT EXISTS budget_events_no_update
BEFORE UPDATE ON budget_events
BEGIN
    SELECT RAISE(ABORT, 'budget events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS budget_events_no_delete
BEFORE DELETE ON budget_events
BEGIN
    SELECT RAISE(ABORT, 'budget events are append-only');
END;

CREATE TABLE IF NOT EXISTS receipts (
    receipt_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    bundle_key TEXT NOT NULL UNIQUE REFERENCES bundles(bundle_key),
    packet_id TEXT NOT NULL REFERENCES packets(packet_id),
    outcome TEXT NOT NULL CHECK (
        outcome IN ('succeeded', 'rejected', 'partial', 'indeterminate')
    ),
    receipt_digest TEXT NOT NULL UNIQUE,
    receipt_json TEXT NOT NULL,
    previous_chain_digest TEXT NOT NULL,
    chain_digest TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TRIGGER IF NOT EXISTS receipts_no_update
BEFORE UPDATE ON receipts
BEGIN
    SELECT RAISE(ABORT, 'receipts are append-only');
END;

CREATE TRIGGER IF NOT EXISTS receipts_no_delete
BEFORE DELETE ON receipts
BEGIN
    SELECT RAISE(ABORT, 'receipts are append-only');
END;

CREATE TABLE IF NOT EXISTS circuits (
    circuit_key TEXT PRIMARY KEY,
    instance_slug TEXT NOT NULL,
    repository_id INTEGER NOT NULL CHECK (repository_id > 0),
    repository_full_name TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('closed', 'open')),
    consecutive_indeterminate INTEGER NOT NULL DEFAULT 0
        CHECK (consecutive_indeterminate >= 0),
    opened_at INTEGER,
    reason_digest TEXT,
    reason_json TEXT,
    last_event_bundle_key TEXT,
    last_event_mode TEXT CHECK (
        last_event_mode IS NULL
        OR last_event_mode IN ('threshold', 'immediate')
    ),
    updated_at INTEGER NOT NULL,
    UNIQUE(instance_slug, repository_id),
    CHECK (
        (state = 'closed' AND opened_at IS NULL)
        OR
        (state = 'open'
         AND opened_at IS NOT NULL
         AND reason_digest IS NOT NULL
         AND reason_json IS NOT NULL)
    ),
    CHECK (
        (last_event_bundle_key IS NULL AND last_event_mode IS NULL)
        OR
        (last_event_bundle_key IS NOT NULL AND last_event_mode IS NOT NULL)
    )
) STRICT;
"""


class ReleaseBrokerStore:
    """Durable SQLite state for one isolated protected release broker."""

    def __init__(self, database_path: Path | str, *, timeout: float = 5.0):
        path = Path(database_path).expanduser()
        if not path.is_absolute():
            raise UnsafeStoreError(
                "release broker database path must be absolute"
            )
        if not path.name or path.name in {".", ".."}:
            raise UnsafeStoreError(
                "release broker database filename is invalid"
            )
        if type(timeout) not in (int, float) or timeout <= 0 or timeout > 60:
            raise ValueError("timeout must be between zero and 60 seconds")

        canonical_parent, directory_fd = _open_secure_directory_tree(
            path.parent
        )
        path = canonical_parent / path.name
        database_fd = -1
        connection: sqlite3.Connection | None = None
        try:
            _require_secure_owner_mode(
                os.fstat(directory_fd),
                field="release broker database directory",
                directory=True,
            )
            self._check_sidecars(directory_fd, path.name)
            try:
                database_fd = os.open(
                    path.name,
                    _file_flags(),
                    0o600,
                    dir_fd=directory_fd,
                )
            except OSError as exc:
                raise UnsafeStoreError(
                    "release broker database file is unsafe"
                ) from exc
            database_info = os.fstat(database_fd)
            _require_secure_owner_mode(
                database_info,
                field="release broker database file",
                directory=False,
            )
            named_info = os.stat(
                path.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if (
                named_info.st_dev,
                named_info.st_ino,
            ) != (
                database_info.st_dev,
                database_info.st_ino,
            ):
                raise UnsafeStoreError(
                    "release broker database name changed while opening"
                )

            uri = "file:" + quote(str(path), safe="/") + "?mode=rw"
            connection = sqlite3.connect(
                uri,
                uri=True,
                timeout=float(timeout),
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            self._configure(connection, timeout=float(timeout))
            self._initialize_schema(connection)
            self._validate_database(connection)
            self._check_sidecars(directory_fd, path.name)
        except Exception:
            if connection is not None:
                connection.close()
            if database_fd >= 0:
                os.close(database_fd)
            os.close(directory_fd)
            raise

        self.path = path
        self._directory_fd = directory_fd
        self._database_fd = database_fd
        self._db = connection
        self._closed = False
        self._binding_digest: str | None = None
        self._binding_json: str | None = None

    @staticmethod
    def _check_sidecars(directory_fd: int, name: str) -> None:
        for suffix in ("-journal", "-wal", "-shm"):
            try:
                info = os.stat(
                    name + suffix,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise UnsafeStoreError(
                    "release broker database sidecar is unsafe"
                ) from exc
            if not stat.S_ISREG(info.st_mode):
                raise UnsafeStoreError(
                    "release broker database sidecar has the wrong type"
                )
            if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
                raise UnsafeStoreError(
                    "release broker database sidecar has an unsafe owner"
                )
            if info.st_mode & 0o077:
                raise UnsafeStoreError(
                    "release broker database sidecar is accessible to others"
                )
            if info.st_nlink != 1:
                raise UnsafeStoreError(
                    "release broker database sidecar must not be hard-linked"
                )

    @staticmethod
    def _configure(
        connection: sqlite3.Connection,
        *,
        timeout: float,
    ) -> None:
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA foreign_keys = ON")
        mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if str(mode).lower() != "wal":
            raise UnsafeStoreError(
                "release broker database could not enable WAL mode"
            )
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA fullfsync = ON")
        connection.execute("PRAGMA checkpoint_fullfsync = ON")
        connection.execute("PRAGMA wal_autocheckpoint = 1000")
        connection.execute("PRAGMA temp_store = MEMORY")
        connection.execute("PRAGMA secure_delete = ON")
        connection.execute(
            f"PRAGMA busy_timeout = {max(1, int(timeout * 1000))}"
        )

    @staticmethod
    def _initialize_schema(connection: sqlite3.Connection) -> None:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version not in {0, SCHEMA_VERSION}:
            raise StoreCorruptionError(
                f"unsupported release broker schema version: {version}"
            )
        if version == 0:
            try:
                connection.executescript(
                    "BEGIN IMMEDIATE;\n"
                    + _SCHEMA
                    + f"\nPRAGMA user_version = {SCHEMA_VERSION};\n"
                    + "COMMIT;\n"
                )
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _validate_database(connection: sqlite3.Connection) -> None:
        settings = {
            "foreign_keys": int(
                connection.execute("PRAGMA foreign_keys").fetchone()[0]
            ),
            "trusted_schema": int(
                connection.execute("PRAGMA trusted_schema").fetchone()[0]
            ),
            "synchronous": int(
                connection.execute("PRAGMA synchronous").fetchone()[0]
            ),
            "journal_mode": str(
                connection.execute("PRAGMA journal_mode").fetchone()[0]
            ).lower(),
        }
        if settings != {
            "foreign_keys": 1,
            "trusted_schema": 0,
            "synchronous": 2,
            "journal_mode": "wal",
        }:
            raise UnsafeStoreError(
                "release broker database durability pragmas are not active"
            )
        if [
            row[0] for row in connection.execute("PRAGMA quick_check").fetchall()
        ] != ["ok"]:
            raise StoreCorruptionError(
                "release broker database integrity check failed"
            )
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise StoreCorruptionError(
                "release broker database foreign-key check failed"
            )

    def __enter__(self) -> ReleaseBrokerStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._db.close()
        finally:
            os.close(self._database_fd)
            os.close(self._directory_fd)

    def _ensure_open(self) -> None:
        if self._closed:
            raise ReleaseBrokerStoreError("release broker store is closed")

    @contextmanager
    def _immediate(self) -> Iterator[None]:
        self._ensure_open()
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._assert_runtime_bound()
            yield
            self._db.execute("COMMIT")
        except Exception:
            if self._db.in_transaction:
                self._db.execute("ROLLBACK")
            raise

    def bind_runtime(
        self,
        binding: Mapping[str, Any],
        *,
        now: datetime | None = None,
    ) -> str:
        """Permanently bind durable state to one canonical trusted config."""

        binding_json = canonical_json(binding)
        binding_digest = sha256_text(binding_json)
        now_epoch = _now_epoch(now)
        self._ensure_open()
        try:
            self._db.execute("BEGIN IMMEDIATE")
            rows = self._db.execute(
                """
                SELECT schema_version, binding_digest, binding_json
                FROM runtime_binding
                ORDER BY singleton
                """
            ).fetchall()
            if len(rows) > 1:
                raise StoreCorruptionError(
                    "release broker has multiple runtime bindings"
                )
            if rows:
                row = rows[0]
                persisted_json = str(row["binding_json"])
                persisted_digest = str(row["binding_digest"])
                if int(row["schema_version"]) != SCHEMA_VERSION:
                    raise StoreCorruptionError(
                        "release broker binding schema is corrupted"
                    )
                _decode_canonical_json(
                    persisted_json, field="release broker runtime binding"
                )
                if sha256_text(persisted_json) != persisted_digest:
                    raise StoreCorruptionError(
                        "release broker runtime binding digest is corrupted"
                    )
                if (
                    persisted_digest != binding_digest
                    or persisted_json != binding_json
                ):
                    raise StoreBindingError(
                        "release broker database is bound to another config"
                    )
            else:
                durable_rows = sum(
                    int(
                        self._db.execute(
                            f"SELECT count(*) FROM {table}"
                        ).fetchone()[0]
                    )
                    for table in (
                        "packets",
                        "owner_nonces",
                        "bundles",
                        "bundle_steps",
                        "mutation_attempts",
                        "recovery_records",
                        "budget_events",
                        "receipts",
                        "circuits",
                    )
                )
                if durable_rows:
                    raise StoreBindingError(
                        "unbound release broker database contains durable state"
                    )
                self._db.execute(
                    """
                    INSERT INTO runtime_binding(
                        singleton, schema_version, binding_digest,
                        binding_json, bound_at
                    ) VALUES (1, ?, ?, ?, ?)
                    """,
                    (
                        SCHEMA_VERSION,
                        binding_digest,
                        binding_json,
                        now_epoch,
                    ),
                )
            self._db.execute("COMMIT")
        except Exception:
            if self._db.in_transaction:
                self._db.execute("ROLLBACK")
            raise
        self._binding_digest = binding_digest
        self._binding_json = binding_json
        return binding_digest

    def _assert_runtime_bound(self) -> None:
        if self._binding_digest is None or self._binding_json is None:
            raise StoreBindingError(
                "release broker store must be bound before use"
            )
        rows = self._db.execute(
            """
            SELECT schema_version, binding_digest, binding_json
            FROM runtime_binding
            ORDER BY singleton
            """
        ).fetchall()
        if len(rows) != 1:
            raise StoreCorruptionError(
                "release broker runtime binding is missing or duplicated"
            )
        row = rows[0]
        persisted_json = str(row["binding_json"])
        persisted_digest = str(row["binding_digest"])
        if (
            int(row["schema_version"]) != SCHEMA_VERSION
            or sha256_text(persisted_json) != persisted_digest
        ):
            raise StoreCorruptionError(
                "release broker runtime binding is corrupted"
            )
        _decode_canonical_json(
            persisted_json, field="release broker runtime binding"
        )
        if (
            persisted_digest != self._binding_digest
            or persisted_json != self._binding_json
        ):
            raise StoreBindingError(
                "release broker runtime binding changed while running"
            )

    def pragma_state(self) -> dict[str, int | str]:
        self._ensure_open()
        return {
            "journal_mode": str(
                self._db.execute("PRAGMA journal_mode").fetchone()[0]
            ).lower(),
            "synchronous": int(
                self._db.execute("PRAGMA synchronous").fetchone()[0]
            ),
            "foreign_keys": int(
                self._db.execute("PRAGMA foreign_keys").fetchone()[0]
            ),
            "trusted_schema": int(
                self._db.execute("PRAGMA trusted_schema").fetchone()[0]
            ),
        }

    @staticmethod
    def _circuit_key(instance_slug: str, repository_id: int) -> str:
        return f"{instance_slug}:{repository_id}"

    def _assert_circuit_closed(
        self,
        *,
        instance_slug: str,
        repository_id: int,
    ) -> None:
        row = self._db.execute(
            """
            SELECT state, consecutive_indeterminate
            FROM circuits
            WHERE instance_slug = ? AND repository_id = ?
            """,
            (instance_slug, repository_id),
        ).fetchone()
        if row is not None and row["state"] == "open":
            raise CircuitOpenError(
                "repository release circuit is open after "
                f"{row['consecutive_indeterminate']} indeterminate outcomes"
            )

    def _hourly_budget(
        self,
        *,
        kind: str,
        budget_name: str,
        limit: int,
        instance_slug: str,
        now_epoch: int,
    ) -> None:
        cutoff = now_epoch - REQUEST_WINDOW_SECONDS
        rows = self._db.execute(
            """
            SELECT occurred_at
            FROM budget_events
            WHERE instance_slug = ?
              AND kind = ?
              AND occurred_at > ?
            ORDER BY occurred_at, event_sequence
            """,
            (instance_slug, kind, cutoff),
        ).fetchall()
        used = len(rows)
        if used >= limit:
            reset_epoch = (
                max(now_epoch + 1, int(rows[0]["occurred_at"]) + 3600)
                if rows
                else now_epoch + 3600
            )
            raise BudgetExceeded(
                budget=budget_name,
                limit=limit,
                used=used,
                reset_at=datetime.fromtimestamp(
                    reset_epoch, tz=timezone.utc
                ),
            )

    def _daily_budget(
        self,
        *,
        kind: str,
        budget_name: str,
        limit: int,
        instance_slug: str,
        day: str,
        now_epoch: int,
    ) -> None:
        used = int(
            self._db.execute(
                """
                SELECT count(*)
                FROM budget_events
                WHERE instance_slug = ?
                  AND kind = ?
                  AND utc_day = ?
                """,
                (instance_slug, kind, day),
            ).fetchone()[0]
        )
        if used >= limit:
            raise BudgetExceeded(
                budget=budget_name,
                limit=limit,
                used=used,
                reset_at=_next_utc_day(now_epoch),
            )

    def _insert_budget_event(
        self,
        *,
        event_key: str,
        kind: str,
        identity: _PacketIdentity,
        now_epoch: int,
        packet_id: str | None,
        bundle_key: str | None,
        position: int | None,
        attempt_id: str | None,
        detail: Mapping[str, Any],
        day: str | None = None,
    ) -> None:
        self._db.execute(
            """
            INSERT INTO budget_events(
                event_key, kind, instance_slug, repository_id,
                occurred_at, utc_day, packet_id, bundle_key,
                position, attempt_id, detail_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_key,
                kind,
                identity.instance_slug,
                identity.repository_id,
                now_epoch,
                day or _utc_day(now_epoch),
                packet_id,
                bundle_key,
                position,
                attempt_id,
                canonical_json(detail),
            ),
        )

    def _validate_packet_row(
        self,
        row: sqlite3.Row,
        identity: _PacketIdentity,
    ) -> None:
        if (
            row["request_digest"] != identity.request_digest
            or row["packet_json"] != identity.packet_json
            or row["packet_json_digest"] != identity.packet_json_digest
            or row["bundle_key"] != identity.bundle_key
            or row["bundle_id"] != identity.bundle_id
            or row["bundle_digest"] != identity.bundle_digest
            or row["owner_key_id"] != identity.owner_key_id
            or row["owner_nonce"] != identity.owner_nonce
            or row["owner_assertion_digest"]
            != identity.owner_assertion_digest
        ):
            raise PacketConflictError(
                "release packet ID conflicts with persisted content"
            )
        if sha256_text(str(row["packet_json"])) != row["packet_json_digest"]:
            raise StoreCorruptionError(
                "persisted release packet digest is corrupted"
            )
        _decode_canonical_json(
            row["packet_json"], field="persisted release packet"
        )

    def _validate_bundle_row(
        self,
        row: sqlite3.Row,
        identity: _PacketIdentity | None = None,
    ) -> None:
        semantic_json = str(row["semantic_json"])
        bundle_json = str(row["bundle_json"])
        if (
            sha256_text(semantic_json) != row["semantic_digest"]
            or sha256_text(bundle_json) != row["bundle_json_digest"]
        ):
            raise StoreCorruptionError(
                "persisted release bundle digest is corrupted"
            )
        semantic_value = _decode_canonical_json(
            semantic_json, field="persisted release bundle semantic"
        )
        bundle_value = _decode_canonical_json(
            bundle_json, field="persisted release bundle"
        )
        expected_key = (
            "jlrb-"
            + str(row["semantic_digest"]).removeprefix("sha256:")[:32]
        )
        if expected_key != row["bundle_key"]:
            raise StoreCorruptionError(
                "persisted release bundle key is corrupted"
            )
        digest_payload = {
            key: value
            for key, value in bundle_value.items()
            if key not in {"bundle_id", "bundle_digest"}
        }
        expected_bundle_digest = sha256_json(digest_payload)
        expected_bundle_id = (
            "jlb-"
            + expected_bundle_digest.removeprefix("sha256:")[:24]
        )
        repository = bundle_value.get("repository")
        ordered_steps = semantic_value.get("ordered_steps")
        if (
            not isinstance(repository, dict)
            or not isinstance(ordered_steps, list)
            or bundle_value.get("bundle_digest") != expected_bundle_digest
            or bundle_value.get("bundle_id") != expected_bundle_id
            or row["bundle_digest"] != expected_bundle_digest
            or row["bundle_id"] != expected_bundle_id
            or row["instance_slug"] != bundle_value.get("instance_slug")
            or int(row["repository_id"]) != repository.get("id")
            or row["repository_full_name"] != repository.get("full_name")
            or row["default_branch"] != repository.get("default_branch")
            or row["initial_base_sha"] != bundle_value.get("initial_base_sha")
            or int(row["step_count"]) != len(ordered_steps)
            or semantic_value.get("instance_slug") != row["instance_slug"]
            or semantic_value.get("repository_id") != row["repository_id"]
            or semantic_value.get("repository_full_name")
            != row["repository_full_name"]
            or semantic_value.get("bundle_id") != row["bundle_id"]
            or semantic_value.get("bundle_digest") != row["bundle_digest"]
            or semantic_value.get("initial_base_sha")
            != row["initial_base_sha"]
        ):
            raise StoreCorruptionError(
                "persisted release bundle columns are corrupted"
            )
        if identity is not None and (
            row["bundle_key"] != identity.bundle_key
            or row["semantic_digest"] != identity.semantic_digest
            or semantic_json != identity.semantic_json
            or bundle_json != identity.bundle_json
            or row["bundle_json_digest"] != identity.bundle_json_digest
            or row["bundle_id"] != identity.bundle_id
            or row["bundle_digest"] != identity.bundle_digest
            or row["initial_base_sha"] != identity.initial_base_sha
            or int(row["step_count"]) != len(identity.steps)
        ):
            raise BundleConflictError(
                "semantic release bundle conflicts with persisted content"
            )

    def _load_bundle_receipt(
        self,
        bundle_key: str,
    ) -> tuple[str, str, str, str, dict[str, Any]] | None:
        row = self._db.execute(
            """
            SELECT receipt_sequence, packet_id, outcome, receipt_digest,
                   receipt_json, previous_chain_digest, chain_digest,
                   created_at, bundle_key
            FROM receipts
            WHERE bundle_key = ?
            """,
            (bundle_key,),
        ).fetchone()
        if row is None:
            return None
        receipt = self._decode_receipt_row(row)
        return (
            str(row["receipt_digest"]),
            str(row["chain_digest"]),
            str(row["packet_id"]),
            str(row["outcome"]),
            receipt,
        )

    @staticmethod
    def _receipt_chain_digest(
        *,
        sequence: int,
        bundle_key: str,
        packet_id: str,
        outcome: str,
        receipt_digest: str,
        previous_chain_digest: str,
        created_at: int,
    ) -> str:
        return sha256_json(
            {
                "schema_version": RECEIPT_CHAIN_SCHEMA,
                "sequence": sequence,
                "bundle_key": bundle_key,
                "packet_id": packet_id,
                "outcome": outcome,
                "receipt_digest": receipt_digest,
                "previous_chain_digest": previous_chain_digest,
                "created_at": _epoch_text(created_at),
            }
        )

    def _decode_receipt_row(self, row: sqlite3.Row) -> dict[str, Any]:
        receipt_json = str(row["receipt_json"])
        receipt = _decode_canonical_json(
            receipt_json, field="release broker receipt"
        )
        if sha256_text(receipt_json) != row["receipt_digest"]:
            raise StoreCorruptionError(
                "release broker receipt digest is corrupted"
            )
        expected_chain = self._receipt_chain_digest(
            sequence=int(row["receipt_sequence"]),
            bundle_key=str(row["bundle_key"]),
            packet_id=str(row["packet_id"]),
            outcome=str(row["outcome"]),
            receipt_digest=str(row["receipt_digest"]),
            previous_chain_digest=str(row["previous_chain_digest"]),
            created_at=int(row["created_at"]),
        )
        if expected_chain != row["chain_digest"]:
            raise StoreCorruptionError(
                "release broker receipt chain entry is corrupted"
            )
        return receipt

    def _reservation(
        self,
        *,
        identity: _PacketIdentity,
        disposition: ReservationDisposition,
        bundle: sqlite3.Row,
    ) -> Reservation:
        receipt = self._load_bundle_receipt(identity.bundle_key)
        if bundle["state"] in TERMINAL_BUNDLE_STATES:
            if receipt is None:
                raise StoreCorruptionError(
                    "terminal release bundle has no receipt"
                )
            if receipt[2] != identity.packet_id:
                raise StoreCorruptionError(
                    "release receipt is bound to another packet"
                )
            return Reservation(
                disposition=disposition,
                packet_id=identity.packet_id,
                bundle_key=identity.bundle_key,
                bundle_id=identity.bundle_id,
                bundle_digest=identity.bundle_digest,
                repository_id=identity.repository_id,
                state=str(bundle["state"]),
                receipt=receipt[4],
                receipt_packet_id=receipt[2],
            )
        if receipt is not None:
            raise StoreCorruptionError(
                "active release bundle unexpectedly has a receipt"
            )
        return Reservation(
            disposition=disposition,
            packet_id=identity.packet_id,
            bundle_key=identity.bundle_key,
            bundle_id=identity.bundle_id,
            bundle_digest=identity.bundle_digest,
            repository_id=identity.repository_id,
            state=str(bundle["state"]),
        )

    def reserve(
        self,
        packet: Mapping[str, Any],
        limits: BudgetLimits,
        *,
        now: datetime | None = None,
    ) -> Reservation:
        """Atomically accept a packet, assertion nonce, and semantic bundle."""

        now_epoch = _now_epoch(now)
        # Canonical identity is computed before the write lock, but freshness
        # is checked again for a genuinely new packet while holding the lock.
        identity = _packet_identity(
            packet,
            now_epoch=now_epoch,
            enforce_freshness=False,
        )
        with self._immediate():
            packet_row = self._db.execute(
                "SELECT * FROM packets WHERE packet_id = ?",
                (identity.packet_id,),
            ).fetchone()
            if packet_row is not None:
                self._validate_packet_row(packet_row, identity)
                bundle = self._db.execute(
                    "SELECT * FROM bundles WHERE bundle_key = ?",
                    (identity.bundle_key,),
                ).fetchone()
                if bundle is None:
                    raise StoreCorruptionError(
                        "accepted release packet has no semantic bundle"
                    )
                self._validate_bundle_row(bundle, identity)
                disposition: ReservationDisposition = (
                    "exact_terminal_replay"
                    if bundle["state"] in TERMINAL_BUNDLE_STATES
                    else "exact_pending"
                )
                return self._reservation(
                    identity=identity,
                    disposition=disposition,
                    bundle=bundle,
                )

            # This is a new authorization.  Expired exact packets may replay,
            # but expired packets may never establish a new reservation.
            identity = _packet_identity(
                packet,
                now_epoch=now_epoch,
                enforce_freshness=True,
            )
            digest_row = self._db.execute(
                "SELECT packet_id FROM packets WHERE request_digest = ?",
                (identity.request_digest,),
            ).fetchone()
            if digest_row is not None:
                raise PacketConflictError(
                    "release request digest belongs to another packet"
                )
            bundle = self._db.execute(
                "SELECT * FROM bundles WHERE bundle_key = ?",
                (identity.bundle_key,),
            ).fetchone()
            if bundle is not None:
                self._validate_bundle_row(bundle, identity)
                raise SemanticTerminalReplayError(
                    "a fresh packet cannot alias an existing release bundle"
                )
            self._assert_circuit_closed(
                instance_slug=identity.instance_slug,
                repository_id=identity.repository_id,
            )
            self._hourly_budget(
                kind="unique_request",
                budget_name="unique_requests_per_hour",
                limit=limits.unique_requests_per_hour,
                instance_slug=identity.instance_slug,
                now_epoch=now_epoch,
            )
            self._hourly_budget(
                kind="owner_assertion",
                budget_name="owner_assertions_per_hour",
                limit=limits.owner_assertions_per_hour,
                instance_slug=identity.instance_slug,
                now_epoch=now_epoch,
            )
            nonce_row = self._db.execute(
                """
                SELECT packet_id, assertion_digest
                FROM owner_nonces
                WHERE owner_key_id = ? AND nonce = ?
                """,
                (identity.owner_key_id, identity.owner_nonce),
            ).fetchone()
            assertion_row = self._db.execute(
                """
                SELECT packet_id, owner_key_id, nonce
                FROM owner_nonces
                WHERE assertion_digest = ?
                """,
                (identity.owner_assertion_digest,),
            ).fetchone()
            if nonce_row is not None or assertion_row is not None:
                raise NonceReplayError(
                    "owner assertion nonce or digest was already consumed"
                )

            if len(identity.steps) > limits.max_prs_per_bundle:
                raise BudgetExceeded(
                    budget="max_prs_per_bundle",
                    limit=limits.max_prs_per_bundle,
                    used=len(identity.steps),
                    reset_at=datetime.fromtimestamp(
                        identity.bundle_expires_at, tz=timezone.utc
                    ),
                )
            conflicting_id = self._db.execute(
                """
                SELECT bundle_key
                FROM bundles
                WHERE instance_slug = ?
                  AND repository_id = ?
                  AND bundle_id = ?
                """,
                (
                    identity.instance_slug,
                    identity.repository_id,
                    identity.bundle_id,
                ),
            ).fetchone()
            if conflicting_id is not None:
                raise BundleConflictError(
                    "release bundle ID conflicts with another digest"
                )
            active = self._db.execute(
                """
                SELECT bundle_key
                FROM bundles
                WHERE repository_id = ?
                  AND state IN ('reserved', 'executing')
                """,
                (identity.repository_id,),
            ).fetchone()
            if active is not None:
                raise ActiveBundleError(
                    "repository already has an active release bundle"
                )
            day = _utc_day(now_epoch)
            self._daily_budget(
                kind="bundle",
                budget_name="bundles_per_day",
                limit=limits.bundles_per_day,
                instance_slug=identity.instance_slug,
                day=day,
                now_epoch=now_epoch,
            )
            self._db.execute(
                """
                INSERT INTO packets(
                    packet_id, request_digest, packet_json,
                    packet_json_digest, instance_slug, repository_id,
                    repository_full_name, bundle_key, bundle_id,
                    bundle_digest, owner_key_id, owner_nonce,
                    owner_assertion_digest, accepted_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    identity.packet_id,
                    identity.request_digest,
                    identity.packet_json,
                    identity.packet_json_digest,
                    identity.instance_slug,
                    identity.repository_id,
                    identity.repository_full_name,
                    identity.bundle_key,
                    identity.bundle_id,
                    identity.bundle_digest,
                    identity.owner_key_id,
                    identity.owner_nonce,
                    identity.owner_assertion_digest,
                    now_epoch,
                    identity.packet_expires_at,
                ),
            )
            try:
                self._db.execute(
                    """
                    INSERT INTO owner_nonces(
                        owner_key_id, nonce, assertion_digest, packet_id,
                        instance_slug, repository_id, issuer, actor_id,
                        consumed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        identity.owner_key_id,
                        identity.owner_nonce,
                        identity.owner_assertion_digest,
                        identity.packet_id,
                        identity.instance_slug,
                        identity.repository_id,
                        identity.owner_issuer,
                        identity.owner_actor_id,
                        now_epoch,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise NonceReplayError(
                    "owner assertion nonce or digest was already consumed"
                ) from exc
            self._insert_budget_event(
                event_key="request:" + identity.packet_id,
                kind="unique_request",
                identity=identity,
                now_epoch=now_epoch,
                packet_id=identity.packet_id,
                bundle_key=identity.bundle_key,
                position=None,
                attempt_id=None,
                detail={
                    "request_digest": identity.request_digest,
                    "window_seconds": REQUEST_WINDOW_SECONDS,
                    "limit": limits.unique_requests_per_hour,
                },
            )
            self._insert_budget_event(
                event_key=(
                    "assertion:"
                    + identity.owner_assertion_digest.removeprefix("sha256:")
                ),
                kind="owner_assertion",
                identity=identity,
                now_epoch=now_epoch,
                packet_id=identity.packet_id,
                bundle_key=identity.bundle_key,
                position=None,
                attempt_id=None,
                detail={
                    "assertion_digest": identity.owner_assertion_digest,
                    "owner_key_id": identity.owner_key_id,
                    "limit": limits.owner_assertions_per_hour,
                },
            )

            self._db.execute(
                """
                INSERT INTO bundles(
                    bundle_key, semantic_digest, semantic_json,
                    bundle_json, bundle_json_digest, instance_slug,
                    repository_id, repository_full_name, default_branch,
                    bundle_id, bundle_digest, initial_base_sha,
                    step_count, state, first_packet_id, last_packet_id,
                    created_at, expires_at, updated_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    'reserved', ?, ?, ?, ?, ?
                )
                """,
                (
                    identity.bundle_key,
                    identity.semantic_digest,
                    identity.semantic_json,
                    identity.bundle_json,
                    identity.bundle_json_digest,
                    identity.instance_slug,
                    identity.repository_id,
                    identity.repository_full_name,
                    identity.default_branch,
                    identity.bundle_id,
                    identity.bundle_digest,
                    identity.initial_base_sha,
                    len(identity.steps),
                    identity.packet_id,
                    identity.packet_id,
                    now_epoch,
                    identity.bundle_expires_at,
                    now_epoch,
                ),
            )
            for step in identity.steps:
                self._db.execute(
                    """
                    INSERT INTO bundle_steps(
                        bundle_key, position, pr_number, head_sha,
                        step_digest, step_json, state,
                        expected_base_sha, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
                    """,
                    (
                        identity.bundle_key,
                        step["position"],
                        step["pr_number"],
                        step["head_sha"],
                        step["step_digest"],
                        step["step_json"],
                        (
                            identity.initial_base_sha
                            if step["position"] == 0
                            else None
                        ),
                        now_epoch,
                        now_epoch,
                    ),
                )
            self._insert_budget_event(
                event_key="bundle:" + identity.bundle_key,
                kind="bundle",
                identity=identity,
                now_epoch=now_epoch,
                packet_id=identity.packet_id,
                bundle_key=identity.bundle_key,
                position=None,
                attempt_id=None,
                detail={
                    "bundle_digest": identity.bundle_digest,
                    "limit": limits.bundles_per_day,
                    "step_count": len(identity.steps),
                },
            )
            bundle = self._db.execute(
                "SELECT * FROM bundles WHERE bundle_key = ?",
                (identity.bundle_key,),
            ).fetchone()
            assert bundle is not None
            return self._reservation(
                identity=identity,
                disposition="new_bundle",
                bundle=bundle,
            )

    def _packet_for_bundle(
        self,
        *,
        packet_id: str,
        bundle_key: str,
    ) -> sqlite3.Row:
        row = self._db.execute(
            "SELECT * FROM packets WHERE packet_id = ?",
            (packet_id,),
        ).fetchone()
        if row is None:
            raise StateTransitionError("release packet is not accepted")
        if row["bundle_key"] != bundle_key:
            raise StateTransitionError(
                "release packet does not bind this bundle"
            )
        if sha256_text(str(row["packet_json"])) != row["packet_json_digest"]:
            raise StoreCorruptionError(
                "persisted release packet digest is corrupted"
            )
        packet_value = _decode_canonical_json(
            row["packet_json"], field="persisted release packet"
        )
        identity = _packet_identity(
            packet_value,
            now_epoch=max(0, int(row["expires_at"]) - 1),
            enforce_freshness=False,
        )
        if (
            identity.packet_id != row["packet_id"]
            or identity.request_digest != row["request_digest"]
            or identity.packet_json_digest != row["packet_json_digest"]
            or identity.bundle_key != row["bundle_key"]
            or identity.bundle_id != row["bundle_id"]
            or identity.bundle_digest != row["bundle_digest"]
            or identity.owner_key_id != row["owner_key_id"]
            or identity.owner_nonce != row["owner_nonce"]
            or identity.owner_assertion_digest
            != row["owner_assertion_digest"]
        ):
            raise StoreCorruptionError(
                "persisted release packet columns are corrupted"
            )
        return row

    def _bundle_and_step(
        self,
        *,
        bundle_key: str,
        position: int,
    ) -> tuple[sqlite3.Row, sqlite3.Row]:
        if not BUNDLE_KEY_RE.fullmatch(bundle_key):
            raise ReleaseBrokerStoreError("release bundle key is invalid")
        if type(position) is not int or position < 0 or position > 49:
            raise ReleaseBrokerStoreError("release step position is invalid")
        bundle = self._db.execute(
            "SELECT * FROM bundles WHERE bundle_key = ?",
            (bundle_key,),
        ).fetchone()
        if bundle is None:
            raise StateTransitionError("release bundle is not reserved")
        self._validate_bundle_row(bundle)
        step = self._db.execute(
            """
            SELECT *
            FROM bundle_steps
            WHERE bundle_key = ? AND position = ?
            """,
            (bundle_key, position),
        ).fetchone()
        if step is None:
            raise StateTransitionError("release step is not reserved")
        if sha256_text(str(step["step_json"])) != step["step_digest"]:
            raise StoreCorruptionError(
                "persisted release step digest is corrupted"
            )
        step_value = _decode_canonical_json(
            step["step_json"], field="persisted release step"
        )
        if (
            step_value.get("position") != int(step["position"])
            or step_value.get("number") != int(step["pr_number"])
            or step_value.get("head_sha") != step["head_sha"]
        ):
            raise StoreCorruptionError(
                "persisted release step columns are corrupted"
            )
        return bundle, step

    def begin_mutation(
        self,
        bundle_key: str,
        position: int,
        packet_id: str,
        attempt_id: str,
        limits: BudgetLimits,
        *,
        expected_base_sha: str,
        precondition_digest: str,
        now: datetime | None = None,
    ) -> MutationReservation:
        """Charge exactly one external squash-merge attempt before mutation."""

        if not PACKET_ID_RE.fullmatch(packet_id):
            raise ReleaseBrokerStoreError("release packet ID is invalid")
        if not ATTEMPT_ID_RE.fullmatch(attempt_id):
            raise ReleaseBrokerStoreError("release attempt ID is invalid")
        expected_base_sha = _require_oid(
            expected_base_sha, field="expected release base"
        )
        precondition_digest = _require_digest(
            precondition_digest, field="release precondition digest"
        )
        now_epoch = _now_epoch(now)
        with self._immediate():
            bundle, step = self._bundle_and_step(
                bundle_key=bundle_key, position=position
            )
            self._packet_for_bundle(
                packet_id=packet_id, bundle_key=bundle_key
            )
            if bundle["state"] in TERMINAL_BUNDLE_STATES:
                receipt = self._load_bundle_receipt(bundle_key)
                if receipt is None:
                    raise StoreCorruptionError(
                        "terminal release bundle has no receipt"
                    )
                return MutationReservation(
                    disposition="terminal_replay",
                    packet_id=packet_id,
                    bundle_key=bundle_key,
                    position=position,
                    attempt_id=None,
                    expected_base_sha=None,
                    charged_at=None,
                    receipt=receipt[4],
                )
            if now_epoch >= int(bundle["expires_at"]):
                raise StateTransitionError(
                    "release bundle execution window has expired"
                )
            self._assert_circuit_closed(
                instance_slug=str(bundle["instance_slug"]),
                repository_id=int(bundle["repository_id"]),
            )
            if step["state"] == "confirmed":
                return MutationReservation(
                    disposition="step_confirmed",
                    packet_id=packet_id,
                    bundle_key=bundle_key,
                    position=position,
                    attempt_id=None,
                    expected_base_sha=str(step["expected_base_sha"]),
                    charged_at=None,
                )
            if step["state"] == "mutation_pending":
                active = self._db.execute(
                    """
                    SELECT *
                    FROM mutation_attempts
                    WHERE attempt_id = ?
                    """,
                    (step["active_attempt_id"],),
                ).fetchone()
                if active is None:
                    raise StoreCorruptionError(
                        "release step points to a missing mutation attempt"
                    )
                if (
                    active["attempt_id"] == attempt_id
                    and active["packet_id"] == packet_id
                    and active["precondition_digest"] == precondition_digest
                    and active["expected_base_sha"] == expected_base_sha
                ):
                    return MutationReservation(
                        disposition="already_charged",
                        packet_id=packet_id,
                        bundle_key=bundle_key,
                        position=position,
                        attempt_id=attempt_id,
                        expected_base_sha=expected_base_sha,
                        charged_at=_epoch_text(int(active["started_at"])),
                    )
                raise PendingRecoveryError(
                    "release step has a charged attempt awaiting recovery"
                )
            if step["state"] != "pending":
                raise StateTransitionError(
                    "release step cannot begin another mutation"
                )

            if position == 0:
                required_base = str(bundle["initial_base_sha"])
            else:
                prior = self._db.execute(
                    """
                    SELECT state, merge_sha
                    FROM bundle_steps
                    WHERE bundle_key = ? AND position = ?
                    """,
                    (bundle_key, position - 1),
                ).fetchone()
                if (
                    prior is None
                    or prior["state"] != "confirmed"
                    or prior["merge_sha"] is None
                ):
                    raise StateTransitionError(
                        "prior release step is not confirmed"
                    )
                required_base = str(prior["merge_sha"])
            if expected_base_sha != required_base:
                raise StateTransitionError(
                    "release attempt base does not match the authorized chain"
                )

            attempts = self._db.execute(
                """
                SELECT attempt_id, packet_id, state
                FROM mutation_attempts
                WHERE bundle_key = ? AND position = ?
                ORDER BY attempt_number
                """,
                (bundle_key, position),
            ).fetchall()
            if len(attempts) >= MAX_ATTEMPTS_PER_STEP:
                raise StateTransitionError(
                    "release step exhausted its single absent-state retry"
                )
            if attempts:
                prior_attempt = attempts[-1]
                if prior_attempt["state"] != "absent":
                    raise StateTransitionError(
                        "release step's previous attempt is not safely absent"
                    )
                if prior_attempt["packet_id"] != packet_id:
                    raise StateTransitionError(
                        "release retry requires exact packet replay"
                    )
            if self._db.execute(
                "SELECT 1 FROM mutation_attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone():
                raise StateTransitionError(
                    "release mutation attempt ID was already consumed"
                )

            day = _utc_day(now_epoch)
            self._daily_budget(
                kind="mutation_attempt",
                budget_name="mutation_attempts_per_day",
                limit=limits.mutation_attempts_per_day,
                instance_slug=str(bundle["instance_slug"]),
                day=day,
                now_epoch=now_epoch,
            )
            confirmed = int(
                self._db.execute(
                    """
                    SELECT count(*)
                    FROM budget_events
                    WHERE instance_slug = ?
                      AND kind = 'confirmed_merge'
                      AND utc_day = ?
                    """,
                    (bundle["instance_slug"], day),
                ).fetchone()[0]
            )
            pending_capacity = int(
                self._db.execute(
                    """
                    SELECT count(*)
                    FROM mutation_attempts AS a
                    JOIN bundles AS b ON b.bundle_key = a.bundle_key
                    WHERE b.instance_slug = ?
                      AND a.merge_budget_day = ?
                      AND a.state = 'pending'
                    """,
                    (bundle["instance_slug"], day),
                ).fetchone()[0]
            )
            used_capacity = confirmed + pending_capacity
            if used_capacity >= limits.confirmed_merges_per_day:
                raise BudgetExceeded(
                    budget="confirmed_merges_per_day",
                    limit=limits.confirmed_merges_per_day,
                    used=used_capacity,
                    reset_at=_next_utc_day(now_epoch),
                )

            identity = _packet_identity(
                _decode_canonical_json(
                    self._db.execute(
                        "SELECT packet_json FROM packets WHERE packet_id = ?",
                        (packet_id,),
                    ).fetchone()["packet_json"],
                    field="persisted release packet",
                ),
                now_epoch=min(now_epoch, int(bundle["expires_at"]) - 1),
                enforce_freshness=False,
            )
            attempt_number = len(attempts) + 1
            self._db.execute(
                """
                INSERT INTO mutation_attempts(
                    attempt_id, bundle_key, position, packet_id,
                    attempt_number, precondition_digest, expected_base_sha,
                    state, merge_budget_day, started_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                """,
                (
                    attempt_id,
                    bundle_key,
                    position,
                    packet_id,
                    attempt_number,
                    precondition_digest,
                    expected_base_sha,
                    day,
                    now_epoch,
                ),
            )
            self._insert_budget_event(
                event_key="attempt:" + attempt_id,
                kind="mutation_attempt",
                identity=identity,
                now_epoch=now_epoch,
                packet_id=packet_id,
                bundle_key=bundle_key,
                position=position,
                attempt_id=attempt_id,
                detail={
                    "attempt_number": attempt_number,
                    "expected_base_sha": expected_base_sha,
                    "limit": limits.mutation_attempts_per_day,
                    "precondition_digest": precondition_digest,
                },
                day=day,
            )
            self._db.execute(
                """
                UPDATE bundle_steps
                SET state = 'mutation_pending',
                    expected_base_sha = ?,
                    active_attempt_id = ?,
                    updated_at = ?
                WHERE bundle_key = ? AND position = ?
                """,
                (
                    expected_base_sha,
                    attempt_id,
                    now_epoch,
                    bundle_key,
                    position,
                ),
            )
            self._db.execute(
                """
                UPDATE bundles
                SET state = 'executing', last_packet_id = ?, updated_at = ?
                WHERE bundle_key = ?
                """,
                (packet_id, now_epoch, bundle_key),
            )
            return MutationReservation(
                disposition="charged",
                packet_id=packet_id,
                bundle_key=bundle_key,
                position=position,
                attempt_id=attempt_id,
                expected_base_sha=expected_base_sha,
                charged_at=_epoch_text(now_epoch),
            )

    def _confirm_step_locked(
        self,
        *,
        bundle: sqlite3.Row,
        step: sqlite3.Row,
        packet_id: str,
        attempt_id: str,
        merge_sha: str,
        parent_sha: str,
        tree_sha: str,
        merged_by: str,
        now_epoch: int,
    ) -> StepConfirmation:
        if step["state"] == "confirmed":
            if (
                step["merge_sha"] == merge_sha
                and step["parent_sha"] == parent_sha
                and step["tree_sha"] == tree_sha
                and step["merged_by"] == merged_by
            ):
                attempt = self._db.execute(
                    """
                    SELECT attempt_id
                    FROM mutation_attempts
                    WHERE bundle_key = ? AND position = ? AND state = 'confirmed'
                    ORDER BY attempt_number DESC
                    LIMIT 1
                    """,
                    (bundle["bundle_key"], step["position"]),
                ).fetchone()
                if attempt is None or attempt["attempt_id"] != attempt_id:
                    raise StateTransitionError(
                        "confirmed release step conflicts with attempt"
                    )
                return StepConfirmation(
                    disposition="already_confirmed",
                    bundle_key=str(bundle["bundle_key"]),
                    position=int(step["position"]),
                    attempt_id=attempt_id,
                    merge_sha=merge_sha,
                    tree_sha=tree_sha,
                )
            raise StateTransitionError(
                "confirmed release step conflicts with persisted merge"
            )
        if (
            step["state"] != "mutation_pending"
            or step["active_attempt_id"] != attempt_id
        ):
            raise StateTransitionError(
                "release confirmation does not match the active attempt"
            )
        attempt = self._db.execute(
            "SELECT * FROM mutation_attempts WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        if (
            attempt is None
            or attempt["state"] != "pending"
            or attempt["packet_id"] != packet_id
            or attempt["bundle_key"] != bundle["bundle_key"]
            or int(attempt["position"]) != int(step["position"])
        ):
            raise StateTransitionError(
                "release confirmation does not match the charged attempt"
            )
        if parent_sha != attempt["expected_base_sha"]:
            raise StateTransitionError(
                "release merge parent does not match the expected base"
            )
        self._db.execute(
            """
            UPDATE mutation_attempts
            SET state = 'confirmed', terminal_at = ?,
                merge_sha = ?, parent_sha = ?, tree_sha = ?, merged_by = ?
            WHERE attempt_id = ?
            """,
            (
                now_epoch,
                merge_sha,
                parent_sha,
                tree_sha,
                merged_by,
                attempt_id,
            ),
        )
        self._db.execute(
            """
            UPDATE bundle_steps
            SET state = 'confirmed', active_attempt_id = NULL,
                merge_sha = ?, parent_sha = ?, tree_sha = ?,
                merged_by = ?, updated_at = ?, confirmed_at = ?
            WHERE bundle_key = ? AND position = ?
            """,
            (
                merge_sha,
                parent_sha,
                tree_sha,
                merged_by,
                now_epoch,
                now_epoch,
                bundle["bundle_key"],
                step["position"],
            ),
        )
        packet = self._db.execute(
            "SELECT packet_json FROM packets WHERE packet_id = ?",
            (packet_id,),
        ).fetchone()
        if packet is None:
            raise StoreCorruptionError(
                "confirmed release attempt has no accepted packet"
            )
        identity = _packet_identity(
            _decode_canonical_json(
                packet["packet_json"], field="persisted release packet"
            ),
            now_epoch=now_epoch,
            enforce_freshness=False,
        )
        self._insert_budget_event(
            event_key=(
                f"confirmed:{bundle['bundle_key']}:{int(step['position'])}"
            ),
            kind="confirmed_merge",
            identity=identity,
            now_epoch=now_epoch,
            packet_id=packet_id,
            bundle_key=str(bundle["bundle_key"]),
            position=int(step["position"]),
            attempt_id=attempt_id,
            detail={
                "attempt_id": attempt_id,
                "merge_sha": merge_sha,
                "parent_sha": parent_sha,
                "tree_sha": tree_sha,
            },
            day=str(attempt["merge_budget_day"]),
        )
        self._db.execute(
            """
            UPDATE bundles
            SET last_packet_id = ?, updated_at = ?
            WHERE bundle_key = ?
            """,
            (packet_id, now_epoch, bundle["bundle_key"]),
        )
        return StepConfirmation(
            disposition="confirmed",
            bundle_key=str(bundle["bundle_key"]),
            position=int(step["position"]),
            attempt_id=attempt_id,
            merge_sha=merge_sha,
            tree_sha=tree_sha,
        )

    def confirm_step(
        self,
        bundle_key: str,
        position: int,
        packet_id: str,
        attempt_id: str,
        *,
        merge_sha: str,
        parent_sha: str,
        tree_sha: str,
        merged_by: str,
        now: datetime | None = None,
    ) -> StepConfirmation:
        """Persist exact read-back proof for one successful squash merge."""

        if not PACKET_ID_RE.fullmatch(packet_id):
            raise ReleaseBrokerStoreError("release packet ID is invalid")
        if not ATTEMPT_ID_RE.fullmatch(attempt_id):
            raise ReleaseBrokerStoreError("release attempt ID is invalid")
        merge_sha = _require_oid(merge_sha, field="release merge SHA")
        parent_sha = _require_oid(parent_sha, field="release parent SHA")
        tree_sha = _require_oid(tree_sha, field="release tree SHA")
        if not MERGE_ACTOR_RE.fullmatch(merged_by):
            raise ReleaseBrokerStoreError("release merge actor is invalid")
        now_epoch = _now_epoch(now)
        with self._immediate():
            bundle, step = self._bundle_and_step(
                bundle_key=bundle_key, position=position
            )
            self._packet_for_bundle(
                packet_id=packet_id, bundle_key=bundle_key
            )
            return self._confirm_step_locked(
                bundle=bundle,
                step=step,
                packet_id=packet_id,
                attempt_id=attempt_id,
                merge_sha=merge_sha,
                parent_sha=parent_sha,
                tree_sha=tree_sha,
                merged_by=merged_by,
                now_epoch=now_epoch,
            )

    def record_recovery(
        self,
        bundle_key: str,
        position: int,
        packet_id: str,
        attempt_id: str,
        recovery_id: str,
        classification: Literal["confirmed", "absent", "indeterminate"],
        evidence: Mapping[str, Any],
        limits: BudgetLimits,
        *,
        merge_sha: str | None = None,
        parent_sha: str | None = None,
        tree_sha: str | None = None,
        merged_by: str | None = None,
        circuit_mode: Literal["none", "threshold", "immediate"] = "none",
        now: datetime | None = None,
    ) -> RecoveryResult:
        """Append crash/read-back evidence and reconcile the charged attempt."""

        if not PACKET_ID_RE.fullmatch(packet_id):
            raise ReleaseBrokerStoreError("release packet ID is invalid")
        if not ATTEMPT_ID_RE.fullmatch(attempt_id):
            raise ReleaseBrokerStoreError("release attempt ID is invalid")
        if not RECOVERY_ID_RE.fullmatch(recovery_id):
            raise ReleaseBrokerStoreError("release recovery ID is invalid")
        if classification not in {"confirmed", "absent", "indeterminate"}:
            raise ReleaseBrokerStoreError(
                "release recovery classification is invalid"
            )
        evidence_json = canonical_json(evidence)
        evidence_digest = sha256_text(evidence_json)
        if classification == "confirmed":
            if None in {merge_sha, parent_sha, tree_sha, merged_by}:
                raise ReleaseBrokerStoreError(
                    "confirmed recovery requires complete merge evidence"
                )
            assert merge_sha is not None
            assert parent_sha is not None
            assert tree_sha is not None
            assert merged_by is not None
            _require_oid(merge_sha, field="recovered merge SHA")
            _require_oid(parent_sha, field="recovered parent SHA")
            _require_oid(tree_sha, field="recovered tree SHA")
            if not MERGE_ACTOR_RE.fullmatch(merged_by):
                raise ReleaseBrokerStoreError(
                    "recovered merge actor is invalid"
                )
        elif any(
            value is not None
            for value in (merge_sha, parent_sha, tree_sha, merged_by)
        ):
            raise ReleaseBrokerStoreError(
                "non-confirmed recovery may not carry merge identity"
            )
        if classification != "indeterminate" and circuit_mode != "none":
            raise ReleaseBrokerStoreError(
                "only indeterminate recovery may affect the circuit"
            )
        now_epoch = _now_epoch(now)
        with self._immediate():
            bundle, step = self._bundle_and_step(
                bundle_key=bundle_key, position=position
            )
            self._packet_for_bundle(
                packet_id=packet_id, bundle_key=bundle_key
            )
            existing = self._db.execute(
                "SELECT * FROM recovery_records WHERE recovery_id = ?",
                (recovery_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["attempt_id"] != attempt_id
                    or existing["bundle_key"] != bundle_key
                    or int(existing["position"]) != position
                    or existing["classification"] != classification
                    or existing["evidence_digest"] != evidence_digest
                    or existing["evidence_json"] != evidence_json
                ):
                    raise StateTransitionError(
                        "release recovery ID conflicts with persisted evidence"
                    )
                persisted_attempt = self._db.execute(
                    """
                    SELECT state, merge_sha, parent_sha, tree_sha, merged_by
                    FROM mutation_attempts
                    WHERE attempt_id = ?
                    """,
                    (attempt_id,),
                ).fetchone()
                if persisted_attempt is None:
                    raise StoreCorruptionError(
                        "release recovery points to a missing attempt"
                    )
                if classification == "confirmed" and (
                    persisted_attempt["state"] != "confirmed"
                    or persisted_attempt["merge_sha"] != merge_sha
                    or persisted_attempt["parent_sha"] != parent_sha
                    or persisted_attempt["tree_sha"] != tree_sha
                    or persisted_attempt["merged_by"] != merged_by
                ):
                    raise StateTransitionError(
                        "release recovery conflicts with persisted merge evidence"
                    )
                if classification == "indeterminate":
                    circuit = self._db.execute(
                        """
                        SELECT last_event_bundle_key, last_event_mode
                        FROM circuits
                        WHERE instance_slug = ? AND repository_id = ?
                        """,
                        (bundle["instance_slug"], bundle["repository_id"]),
                    ).fetchone()
                    persisted_mode = (
                        str(circuit["last_event_mode"])
                        if circuit is not None
                        and circuit["last_event_bundle_key"] == bundle_key
                        else "none"
                    )
                    if persisted_mode != circuit_mode:
                        raise StateTransitionError(
                            "release recovery conflicts with persisted circuit mode"
                        )
                return RecoveryResult(
                    disposition="already_recorded",
                    recovery_id=recovery_id,
                    bundle_key=bundle_key,
                    position=position,
                    attempt_id=attempt_id,
                    classification=classification,
                )
            attempt = self._db.execute(
                "SELECT * FROM mutation_attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if (
                attempt is None
                or attempt["bundle_key"] != bundle_key
                or int(attempt["position"]) != position
                or attempt["packet_id"] != packet_id
            ):
                raise StateTransitionError(
                    "release recovery does not match the charged attempt"
                )
            if attempt["state"] != "pending":
                raise StateTransitionError(
                    "release recovery attempt is already terminal"
                )
            self._db.execute(
                """
                INSERT INTO recovery_records(
                    recovery_id, attempt_id, bundle_key, position,
                    classification, evidence_digest, evidence_json,
                    recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    recovery_id,
                    attempt_id,
                    bundle_key,
                    position,
                    classification,
                    evidence_digest,
                    evidence_json,
                    now_epoch,
                ),
            )
            if classification == "confirmed":
                assert merge_sha is not None
                assert parent_sha is not None
                assert tree_sha is not None
                assert merged_by is not None
                self._confirm_step_locked(
                    bundle=bundle,
                    step=step,
                    packet_id=packet_id,
                    attempt_id=attempt_id,
                    merge_sha=merge_sha,
                    parent_sha=parent_sha,
                    tree_sha=tree_sha,
                    merged_by=merged_by,
                    now_epoch=now_epoch,
                )
            elif classification == "absent":
                if (
                    step["state"] != "mutation_pending"
                    or step["active_attempt_id"] != attempt_id
                ):
                    raise StateTransitionError(
                        "absent recovery does not match the active step"
                    )
                self._db.execute(
                    """
                    UPDATE mutation_attempts
                    SET state = 'absent', terminal_at = ?,
                        terminal_detail_json = ?
                    WHERE attempt_id = ?
                    """,
                    (now_epoch, evidence_json, attempt_id),
                )
                self._db.execute(
                    """
                    UPDATE bundle_steps
                    SET state = 'pending', active_attempt_id = NULL,
                        terminal_detail_json = ?, updated_at = ?
                    WHERE bundle_key = ? AND position = ?
                    """,
                    (
                        evidence_json,
                        now_epoch,
                        bundle_key,
                        position,
                    ),
                )
            else:
                if (
                    step["state"] != "mutation_pending"
                    or step["active_attempt_id"] != attempt_id
                ):
                    raise StateTransitionError(
                        "indeterminate recovery does not match the active step"
                    )
                self._db.execute(
                    """
                    UPDATE mutation_attempts
                    SET state = 'indeterminate', terminal_at = ?,
                        terminal_detail_json = ?
                    WHERE attempt_id = ?
                    """,
                    (now_epoch, evidence_json, attempt_id),
                )
                self._db.execute(
                    """
                    UPDATE bundle_steps
                    SET state = 'indeterminate', active_attempt_id = NULL,
                        terminal_detail_json = ?, updated_at = ?
                    WHERE bundle_key = ? AND position = ?
                    """,
                    (
                        evidence_json,
                        now_epoch,
                        bundle_key,
                        position,
                    ),
                )
                if circuit_mode == "immediate":
                    self._record_circuit_locked(
                        bundle=bundle,
                        mode="immediate",
                        reason={
                            "attempt_id": attempt_id,
                            "bundle_key": bundle_key,
                            "reason": "indeterminate_recovery",
                            "evidence_digest": evidence_digest,
                        },
                        limits=limits,
                        now_epoch=now_epoch,
                    )
                elif circuit_mode == "threshold":
                    self._record_circuit_locked(
                        bundle=bundle,
                        mode="threshold",
                        reason={
                            "attempt_id": attempt_id,
                            "bundle_key": bundle_key,
                            "reason": "indeterminate_recovery",
                            "evidence_digest": evidence_digest,
                        },
                        limits=limits,
                        now_epoch=now_epoch,
                    )
            return RecoveryResult(
                disposition="recorded",
                recovery_id=recovery_id,
                bundle_key=bundle_key,
                position=position,
                attempt_id=attempt_id,
                classification=classification,
            )

    def stop_step(
        self,
        bundle_key: str,
        position: int,
        packet_id: str,
        state: Literal["rejected", "indeterminate"],
        detail: Mapping[str, Any],
        *,
        now: datetime | None = None,
    ) -> str:
        """Stop an unmutated step after deterministic precondition drift."""

        if state not in {"rejected", "indeterminate"}:
            raise ReleaseBrokerStoreError("release stop state is invalid")
        detail_json = canonical_json(detail)
        now_epoch = _now_epoch(now)
        with self._immediate():
            bundle, step = self._bundle_and_step(
                bundle_key=bundle_key, position=position
            )
            self._packet_for_bundle(
                packet_id=packet_id, bundle_key=bundle_key
            )
            if step["state"] == state:
                if step["terminal_detail_json"] != detail_json:
                    raise StateTransitionError(
                        "release stopped step conflicts with persisted detail"
                    )
                return "already_stopped"
            if step["state"] != "pending":
                raise StateTransitionError(
                    "only an unmutated pending step may be stopped"
                )
            self._db.execute(
                """
                UPDATE bundle_steps
                SET state = ?, terminal_detail_json = ?, updated_at = ?
                WHERE bundle_key = ? AND position = ?
                """,
                (state, detail_json, now_epoch, bundle_key, position),
            )
            self._db.execute(
                """
                UPDATE bundles
                SET last_packet_id = ?, updated_at = ?
                WHERE bundle_key = ?
                """,
                (packet_id, now_epoch, bundle_key),
            )
            return "stopped"

    def _record_circuit_locked(
        self,
        *,
        bundle: sqlite3.Row,
        mode: Literal["none", "threshold", "immediate", "success"],
        reason: Mapping[str, Any] | None,
        limits: BudgetLimits,
        now_epoch: int,
    ) -> None:
        if mode == "none":
            return
        row = self._db.execute(
            """
            SELECT *
            FROM circuits
            WHERE instance_slug = ? AND repository_id = ?
            """,
            (bundle["instance_slug"], bundle["repository_id"]),
        ).fetchone()
        if mode == "success":
            if row is None:
                return
            if row["state"] == "open":
                return
            self._db.execute(
                """
                UPDATE circuits
                SET consecutive_indeterminate = 0,
                    reason_digest = NULL, reason_json = NULL,
                    last_event_bundle_key = NULL,
                    last_event_mode = NULL,
                    updated_at = ?
                WHERE circuit_key = ?
                """,
                (now_epoch, row["circuit_key"]),
            )
            return
        reason_value = dict(reason or {})
        reason_json = canonical_json(reason_value)
        reason_digest = sha256_text(reason_json)
        if (
            row is not None
            and row["last_event_bundle_key"] == bundle["bundle_key"]
        ):
            if mode != "immediate" or row["state"] == "open":
                return
            # Escalating a threshold-classified event for the same bundle to
            # immediate opens the circuit without counting the bundle twice.
            self._db.execute(
                """
                UPDATE circuits
                SET state = 'open',
                    opened_at = COALESCE(opened_at, ?),
                    reason_digest = ?,
                    reason_json = ?,
                    last_event_mode = 'immediate',
                    updated_at = ?
                WHERE circuit_key = ?
                """,
                (
                    now_epoch,
                    reason_digest,
                    reason_json,
                    now_epoch,
                    row["circuit_key"],
                ),
            )
            return
        prior_count = (
            int(row["consecutive_indeterminate"]) if row is not None else 0
        )
        count = prior_count + 1
        open_now = (
            mode == "immediate"
            or count >= limits.consecutive_indeterminate_limit
            or (row is not None and row["state"] == "open")
        )
        state = "open" if open_now else "closed"
        opened_at = (
            int(row["opened_at"])
            if row is not None and row["opened_at"] is not None
            else (now_epoch if open_now else None)
        )
        self._db.execute(
            """
            INSERT INTO circuits(
                circuit_key, instance_slug, repository_id,
                repository_full_name, state, consecutive_indeterminate,
                opened_at, reason_digest, reason_json,
                last_event_bundle_key, last_event_mode, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(circuit_key) DO UPDATE SET
                repository_full_name = excluded.repository_full_name,
                state = excluded.state,
                consecutive_indeterminate =
                    excluded.consecutive_indeterminate,
                opened_at = excluded.opened_at,
                reason_digest = excluded.reason_digest,
                reason_json = excluded.reason_json,
                last_event_bundle_key = excluded.last_event_bundle_key,
                last_event_mode = excluded.last_event_mode,
                updated_at = excluded.updated_at
            """,
            (
                self._circuit_key(
                    str(bundle["instance_slug"]),
                    int(bundle["repository_id"]),
                ),
                bundle["instance_slug"],
                bundle["repository_id"],
                bundle["repository_full_name"],
                state,
                count,
                opened_at,
                reason_digest if open_now else None,
                reason_json if open_now else None,
                bundle["bundle_key"],
                mode,
                now_epoch,
            ),
        )

    def terminalize_bundle(
        self,
        bundle_key: str,
        packet_id: str,
        outcome: Literal[
            "succeeded", "rejected", "partial", "indeterminate"
        ],
        receipt: Mapping[str, Any],
        limits: BudgetLimits,
        *,
        circuit_mode: Literal[
            "none", "threshold", "immediate"
        ] | None = None,
        circuit_reason: Mapping[str, Any] | None = None,
        expected_previous_chain_digest: str | None = None,
        now: datetime | None = None,
    ) -> Terminalization:
        """Atomically append a receipt and make the bundle terminal."""

        if not BUNDLE_KEY_RE.fullmatch(bundle_key):
            raise ReleaseBrokerStoreError("release bundle key is invalid")
        if not PACKET_ID_RE.fullmatch(packet_id):
            raise ReleaseBrokerStoreError("release packet ID is invalid")
        if outcome not in TERMINAL_BUNDLE_STATES:
            raise ReleaseBrokerStoreError("release outcome is invalid")
        receipt_json = canonical_json(receipt)
        receipt_digest = sha256_text(receipt_json)
        receipt_value = _decode_canonical_json(
            receipt_json, field="release terminal receipt"
        )
        now_epoch = _now_epoch(now)
        if circuit_mode is None:
            circuit_mode = (
                "threshold" if outcome == "indeterminate" else "none"
            )
        if circuit_mode not in {"none", "threshold", "immediate"}:
            raise ReleaseBrokerStoreError("release circuit mode is invalid")
        if expected_previous_chain_digest is not None:
            expected_previous_chain_digest = _require_digest(
                expected_previous_chain_digest,
                field="expected previous receipt-chain digest",
            )
        with self._immediate():
            bundle = self._db.execute(
                "SELECT * FROM bundles WHERE bundle_key = ?",
                (bundle_key,),
            ).fetchone()
            if bundle is None:
                raise StateTransitionError("release bundle is not reserved")
            self._validate_bundle_row(bundle)
            if (
                bundle["first_packet_id"] != packet_id
                or bundle["last_packet_id"] != packet_id
            ):
                raise StoreCorruptionError(
                    "release bundle packet identity is ambiguous"
                )
            self._packet_for_bundle(
                packet_id=packet_id, bundle_key=bundle_key
            )
            existing = self._load_bundle_receipt(bundle_key)
            if bundle["state"] in TERMINAL_BUNDLE_STATES:
                if existing is None:
                    raise StoreCorruptionError(
                        "terminal release bundle has no receipt"
                    )
                if (
                    existing[0] != receipt_digest
                    or existing[2] != packet_id
                    or existing[3] != outcome
                ):
                    raise StateTransitionError(
                        "terminal release bundle conflicts with receipt"
                    )
                return Terminalization(
                    disposition="receipt_replay",
                    bundle_key=bundle_key,
                    packet_id=packet_id,
                    outcome=outcome,
                    receipt_digest=existing[0],
                    chain_digest=existing[1],
                    receipt=existing[4],
                )
            if existing is not None:
                raise StoreCorruptionError(
                    "active release bundle unexpectedly has a receipt"
                )

            steps = self._db.execute(
                """
                SELECT position, state, active_attempt_id
                FROM bundle_steps
                WHERE bundle_key = ?
                ORDER BY position
                """,
                (bundle_key,),
            ).fetchall()
            if len(steps) != int(bundle["step_count"]):
                raise StoreCorruptionError(
                    "release bundle step count is corrupted"
                )
            if any(step["state"] == "mutation_pending" for step in steps):
                raise PendingRecoveryError(
                    "release bundle has a charged attempt awaiting recovery"
                )
            confirmed = sum(
                1 for step in steps if step["state"] == "confirmed"
            )
            if outcome == "succeeded" and confirmed != len(steps):
                raise StateTransitionError(
                    "successful release requires every step confirmed"
                )
            if outcome == "rejected" and confirmed:
                raise StateTransitionError(
                    "rejected release may not hide a confirmed merge"
                )
            if outcome == "partial" and confirmed == 0:
                raise StateTransitionError(
                    "partial release requires a confirmed prefix"
                )
            if outcome == "indeterminate" and not any(
                step["state"] == "indeterminate" for step in steps
            ):
                raise StateTransitionError(
                    "indeterminate release requires an indeterminate step"
                )

            prior = self._db.execute(
                """
                SELECT receipt_sequence, chain_digest
                FROM receipts
                ORDER BY receipt_sequence DESC
                LIMIT 1
                """
            ).fetchone()
            sequence = (
                int(prior["receipt_sequence"]) + 1 if prior is not None else 1
            )
            previous_chain_digest = (
                str(prior["chain_digest"])
                if prior is not None
                else ZERO_DIGEST
            )
            if (
                expected_previous_chain_digest is not None
                and expected_previous_chain_digest
                != previous_chain_digest
            ):
                raise StateTransitionError(
                    "release receipt-chain head changed before terminalization"
                )
            chain_digest = self._receipt_chain_digest(
                sequence=sequence,
                bundle_key=bundle_key,
                packet_id=packet_id,
                outcome=outcome,
                receipt_digest=receipt_digest,
                previous_chain_digest=previous_chain_digest,
                created_at=now_epoch,
            )
            self._db.execute(
                """
                INSERT INTO receipts(
                    receipt_sequence, bundle_key, packet_id, outcome,
                    receipt_digest, receipt_json, previous_chain_digest,
                    chain_digest, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sequence,
                    bundle_key,
                    packet_id,
                    outcome,
                    receipt_digest,
                    receipt_json,
                    previous_chain_digest,
                    chain_digest,
                    now_epoch,
                ),
            )
            self._db.execute(
                """
                UPDATE bundles
                SET state = ?, last_packet_id = ?, updated_at = ?,
                    terminal_at = ?, terminal_outcome = ?,
                    terminal_receipt_sequence = ?
                WHERE bundle_key = ?
                """,
                (
                    outcome,
                    packet_id,
                    now_epoch,
                    now_epoch,
                    outcome,
                    sequence,
                    bundle_key,
                ),
            )
            if outcome == "succeeded":
                self._record_circuit_locked(
                    bundle=bundle,
                    mode="success",
                    reason=None,
                    limits=limits,
                    now_epoch=now_epoch,
                )
            elif circuit_mode != "none":
                self._record_circuit_locked(
                    bundle=bundle,
                    mode=circuit_mode,
                    reason=(
                        circuit_reason
                        or {
                            "bundle_key": bundle_key,
                            "outcome": outcome,
                            "reason": "terminal_release_outcome",
                        }
                    ),
                    limits=limits,
                    now_epoch=now_epoch,
                )
            return Terminalization(
                disposition="terminalized",
                bundle_key=bundle_key,
                packet_id=packet_id,
                outcome=outcome,
                receipt_digest=receipt_digest,
                chain_digest=chain_digest,
                receipt=receipt_value,
            )

    def pending_recovery(self) -> list[PendingRecovery]:
        """Return charged attempts that require read-only live reconciliation."""

        self._ensure_open()
        self._assert_runtime_bound()
        rows = self._db.execute(
            """
            SELECT b.bundle_key, b.repository_id, b.repository_full_name,
                   s.position, s.pr_number, s.head_sha,
                   a.packet_id, a.expected_base_sha, a.attempt_id,
                   a.precondition_digest, a.started_at, a.attempt_number
            FROM mutation_attempts AS a
            JOIN bundles AS b ON b.bundle_key = a.bundle_key
            JOIN bundle_steps AS s
              ON s.bundle_key = a.bundle_key
             AND s.position = a.position
            WHERE a.state = 'pending'
              AND s.state = 'mutation_pending'
              AND s.active_attempt_id = a.attempt_id
            ORDER BY a.started_at, b.bundle_key, s.position
            """
        ).fetchall()
        return [
            PendingRecovery(
                bundle_key=str(row["bundle_key"]),
                packet_id=str(row["packet_id"]),
                repository_id=int(row["repository_id"]),
                repository_full_name=str(row["repository_full_name"]),
                position=int(row["position"]),
                pr_number=int(row["pr_number"]),
                head_sha=str(row["head_sha"]),
                expected_base_sha=str(row["expected_base_sha"]),
                attempt_id=str(row["attempt_id"]),
                precondition_digest=str(row["precondition_digest"]),
                started_at=_epoch_text(int(row["started_at"])),
                attempt_number=int(row["attempt_number"]),
            )
            for row in rows
        ]

    def bundles_awaiting_terminal_receipt(self) -> list[str]:
        """Return active bundles whose steps no longer contain live attempts."""

        self._ensure_open()
        self._assert_runtime_bound()
        rows = self._db.execute(
            """
            SELECT b.bundle_key
            FROM bundles AS b
            WHERE b.state IN ('reserved', 'executing')
              AND NOT EXISTS (
                  SELECT 1
                  FROM bundle_steps AS s
                  WHERE s.bundle_key = b.bundle_key
                    AND s.state = 'mutation_pending'
              )
              AND (
                  NOT EXISTS (
                      SELECT 1
                      FROM bundle_steps AS s
                      WHERE s.bundle_key = b.bundle_key
                        AND s.state = 'pending'
                  )
                  OR EXISTS (
                      SELECT 1
                      FROM bundle_steps AS s
                      WHERE s.bundle_key = b.bundle_key
                        AND s.state IN ('rejected', 'indeterminate')
                  )
                  OR EXISTS (
                      SELECT 1
                      FROM bundle_steps AS s
                      WHERE s.bundle_key = b.bundle_key
                        AND s.state = 'pending'
                        AND (
                            SELECT count(*)
                            FROM mutation_attempts AS a
                            WHERE a.bundle_key = s.bundle_key
                              AND a.position = s.position
                        ) >= 2
                  )
              )
            ORDER BY b.created_at, b.bundle_key
            """
        ).fetchall()
        return [str(row["bundle_key"]) for row in rows]

    def receipt_for_packet(
        self,
        packet_id: str,
    ) -> dict[str, Any] | None:
        if not PACKET_ID_RE.fullmatch(packet_id):
            raise ReleaseBrokerStoreError("release packet ID is invalid")
        self._ensure_open()
        self._assert_runtime_bound()
        row = self._db.execute(
            """
            SELECT p.bundle_key, b.first_packet_id, b.last_packet_id
            FROM packets AS p
            JOIN bundles AS b ON b.bundle_key = p.bundle_key
            WHERE p.packet_id = ?
            """,
            (packet_id,),
        ).fetchone()
        if row is None:
            return None
        if (
            row["first_packet_id"] != packet_id
            or row["last_packet_id"] != packet_id
        ):
            raise StoreCorruptionError(
                "release bundle packet identity is ambiguous"
            )
        receipt = self._load_bundle_receipt(str(row["bundle_key"]))
        if receipt is None:
            return None
        if receipt[2] != packet_id:
            raise StoreCorruptionError(
                "release receipt is bound to another packet"
            )
        return receipt[4]

    def load_packet(self, packet_id: str) -> dict[str, Any]:
        """Load and fully revalidate one canonical accepted recovery packet."""

        if not PACKET_ID_RE.fullmatch(packet_id):
            raise ReleaseBrokerStoreError("release packet ID is invalid")
        self._ensure_open()
        self._assert_runtime_bound()
        row = self._db.execute(
            "SELECT * FROM packets WHERE packet_id = ?",
            (packet_id,),
        ).fetchone()
        if row is None:
            raise StateTransitionError("release packet is not accepted")
        packet = _decode_canonical_json(
            row["packet_json"], field="persisted release packet"
        )
        identity = _packet_identity(
            packet,
            now_epoch=max(0, int(row["expires_at"]) - 1),
            enforce_freshness=False,
        )
        self._validate_packet_row(row, identity)
        bundle = self._db.execute(
            "SELECT * FROM bundles WHERE bundle_key = ?",
            (identity.bundle_key,),
        ).fetchone()
        if bundle is None:
            raise StoreCorruptionError(
                "accepted release packet has no semantic bundle"
            )
        self._validate_bundle_row(bundle, identity)
        return packet

    def verify_receipt_chain(self) -> str:
        """Verify the complete append-only chain and return its head digest."""

        self._ensure_open()
        self._assert_runtime_bound()
        rows = self._db.execute(
            """
            SELECT receipt_sequence, bundle_key, packet_id, outcome,
                   receipt_digest, receipt_json, previous_chain_digest,
                   chain_digest, created_at
            FROM receipts
            ORDER BY receipt_sequence
            """
        ).fetchall()
        previous = ZERO_DIGEST
        for expected_sequence, row in enumerate(rows, start=1):
            if int(row["receipt_sequence"]) != expected_sequence:
                raise StoreCorruptionError(
                    "release receipt chain sequence is not contiguous"
                )
            if row["previous_chain_digest"] != previous:
                raise StoreCorruptionError(
                    "release receipt chain predecessor is corrupted"
                )
            self._decode_receipt_row(row)
            previous = str(row["chain_digest"])
        return previous

    def latest_receipt_digest(self) -> str:
        self._ensure_open()
        self._assert_runtime_bound()
        row = self._db.execute(
            """
            SELECT receipt_digest
            FROM receipts
            ORDER BY receipt_sequence DESC
            LIMIT 1
            """
        ).fetchone()
        if row is None:
            return ZERO_DIGEST
        self.verify_receipt_chain()
        return str(row["receipt_digest"])

    def latest_receipt_chain_digest(self) -> str:
        return self.verify_receipt_chain()

    def open_circuit(
        self,
        *,
        instance_slug: str,
        repository_id: int,
        repository_full_name: str,
        reason: Mapping[str, Any],
        now: datetime | None = None,
    ) -> None:
        """Immediately open a repository circuit for a store/service invariant."""

        if not INSTANCE_RE.fullmatch(instance_slug):
            raise ReleaseBrokerStoreError("release instance slug is invalid")
        _require_positive_int(repository_id, field="release repository ID")
        if not REPOSITORY_RE.fullmatch(repository_full_name):
            raise ReleaseBrokerStoreError("release repository name is invalid")
        reason_json = canonical_json(reason)
        reason_digest = sha256_text(reason_json)
        now_epoch = _now_epoch(now)
        with self._immediate():
            row = self._db.execute(
                """
                SELECT state, consecutive_indeterminate, opened_at,
                       reason_digest
                FROM circuits
                WHERE instance_slug = ? AND repository_id = ?
                """,
                (instance_slug, repository_id),
            ).fetchone()
            if (
                row is not None
                and row["state"] == "open"
                and row["reason_digest"] == reason_digest
            ):
                return
            count = (
                int(row["consecutive_indeterminate"]) + 1
                if row is not None
                else 1
            )
            opened_at = (
                int(row["opened_at"])
                if row is not None and row["opened_at"] is not None
                else now_epoch
            )
            self._db.execute(
                """
                INSERT INTO circuits(
                    circuit_key, instance_slug, repository_id,
                    repository_full_name, state,
                    consecutive_indeterminate, opened_at,
                    reason_digest, reason_json,
                    last_event_bundle_key, last_event_mode, updated_at
                ) VALUES (
                    ?, ?, ?, ?, 'open', ?, ?, ?, ?,
                    NULL, NULL, ?
                )
                ON CONFLICT(circuit_key) DO UPDATE SET
                    repository_full_name = excluded.repository_full_name,
                    state = 'open',
                    consecutive_indeterminate =
                        excluded.consecutive_indeterminate,
                    opened_at = excluded.opened_at,
                    reason_digest = excluded.reason_digest,
                    reason_json = excluded.reason_json,
                    last_event_bundle_key = NULL,
                    last_event_mode = NULL,
                    updated_at = excluded.updated_at
                """,
                (
                    self._circuit_key(instance_slug, repository_id),
                    instance_slug,
                    repository_id,
                    repository_full_name,
                    count,
                    opened_at,
                    reason_digest,
                    reason_json,
                    now_epoch,
                ),
            )

    def circuit_status(
        self,
        instance_slug: str,
        repository_id: int,
    ) -> dict[str, Any]:
        if not INSTANCE_RE.fullmatch(instance_slug):
            raise ReleaseBrokerStoreError("release instance slug is invalid")
        _require_positive_int(repository_id, field="release repository ID")
        self._ensure_open()
        self._assert_runtime_bound()
        row = self._db.execute(
            """
            SELECT *
            FROM circuits
            WHERE instance_slug = ? AND repository_id = ?
            """,
            (instance_slug, repository_id),
        ).fetchone()
        if row is None:
            return {
                "state": "closed",
                "consecutive_indeterminate": 0,
                "opened_at": None,
                "reason": None,
            }
        reason = None
        if row["reason_json"] is not None:
            reason = _decode_canonical_json(
                row["reason_json"], field="release circuit reason"
            )
            if sha256_text(str(row["reason_json"])) != row["reason_digest"]:
                raise StoreCorruptionError(
                    "release circuit reason digest is corrupted"
                )
        return {
            "state": str(row["state"]),
            "consecutive_indeterminate": int(
                row["consecutive_indeterminate"]
            ),
            "opened_at": (
                _epoch_text(int(row["opened_at"]))
                if row["opened_at"] is not None
                else None
            ),
            "reason": reason,
            "updated_at": _epoch_text(int(row["updated_at"])),
        }

    def close_circuit(
        self,
        instance_slug: str,
        repository_id: int,
        repository_full_name: str,
        *,
        now: datetime | None = None,
    ) -> None:
        """Explicit root-operator recovery; packets cannot close circuits."""

        if not INSTANCE_RE.fullmatch(instance_slug):
            raise ReleaseBrokerStoreError("release instance slug is invalid")
        _require_positive_int(repository_id, field="release repository ID")
        if not REPOSITORY_RE.fullmatch(repository_full_name):
            raise ReleaseBrokerStoreError("release repository name is invalid")
        now_epoch = _now_epoch(now)
        with self._immediate():
            self._db.execute(
                """
                INSERT INTO circuits(
                    circuit_key, instance_slug, repository_id,
                    repository_full_name, state,
                    consecutive_indeterminate, opened_at,
                    reason_digest, reason_json,
                    last_event_bundle_key, last_event_mode, updated_at
                ) VALUES (
                    ?, ?, ?, ?, 'closed', 0, NULL, NULL, NULL,
                    NULL, NULL, ?
                )
                ON CONFLICT(circuit_key) DO UPDATE SET
                    repository_full_name = excluded.repository_full_name,
                    state = 'closed',
                    consecutive_indeterminate = 0,
                    opened_at = NULL,
                    reason_digest = NULL,
                    reason_json = NULL,
                    last_event_bundle_key = NULL,
                    last_event_mode = NULL,
                    updated_at = excluded.updated_at
                """,
                (
                    self._circuit_key(instance_slug, repository_id),
                    instance_slug,
                    repository_id,
                    repository_full_name,
                    now_epoch,
                ),
            )

    @staticmethod
    def _optional_detail(
        value: Any,
        *,
        field: str,
    ) -> dict[str, Any] | None:
        if value is None:
            return None
        return _decode_canonical_json(value, field=field)

    def _snapshot_step_history(
        self,
        *,
        bundle: sqlite3.Row,
        step: sqlite3.Row,
    ) -> tuple[
        dict[str, Any] | None,
        dict[str, Any] | None,
        dict[str, Any] | None,
    ]:
        """Validate and project one step's attempts and recovery evidence."""

        bundle_key = str(bundle["bundle_key"])
        position = int(step["position"])
        step_detail = self._optional_detail(
            step["terminal_detail_json"],
            field=f"release step {position} terminal detail",
        )
        attempts = self._db.execute(
            """
            SELECT *
            FROM mutation_attempts
            WHERE bundle_key = ? AND position = ?
            ORDER BY attempt_number
            """,
            (bundle_key, position),
        ).fetchall()
        if len(attempts) > MAX_ATTEMPTS_PER_STEP:
            raise StoreCorruptionError(
                "release step has too many mutation attempts"
            )

        attempt_values: list[dict[str, Any]] = []
        attempts_by_id: dict[str, tuple[sqlite3.Row, dict[str, Any]]] = {}
        for expected_number, attempt in enumerate(attempts, start=1):
            attempt_id = str(attempt["attempt_id"])
            if (
                not ATTEMPT_ID_RE.fullmatch(attempt_id)
                or int(attempt["attempt_number"]) != expected_number
                or attempt["bundle_key"] != bundle_key
                or int(attempt["position"]) != position
                or attempt["state"] not in ATTEMPT_STATES
            ):
                raise StoreCorruptionError(
                    "release mutation-attempt identity is corrupted"
                )
            packet_id = str(attempt["packet_id"])
            self._packet_for_bundle(
                packet_id=packet_id,
                bundle_key=bundle_key,
            )
            precondition_digest = str(attempt["precondition_digest"])
            expected_base_sha = str(attempt["expected_base_sha"])
            if not SHA256_RE.fullmatch(precondition_digest):
                raise StoreCorruptionError(
                    "release mutation precondition digest is corrupted"
                )
            if not OID_RE.fullmatch(expected_base_sha):
                raise StoreCorruptionError(
                    "release mutation expected base is corrupted"
                )
            if (
                step["expected_base_sha"] is None
                or expected_base_sha != step["expected_base_sha"]
            ):
                raise StoreCorruptionError(
                    "release mutation base conflicts with its step"
                )
            try:
                budget_day = datetime.strptime(
                    str(attempt["merge_budget_day"]), "%Y-%m-%d"
                ).strftime("%Y-%m-%d")
            except ValueError as exc:
                raise StoreCorruptionError(
                    "release mutation budget day is corrupted"
                ) from exc
            started_at = int(attempt["started_at"])
            if budget_day != _utc_day(started_at):
                raise StoreCorruptionError(
                    "release mutation budget day does not match its start"
                )
            terminal_at = (
                int(attempt["terminal_at"])
                if attempt["terminal_at"] is not None
                else None
            )
            if terminal_at is not None and terminal_at < started_at:
                raise StoreCorruptionError(
                    "release mutation terminal time predates its start"
                )
            attempt_detail = self._optional_detail(
                attempt["terminal_detail_json"],
                field=(
                    f"release mutation attempt {attempt_id} terminal detail"
                ),
            )
            state = str(attempt["state"])
            merge_sha = attempt["merge_sha"]
            parent_sha = attempt["parent_sha"]
            tree_sha = attempt["tree_sha"]
            merged_by = attempt["merged_by"]
            if state == "confirmed":
                if (
                    not isinstance(merge_sha, str)
                    or not OID_RE.fullmatch(merge_sha)
                    or not isinstance(parent_sha, str)
                    or not OID_RE.fullmatch(parent_sha)
                    or not isinstance(tree_sha, str)
                    or not OID_RE.fullmatch(tree_sha)
                    or not isinstance(merged_by, str)
                    or not MERGE_ACTOR_RE.fullmatch(merged_by)
                    or parent_sha != expected_base_sha
                    or terminal_at is None
                ):
                    raise StoreCorruptionError(
                        "confirmed release mutation evidence is corrupted"
                    )
            elif any(
                value is not None
                for value in (merge_sha, parent_sha, tree_sha, merged_by)
            ):
                raise StoreCorruptionError(
                    "non-confirmed release mutation carries merge evidence"
                )
            if state == "pending" and (
                terminal_at is not None or attempt_detail is not None
            ):
                raise StoreCorruptionError(
                    "pending release mutation carries terminal evidence"
                )
            if state in {"absent", "indeterminate"} and (
                terminal_at is None or attempt_detail is None
            ):
                raise StoreCorruptionError(
                    "reconciled release mutation lacks terminal evidence"
                )

            projected_attempt = {
                "attempt_id": attempt_id,
                "packet_id": packet_id,
                "attempt_number": expected_number,
                "precondition_digest": precondition_digest,
                "expected_base_sha": expected_base_sha,
                "state": state,
                "started_at": _epoch_text(started_at),
                "terminal_at": (
                    _epoch_text(terminal_at)
                    if terminal_at is not None
                    else None
                ),
                "merge_sha": merge_sha,
                "parent_sha": parent_sha,
                "tree_sha": tree_sha,
                "merged_by": merged_by,
                "terminal_detail": attempt_detail,
            }
            attempt_values.append(projected_attempt)
            attempts_by_id[attempt_id] = (attempt, projected_attempt)

        if (
            len(attempt_values) == MAX_ATTEMPTS_PER_STEP
            and attempt_values[0]["state"] != "absent"
        ):
            raise StoreCorruptionError(
                "release retry does not follow an absent first attempt"
            )

        recoveries = self._db.execute(
            """
            SELECT *
            FROM recovery_records
            WHERE bundle_key = ? AND position = ?
            ORDER BY recovery_sequence
            """,
            (bundle_key, position),
        ).fetchall()
        recovery_attempt_ids: set[str] = set()
        recovery_values: list[dict[str, Any]] = []
        for recovery in recoveries:
            recovery_id = str(recovery["recovery_id"])
            attempt_id = str(recovery["attempt_id"])
            classification = str(recovery["classification"])
            if (
                not RECOVERY_ID_RE.fullmatch(recovery_id)
                or attempt_id not in attempts_by_id
                or attempt_id in recovery_attempt_ids
                or classification
                not in {"confirmed", "absent", "indeterminate"}
            ):
                raise StoreCorruptionError(
                    "release recovery identity is corrupted"
                )
            recovery_attempt_ids.add(attempt_id)
            attempt_row, attempt_value = attempts_by_id[attempt_id]
            if (
                classification != attempt_row["state"]
                or classification != attempt_value["state"]
            ):
                raise StoreCorruptionError(
                    "release recovery classification conflicts with attempt"
                )
            evidence_json = str(recovery["evidence_json"])
            evidence_digest = str(recovery["evidence_digest"])
            evidence = _decode_canonical_json(
                evidence_json,
                field=f"release recovery {recovery_id} evidence",
            )
            if (
                not SHA256_RE.fullmatch(evidence_digest)
                or sha256_text(evidence_json) != evidence_digest
            ):
                raise StoreCorruptionError(
                    "release recovery evidence digest is corrupted"
                )
            if (
                classification in {"absent", "indeterminate"}
                and attempt_value["terminal_detail"] != evidence
            ):
                raise StoreCorruptionError(
                    "release recovery evidence conflicts with attempt detail"
                )
            recorded_at = int(recovery["recorded_at"])
            if recorded_at < int(attempt_row["started_at"]):
                raise StoreCorruptionError(
                    "release recovery predates its mutation attempt"
                )
            recovery_values.append(
                {
                    "recovery_id": recovery_id,
                    "attempt_id": attempt_id,
                    "classification": classification,
                    "evidence_digest": evidence_digest,
                    "evidence": evidence,
                    "recorded_at": _epoch_text(recorded_at),
                }
            )

        for attempt, projected in attempts_by_id.values():
            if (
                projected["state"] in {"absent", "indeterminate"}
                and projected["attempt_id"] not in recovery_attempt_ids
            ):
                raise StoreCorruptionError(
                    "reconciled release mutation lacks recovery evidence"
                )

        latest_attempt = attempt_values[-1] if attempt_values else None
        latest_recovery = recovery_values[-1] if recovery_values else None
        step_state = str(step["state"])
        if step_state == "mutation_pending":
            if (
                latest_attempt is None
                or latest_attempt["state"] != "pending"
                or step["active_attempt_id"]
                != latest_attempt["attempt_id"]
                or (
                    len(attempt_values) == 1
                    and step_detail is not None
                )
                or (
                    len(attempt_values) == 2
                    and step_detail
                    != attempt_values[0]["terminal_detail"]
                )
            ):
                raise StoreCorruptionError(
                    "pending release step conflicts with its latest attempt"
                )
        elif step_state == "confirmed":
            if (
                latest_attempt is None
                or latest_attempt["state"] != "confirmed"
                or step["active_attempt_id"] is not None
                or latest_attempt["merge_sha"] != step["merge_sha"]
                or latest_attempt["parent_sha"] != step["parent_sha"]
                or latest_attempt["tree_sha"] != step["tree_sha"]
                or latest_attempt["merged_by"] != step["merged_by"]
                or step["confirmed_at"] is None
                or latest_attempt["terminal_at"]
                != _epoch_text(int(step["confirmed_at"]))
                or (
                    len(attempt_values) == 1
                    and step_detail is not None
                )
                or (
                    len(attempt_values) == 2
                    and step_detail
                    != attempt_values[0]["terminal_detail"]
                )
            ):
                raise StoreCorruptionError(
                    "confirmed release step conflicts with its attempt"
                )
        elif step_state == "pending":
            if (
                step["active_attempt_id"] is not None
                or (
                    latest_attempt is not None
                    and latest_attempt["state"] != "absent"
                )
                or (
                    latest_attempt is not None
                    and step_detail != latest_attempt["terminal_detail"]
                )
            ):
                raise StoreCorruptionError(
                    "pending release step has inconsistent attempt history"
                )
        elif step_state == "rejected":
            if (
                step["active_attempt_id"] is not None
                or step_detail is None
                or (
                    latest_attempt is not None
                    and latest_attempt["state"] != "absent"
                )
            ):
                raise StoreCorruptionError(
                    "rejected release step has inconsistent history"
                )
        elif step_state == "indeterminate":
            if (
                step["active_attempt_id"] is not None
                or step_detail is None
                or (
                    latest_attempt is not None
                    and latest_attempt["state"] != "indeterminate"
                )
                or (
                    latest_attempt is not None
                    and step_detail != latest_attempt["terminal_detail"]
                )
            ):
                raise StoreCorruptionError(
                    "indeterminate release step has inconsistent history"
                )
        else:
            raise StoreCorruptionError("release step state is corrupted")

        return latest_attempt, latest_recovery, step_detail

    def bundle_snapshot(self, bundle_key: str) -> dict[str, Any]:
        if not BUNDLE_KEY_RE.fullmatch(bundle_key):
            raise ReleaseBrokerStoreError("release bundle key is invalid")
        self._ensure_open()
        self._assert_runtime_bound()
        bundle = self._db.execute(
            "SELECT * FROM bundles WHERE bundle_key = ?",
            (bundle_key,),
        ).fetchone()
        if bundle is None:
            raise StateTransitionError("release bundle is not reserved")
        self._validate_bundle_row(bundle)
        steps = self._db.execute(
            """
            SELECT *
            FROM bundle_steps
            WHERE bundle_key = ?
            ORDER BY position
            """,
            (bundle_key,),
        ).fetchall()
        if len(steps) != int(bundle["step_count"]):
            raise StoreCorruptionError(
                "release bundle step count is corrupted"
            )
        normalized_steps: list[dict[str, Any]] = []
        for expected_position, step in enumerate(steps):
            if int(step["position"]) != expected_position:
                raise StoreCorruptionError(
                    "release bundle step order is corrupted"
                )
            if sha256_text(str(step["step_json"])) != step["step_digest"]:
                raise StoreCorruptionError(
                    "persisted release step digest is corrupted"
                )
            step_value = _decode_canonical_json(
                step["step_json"], field="persisted release step"
            )
            if (
                step_value.get("position") != expected_position
                or step_value.get("number") != int(step["pr_number"])
                or step_value.get("head_sha") != step["head_sha"]
            ):
                raise StoreCorruptionError(
                    "persisted release step columns are corrupted"
                )
            (
                latest_attempt,
                latest_recovery,
                step_detail,
            ) = self._snapshot_step_history(
                bundle=bundle,
                step=step,
            )
            normalized_steps.append(
                {
                    "position": int(step["position"]),
                    "pr_number": int(step["pr_number"]),
                    "head_sha": str(step["head_sha"]),
                    "state": str(step["state"]),
                    "expected_base_sha": step["expected_base_sha"],
                    "active_attempt_id": step["active_attempt_id"],
                    "merge_sha": step["merge_sha"],
                    "parent_sha": step["parent_sha"],
                    "tree_sha": step["tree_sha"],
                    "merged_by": step["merged_by"],
                    "confirmed_at": (
                        _epoch_text(int(step["confirmed_at"]))
                        if step["confirmed_at"] is not None
                        else None
                    ),
                    "terminal_detail": step_detail,
                    "latest_attempt": latest_attempt,
                    "latest_recovery": latest_recovery,
                }
            )
        first_packet_id = str(bundle["first_packet_id"])
        last_packet_id = str(bundle["last_packet_id"])
        self._packet_for_bundle(
            packet_id=first_packet_id,
            bundle_key=bundle_key,
        )
        self._packet_for_bundle(
            packet_id=last_packet_id,
            bundle_key=bundle_key,
        )
        return {
            "bundle_key": str(bundle["bundle_key"]),
            "bundle_id": str(bundle["bundle_id"]),
            "bundle_digest": str(bundle["bundle_digest"]),
            "instance_slug": str(bundle["instance_slug"]),
            "repository_id": int(bundle["repository_id"]),
            "repository_full_name": str(bundle["repository_full_name"]),
            "default_branch": str(bundle["default_branch"]),
            "initial_base_sha": str(bundle["initial_base_sha"]),
            "step_count": int(bundle["step_count"]),
            "state": str(bundle["state"]),
            "first_packet_id": first_packet_id,
            "last_packet_id": last_packet_id,
            "created_at": _epoch_text(int(bundle["created_at"])),
            "expires_at": _epoch_text(int(bundle["expires_at"])),
            "updated_at": _epoch_text(int(bundle["updated_at"])),
            "terminal_at": (
                _epoch_text(int(bundle["terminal_at"]))
                if bundle["terminal_at"] is not None
                else None
            ),
            "terminal_outcome": bundle["terminal_outcome"],
            "steps": normalized_steps,
        }

    def counts(self) -> dict[str, int]:
        self._ensure_open()
        return {
            table: int(
                self._db.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0]
            )
            for table in (
                "runtime_binding",
                "packets",
                "owner_nonces",
                "bundles",
                "bundle_steps",
                "mutation_attempts",
                "recovery_records",
                "budget_events",
                "receipts",
                "circuits",
            )
        }
