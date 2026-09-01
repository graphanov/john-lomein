#!/usr/bin/env python3
"""Durable control state for the isolated John Lomein action broker.

The broker service is expected to run under a credential-owning OS identity
that is different from the model runtime.  This module is deliberately free of
GitHub credentials and network code.  It owns only the durable decisions that
must survive a process crash:

* exact protected-packet acceptance and request-rate accounting;
* semantic action idempotency;
* one durable charge for each mutation attempt;
* pending-attempt recovery and fail-closed indeterminate outcomes;
* terminal receipts written atomically with terminal effect state; and
* action-scoped circuit breakers.

The database directory is part of the security boundary.  It must already
exist, be owned by the broker user, and grant no group or world permissions.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Literal
from urllib.parse import quote


SCHEMA_VERSION = 2
ZERO_HASH = "0" * 64
PACKET_SCHEMA = "john-lomein.protected-action-packet.v1"
PACKET_AUTHORITY = "request_only_no_execution_authority"
EFFECT_SEMANTIC_SCHEMA = "john-lomein.broker-effect-semantic.v1"

ALLOWED_ACTIONS = frozenset({"mark_pr_ready", "resolve_review_thread"})
TERMINAL_STATES = frozenset({"completed", "reconciled", "indeterminate"})
EFFECT_STATES = frozenset({"pending", *TERMINAL_STATES})

MAX_JSON_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_CLOCK_SKEW_SECONDS = 300
MIN_PACKET_TTL_SECONDS = 60
MAX_PACKET_TTL_SECONDS = 3600
REQUEST_WINDOW_SECONDS = 3600

PACKET_ID_RE = re.compile(r"^jlpa-[0-9a-f]{24}$")
PACKET_REQUESTER = "john-lomein-maintainer"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
INSTANCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
REPO_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)
OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
THREAD_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,255}$")
ATTEMPT_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,127}$")
EFFECT_KEY_RE = re.compile(r"^jle-[0-9a-f]{32}$")

Disposition = Literal[
    "reserved",
    "duplicate_pending",
    "receipt_replay",
    "semantic_completed",
    "indeterminate",
]
MutationDisposition = Literal[
    "charged",
    "already_charged",
    "receipt_replay",
    "semantic_completed",
    "indeterminate",
]


class BrokerStoreError(RuntimeError):
    """Base class for fail-closed durable-state errors."""


class UnsafeStoreError(BrokerStoreError):
    """The database path or containing directory is not trustworthy."""


class StoreCorruptionError(BrokerStoreError):
    """Persisted state does not satisfy the canonical store contract."""


class PacketConflictError(BrokerStoreError):
    """A packet identifier or digest was reused for different content."""


class EffectStateError(BrokerStoreError):
    """An effect transition is invalid or conflicts with durable state."""


class PendingRecoveryError(EffectStateError):
    """A charged mutation is pending live-state reconciliation."""


class CircuitOpenError(BrokerStoreError):
    """An action circuit is open and cannot accept new work."""


class BudgetExceeded(BrokerStoreError):
    """A durable request or mutation budget has no remaining capacity."""

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
            f"{budget} budget exhausted "
            f"({used}/{limit}); resets at {utc_text(self.reset_at)}"
        )


@dataclass(frozen=True)
class BudgetLimits:
    """Fail-closed limits supplied by the broker's trusted policy."""

    requests_per_hour: int
    daily_mutations: int
    mark_pr_ready_per_day: int
    review_threads_per_day: int
    consecutive_indeterminate_limit: int

    def __post_init__(self) -> None:
        for field_name in (
            "requests_per_hour",
            "daily_mutations",
            "mark_pr_ready_per_day",
            "review_threads_per_day",
        ):
            value = getattr(self, field_name)
            if type(value) is not int or value < 0 or value > 1_000_000:
                raise ValueError(
                    f"{field_name} must be an integer between 0 and 1000000"
                )
        value = self.consecutive_indeterminate_limit
        if type(value) is not int or value < 1 or value > 1_000_000:
            raise ValueError(
                "consecutive_indeterminate_limit must be an integer "
                "between 1 and 1000000"
            )

    def action_daily_limit(self, action: str) -> int:
        if action == "mark_pr_ready":
            return self.mark_pr_ready_per_day
        if action == "resolve_review_thread":
            return self.review_threads_per_day
        raise ValueError("unsupported broker action")


@dataclass(frozen=True)
class Reservation:
    disposition: Disposition
    packet_id: str
    effect_key: str
    action: str
    state: str
    receipt: dict[str, Any] | None = None
    receipt_packet_id: str | None = None


@dataclass(frozen=True)
class MutationReservation:
    disposition: MutationDisposition
    packet_id: str
    effect_key: str
    action: str
    attempt_key: str | None
    charged_at: str | None
    receipt: dict[str, Any] | None = None
    receipt_packet_id: str | None = None


@dataclass(frozen=True)
class Terminalization:
    disposition: Literal["terminalized", "receipt_replay"]
    packet_id: str
    effect_key: str | None
    action: str
    state: str
    receipt_digest: str
    receipt: dict[str, Any]


@dataclass(frozen=True)
class PendingRecovery:
    packet_id: str
    effect_key: str
    action: str
    repo: str
    pr_number: int
    head_sha: str
    thread_node_id: str | None
    attempt_key: str
    precondition_digest: str
    attempt_started_at: str
    mutation_attempts: int


@dataclass(frozen=True)
class _PacketIdentity:
    packet_id: str
    request_digest: str
    packet_json: str
    instance_slug: str
    action: str
    repo: str
    pr_number: int
    head_sha: str
    thread_node_ids: tuple[str, ...]
    created_at: int
    expires_at: int


def utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise BrokerStoreError(f"{field} must be a UTC timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise BrokerStoreError(f"{field} must be a UTC timestamp") from exc


def _now_epoch(value: datetime | None) -> int:
    current = value or datetime.now(timezone.utc)
    if not isinstance(current, datetime) or current.tzinfo is None:
        raise ValueError("now must be a timezone-aware datetime")
    return int(current.astimezone(timezone.utc).timestamp())


def _epoch_text(value: int) -> str:
    return utc_text(datetime.fromtimestamp(value, tz=timezone.utc))


def _normalize_json(
    value: Any,
    *,
    depth: int = 0,
    ancestors: frozenset[int] = frozenset(),
) -> Any:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("JSON exceeds the maximum nesting depth")
    if value is None or type(value) in (bool, str):
        return value
    if type(value) is int:
        if value < -(2**63) or value > 2**63 - 1:
            raise ValueError("JSON integer is outside the signed 64-bit range")
        return value
    if isinstance(value, float):
        raise ValueError("JSON floating-point values are not accepted")
    if isinstance(value, Mapping):
        marker = id(value)
        if marker in ancestors:
            raise ValueError("JSON contains a reference cycle")
        next_ancestors = ancestors | {marker}
        result: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("JSON object keys must be strings")
            result[key] = _normalize_json(
                item,
                depth=depth + 1,
                ancestors=next_ancestors,
            )
        return result
    if isinstance(value, list):
        marker = id(value)
        if marker in ancestors:
            raise ValueError("JSON contains a reference cycle")
        next_ancestors = ancestors | {marker}
        return [
            _normalize_json(
                item,
                depth=depth + 1,
                ancestors=next_ancestors,
            )
            for item in value
        ]
    raise ValueError(f"unsupported JSON value type: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    normalized = _normalize_json(value)
    encoded = json.dumps(
        normalized,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    if len(encoded.encode("utf-8")) > MAX_JSON_BYTES:
        raise ValueError("canonical JSON exceeds the size limit")
    return encoded


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StoreCorruptionError(
                "persisted JSON contains duplicate object fields"
            )
        result[key] = value
    return result


def _reject_nonfinite(_: str) -> None:
    raise StoreCorruptionError("persisted JSON contains a non-finite number")


def _decode_canonical_json(raw: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(raw, str):
        raise StoreCorruptionError(f"{field} is not stored as text")
    if len(raw.encode("utf-8")) > MAX_JSON_BYTES:
        raise StoreCorruptionError(f"{field} exceeds its size limit")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except StoreCorruptionError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise StoreCorruptionError(f"{field} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise StoreCorruptionError(f"{field} must contain a JSON object")
    try:
        expected = canonical_json(value)
    except ValueError as exc:
        raise StoreCorruptionError(f"{field} violates canonical JSON") from exc
    if raw != expected:
        raise StoreCorruptionError(f"{field} is not canonical JSON")
    return value


def _mapping(value: Any, *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BrokerStoreError(f"{field} must be an object")
    return value


def _positive_int(value: Any, *, field: str) -> int:
    if type(value) is not int or value <= 0 or value > 2**31 - 1:
        raise BrokerStoreError(f"{field} must be a positive integer")
    return value


def _packet_identity(
    packet: Mapping[str, Any],
    *,
    now_epoch: int,
) -> _PacketIdentity:
    expected_keys = {
        "schema_version",
        "authority",
        "requested_by",
        "created_at",
        "expires_at",
        "request",
        "packet_id",
        "request_digest",
    }
    if set(packet) != expected_keys:
        raise BrokerStoreError("protected-action packet fields are invalid")
    if packet.get("schema_version") != PACKET_SCHEMA:
        raise BrokerStoreError("protected-action packet schema is unsupported")
    if packet.get("authority") != PACKET_AUTHORITY:
        raise BrokerStoreError("protected-action packet has no request authority")
    if packet.get("requested_by") != PACKET_REQUESTER:
        raise BrokerStoreError("protected-action packet requester is invalid")

    packet_id = packet.get("packet_id")
    request_digest = packet.get("request_digest")
    if not isinstance(packet_id, str) or not PACKET_ID_RE.fullmatch(packet_id):
        raise BrokerStoreError("protected-action packet id is invalid")
    if (
        not isinstance(request_digest, str)
        or not SHA256_RE.fullmatch(request_digest)
    ):
        raise BrokerStoreError("protected-action packet digest is invalid")

    body = {
        key: packet[key]
        for key in (
            "schema_version",
            "authority",
            "requested_by",
            "created_at",
            "expires_at",
            "request",
        )
    }
    computed_digest = sha256_json(body)
    if computed_digest != request_digest:
        raise BrokerStoreError("protected-action packet digest does not match")
    if packet_id != f"jlpa-{computed_digest[:24]}":
        raise BrokerStoreError("protected-action packet id does not match")

    created = _parse_utc(packet.get("created_at"), field="packet created_at")
    expires = _parse_utc(packet.get("expires_at"), field="packet expires_at")
    created_epoch = int(created.timestamp())
    expires_epoch = int(expires.timestamp())
    lifetime = expires_epoch - created_epoch
    if (
        lifetime < MIN_PACKET_TTL_SECONDS
        or lifetime > MAX_PACKET_TTL_SECONDS
    ):
        raise BrokerStoreError("protected-action packet lifetime is invalid")
    if created_epoch > now_epoch + MAX_CLOCK_SKEW_SECONDS:
        raise BrokerStoreError("protected-action packet is from the future")
    if now_epoch >= expires_epoch:
        raise BrokerStoreError("protected-action packet has expired")

    request = _mapping(packet.get("request"), field="packet request")
    instance_slug = request.get("instance_slug")
    action = request.get("action")
    repo = request.get("repo")
    if (
        not isinstance(instance_slug, str)
        or not INSTANCE_RE.fullmatch(instance_slug)
    ):
        raise BrokerStoreError("packet instance slug is invalid")
    if action not in ALLOWED_ACTIONS:
        raise BrokerStoreError("packet action is unsupported")
    if not isinstance(repo, str) or not REPO_RE.fullmatch(repo):
        raise BrokerStoreError("packet repository is invalid")

    pr = _mapping(request.get("pr"), field="packet request pr")
    pr_number = _positive_int(pr.get("number"), field="packet pr number")
    head_sha = pr.get("head_sha")
    if not isinstance(head_sha, str) or not OID_RE.fullmatch(head_sha):
        raise BrokerStoreError("packet PR head is invalid")

    targets = _mapping(
        request.get("targets"),
        field="packet request targets",
    )
    node_ids = targets.get("thread_node_ids")
    if not isinstance(node_ids, list):
        raise BrokerStoreError("packet thread targets must be an array")
    normalized_ids: list[str] = []
    for node_id in node_ids:
        if (
            not isinstance(node_id, str)
            or not THREAD_ID_RE.fullmatch(node_id)
        ):
            raise BrokerStoreError("packet thread target is invalid")
        normalized_ids.append(node_id)
    if len(normalized_ids) != len(set(normalized_ids)):
        raise BrokerStoreError("packet thread targets must be unique")
    if action == "mark_pr_ready" and normalized_ids:
        raise BrokerStoreError("mark-ready packets cannot target threads")
    if action == "resolve_review_thread" and len(normalized_ids) != 1:
        raise BrokerStoreError(
            "broker v1 requires exactly one review-thread target per packet"
        )

    return _PacketIdentity(
        packet_id=packet_id,
        request_digest=request_digest,
        packet_json=canonical_json(packet),
        instance_slug=instance_slug,
        action=action,
        repo=repo,
        pr_number=pr_number,
        head_sha=head_sha,
        thread_node_ids=tuple(normalized_ids),
        created_at=created_epoch,
        expires_at=expires_epoch,
    )


def _semantic_identity(
    identity: _PacketIdentity,
    *,
    thread_node_id: str | None,
) -> tuple[str, str | None, str]:
    if identity.action == "mark_pr_ready":
        if thread_node_id is not None:
            raise BrokerStoreError("mark-ready effects cannot select a thread")
        semantic = {
            "schema_version": EFFECT_SEMANTIC_SCHEMA,
            "action": identity.action,
            "repo": identity.repo,
            "pr_number": identity.pr_number,
            "head_sha": identity.head_sha,
        }
        selected_thread = None
    else:
        selected_thread = thread_node_id
        if selected_thread is None:
            selected_thread = identity.thread_node_ids[0]
        if selected_thread not in identity.thread_node_ids:
            raise BrokerStoreError(
                "selected thread is not bound by the protected packet"
            )
        semantic = {
            "schema_version": EFFECT_SEMANTIC_SCHEMA,
            "action": identity.action,
            "repo": identity.repo,
            "pr_number": identity.pr_number,
            "thread_node_id": selected_thread,
        }
    semantic_json = canonical_json(semantic)
    effect_key = "jle-" + hashlib.sha256(
        semantic_json.encode("utf-8")
    ).hexdigest()[:32]
    return effect_key, selected_thread, semantic_json


def semantic_effect_key(
    packet: Mapping[str, Any],
    *,
    thread_node_id: str | None = None,
    now: datetime | None = None,
) -> str:
    now_epoch = _now_epoch(now)
    identity = _packet_identity(packet, now_epoch=now_epoch)
    return _semantic_identity(
        identity,
        thread_node_id=thread_node_id,
    )[0]


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
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _open_secure_directory_tree(path: Path) -> tuple[Path, int]:
    """Open a canonical directory through non-writable trusted ancestors."""

    try:
        direct_info = os.lstat(path)
    except OSError as exc:
        raise UnsafeStoreError(
            "broker database directory is unavailable"
        ) from exc
    if stat.S_ISLNK(direct_info.st_mode):
        raise UnsafeStoreError(
            "broker database directory must not be a symlink"
        )
    try:
        canonical = path.resolve(strict=True)
    except OSError as exc:
        raise UnsafeStoreError(
            "broker database directory is unavailable"
        ) from exc

    try:
        current_fd = os.open("/", _directory_flags())
    except OSError as exc:
        raise UnsafeStoreError("filesystem root is unsafe") from exc
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
                    "broker database path contains an unsafe directory"
                ) from exc
            os.close(current_fd)
            current_fd = next_fd
            info = os.fstat(current_fd)
            if not stat.S_ISDIR(info.st_mode):
                raise UnsafeStoreError(
                    "broker database path component is not a directory"
                )
            if hasattr(os, "geteuid") and info.st_uid not in {
                0,
                os.geteuid(),
            }:
                raise UnsafeStoreError(
                    "broker database path has an untrusted owner"
                )
            writable_by_other = bool(info.st_mode & 0o022)
            sticky_root = bool(
                info.st_mode & stat.S_ISVTX and info.st_uid == 0
            )
            if writable_by_other and not sticky_root:
                raise UnsafeStoreError(
                    "broker database path is writable by another identity"
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
CREATE TABLE IF NOT EXISTS broker_binding (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    binding_digest TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    bound_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS packets (
    packet_id TEXT PRIMARY KEY,
    request_digest TEXT NOT NULL UNIQUE,
    instance_slug TEXT NOT NULL,
    action TEXT NOT NULL CHECK (
        action IN ('mark_pr_ready', 'resolve_review_thread')
    ),
    repo TEXT NOT NULL,
    pr_number INTEGER NOT NULL CHECK (pr_number > 0),
    head_sha TEXT NOT NULL,
    packet_json TEXT NOT NULL,
    accepted_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > accepted_at)
) STRICT;

CREATE TABLE IF NOT EXISTS effects (
    effect_key TEXT PRIMARY KEY,
    semantic_json TEXT NOT NULL UNIQUE,
    instance_slug TEXT NOT NULL,
    action TEXT NOT NULL CHECK (
        action IN ('mark_pr_ready', 'resolve_review_thread')
    ),
    repo TEXT NOT NULL,
    pr_number INTEGER NOT NULL CHECK (pr_number > 0),
    head_sha TEXT NOT NULL,
    thread_node_id TEXT,
    state TEXT NOT NULL CHECK (
        state IN ('pending', 'completed', 'reconciled', 'indeterminate')
    ),
    first_packet_id TEXT NOT NULL REFERENCES packets(packet_id),
    last_packet_id TEXT NOT NULL REFERENCES packets(packet_id),
    active_attempt_key TEXT,
    active_attempt_packet_id TEXT REFERENCES packets(packet_id),
    active_precondition_digest TEXT,
    active_attempt_started_at INTEGER,
    mutation_attempts INTEGER NOT NULL DEFAULT 0
        CHECK (mutation_attempts >= 0),
    last_reconciliation_json TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    terminal_at INTEGER,
    CHECK (
        (action = 'mark_pr_ready' AND thread_node_id IS NULL)
        OR
        (action = 'resolve_review_thread' AND thread_node_id IS NOT NULL)
    ),
    CHECK (
        (active_attempt_key IS NULL
         AND active_attempt_packet_id IS NULL
         AND active_precondition_digest IS NULL
         AND active_attempt_started_at IS NULL)
        OR
        (active_attempt_key IS NOT NULL
         AND active_attempt_packet_id IS NOT NULL
         AND active_precondition_digest IS NOT NULL
         AND active_attempt_started_at IS NOT NULL)
    ),
    CHECK (
        (state = 'pending' AND terminal_at IS NULL)
        OR
        (state != 'pending' AND terminal_at IS NOT NULL)
    )
) STRICT;

CREATE TABLE IF NOT EXISTS budget_events (
    event_key TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('request', 'mutation')),
    instance_slug TEXT NOT NULL,
    action TEXT NOT NULL CHECK (
        action IN ('mark_pr_ready', 'resolve_review_thread')
    ),
    occurred_at INTEGER NOT NULL,
    utc_day TEXT NOT NULL,
    packet_id TEXT NOT NULL REFERENCES packets(packet_id),
    effect_key TEXT REFERENCES effects(effect_key),
    attempt_key TEXT,
    detail_json TEXT NOT NULL,
    CHECK (
        (kind = 'request' AND effect_key IS NULL AND attempt_key IS NULL)
        OR
        (kind = 'mutation' AND effect_key IS NOT NULL
         AND attempt_key IS NOT NULL)
    )
) STRICT;

CREATE INDEX IF NOT EXISTS budget_request_window
ON budget_events(instance_slug, kind, occurred_at);

CREATE INDEX IF NOT EXISTS budget_mutation_day
ON budget_events(instance_slug, kind, utc_day, action);

CREATE TABLE IF NOT EXISTS receipts (
    receipt_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_digest TEXT NOT NULL UNIQUE,
    effect_key TEXT REFERENCES effects(effect_key),
    packet_id TEXT NOT NULL UNIQUE REFERENCES packets(packet_id),
    terminal_state TEXT NOT NULL CHECK (
        terminal_state IN (
            'completed', 'reconciled', 'indeterminate', 'rejected', 'failed'
        )
    ),
    receipt_json TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS circuit_breakers (
    circuit_key TEXT PRIMARY KEY,
    instance_slug TEXT NOT NULL,
    action TEXT NOT NULL CHECK (
        action IN ('mark_pr_ready', 'resolve_review_thread')
    ),
    state TEXT NOT NULL CHECK (state IN ('closed', 'open')),
    consecutive_indeterminate INTEGER NOT NULL DEFAULT 0
        CHECK (consecutive_indeterminate >= 0),
    opened_at INTEGER,
    reason_json TEXT,
    updated_at INTEGER NOT NULL,
    UNIQUE(instance_slug, action),
    CHECK (
        (state = 'closed' AND opened_at IS NULL)
        OR
        (state = 'open' AND opened_at IS NOT NULL)
    )
) STRICT;
"""


class BrokerStore:
    """Crash-safe SQLite state used by a single isolated broker service."""

    def __init__(self, database_path: Path | str, *, timeout: float = 5.0):
        path = Path(database_path).expanduser()
        if not path.is_absolute():
            raise UnsafeStoreError("broker database path must be absolute")
        if not path.name or path.name in {".", ".."}:
            raise UnsafeStoreError("broker database filename is invalid")
        if type(timeout) not in (int, float) or timeout <= 0 or timeout > 60:
            raise ValueError("timeout must be between zero and 60 seconds")

        try:
            canonical_parent, directory_fd = _open_secure_directory_tree(
                path.parent
            )
            path = canonical_parent / path.name
        except UnsafeStoreError:
            raise
        database_fd = -1
        connection: sqlite3.Connection | None = None
        try:
            directory_info = os.fstat(directory_fd)
            _require_secure_owner_mode(
                directory_info,
                field="broker database directory",
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
                    "broker database file is unsafe"
                ) from exc
            database_info = os.fstat(database_fd)
            _require_secure_owner_mode(
                database_info,
                field="broker database file",
                directory=False,
            )

            # Recheck the name while retaining both the directory and database
            # descriptors.  The non-writable broker-owned directory prevents
            # the unprivileged runtime from swapping the name afterward.
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
                    "broker database name changed during validation"
                )

            uri = "file:" + quote(str(path), safe="/") + "?mode=rw"
            connection = sqlite3.connect(
                uri,
                uri=True,
                timeout=float(timeout),
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            self._configure(connection)
            self._initialize_schema(connection)
            self._validate_database(connection)
            self._check_sidecars(directory_fd, path.name)

            post_info = os.stat(
                path.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if (
                post_info.st_dev,
                post_info.st_ino,
            ) != (
                database_info.st_dev,
                database_info.st_ino,
            ):
                raise UnsafeStoreError(
                    "broker database changed while opening"
                )
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

    @staticmethod
    def _check_sidecars(directory_fd: int, name: str) -> None:
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = name + suffix
            try:
                info = os.stat(
                    sidecar,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise UnsafeStoreError(
                    "broker database sidecar is unsafe"
                ) from exc
            if not stat.S_ISREG(info.st_mode):
                raise UnsafeStoreError(
                    "broker database sidecar has the wrong file type"
                )
            if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
                raise UnsafeStoreError(
                    "broker database sidecar has an unsafe owner"
                )
            if info.st_mode & 0o022:
                raise UnsafeStoreError(
                    "broker database sidecar is writable by another identity"
                )
            if info.st_nlink != 1:
                raise UnsafeStoreError(
                    "broker database sidecar must not be hard-linked"
                )

    @staticmethod
    def _configure(connection: sqlite3.Connection) -> None:
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA foreign_keys = ON")
        mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if str(mode).lower() != "wal":
            raise UnsafeStoreError("broker database could not enable WAL mode")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA fullfsync = ON")
        connection.execute("PRAGMA checkpoint_fullfsync = ON")
        connection.execute("PRAGMA wal_autocheckpoint = 1000")
        connection.execute("PRAGMA temp_store = MEMORY")
        connection.execute("PRAGMA secure_delete = ON")
        connection.execute("PRAGMA busy_timeout = 5000")

    @staticmethod
    def _initialize_schema(connection: sqlite3.Connection) -> None:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version not in (0, 1, SCHEMA_VERSION):
            raise StoreCorruptionError(
                f"unsupported broker database schema version: {version}"
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
        elif version == 1:
            try:
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE IF NOT EXISTS broker_binding (
                        singleton INTEGER PRIMARY KEY
                            CHECK (singleton = 1),
                        binding_digest TEXT NOT NULL,
                        binding_json TEXT NOT NULL,
                        bound_at INTEGER NOT NULL
                    ) STRICT;
                    PRAGMA user_version = 2;
                    COMMIT;
                    """
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
        }
        if settings != {
            "foreign_keys": 1,
            "trusted_schema": 0,
            "synchronous": 2,
        }:
            raise UnsafeStoreError(
                "broker database durability pragmas are not active"
            )
        quick = connection.execute("PRAGMA quick_check").fetchall()
        if [row[0] for row in quick] != ["ok"]:
            raise StoreCorruptionError("broker database integrity check failed")
        foreign = connection.execute("PRAGMA foreign_key_check").fetchall()
        if foreign:
            raise StoreCorruptionError(
                "broker database foreign-key check failed"
            )

    def __enter__(self) -> BrokerStore:
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
            raise BrokerStoreError("broker store is closed")

    def bind_runtime(
        self,
        binding: Mapping[str, Any],
        *,
        now: datetime | None = None,
    ) -> str:
        """Permanently bind durable state to one normalized broker config.

        A legacy database that already contains broker decisions cannot be
        adopted implicitly because there is no trustworthy way to prove which
        policy, repository, App installation, or receipt key produced them.
        """

        binding_json = canonical_json(binding)
        binding_digest = hashlib.sha256(
            binding_json.encode("utf-8")
        ).hexdigest()
        now_epoch = _now_epoch(now)
        with self._immediate():
            rows = self._db.execute(
                """
                SELECT binding_digest, binding_json
                FROM broker_binding
                ORDER BY singleton
                """
            ).fetchall()
            if len(rows) > 1:
                raise StoreCorruptionError(
                    "broker database has multiple runtime bindings"
                )
            if rows:
                persisted_json = str(rows[0]["binding_json"])
                persisted_digest = str(rows[0]["binding_digest"])
                if (
                    not SHA256_RE.fullmatch(persisted_digest)
                    or hashlib.sha256(
                        persisted_json.encode("utf-8")
                    ).hexdigest()
                    != persisted_digest
                ):
                    raise StoreCorruptionError(
                        "broker runtime binding is corrupted"
                    )
                _decode_canonical_json(
                    persisted_json,
                    field="broker runtime binding",
                )
                if (
                    persisted_digest != binding_digest
                    or persisted_json != binding_json
                ):
                    raise StoreCorruptionError(
                        "broker database is bound to a different config"
                    )
                return binding_digest

            durable_rows = sum(
                int(
                    self._db.execute(
                        f"SELECT count(*) FROM {table}"
                    ).fetchone()[0]
                )
                for table in (
                    "packets",
                    "effects",
                    "budget_events",
                    "receipts",
                    "circuit_breakers",
                )
            )
            if durable_rows:
                raise StoreCorruptionError(
                    "unbound broker database already contains durable state"
                )
            self._db.execute(
                """
                INSERT INTO broker_binding(
                    singleton, binding_digest, binding_json, bound_at
                ) VALUES (1, ?, ?, ?)
                """,
                (binding_digest, binding_json, now_epoch),
            )
            return binding_digest

    @contextmanager
    def _immediate(self) -> Iterator[None]:
        self._ensure_open()
        try:
            self._db.execute("BEGIN IMMEDIATE")
            yield
            self._db.execute("COMMIT")
        except Exception:
            if self._db.in_transaction:
                self._db.execute("ROLLBACK")
            raise

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
    def _circuit_key(instance_slug: str, action: str) -> str:
        return f"{instance_slug}:{action}"

    def _assert_circuit_closed(
        self,
        *,
        instance_slug: str,
        action: str,
    ) -> None:
        row = self._db.execute(
            """
            SELECT state, consecutive_indeterminate
            FROM circuit_breakers
            WHERE instance_slug = ? AND action = ?
            """,
            (instance_slug, action),
        ).fetchone()
        if row is not None and row["state"] == "open":
            raise CircuitOpenError(
                f"{action} circuit is open after "
                f"{row['consecutive_indeterminate']} "
                "indeterminate outcomes"
            )

    @staticmethod
    def _utc_day(epoch: int) -> str:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime(
            "%Y-%m-%d"
        )

    def _request_budget(
        self,
        *,
        identity: _PacketIdentity,
        limits: BudgetLimits,
        now_epoch: int,
    ) -> None:
        cutoff = now_epoch - REQUEST_WINDOW_SECONDS
        rows = self._db.execute(
            """
            SELECT occurred_at
            FROM budget_events
            WHERE instance_slug = ?
              AND kind = 'request'
              AND occurred_at > ?
            ORDER BY occurred_at
            """,
            (identity.instance_slug, cutoff),
        ).fetchall()
        used = len(rows)
        if used >= limits.requests_per_hour:
            if rows:
                reset_epoch = max(
                    now_epoch + 1,
                    int(rows[0]["occurred_at"]) + REQUEST_WINDOW_SECONDS,
                )
            else:
                reset_epoch = now_epoch + REQUEST_WINDOW_SECONDS
            raise BudgetExceeded(
                budget="requests_per_hour",
                limit=limits.requests_per_hour,
                used=used,
                reset_at=datetime.fromtimestamp(
                    reset_epoch,
                    tz=timezone.utc,
                ),
            )

        detail = canonical_json(
            {
                "kind": "request",
                "limit": limits.requests_per_hour,
                "request_digest": identity.request_digest,
                "window_seconds": REQUEST_WINDOW_SECONDS,
            }
        )
        self._db.execute(
            """
            INSERT INTO budget_events(
                event_key, kind, instance_slug, action, occurred_at,
                utc_day, packet_id, effect_key, attempt_key, detail_json
            ) VALUES (?, 'request', ?, ?, ?, ?, ?, NULL, NULL, ?)
            """,
            (
                "request:" + identity.packet_id,
                identity.instance_slug,
                identity.action,
                now_epoch,
                self._utc_day(now_epoch),
                identity.packet_id,
                detail,
            ),
        )

    @staticmethod
    def _decode_receipt_row(
        row: sqlite3.Row,
    ) -> tuple[str, str, str, dict[str, Any]]:
        value = _decode_canonical_json(
            row["receipt_json"],
            field="broker receipt",
        )
        digest = hashlib.sha256(
            row["receipt_json"].encode("utf-8")
        ).hexdigest()
        if digest != row["receipt_digest"]:
            raise StoreCorruptionError("broker receipt digest does not match")
        return (
            digest,
            str(row["packet_id"]),
            str(row["terminal_state"]),
            value,
        )

    def _load_packet_receipt(
        self,
        packet_id: str,
    ) -> tuple[str, str, str, dict[str, Any]] | None:
        row = self._db.execute(
            """
            SELECT receipt_digest, packet_id, terminal_state, receipt_json
            FROM receipts
            WHERE packet_id = ?
            """,
            (packet_id,),
        ).fetchone()
        if row is None:
            return None
        return self._decode_receipt_row(row)

    def _load_latest_effect_receipt(
        self,
        effect_key: str,
    ) -> tuple[str, str, str, dict[str, Any]] | None:
        row = self._db.execute(
            """
            SELECT receipt_digest, packet_id, terminal_state, receipt_json
            FROM receipts
            WHERE effect_key = ?
              AND terminal_state IN (
                  'completed', 'reconciled', 'indeterminate'
              )
            ORDER BY receipt_sequence DESC
            LIMIT 1
            """,
            (effect_key,),
        ).fetchone()
        if row is None:
            return None
        return self._decode_receipt_row(row)

    def receipt_for_packet(
        self,
        packet_id: str,
    ) -> dict[str, Any] | None:
        """Return the exact canonical receipt bound to one accepted packet."""

        if not PACKET_ID_RE.fullmatch(packet_id):
            raise BrokerStoreError("packet id is invalid")
        self._ensure_open()
        persisted = self._load_packet_receipt(packet_id)
        return persisted[3] if persisted is not None else None

    def latest_receipt_digest(self) -> str:
        """Return the current broker-wide receipt-chain head."""

        self._ensure_open()
        row = self._db.execute(
            """
            SELECT receipt_digest, packet_id, terminal_state, receipt_json
            FROM receipts
            ORDER BY receipt_sequence DESC
            LIMIT 1
            """
        ).fetchone()
        if row is None:
            return ZERO_HASH
        return self._decode_receipt_row(row)[0]

    def load_packet(self, packet_id: str) -> dict[str, Any]:
        """Load and revalidate a canonical accepted packet for recovery."""

        if not PACKET_ID_RE.fullmatch(packet_id):
            raise BrokerStoreError("packet id is invalid")
        self._ensure_open()
        row = self._db.execute(
            """
            SELECT request_digest, instance_slug, action, repo, pr_number,
                   head_sha, packet_json, expires_at
            FROM packets
            WHERE packet_id = ?
            """,
            (packet_id,),
        ).fetchone()
        if row is None:
            raise BrokerStoreError("accepted packet does not exist")
        packet = _decode_canonical_json(
            row["packet_json"],
            field="protected-action packet",
        )
        identity = _packet_identity(
            packet,
            now_epoch=int(row["expires_at"]) - 1,
        )
        expected = (
            identity.request_digest,
            identity.instance_slug,
            identity.action,
            identity.repo,
            identity.pr_number,
            identity.head_sha,
        )
        persisted = (
            str(row["request_digest"]),
            str(row["instance_slug"]),
            str(row["action"]),
            str(row["repo"]),
            int(row["pr_number"]),
            str(row["head_sha"]),
        )
        if identity.packet_id != packet_id or expected != persisted:
            raise StoreCorruptionError(
                "accepted packet columns do not match canonical packet"
            )
        return packet

    def _reservation_from_effect(
        self,
        row: sqlite3.Row,
        *,
        packet_id: str,
        new_effect: bool,
    ) -> Reservation:
        state = str(row["state"])
        exact = self._load_packet_receipt(packet_id)
        if exact is not None:
            return Reservation(
                disposition="receipt_replay",
                packet_id=packet_id,
                effect_key=str(row["effect_key"]),
                action=str(row["action"]),
                state=exact[2],
                receipt=exact[3],
                receipt_packet_id=exact[1],
            )
        if state in {"completed", "reconciled"}:
            persisted = self._load_latest_effect_receipt(
                str(row["effect_key"])
            )
            if persisted is None:
                raise StoreCorruptionError(
                    "terminal broker effect has no receipt"
                )
            return Reservation(
                disposition="semantic_completed",
                packet_id=packet_id,
                effect_key=str(row["effect_key"]),
                action=str(row["action"]),
                state=state,
                receipt=persisted[3],
                receipt_packet_id=persisted[1],
            )
        if state == "indeterminate":
            persisted = self._load_latest_effect_receipt(
                str(row["effect_key"])
            )
            if persisted is None:
                raise StoreCorruptionError(
                    "indeterminate broker effect has no receipt"
                )
            return Reservation(
                disposition="indeterminate",
                packet_id=packet_id,
                effect_key=str(row["effect_key"]),
                action=str(row["action"]),
                state=state,
                receipt=persisted[3],
                receipt_packet_id=persisted[1],
            )
        return Reservation(
            disposition="reserved" if new_effect else "duplicate_pending",
            packet_id=packet_id,
            effect_key=str(row["effect_key"]),
            action=str(row["action"]),
            state=state,
        )

    def reserve(
        self,
        packet: Mapping[str, Any],
        limits: BudgetLimits,
        *,
        thread_node_id: str | None = None,
        now: datetime | None = None,
    ) -> Reservation:
        """Accept one packet/effect under an immediate durable reservation.

        A multi-thread packet is intentionally expanded one thread at a time.
        The packet itself consumes request budget only once, while every thread
        gets its own semantic effect and later mutation charge.
        """

        now_epoch = _now_epoch(now)
        identity = _packet_identity(packet, now_epoch=now_epoch)
        effect_key, selected_thread, semantic_json = _semantic_identity(
            identity,
            thread_node_id=thread_node_id,
        )

        with self._immediate():
            existing_packet = self._db.execute(
                """
                SELECT packet_id, request_digest, packet_json
                FROM packets
                WHERE packet_id = ?
                """,
                (identity.packet_id,),
            ).fetchone()
            if existing_packet is not None:
                if (
                    existing_packet["request_digest"]
                    != identity.request_digest
                    or existing_packet["packet_json"] != identity.packet_json
                ):
                    raise PacketConflictError(
                        "packet id conflicts with persisted packet content"
                    )
            else:
                digest_packet = self._db.execute(
                    """
                    SELECT packet_id, packet_json
                    FROM packets
                    WHERE request_digest = ?
                    """,
                    (identity.request_digest,),
                ).fetchone()
                if digest_packet is not None:
                    raise PacketConflictError(
                        "packet digest conflicts with another packet"
                    )
                self._assert_circuit_closed(
                    instance_slug=identity.instance_slug,
                    action=identity.action,
                )
                self._db.execute(
                    """
                    INSERT INTO packets(
                        packet_id, request_digest, instance_slug, action,
                        repo, pr_number, head_sha, packet_json, accepted_at,
                        expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        identity.packet_id,
                        identity.request_digest,
                        identity.instance_slug,
                        identity.action,
                        identity.repo,
                        identity.pr_number,
                        identity.head_sha,
                        identity.packet_json,
                        now_epoch,
                        identity.expires_at,
                    ),
                )
                self._request_budget(
                    identity=identity,
                    limits=limits,
                    now_epoch=now_epoch,
                )

            effect = self._db.execute(
                "SELECT * FROM effects WHERE effect_key = ?",
                (effect_key,),
            ).fetchone()
            new_effect = effect is None
            if effect is None:
                self._assert_circuit_closed(
                    instance_slug=identity.instance_slug,
                    action=identity.action,
                )
                self._db.execute(
                    """
                    INSERT INTO effects(
                        effect_key, semantic_json, instance_slug, action,
                        repo, pr_number, head_sha, thread_node_id, state,
                        first_packet_id, last_packet_id, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)
                    """,
                    (
                        effect_key,
                        semantic_json,
                        identity.instance_slug,
                        identity.action,
                        identity.repo,
                        identity.pr_number,
                        identity.head_sha,
                        selected_thread,
                        identity.packet_id,
                        identity.packet_id,
                        now_epoch,
                        now_epoch,
                    ),
                )
                effect = self._db.execute(
                    "SELECT * FROM effects WHERE effect_key = ?",
                    (effect_key,),
                ).fetchone()
            else:
                if effect["semantic_json"] != semantic_json:
                    raise StoreCorruptionError(
                        "semantic effect key collides with different content"
                    )
                if effect["instance_slug"] != identity.instance_slug:
                    raise EffectStateError(
                        "semantic effect is owned by another broker instance"
                    )
                self._db.execute(
                    """
                    UPDATE effects
                    SET last_packet_id = ?, updated_at = ?
                    WHERE effect_key = ?
                    """,
                    (identity.packet_id, now_epoch, effect_key),
                )
                effect = self._db.execute(
                    "SELECT * FROM effects WHERE effect_key = ?",
                    (effect_key,),
                ).fetchone()
            assert effect is not None
            return self._reservation_from_effect(
                effect,
                packet_id=identity.packet_id,
                new_effect=new_effect,
            )

    def _packet_belongs_to_effect(
        self,
        *,
        packet_id: str,
        effect: sqlite3.Row,
        now_epoch: int,
        allow_expired: bool = False,
    ) -> _PacketIdentity:
        row = self._db.execute(
            "SELECT packet_json FROM packets WHERE packet_id = ?",
            (packet_id,),
        ).fetchone()
        if row is None:
            raise EffectStateError("mutation packet is not accepted")
        packet = _decode_canonical_json(
            row["packet_json"],
            field="protected-action packet",
        )
        expires = _parse_utc(packet["expires_at"], field="packet expires_at")
        validation_epoch = now_epoch
        if allow_expired:
            # An already charged attempt or a packet-level outcome may finish
            # after expiry.  Only association is being checked in that case;
            # begin_mutation deliberately does not use this exception.
            validation_epoch = min(
                now_epoch,
                int(expires.timestamp()) - 1,
            )
        identity = _packet_identity(
            packet,
            now_epoch=validation_epoch,
        )
        selected_thread = (
            str(effect["thread_node_id"])
            if effect["thread_node_id"] is not None
            else None
        )
        expected_key = _semantic_identity(
            identity,
            thread_node_id=selected_thread,
        )[0]
        if (
            expected_key != effect["effect_key"]
            or identity.instance_slug != effect["instance_slug"]
        ):
            raise EffectStateError(
                "mutation packet does not bind the semantic effect"
            )
        return identity

    def _mutation_budget(
        self,
        *,
        effect: sqlite3.Row,
        packet_id: str,
        attempt_key: str,
        precondition_digest: str,
        limits: BudgetLimits,
        now_epoch: int,
    ) -> None:
        utc_day = self._utc_day(now_epoch)
        global_used = int(
            self._db.execute(
                """
                SELECT count(*)
                FROM budget_events
                WHERE instance_slug = ?
                  AND kind = 'mutation'
                  AND utc_day = ?
                """,
                (effect["instance_slug"], utc_day),
            ).fetchone()[0]
        )
        if global_used >= limits.daily_mutations:
            reset = datetime.strptime(
                utc_day, "%Y-%m-%d"
            ).replace(tzinfo=timezone.utc) + timedelta(days=1)
            raise BudgetExceeded(
                budget="daily_mutations",
                limit=limits.daily_mutations,
                used=global_used,
                reset_at=reset,
            )

        action_limit = limits.action_daily_limit(str(effect["action"]))
        action_used = int(
            self._db.execute(
                """
                SELECT count(*)
                FROM budget_events
                WHERE instance_slug = ?
                  AND kind = 'mutation'
                  AND utc_day = ?
                  AND action = ?
                """,
                (
                    effect["instance_slug"],
                    utc_day,
                    effect["action"],
                ),
            ).fetchone()[0]
        )
        if action_used >= action_limit:
            reset = datetime.strptime(
                utc_day, "%Y-%m-%d"
            ).replace(tzinfo=timezone.utc) + timedelta(days=1)
            budget_name = (
                "mark_pr_ready_per_day"
                if effect["action"] == "mark_pr_ready"
                else "review_threads_per_day"
            )
            raise BudgetExceeded(
                budget=budget_name,
                limit=action_limit,
                used=action_used,
                reset_at=reset,
            )

        detail = canonical_json(
            {
                "action_limit": action_limit,
                "attempt_key": attempt_key,
                "daily_mutations_limit": limits.daily_mutations,
                "effect_key": effect["effect_key"],
                "kind": "mutation",
                "precondition_digest": precondition_digest,
            }
        )
        self._db.execute(
            """
            INSERT INTO budget_events(
                event_key, kind, instance_slug, action, occurred_at,
                utc_day, packet_id, effect_key, attempt_key, detail_json
            ) VALUES (?, 'mutation', ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"mutation:{effect['effect_key']}:{attempt_key}",
                effect["instance_slug"],
                effect["action"],
                now_epoch,
                utc_day,
                packet_id,
                effect["effect_key"],
                attempt_key,
                detail,
            ),
        )

    def begin_mutation(
        self,
        effect_key: str,
        packet_id: str,
        attempt_key: str,
        limits: BudgetLimits,
        *,
        precondition_digest: str,
        now: datetime | None = None,
    ) -> MutationReservation:
        """Reserve and charge exactly one externally visible mutation attempt."""

        if not EFFECT_KEY_RE.fullmatch(effect_key):
            raise BrokerStoreError("effect key is invalid")
        if not PACKET_ID_RE.fullmatch(packet_id):
            raise BrokerStoreError("packet id is invalid")
        if not ATTEMPT_KEY_RE.fullmatch(attempt_key):
            raise BrokerStoreError("mutation attempt key is invalid")
        if not SHA256_RE.fullmatch(precondition_digest):
            raise BrokerStoreError("precondition digest is invalid")
        now_epoch = _now_epoch(now)

        with self._immediate():
            effect = self._db.execute(
                "SELECT * FROM effects WHERE effect_key = ?",
                (effect_key,),
            ).fetchone()
            if effect is None:
                raise EffectStateError("semantic effect is not reserved")

            exact_receipt = self._load_packet_receipt(packet_id)
            if exact_receipt is not None:
                return MutationReservation(
                    disposition="receipt_replay",
                    packet_id=packet_id,
                    effect_key=effect_key,
                    action=str(effect["action"]),
                    attempt_key=None,
                    charged_at=None,
                    receipt=exact_receipt[3],
                    receipt_packet_id=exact_receipt[1],
                )
            if effect["state"] in TERMINAL_STATES:
                persisted = self._load_latest_effect_receipt(effect_key)
                if persisted is None:
                    raise StoreCorruptionError(
                        "terminal broker effect has no receipt"
                    )
                return MutationReservation(
                    disposition=(
                        "indeterminate"
                        if effect["state"] == "indeterminate"
                        else "semantic_completed"
                    ),
                    packet_id=packet_id,
                    effect_key=effect_key,
                    action=str(effect["action"]),
                    attempt_key=None,
                    charged_at=None,
                    receipt=persisted[3],
                    receipt_packet_id=persisted[1],
                )

            self._packet_belongs_to_effect(
                packet_id=packet_id,
                effect=effect,
                now_epoch=now_epoch,
            )
            if effect["active_attempt_key"] is not None:
                if (
                    effect["active_attempt_key"] == attempt_key
                    and effect["active_attempt_packet_id"] == packet_id
                    and effect["active_precondition_digest"]
                    == precondition_digest
                ):
                    return MutationReservation(
                        disposition="already_charged",
                        packet_id=packet_id,
                        effect_key=effect_key,
                        action=str(effect["action"]),
                        attempt_key=attempt_key,
                        charged_at=_epoch_text(
                            int(effect["active_attempt_started_at"])
                        ),
                    )
                raise PendingRecoveryError(
                    "semantic effect already has a charged pending attempt"
                )
            if int(effect["mutation_attempts"]) >= 2:
                raise EffectStateError(
                    "semantic effect exhausted its single absent-state retry; "
                    "terminalize it as indeterminate"
                )
            prior_attempt = self._db.execute(
                """
                SELECT 1
                FROM budget_events
                WHERE kind = 'mutation'
                  AND effect_key = ?
                  AND attempt_key = ?
                """,
                (effect_key, attempt_key),
            ).fetchone()
            if prior_attempt is not None:
                raise EffectStateError(
                    "mutation attempt key was already consumed"
                )

            self._assert_circuit_closed(
                instance_slug=str(effect["instance_slug"]),
                action=str(effect["action"]),
            )
            self._mutation_budget(
                effect=effect,
                packet_id=packet_id,
                attempt_key=attempt_key,
                precondition_digest=precondition_digest,
                limits=limits,
                now_epoch=now_epoch,
            )
            self._db.execute(
                """
                UPDATE effects
                SET active_attempt_key = ?,
                    active_attempt_packet_id = ?,
                    active_precondition_digest = ?,
                    active_attempt_started_at = ?,
                    mutation_attempts = mutation_attempts + 1,
                    updated_at = ?
                WHERE effect_key = ?
                """,
                (
                    attempt_key,
                    packet_id,
                    precondition_digest,
                    now_epoch,
                    now_epoch,
                    effect_key,
                ),
            )
            return MutationReservation(
                disposition="charged",
                packet_id=packet_id,
                effect_key=effect_key,
                action=str(effect["action"]),
                attempt_key=attempt_key,
                charged_at=_epoch_text(now_epoch),
            )

    def reconcile_absent(
        self,
        effect_key: str,
        packet_id: str,
        attempt_key: str,
        evidence: Mapping[str, Any],
        *,
        now: datetime | None = None,
    ) -> str:
        """Record proof that a charged attempt had no live effect.

        The effect remains pending and a later retry must use a new attempt key,
        which consumes a new mutation budget unit.
        """

        if not EFFECT_KEY_RE.fullmatch(effect_key):
            raise BrokerStoreError("effect key is invalid")
        if not PACKET_ID_RE.fullmatch(packet_id):
            raise BrokerStoreError("packet id is invalid")
        if not ATTEMPT_KEY_RE.fullmatch(attempt_key):
            raise BrokerStoreError("mutation attempt key is invalid")
        now_epoch = _now_epoch(now)
        evidence_value = _decode_canonical_json(
            canonical_json(evidence),
            field="reconciliation evidence",
        )

        with self._immediate():
            effect = self._db.execute(
                "SELECT * FROM effects WHERE effect_key = ?",
                (effect_key,),
            ).fetchone()
            if effect is None or effect["state"] != "pending":
                raise EffectStateError(
                    "only a pending effect can reconcile an absent attempt"
                )
            if effect["active_attempt_key"] is None:
                if effect["last_reconciliation_json"] is not None:
                    previous = _decode_canonical_json(
                        effect["last_reconciliation_json"],
                        field="last reconciliation",
                    )
                    if (
                        previous.get("attempt_key") == attempt_key
                        and previous.get("packet_id") == packet_id
                        and previous.get("result") == "absent"
                        and previous.get("evidence") == evidence_value
                    ):
                        return "already_reconciled_absent"
                raise EffectStateError("effect has no attempt to reconcile")
            if (
                effect["active_attempt_key"] != attempt_key
                or effect["active_attempt_packet_id"] != packet_id
            ):
                raise EffectStateError(
                    "reconciliation does not match the active attempt"
                )
            if int(effect["mutation_attempts"]) >= 2:
                raise EffectStateError(
                    "the retry attempt cannot be recycled; terminalize the "
                    "effect as indeterminate"
                )
            reconciliation_json = canonical_json(
                {
                    "attempt_key": attempt_key,
                    "evidence": evidence_value,
                    "observed_at": _epoch_text(now_epoch),
                    "packet_id": packet_id,
                    "precondition_digest": effect[
                        "active_precondition_digest"
                    ],
                    "result": "absent",
                }
            )
            self._db.execute(
                """
                UPDATE effects
                SET active_attempt_key = NULL,
                    active_attempt_packet_id = NULL,
                    active_precondition_digest = NULL,
                    active_attempt_started_at = NULL,
                    last_reconciliation_json = ?,
                    updated_at = ?
                WHERE effect_key = ?
                """,
                (reconciliation_json, now_epoch, effect_key),
            )
            return "reconciled_absent"

    def _record_terminal_circuit(
        self,
        *,
        effect: sqlite3.Row,
        state: str,
        limits: BudgetLimits | None,
        now_epoch: int,
    ) -> None:
        circuit_key = self._circuit_key(
            str(effect["instance_slug"]),
            str(effect["action"]),
        )
        row = self._db.execute(
            """
            SELECT consecutive_indeterminate
            FROM circuit_breakers
            WHERE circuit_key = ?
            """,
            (circuit_key,),
        ).fetchone()
        if state == "indeterminate":
            if limits is None:
                raise EffectStateError(
                    "indeterminate terminalization requires circuit limits"
                )
            count = (
                int(row["consecutive_indeterminate"]) + 1
                if row is not None
                else 1
            )
            circuit_state = (
                "open"
                if count >= limits.consecutive_indeterminate_limit
                else "closed"
            )
            opened_at = now_epoch if circuit_state == "open" else None
            reason_json = canonical_json(
                {
                    "effect_key": effect["effect_key"],
                    "limit": limits.consecutive_indeterminate_limit,
                    "reason": "consecutive_indeterminate_effects",
                }
            )
        else:
            count = 0
            circuit_state = "closed"
            opened_at = None
            reason_json = None
        self._db.execute(
            """
            INSERT INTO circuit_breakers(
                circuit_key, instance_slug, action, state,
                consecutive_indeterminate, opened_at, reason_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(circuit_key) DO UPDATE SET
                state = excluded.state,
                consecutive_indeterminate =
                    excluded.consecutive_indeterminate,
                opened_at = excluded.opened_at,
                reason_json = excluded.reason_json,
                updated_at = excluded.updated_at
            """,
            (
                circuit_key,
                effect["instance_slug"],
                effect["action"],
                circuit_state,
                count,
                opened_at,
                reason_json,
                now_epoch,
            ),
        )

    def record_packet_receipt(
        self,
        packet_id: str,
        state: Literal["rejected", "failed", "reconciled"],
        receipt: Mapping[str, Any],
        *,
        effect_key: str | None = None,
        now: datetime | None = None,
    ) -> Terminalization:
        """Persist a signed packet outcome that did not mutate GitHub.

        ``rejected`` and ``failed`` are pre-mutation outcomes.  ``reconciled``
        is used when a different packet already completed the same semantic
        effect and live GitHub state confirms that no second mutation is
        needed.  Every accepted packet can therefore replay an exact receipt
        without confusing semantic equivalence with packet identity.
        """

        if not PACKET_ID_RE.fullmatch(packet_id):
            raise BrokerStoreError("packet id is invalid")
        if state not in {"rejected", "failed", "reconciled"}:
            raise BrokerStoreError("packet receipt state is invalid")
        if effect_key is not None and not EFFECT_KEY_RE.fullmatch(effect_key):
            raise BrokerStoreError("effect key is invalid")
        if state == "reconciled" and effect_key is None:
            raise BrokerStoreError(
                "a reconciled packet receipt requires a semantic effect"
            )
        receipt_json = canonical_json(receipt)
        receipt_digest = hashlib.sha256(
            receipt_json.encode("utf-8")
        ).hexdigest()
        receipt_value = _decode_canonical_json(
            receipt_json,
            field="broker receipt",
        )
        now_epoch = _now_epoch(now)

        with self._immediate():
            packet = self._db.execute(
                "SELECT action FROM packets WHERE packet_id = ?",
                (packet_id,),
            ).fetchone()
            if packet is None:
                raise EffectStateError(
                    "packet receipt requires an accepted packet"
                )
            existing = self._load_packet_receipt(packet_id)
            if existing is not None:
                row = self._db.execute(
                    """
                    SELECT effect_key
                    FROM receipts
                    WHERE packet_id = ?
                    """,
                    (packet_id,),
                ).fetchone()
                existing_effect = (
                    str(row["effect_key"])
                    if row["effect_key"] is not None
                    else None
                )
                if (
                    existing[0] != receipt_digest
                    or existing[2] != state
                    or existing_effect != effect_key
                ):
                    raise EffectStateError(
                        "packet conflicts with its persisted receipt"
                    )
                return Terminalization(
                    disposition="receipt_replay",
                    packet_id=packet_id,
                    effect_key=effect_key,
                    action=str(packet["action"]),
                    state=state,
                    receipt_digest=receipt_digest,
                    receipt=existing[3],
                )

            effect: sqlite3.Row | None = None
            if effect_key is not None:
                effect = self._db.execute(
                    "SELECT * FROM effects WHERE effect_key = ?",
                    (effect_key,),
                ).fetchone()
                if effect is None:
                    raise EffectStateError(
                        "packet receipt semantic effect does not exist"
                    )
                self._packet_belongs_to_effect(
                    packet_id=packet_id,
                    effect=effect,
                    now_epoch=now_epoch,
                    allow_expired=True,
                )
                if state == "reconciled":
                    if effect["state"] == "indeterminate":
                        raise EffectStateError(
                            "an indeterminate effect cannot be rewritten as "
                            "reconciled"
                        )
                    if (
                        effect["state"] == "pending"
                        and effect["active_attempt_key"] is not None
                    ):
                        raise EffectStateError(
                            "an already-satisfied reconciliation cannot hide "
                            "a charged attempt"
                        )
                elif effect["active_attempt_key"] is not None:
                    raise EffectStateError(
                        "pre-mutation receipt cannot hide a charged attempt"
                    )

            try:
                self._db.execute(
                    """
                    INSERT INTO receipts(
                        receipt_digest, effect_key, packet_id, terminal_state,
                        receipt_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        receipt_digest,
                        effect_key,
                        packet_id,
                        state,
                        receipt_json,
                        now_epoch,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise EffectStateError(
                    "packet receipt conflicts with durable receipt state"
                ) from exc
            if (
                state == "reconciled"
                and effect is not None
                and effect["state"] == "pending"
            ):
                self._db.execute(
                    """
                    UPDATE effects
                    SET state = 'reconciled',
                        updated_at = ?,
                        terminal_at = ?
                    WHERE effect_key = ?
                    """,
                    (now_epoch, now_epoch, effect_key),
                )
                self._record_terminal_circuit(
                    effect=effect,
                    state="reconciled",
                    limits=None,
                    now_epoch=now_epoch,
                )
            return Terminalization(
                disposition="terminalized",
                packet_id=packet_id,
                effect_key=effect_key,
                action=str(packet["action"]),
                state=state,
                receipt_digest=receipt_digest,
                receipt=receipt_value,
            )

    def terminalize(
        self,
        effect_key: str,
        packet_id: str,
        attempt_key: str,
        state: Literal["completed", "reconciled", "indeterminate"],
        receipt: Mapping[str, Any],
        limits: BudgetLimits,
        *,
        now: datetime | None = None,
    ) -> Terminalization:
        """Atomically persist a receipt and make an effect terminal."""

        if not EFFECT_KEY_RE.fullmatch(effect_key):
            raise BrokerStoreError("effect key is invalid")
        if not PACKET_ID_RE.fullmatch(packet_id):
            raise BrokerStoreError("packet id is invalid")
        if not ATTEMPT_KEY_RE.fullmatch(attempt_key):
            raise BrokerStoreError("mutation attempt key is invalid")
        if state not in TERMINAL_STATES:
            raise BrokerStoreError("terminal broker state is invalid")
        receipt_json = canonical_json(receipt)
        receipt_digest = hashlib.sha256(
            receipt_json.encode("utf-8")
        ).hexdigest()
        receipt_value = _decode_canonical_json(
            receipt_json,
            field="broker receipt",
        )
        now_epoch = _now_epoch(now)

        with self._immediate():
            effect = self._db.execute(
                "SELECT * FROM effects WHERE effect_key = ?",
                (effect_key,),
            ).fetchone()
            if effect is None:
                raise EffectStateError("semantic effect is not reserved")

            if effect["state"] in TERMINAL_STATES:
                persisted = self._load_packet_receipt(packet_id)
                if persisted is None:
                    raise EffectStateError(
                        "semantic effect is already terminal; record a "
                        "packet-bound reconciled receipt instead"
                    )
                if (
                    persisted[0] != receipt_digest
                    or persisted[1] != packet_id
                    or persisted[2] != state
                ):
                    raise EffectStateError(
                        "terminal effect conflicts with persisted receipt"
                    )
                return Terminalization(
                    disposition="receipt_replay",
                    packet_id=packet_id,
                    effect_key=effect_key,
                    action=str(effect["action"]),
                    state=state,
                    receipt_digest=receipt_digest,
                    receipt=persisted[3],
                )

            self._packet_belongs_to_effect(
                packet_id=packet_id,
                effect=effect,
                now_epoch=now_epoch,
                allow_expired=True,
            )
            if (
                effect["active_attempt_key"] != attempt_key
                or effect["active_attempt_packet_id"] != packet_id
            ):
                raise EffectStateError(
                    "terminal receipt does not match the charged attempt"
                )

            self._db.execute(
                """
                INSERT INTO receipts(
                    receipt_digest, effect_key, packet_id, terminal_state,
                    receipt_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt_digest,
                    effect_key,
                    packet_id,
                    state,
                    receipt_json,
                    now_epoch,
                ),
            )
            self._db.execute(
                """
                UPDATE effects
                SET state = ?,
                    active_attempt_key = NULL,
                    active_attempt_packet_id = NULL,
                    active_precondition_digest = NULL,
                    active_attempt_started_at = NULL,
                    updated_at = ?,
                    terminal_at = ?
                WHERE effect_key = ?
                """,
                (state, now_epoch, now_epoch, effect_key),
            )
            self._record_terminal_circuit(
                effect=effect,
                state=state,
                limits=limits,
                now_epoch=now_epoch,
            )
            return Terminalization(
                disposition="terminalized",
                packet_id=packet_id,
                effect_key=effect_key,
                action=str(effect["action"]),
                state=state,
                receipt_digest=receipt_digest,
                receipt=receipt_value,
            )

    def pending_recovery(self) -> list[PendingRecovery]:
        """Return charged attempts whose live effect must be reconciled."""

        self._ensure_open()
        rows = self._db.execute(
            """
            SELECT e.effect_key, e.action, e.repo, e.pr_number,
                   p.head_sha AS active_head_sha, e.thread_node_id,
                   e.active_attempt_key, e.active_attempt_packet_id,
                   e.active_precondition_digest,
                   e.active_attempt_started_at, e.mutation_attempts
            FROM effects AS e
            JOIN packets AS p
              ON p.packet_id = e.active_attempt_packet_id
            WHERE e.state = 'pending'
              AND e.active_attempt_key IS NOT NULL
            ORDER BY e.active_attempt_started_at, e.effect_key
            """
        ).fetchall()
        return [
            PendingRecovery(
                packet_id=str(row["active_attempt_packet_id"]),
                effect_key=str(row["effect_key"]),
                action=str(row["action"]),
                repo=str(row["repo"]),
                pr_number=int(row["pr_number"]),
                head_sha=str(row["active_head_sha"]),
                thread_node_id=(
                    str(row["thread_node_id"])
                    if row["thread_node_id"] is not None
                    else None
                ),
                attempt_key=str(row["active_attempt_key"]),
                precondition_digest=str(
                    row["active_precondition_digest"]
                ),
                attempt_started_at=_epoch_text(
                    int(row["active_attempt_started_at"])
                ),
                mutation_attempts=int(row["mutation_attempts"]),
            )
            for row in rows
        ]

    def circuit_status(
        self,
        instance_slug: str,
        action: str,
    ) -> dict[str, Any]:
        if not INSTANCE_RE.fullmatch(instance_slug):
            raise BrokerStoreError("instance slug is invalid")
        if action not in ALLOWED_ACTIONS:
            raise BrokerStoreError("broker action is unsupported")
        self._ensure_open()
        row = self._db.execute(
            """
            SELECT state, consecutive_indeterminate, opened_at, reason_json,
                   updated_at
            FROM circuit_breakers
            WHERE instance_slug = ? AND action = ?
            """,
            (instance_slug, action),
        ).fetchone()
        if row is None:
            return {
                "state": "closed",
                "consecutive_indeterminate": 0,
                "opened_at": None,
                "reason": None,
            }
        reason = (
            _decode_canonical_json(
                row["reason_json"],
                field="circuit reason",
            )
            if row["reason_json"] is not None
            else None
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
        action: str,
        *,
        now: datetime | None = None,
    ) -> None:
        """Explicit operator/service recovery after an open circuit."""

        if not INSTANCE_RE.fullmatch(instance_slug):
            raise BrokerStoreError("instance slug is invalid")
        if action not in ALLOWED_ACTIONS:
            raise BrokerStoreError("broker action is unsupported")
        now_epoch = _now_epoch(now)
        with self._immediate():
            self._db.execute(
                """
                INSERT INTO circuit_breakers(
                    circuit_key, instance_slug, action, state,
                    consecutive_indeterminate, opened_at, reason_json,
                    updated_at
                ) VALUES (?, ?, ?, 'closed', 0, NULL, NULL, ?)
                ON CONFLICT(circuit_key) DO UPDATE SET
                    state = 'closed',
                    consecutive_indeterminate = 0,
                    opened_at = NULL,
                    reason_json = NULL,
                    updated_at = excluded.updated_at
                """,
                (
                    self._circuit_key(instance_slug, action),
                    instance_slug,
                    action,
                    now_epoch,
                ),
            )

    def counts(self) -> dict[str, int]:
        """Small observability projection for tests and broker health checks."""

        self._ensure_open()
        return {
            table: int(
                self._db.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0]
            )
            for table in (
                "packets",
                "effects",
                "budget_events",
                "receipts",
                "circuit_breakers",
            )
        }
