#!/usr/bin/env python3
"""Durable autonomy budgets, idempotency, circuits, and audit journal.

This module is deterministic cooperative-runtime control and defense in depth.
It makes budget, idempotency, and circuit decisions independently of model
output, but it is not a credential boundary against another process running as
the same OS identity. High-consequence mutations remain subject to the
separately isolated protected broker. Journal entries contain only bounded
operational metadata; raw prompts, model output, credentials, and local
checkout paths never belong here. The online control path reads a sealed
SQLite projection plus a bounded active segment; explicit verification still
walks the complete hash-chained archive.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shlex
import sqlite3
import stat
import sys
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote

POLICY_SCHEMA = "john-lomein.autonomy-policy.v1"
EVENT_SCHEMA = "john-lomein.autonomy-event.v1"
STATUS_SCHEMA = "john-lomein.autonomy-status.v1"
CHECKPOINT_SCHEMA = "john-lomein.autonomy-checkpoint.v2"
LEGACY_CHECKPOINT_SCHEMA = "john-lomein.autonomy-checkpoint.v1"
ARCHIVE_MANIFEST_SCHEMA = "john-lomein.autonomy-archive-manifest.v1"
CONTROL_SEAL_SCHEMA = "john-lomein.autonomy-control-seal.v1"
CONTROL_INDEX_SCHEMA_VERSION = 1
CONTROL_INDEX_FILENAME = "control-index.sqlite3"
CONTROL_INDEX_FIELD = "control_index_sha256"

LANES = ("maintainer", "forge", "portfolio", "triage", "release")
EFFECT_KINDS = (
    "public_comments",
    "issues",
    "labels",
    "branches",
    "pull_requests",
    "pull_request_updates",
    "merges",
    "workflow_dispatches",
    "publishes",
    "github_writes",
)

DEFAULT_POLICY: dict[str, Any] = {
    "schema_version": POLICY_SCHEMA,
    "circuit_breaker": {
        "failure_threshold": 3,
        "cooldown_seconds": 1800,
    },
    "budgets": {
        "max_daily_runtime_seconds": 28800,
        "max_daily_runs": {
            "maintainer": 48,
            "forge": 16,
            "portfolio": 4,
            "triage": 24,
            "release": 48,
        },
        "max_run_seconds": {
            "maintainer": 7200,
            "forge": 7200,
            "portfolio": 3600,
            "triage": 300,
            "release": 1800,
        },
        "max_daily_effects": {
            "public_comments": 40,
            "issues": 8,
            "labels": 20,
            "branches": 8,
            "pull_requests": 6,
            "pull_request_updates": 0,
            "merges": 0,
            "workflow_dispatches": 0,
            "publishes": 0,
            "github_writes": 0,
        },
    },
}

SUCCESS_STATUSES = frozenset(
    {
        "ok",
        "success",
        "clean",
        "clean_idle",
        "no_action_needed",
        "owner_gate",
        "codex_pending",
    }
)
FAILURE_STATUSES = frozenset(
    {
        "failed",
        "crashed",
        "blocked",
        "blocked_external",
        "blocked_checkout",
        "blocked_implementation",
        "budget_exhausted",
        "spawn_failed",
        "abandoned",
    }
)
IDEMPOTENT_SUCCESS_STATUSES = SUCCESS_STATUSES
TERMINAL_EVENT_TYPES = frozenset({"run_finished", "run_abandoned"})
SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GITHUB_REPO_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)
INSTANCE_SLUG_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
)
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
JOURNAL_NAME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}\.jsonl$")
ARCHIVE_STAGING_RE = re.compile(
    r"^\.tmp-[0-9]{8}-[0-9a-f]{32}$"
)
MAX_EVENTS = 100_000
MAX_LINE_BYTES = 16_384
MAX_EFFECT_RECEIPT_BYTES = 4_096
MAX_JOURNAL_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MANIFEST_BYTES = 4 * 1024 * 1024
# Rotation targets and hard limits apply to the active segment, never to the
# cumulative archive.
CHECKPOINT_EVENT_TARGET = 10_000
CHECKPOINT_BYTE_TARGET = 8 * 1024 * 1024
CHECKPOINT_FILE_TARGET = 64
LOCK_TIMEOUT_SECONDS = 30.0
MIN_RUN_RESERVATION_SECONDS = 30
ZERO_HASH = "0" * 64
CONTROL_BUCKET_COUNT = 256


class AutonomyError(RuntimeError):
    pass


EFFECT_EVENT_TYPES = frozenset(
    {
        "effect_pending",
        "effect_completed",
        "effect_failed",
        "effect_reconciled_completed",
        "effect_reconciled_absent",
    }
)
EFFECT_TERMINAL_EVENT_TYPES = frozenset(
    EFFECT_EVENT_TYPES - {"effect_pending"}
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_text(value: datetime | None = None) -> str:
    value = value or utc_now()
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError) as exc:
        raise AutonomyError(f"invalid autonomy timestamp: {value!r}") from exc
    return parsed.replace(tzinfo=timezone.utc)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


EMPTY_BUCKET_DIGEST = sha256_json([])


def _mapping(value: Any, *, field: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be a mapping")
    return value


def _strict_int(
    value: Any,
    *,
    field: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    if value is None:
        return default
    if type(value) is not int:
        raise ValueError(f"{field} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(
            f"{field} must be between {minimum} and {maximum}"
        )
    return value


def _reject_unknown(
    mapping: Mapping[str, Any],
    allowed: set[str],
    *,
    field: str,
) -> None:
    unknown = sorted(str(key) for key in mapping if key not in allowed)
    if unknown:
        raise ValueError(f"{field} contains unknown fields: {unknown}")


def normalize_policy(value: Any) -> dict[str, Any]:
    raw = _mapping(value, field="autonomy")
    _reject_unknown(
        raw,
        {"schema_version", "circuit_breaker", "budgets"},
        field="autonomy",
    )
    supplied_schema = raw.get("schema_version")
    if supplied_schema not in (None, POLICY_SCHEMA):
        raise ValueError("autonomy.schema_version is unsupported")

    circuit = _mapping(
        raw.get("circuit_breaker"),
        field="autonomy.circuit_breaker",
    )
    _reject_unknown(
        circuit,
        {"failure_threshold", "cooldown_seconds"},
        field="autonomy.circuit_breaker",
    )
    default_circuit = DEFAULT_POLICY["circuit_breaker"]

    budgets = _mapping(raw.get("budgets"), field="autonomy.budgets")
    _reject_unknown(
        budgets,
        {
            "max_daily_runtime_seconds",
            "max_daily_runs",
            "max_run_seconds",
            "max_daily_effects",
        },
        field="autonomy.budgets",
    )
    default_budgets = DEFAULT_POLICY["budgets"]

    raw_daily_runs = _mapping(
        budgets.get("max_daily_runs"),
        field="autonomy.budgets.max_daily_runs",
    )
    _reject_unknown(
        raw_daily_runs,
        set(LANES),
        field="autonomy.budgets.max_daily_runs",
    )
    raw_run_seconds = _mapping(
        budgets.get("max_run_seconds"),
        field="autonomy.budgets.max_run_seconds",
    )
    _reject_unknown(
        raw_run_seconds,
        set(LANES),
        field="autonomy.budgets.max_run_seconds",
    )
    raw_effects = _mapping(
        budgets.get("max_daily_effects"),
        field="autonomy.budgets.max_daily_effects",
    )
    _reject_unknown(
        raw_effects,
        set(EFFECT_KINDS),
        field="autonomy.budgets.max_daily_effects",
    )

    return {
        "schema_version": POLICY_SCHEMA,
        "circuit_breaker": {
            "failure_threshold": _strict_int(
                circuit.get("failure_threshold"),
                field="autonomy.circuit_breaker.failure_threshold",
                default=default_circuit["failure_threshold"],
                minimum=1,
                maximum=20,
            ),
            "cooldown_seconds": _strict_int(
                circuit.get("cooldown_seconds"),
                field="autonomy.circuit_breaker.cooldown_seconds",
                default=default_circuit["cooldown_seconds"],
                minimum=60,
                maximum=7 * 24 * 60 * 60,
            ),
        },
        "budgets": {
            "max_daily_runtime_seconds": _strict_int(
                budgets.get("max_daily_runtime_seconds"),
                field="autonomy.budgets.max_daily_runtime_seconds",
                default=default_budgets["max_daily_runtime_seconds"],
                minimum=60,
                maximum=24 * 60 * 60,
            ),
            "max_daily_runs": {
                lane: _strict_int(
                    raw_daily_runs.get(lane),
                    field=f"autonomy.budgets.max_daily_runs.{lane}",
                    default=default_budgets["max_daily_runs"][lane],
                    minimum=1,
                    maximum=1000,
                )
                for lane in LANES
            },
            "max_run_seconds": {
                lane: _strict_int(
                    raw_run_seconds.get(lane),
                    field=f"autonomy.budgets.max_run_seconds.{lane}",
                    default=default_budgets["max_run_seconds"][lane],
                    minimum=30,
                    maximum=24 * 60 * 60,
                )
                for lane in LANES
            },
            "max_daily_effects": {
                effect: _strict_int(
                    raw_effects.get(effect),
                    field=f"autonomy.budgets.max_daily_effects.{effect}",
                    default=default_budgets["max_daily_effects"][effect],
                    minimum=0,
                    maximum=10_000,
                )
                for effect in EFFECT_KINDS
            },
        },
    }


def policy_from_env(env: Mapping[str, str]) -> dict[str, Any]:
    raw = env.get("BOT_AUTONOMY_POLICY_JSON") or ""
    if not raw:
        return normalize_policy({})
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AutonomyError("deployed autonomy policy is invalid JSON") from exc
    try:
        return normalize_policy(parsed)
    except ValueError as exc:
        raise AutonomyError(f"deployed autonomy policy invalid: {exc}") from exc


def policy_from_runtime(runtime_home: str | Path) -> dict[str, Any]:
    runtime = _runtime_root(runtime_home)
    path = runtime / "state" / "john-lomein-autonomy-policy.json"
    if path.is_symlink():
        raise AutonomyError("deployed autonomy policy stamp is a symlink")
    try:
        if path.stat().st_size > 64 * 1024:
            raise AutonomyError("deployed autonomy policy stamp is too large")
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AutonomyError("deployed autonomy policy stamp is missing") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise AutonomyError("deployed autonomy policy stamp is unreadable") from exc
    if not isinstance(value, Mapping):
        raise AutonomyError("deployed autonomy policy stamp is not an object")
    if value.get("schema_version") != "john-lomein.autonomy-deployment.v1":
        raise AutonomyError("deployed autonomy policy stamp schema mismatch")
    try:
        policy = normalize_policy(value.get("policy"))
    except ValueError as exc:
        raise AutonomyError(
            f"deployed autonomy policy stamp invalid: {exc}"
        ) from exc
    expected = str(value.get("policy_sha256") or "")
    if not SHA256_RE.fullmatch(expected) or expected != sha256_json(policy):
        raise AutonomyError("deployed autonomy policy stamp digest mismatch")
    return policy


def deployed_runtime_control(runtime_home: str | Path) -> dict[str, str]:
    runtime = _runtime_root(runtime_home)
    path = runtime / "scripts" / "john-lomein-instance.env"
    if path.is_symlink():
        raise AutonomyError("deployed runtime control env is a symlink")
    try:
        info = path.stat()
        if info.st_size > 1024 * 1024:
            raise AutonomyError("deployed runtime control env is too large")
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise AutonomyError(
                "deployed runtime control env is group/world writable"
            )
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise AutonomyError("deployed runtime control env is missing") from exc
    except OSError as exc:
        raise AutonomyError("deployed runtime control env is unreadable") from exc
    wanted = {
        "BOT_SLUG",
        "BOT_REPO",
        "BOT_DEFAULT_BRANCH",
        "BOT_HERMES_HOME",
        "BOT_LOCAL",
        "BOT_FORBIDDEN_PATHS_JSON",
        "BOT_FORGE_PROFILE",
        "BOT_MAINTAINER_PROFILE",
        "BOT_OSC_PORTFOLIO_BRANCH_PREFIX",
        "BOT_READINESS_LABELS",
        "BOT_AUTONOMOUS_SAFE_LABELS",
        "BOT_MISSION_COMPLETE",
        "BOT_MUTATION_ENABLED",
        "BOT_OSC_PORTFOLIO_ENABLED",
        "BOT_PROTECTED_RELEASE_BROKER_ENABLED",
    }
    values: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key not in wanted:
            continue
        try:
            parts = shlex.split(value, posix=True)
        except ValueError as exc:
            raise AutonomyError(
                f"deployed runtime control field {key} is malformed"
            ) from exc
        values[key] = parts[0] if parts else ""
    slug = values.get("BOT_SLUG") or ""
    repo = values.get("BOT_REPO") or ""
    branch = values.get("BOT_DEFAULT_BRANCH") or ""
    recorded_home = values.get("BOT_HERMES_HOME") or ""
    portfolio_prefix = (
        values.get("BOT_OSC_PORTFOLIO_BRANCH_PREFIX") or "portfolio/"
    )
    mission_complete = values.get("BOT_MISSION_COMPLETE")
    mutation_enabled = values.get("BOT_MUTATION_ENABLED")
    portfolio_enabled = values.get("BOT_OSC_PORTFOLIO_ENABLED")
    forbidden_raw = values.get("BOT_FORBIDDEN_PATHS_JSON")
    expected_profiles = {
        "BOT_MAINTAINER_PROFILE": "john-lomein-maintainer",
        "BOT_FORGE_PROFILE": "john-lomein-forge",
    }
    if not INSTANCE_SLUG_RE.fullmatch(slug):
        raise AutonomyError("deployed instance slug is invalid")
    if not GITHUB_REPO_RE.fullmatch(repo):
        raise AutonomyError("deployed target repository is invalid")
    if not BRANCH_RE.fullmatch(branch):
        raise AutonomyError("deployed default branch is invalid")
    if (
        not recorded_home
        or Path(recorded_home).expanduser().resolve() != runtime
    ):
        raise AutonomyError("deployed runtime control home mismatch")
    if (
        not BRANCH_RE.fullmatch(portfolio_prefix.rstrip("/") + "/x")
        or not portfolio_prefix.endswith("/")
    ):
        raise AutonomyError("deployed portfolio branch prefix is invalid")
    if mutation_enabled not in {"0", "1"}:
        raise AutonomyError(
            "deployed mutation kill switch must be exactly 0 or 1"
        )
    if mission_complete not in {"0", "1"}:
        raise AutonomyError(
            "deployed owner mission gate must be exactly 0 or 1"
        )
    if portfolio_enabled not in {"0", "1"}:
        raise AutonomyError(
            "deployed portfolio gate must be exactly 0 or 1"
        )
    if forbidden_raw is None:
        raise AutonomyError(
            "deployed forbidden-path policy is missing"
        )
    for key, expected in expected_profiles.items():
        configured = values.get(key) or expected
        if configured != expected:
            raise AutonomyError(
                f"deployed runtime control {key} must be {expected}"
            )
        values[key] = configured
    try:
        forbidden = json.loads(forbidden_raw)
    except json.JSONDecodeError as exc:
        raise AutonomyError(
            "deployed forbidden-path policy is invalid JSON"
        ) from exc
    if (
        not isinstance(forbidden, list)
        or len(forbidden) > 256
        or any(
            not isinstance(item, str)
            or not item
            or len(item) > 512
            for item in forbidden
        )
    ):
        raise AutonomyError(
            "deployed forbidden-path policy is invalid"
        )
    values["BOT_FORBIDDEN_PATHS_JSON"] = json.dumps(
        forbidden,
        separators=(",", ":"),
    )
    return values


def anchored_runtime_home(
    script_directory: str | Path,
    supplied_runtime_home: str | Path,
) -> Path:
    """Bind a deployed client to the runtime that contains its script."""

    scripts = Path(script_directory).expanduser().resolve()
    supplied = Path(supplied_runtime_home).expanduser().resolve()
    if (scripts / "john-lomein-instance.env").exists():
        deployed = scripts.parent.resolve()
        if supplied != deployed:
            raise AutonomyError(
                "supplied runtime home does not match deployed client"
            )
        return deployed
    return supplied


def require_effective_mutation(control: Mapping[str, str]) -> None:
    """Require mission provenance and the deployed mutation kill switch."""

    if control.get("BOT_MISSION_COMPLETE") != "1":
        raise AutonomyError("runtime owner mission gate is incomplete")
    if control.get("BOT_MUTATION_ENABLED") != "1":
        raise AutonomyError("runtime mutation kill switch is disabled")


def require_effective_lane(
    control: Mapping[str, str],
    lane: str,
) -> None:
    """Require the effective authority for one mutating autonomy lane."""

    require_effective_mutation(control)
    if lane == "portfolio" and (
        control.get("BOT_OSC_PORTFOLIO_ENABLED") != "1"
    ):
        raise AutonomyError("runtime portfolio authority is disabled")


def require_effective_protected_release(
    control: Mapping[str, str],
) -> None:
    """Require every deployed gate for a protected release submission."""

    require_effective_mutation(control)
    if control.get("BOT_PROTECTED_RELEASE_BROKER_ENABLED") != "1":
        raise AutonomyError(
            "runtime protected release authority is disabled"
        )


def require_active_run(
    runtime_home: str | Path,
    policy: Mapping[str, Any],
    lane: str,
    run_id: str,
    *,
    now: datetime | None = None,
) -> None:
    """Require a live, journaled run for an individual local effect."""

    lane = _validate_lane(lane)
    if not isinstance(run_id, str) or not run_id:
        raise AutonomyError("local effect is missing an autonomy run")
    normalized = normalize_policy(policy)
    observed_at = now or utc_now()
    with autonomy_lock(runtime_home):
        _recover_stale_runs_unlocked(
            runtime_home,
            normalized,
            observed_at,
        )
        handle = _verify_or_rebuild_control_components_unlocked(
            runtime_home,
            active_runs=True,
        )
        try:
            if handle.connection is None:
                raise _ControlIndexInvalid("control index is closed")
            row = handle.connection.execute(
                "SELECT lane FROM active_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if row is None:
                raise AutonomyError(
                    "local effect does not belong to a journaled run"
                )
            if str(row["lane"]) != lane:
                raise AutonomyError(
                    "local effect lane does not match its journaled run"
                )
        finally:
            handle.close()


def lane_max_run_seconds(policy: Mapping[str, Any], lane: str) -> int:
    if lane not in LANES:
        raise AutonomyError(f"unknown autonomy lane: {lane}")
    normalized = normalize_policy(policy)
    return int(normalized["budgets"]["max_run_seconds"][lane])


def _runtime_root(runtime_home: str | Path) -> Path:
    raw = Path(runtime_home).expanduser()
    if raw.is_symlink():
        raise AutonomyError("autonomy runtime root is a symlink")
    return raw.resolve()


def autonomy_root(
    runtime_home: str | Path,
    *,
    create: bool = True,
) -> Path:
    runtime = _runtime_root(runtime_home)
    state = runtime / "state"
    if state.is_symlink():
        raise AutonomyError("autonomy state root is a symlink")
    root = state / "autonomy"
    if root.is_symlink():
        raise AutonomyError("autonomy root is a symlink")
    if create:
        state.mkdir(parents=True, exist_ok=True)
        existed = root.exists()
        root.mkdir(parents=True, exist_ok=True)
        if not existed:
            os.chmod(root, 0o700)
    if root.exists():
        info = root.stat()
        if not stat.S_ISDIR(info.st_mode):
            raise AutonomyError("autonomy root is not a directory")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise AutonomyError("autonomy root has an unsafe owner")
        if info.st_mode & 0o077:
            raise AutonomyError(
                "autonomy root grants group/world permissions"
            )
    return root


def _journal_root(runtime_home: str | Path, *, create: bool = True) -> Path:
    root = autonomy_root(runtime_home, create=create)
    journal = root / "journal"
    if journal.is_symlink():
        raise AutonomyError("autonomy journal root is a symlink")
    if create:
        journal.mkdir(parents=True, exist_ok=True)
        os.chmod(journal, 0o700)
    return journal


@contextmanager
def autonomy_lock(runtime_home: str | Path):
    root = autonomy_root(runtime_home)
    path = root / ".lock"
    if path.is_symlink():
        raise AutonomyError("autonomy lock is a symlink")
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise AutonomyError(
                        "timed out waiting for autonomy journal lock"
                    )
                time.sleep(0.05)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


@contextmanager
def mutation_lease(
    runtime_home: str | Path,
    lane: str,
    *,
    wait_seconds: float = 0.0,
):
    """Hold the single instance-wide mutation lease for an entire lane run."""
    lane = _validate_lane(lane)
    root = autonomy_root(runtime_home)
    path = root / ".mutation.lock"
    if path.is_symlink():
        raise AutonomyError("autonomy mutation lock is a symlink")
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    deadline = time.monotonic() + max(0.0, wait_seconds)
    acquired = False
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise AutonomyError(
                        "instance mutation lease is already held"
                    ) from exc
                time.sleep(0.05)
        os.ftruncate(fd, 0)
        os.write(
            fd,
            canonical_json(
                {
                    "schema_version": "john-lomein.mutation-lease.v1",
                    "lane": lane,
                    "pid": os.getpid(),
                    "acquired_at": utc_text(),
                }
            )
            + b"\n",
        )
        os.fsync(fd)
        yield
    finally:
        if acquired:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
        else:
            os.close(fd)


def _event_without_hash(event: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in event.items() if key != "event_hash"}


def _event_hash(event: Mapping[str, Any]) -> str:
    return sha256_json(_event_without_hash(event))


def _journal_files(runtime_home: str | Path) -> list[Path]:
    journal = _journal_root(runtime_home, create=False)
    if not journal.exists():
        return []
    files: list[Path] = []
    for path in sorted(journal.iterdir()):
        if path.is_symlink():
            raise AutonomyError(
                f"autonomy journal contains symlink: {path.name}"
            )
        if not path.is_file() or not JOURNAL_NAME_RE.fullmatch(path.name):
            raise AutonomyError(
                f"autonomy journal contains unexpected entry: {path.name}"
            )
        files.append(path)
    return files


def _archive_root(
    runtime_home: str | Path,
    *,
    create: bool = True,
) -> Path:
    root = autonomy_root(runtime_home, create=create)
    archive = root / "archive"
    if archive.is_symlink():
        raise AutonomyError("autonomy archive root is a symlink")
    if create:
        archive.mkdir(parents=True, exist_ok=True)
        os.chmod(archive, 0o700)
    return archive


def _checkpoint_path(runtime_home: str | Path) -> Path:
    return autonomy_root(runtime_home) / "checkpoint.json"


def _without_digest(
    value: Mapping[str, Any],
    digest_field: str,
) -> dict[str, Any]:
    return {
        key: item
        for key, item in value.items()
        if key != digest_field
    }


def _object_digest(
    value: Mapping[str, Any],
    digest_field: str,
) -> str:
    return sha256_json(_without_digest(value, digest_field))


def _write_all(fd: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(fd, raw[offset:])
        if written <= 0:
            raise AutonomyError("autonomy durable write made no progress")
        offset += written


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    if path.is_symlink():
        raise AutonomyError(f"autonomy state file is a symlink: {path.name}")
    raw = canonical_json(value) + b"\n"
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temporary, flags, 0o600)
    try:
        _write_all(fd, raw)
        os.fsync(fd)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        finally:
            raise
    finally:
        os.close(fd)
    try:
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _validate_event(
    event: Any,
    *,
    expected_sequence: int | None = None,
    previous_hash: str | None = None,
) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise AutonomyError("autonomy journal event is not an object")
    if event.get("schema_version") != EVENT_SCHEMA:
        raise AutonomyError("autonomy journal schema mismatch")
    sequence = event.get("sequence")
    if type(sequence) is not int or sequence < 1:
        raise AutonomyError("autonomy journal sequence is invalid")
    if expected_sequence is not None and sequence != expected_sequence:
        raise AutonomyError("autonomy journal sequence mismatch")
    observed_previous = str(event.get("previous_hash") or "")
    if not SHA256_RE.fullmatch(observed_previous):
        raise AutonomyError("autonomy journal previous hash invalid")
    if previous_hash is not None and observed_previous != previous_hash:
        raise AutonomyError("autonomy journal chain mismatch")
    observed_hash = str(event.get("event_hash") or "")
    if not SHA256_RE.fullmatch(observed_hash):
        raise AutonomyError("autonomy journal event hash invalid")
    if observed_hash != _event_hash(event):
        raise AutonomyError("autonomy journal event was modified")
    control_digest = event.get(CONTROL_INDEX_FIELD)
    if control_digest is not None and not SHA256_RE.fullmatch(
        str(control_digest)
    ):
        raise AutonomyError(
            "autonomy journal control index digest is invalid"
        )
    return event


def _read_event_files(
    paths: list[Path],
    *,
    expected_sequence: int,
    previous_hash: str,
    active_limits: bool,
) -> tuple[list[dict[str, Any]], int, str, int]:
    events: list[dict[str, Any]] = []
    total_bytes = 0
    for path in paths:
        size = path.stat().st_size
        total_bytes += size
        if active_limits and total_bytes > MAX_JOURNAL_BYTES:
            raise AutonomyError("autonomy active journal exceeds size limit")
        with path.open("rb") as handle:
            for line_number, raw in enumerate(handle, 1):
                if len(raw) > MAX_LINE_BYTES:
                    raise AutonomyError(
                        f"autonomy journal line too large: "
                        f"{path.name}:{line_number}"
                    )
                if not raw.endswith(b"\n"):
                    raise AutonomyError(
                        f"autonomy journal has partial final record: "
                        f"{path.name}:{line_number}"
                    )
                try:
                    event = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise AutonomyError(
                        f"autonomy journal unreadable: "
                        f"{path.name}:{line_number}"
                    ) from exc
                event = _validate_event(
                    event,
                    expected_sequence=expected_sequence,
                    previous_hash=previous_hash,
                )
                events.append(event)
                if active_limits and len(events) > MAX_EVENTS:
                    raise AutonomyError(
                        "autonomy active journal event limit exceeded"
                    )
                previous_hash = str(event["event_hash"])
                expected_sequence += 1
    return events, expected_sequence, previous_hash, total_bytes


# Authority-bearing sets use fixed digest buckets. A lookup verifies only its
# bucket (or a small globally bounded table), while the complete seal digest is
# anchored in every new journal event and archive checkpoint. This keeps the
# online path independent of historical cardinality without allowing a deleted
# idempotency or budget row to silently grant work.
_CONTROL_INDEX_SCHEMA = """
CREATE TABLE control_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    last_sequence INTEGER NOT NULL CHECK (last_sequence >= 0),
    chain_head TEXT NOT NULL,
    archive_generation INTEGER NOT NULL CHECK (archive_generation >= 0),
    archived_through_sequence INTEGER NOT NULL
        CHECK (archived_through_sequence >= 0),
    archived_chain_head TEXT NOT NULL,
    archive_manifest_hash TEXT NOT NULL,
    authority_seal_json TEXT NOT NULL,
    authority_seal_sha256 TEXT NOT NULL
) STRICT;

CREATE TABLE successful_runs (
    lane TEXT NOT NULL,
    idempotency_key_sha256 TEXT NOT NULL,
    run_id TEXT NOT NULL,
    terminal_sequence INTEGER NOT NULL,
    bucket INTEGER NOT NULL CHECK (bucket BETWEEN 0 AND 255),
    PRIMARY KEY (lane, idempotency_key_sha256)
) STRICT;
CREATE INDEX successful_runs_bucket
    ON successful_runs(bucket, lane, idempotency_key_sha256);

CREATE TABLE active_runs (
    run_id TEXT PRIMARY KEY,
    lane TEXT NOT NULL,
    idempotency_key_sha256 TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    max_run_seconds INTEGER NOT NULL,
    allowed_run_seconds INTEGER NOT NULL,
    start_sequence INTEGER NOT NULL,
    event_json TEXT NOT NULL
) STRICT;
CREATE INDEX active_runs_key
    ON active_runs(lane, idempotency_key_sha256);

CREATE TABLE terminal_runs (
    run_id TEXT PRIMARY KEY,
    lane TEXT NOT NULL,
    idempotency_key_sha256 TEXT NOT NULL,
    status TEXT NOT NULL,
    exit_code INTEGER NOT NULL,
    duration_seconds INTEGER NOT NULL,
    terminal_sequence INTEGER NOT NULL,
    event_json TEXT NOT NULL
) STRICT;

CREATE TABLE daily_runtime (
    utc_date TEXT PRIMARY KEY,
    runtime_seconds INTEGER NOT NULL CHECK (runtime_seconds >= 0),
    bucket INTEGER NOT NULL CHECK (bucket BETWEEN 0 AND 255)
) STRICT;
CREATE INDEX daily_runtime_bucket
    ON daily_runtime(bucket, utc_date);

CREATE TABLE daily_lane_runs (
    utc_date TEXT NOT NULL,
    lane TEXT NOT NULL,
    run_count INTEGER NOT NULL CHECK (run_count >= 0),
    bucket INTEGER NOT NULL CHECK (bucket BETWEEN 0 AND 255),
    PRIMARY KEY (utc_date, lane)
) STRICT;
CREATE INDEX daily_lane_runs_bucket
    ON daily_lane_runs(bucket, utc_date, lane);

CREATE TABLE daily_effects (
    utc_date TEXT NOT NULL,
    effect_kind TEXT NOT NULL,
    effect_count INTEGER NOT NULL CHECK (effect_count >= 0),
    bucket INTEGER NOT NULL CHECK (bucket BETWEEN 0 AND 255),
    PRIMARY KEY (utc_date, effect_kind)
) STRICT;
CREATE INDEX daily_effects_bucket
    ON daily_effects(bucket, utc_date, effect_kind);

CREATE TABLE lane_circuits (
    lane TEXT PRIMARY KEY,
    consecutive_failures INTEGER NOT NULL
        CHECK (consecutive_failures >= 0),
    latest_failure_at TEXT,
    terminal_sequence INTEGER NOT NULL CHECK (terminal_sequence >= 0)
) STRICT;

CREATE TABLE latest_effects (
    effect_kind TEXT NOT NULL,
    idempotency_key_sha256 TEXT NOT NULL,
    effect_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    receipt_json TEXT,
    latest_sequence INTEGER NOT NULL,
    bucket INTEGER NOT NULL CHECK (bucket BETWEEN 0 AND 255),
    event_json TEXT NOT NULL,
    PRIMARY KEY (effect_kind, idempotency_key_sha256)
) STRICT;
CREATE INDEX latest_effects_bucket
    ON latest_effects(bucket, effect_kind, idempotency_key_sha256);
CREATE INDEX latest_effects_effect_id
    ON latest_effects(effect_id);

CREATE TABLE pending_effects (
    effect_id TEXT PRIMARY KEY,
    lane TEXT NOT NULL,
    run_id TEXT NOT NULL,
    effect_kind TEXT NOT NULL,
    idempotency_key_sha256 TEXT NOT NULL,
    before_sha256 TEXT,
    recorded_at TEXT NOT NULL,
    pending_sequence INTEGER NOT NULL,
    event_json TEXT NOT NULL
) STRICT;
CREATE INDEX pending_effects_key
    ON pending_effects(effect_kind, idempotency_key_sha256);

CREATE TABLE terminal_effects (
    effect_id TEXT PRIMARY KEY,
    lane TEXT NOT NULL,
    run_id TEXT NOT NULL,
    effect_kind TEXT NOT NULL,
    idempotency_key_sha256 TEXT NOT NULL,
    event_type TEXT NOT NULL,
    receipt_json TEXT,
    terminal_sequence INTEGER NOT NULL,
    first_event_json TEXT NOT NULL,
    event_json TEXT NOT NULL
) STRICT;
"""


class _ControlIndexInvalid(AutonomyError):
    """A disposable control projection must be rebuilt."""


class _ControlIndexUnsafe(AutonomyError):
    """The control projection path is outside the trusted local boundary."""


def _control_index_path(runtime_home: str | Path) -> Path:
    return autonomy_root(runtime_home) / CONTROL_INDEX_FILENAME


def _bucket_for_text(value: str) -> int:
    return int(hashlib.sha256(value.encode("utf-8")).hexdigest()[:2], 16)


def _bucket_for_key_digest(value: str) -> int:
    if not SHA256_RE.fullmatch(value):
        raise _ControlIndexInvalid("control index key digest is invalid")
    return int(value[:2], 16)


def _empty_control_seal() -> dict[str, Any]:
    empty = [EMPTY_BUCKET_DIGEST] * CONTROL_BUCKET_COUNT
    empty_circuits = [
        {
            "lane": lane,
            "consecutive_failures": 0,
            "latest_failure_at": None,
            "terminal_sequence": 0,
        }
        for lane in sorted(LANES)
    ]
    return {
        "schema_version": CONTROL_SEAL_SCHEMA,
        "successful_runs": list(empty),
        "daily": list(empty),
        "latest_effects": list(empty),
        "active_runs": EMPTY_BUCKET_DIGEST,
        "pending_effects": EMPTY_BUCKET_DIGEST,
        "lane_circuits": sha256_json(empty_circuits),
    }


def _validate_control_seal(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "successful_runs",
        "daily",
        "latest_effects",
        "active_runs",
        "pending_effects",
        "lane_circuits",
    }:
        raise _ControlIndexInvalid("control index seal fields are invalid")
    if value.get("schema_version") != CONTROL_SEAL_SCHEMA:
        raise _ControlIndexInvalid("control index seal schema mismatch")
    for field in ("successful_runs", "daily", "latest_effects"):
        buckets = value.get(field)
        if (
            not isinstance(buckets, list)
            or len(buckets) != CONTROL_BUCKET_COUNT
            or any(
                not isinstance(item, str)
                or not SHA256_RE.fullmatch(item)
                for item in buckets
            )
        ):
            raise _ControlIndexInvalid(
                f"control index seal {field} buckets are invalid"
            )
    for field in ("active_runs", "pending_effects", "lane_circuits"):
        if not SHA256_RE.fullmatch(str(value.get(field) or "")):
            raise _ControlIndexInvalid(
                f"control index seal {field} digest is invalid"
            )
    return value


def _control_seal_digest(seal: Mapping[str, Any]) -> str:
    return sha256_json(seal)


def _control_meta(connection: sqlite3.Connection) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT last_sequence, chain_head, archive_generation,
               archived_through_sequence, archived_chain_head,
               archive_manifest_hash, authority_seal_json,
               authority_seal_sha256
        FROM control_meta
        WHERE singleton = 1
        """
    ).fetchone()
    if row is None:
        raise _ControlIndexInvalid("control index metadata is missing")
    if (
        type(row["last_sequence"]) is not int
        or int(row["last_sequence"]) < 0
        or not SHA256_RE.fullmatch(str(row["chain_head"]))
        or type(row["archive_generation"]) is not int
        or int(row["archive_generation"]) < 0
        or type(row["archived_through_sequence"]) is not int
        or int(row["archived_through_sequence"]) < 0
        or not SHA256_RE.fullmatch(str(row["archived_chain_head"]))
        or not SHA256_RE.fullmatch(str(row["archive_manifest_hash"]))
        or not SHA256_RE.fullmatch(str(row["authority_seal_sha256"]))
    ):
        raise _ControlIndexInvalid("control index metadata is invalid")
    try:
        seal = _validate_control_seal(
            json.loads(str(row["authority_seal_json"]))
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _ControlIndexInvalid(
            "control index seal is unreadable"
        ) from exc
    if _control_seal_digest(seal) != str(
        row["authority_seal_sha256"]
    ):
        raise _ControlIndexInvalid("control index seal was modified")
    return row


def _row_dicts(
    rows: list[sqlite3.Row],
    fields: tuple[str, ...],
) -> list[dict[str, Any]]:
    return [
        {field: row[field] for field in fields}
        for row in rows
    ]


def _successful_bucket_digest(
    connection: sqlite3.Connection,
    bucket: int,
) -> str:
    fields = (
        "lane",
        "idempotency_key_sha256",
        "run_id",
        "terminal_sequence",
    )
    rows = connection.execute(
        """
        SELECT lane, idempotency_key_sha256, run_id, terminal_sequence
        FROM successful_runs
        WHERE bucket = ?
        ORDER BY lane, idempotency_key_sha256
        """,
        (bucket,),
    ).fetchall()
    return sha256_json(_row_dicts(rows, fields))


def _daily_bucket_digest(
    connection: sqlite3.Connection,
    bucket: int,
) -> str:
    rows: list[dict[str, Any]] = []
    for row in connection.execute(
        """
        SELECT utc_date, runtime_seconds
        FROM daily_runtime
        WHERE bucket = ?
        ORDER BY utc_date
        """,
        (bucket,),
    ).fetchall():
        rows.append(
            {
                "kind": "runtime",
                "utc_date": row["utc_date"],
                "runtime_seconds": row["runtime_seconds"],
            }
        )
    for row in connection.execute(
        """
        SELECT utc_date, lane, run_count
        FROM daily_lane_runs
        WHERE bucket = ?
        ORDER BY utc_date, lane
        """,
        (bucket,),
    ).fetchall():
        rows.append(
            {
                "kind": "lane_runs",
                "utc_date": row["utc_date"],
                "lane": row["lane"],
                "run_count": row["run_count"],
            }
        )
    for row in connection.execute(
        """
        SELECT utc_date, effect_kind, effect_count
        FROM daily_effects
        WHERE bucket = ?
        ORDER BY utc_date, effect_kind
        """,
        (bucket,),
    ).fetchall():
        rows.append(
            {
                "kind": "effects",
                "utc_date": row["utc_date"],
                "effect_kind": row["effect_kind"],
                "effect_count": row["effect_count"],
            }
        )
    rows.sort(key=canonical_json)
    return sha256_json(rows)


def _latest_effect_bucket_digest(
    connection: sqlite3.Connection,
    bucket: int,
) -> str:
    fields = (
        "effect_kind",
        "idempotency_key_sha256",
        "effect_id",
        "event_type",
        "receipt_json",
        "latest_sequence",
    )
    rows = connection.execute(
        """
        SELECT effect_kind, idempotency_key_sha256, effect_id, event_type,
               receipt_json, latest_sequence
        FROM latest_effects
        WHERE bucket = ?
        ORDER BY effect_kind, idempotency_key_sha256
        """,
        (bucket,),
    ).fetchall()
    return sha256_json(_row_dicts(rows, fields))


def _active_runs_digest(connection: sqlite3.Connection) -> str:
    fields = (
        "run_id",
        "lane",
        "idempotency_key_sha256",
        "recorded_at",
        "max_run_seconds",
        "allowed_run_seconds",
        "start_sequence",
    )
    rows = connection.execute(
        """
        SELECT run_id, lane, idempotency_key_sha256, recorded_at,
               max_run_seconds, allowed_run_seconds, start_sequence
        FROM active_runs
        ORDER BY run_id
        """
    ).fetchall()
    return sha256_json(_row_dicts(rows, fields))


def _pending_effects_digest(connection: sqlite3.Connection) -> str:
    fields = (
        "effect_id",
        "lane",
        "run_id",
        "effect_kind",
        "idempotency_key_sha256",
        "before_sha256",
        "recorded_at",
        "pending_sequence",
    )
    rows = connection.execute(
        """
        SELECT effect_id, lane, run_id, effect_kind,
               idempotency_key_sha256, before_sha256, recorded_at,
               pending_sequence
        FROM pending_effects
        ORDER BY effect_id
        """
    ).fetchall()
    return sha256_json(_row_dicts(rows, fields))


def _lane_circuits_digest(connection: sqlite3.Connection) -> str:
    fields = (
        "lane",
        "consecutive_failures",
        "latest_failure_at",
        "terminal_sequence",
    )
    rows = connection.execute(
        """
        SELECT lane, consecutive_failures, latest_failure_at,
               terminal_sequence
        FROM lane_circuits
        ORDER BY lane
        """
    ).fetchall()
    return sha256_json(_row_dicts(rows, fields))


def _refresh_control_seal(
    connection: sqlite3.Connection,
    seal: Mapping[str, Any],
    *,
    successful_buckets: set[int] | None = None,
    daily_buckets: set[int] | None = None,
    effect_buckets: set[int] | None = None,
    active_runs: bool = False,
    pending_effects: bool = False,
    lane_circuits: bool = False,
) -> dict[str, Any]:
    refreshed = json.loads(canonical_json(seal))
    for bucket in successful_buckets or set():
        refreshed["successful_runs"][bucket] = (
            _successful_bucket_digest(connection, bucket)
        )
    for bucket in daily_buckets or set():
        refreshed["daily"][bucket] = _daily_bucket_digest(
            connection,
            bucket,
        )
    for bucket in effect_buckets or set():
        refreshed["latest_effects"][bucket] = (
            _latest_effect_bucket_digest(connection, bucket)
        )
    if active_runs:
        refreshed["active_runs"] = _active_runs_digest(connection)
    if pending_effects:
        refreshed["pending_effects"] = _pending_effects_digest(connection)
    if lane_circuits:
        refreshed["lane_circuits"] = _lane_circuits_digest(connection)
    return _validate_control_seal(refreshed)


def _verify_control_components(
    connection: sqlite3.Connection,
    *,
    successful_buckets: set[int] | None = None,
    daily_buckets: set[int] | None = None,
    effect_buckets: set[int] | None = None,
    active_runs: bool = False,
    pending_effects: bool = False,
    lane_circuits: bool = False,
) -> None:
    meta = _control_meta(connection)
    seal = _validate_control_seal(
        json.loads(str(meta["authority_seal_json"]))
    )
    for bucket in successful_buckets or set():
        if (
            _successful_bucket_digest(connection, bucket)
            != seal["successful_runs"][bucket]
        ):
            raise _ControlIndexInvalid(
                "control index successful-run projection was modified"
            )
    for bucket in daily_buckets or set():
        if (
            _daily_bucket_digest(connection, bucket)
            != seal["daily"][bucket]
        ):
            raise _ControlIndexInvalid(
                "control index daily projection was modified"
            )
    for bucket in effect_buckets or set():
        if (
            _latest_effect_bucket_digest(connection, bucket)
            != seal["latest_effects"][bucket]
        ):
            raise _ControlIndexInvalid(
                "control index effect projection was modified"
            )
    if (
        active_runs
        and _active_runs_digest(connection) != seal["active_runs"]
    ):
        raise _ControlIndexInvalid(
            "control index active-run projection was modified"
        )
    if (
        pending_effects
        and _pending_effects_digest(connection)
        != seal["pending_effects"]
    ):
        raise _ControlIndexInvalid(
            "control index pending-effect projection was modified"
        )
    if (
        lane_circuits
        and _lane_circuits_digest(connection)
        != seal["lane_circuits"]
    ):
        raise _ControlIndexInvalid(
            "control index circuit projection was modified"
        )


def _runtime_allocations(
    recorded_at: str,
    duration_seconds: int,
) -> dict[str, int]:
    if duration_seconds < 0 or duration_seconds > 24 * 60 * 60:
        raise _ControlIndexInvalid(
            "control index runtime duration is invalid"
        )
    start = parse_utc(recorded_at)
    end = start + timedelta(seconds=duration_seconds)
    allocations: dict[str, int] = {}
    cursor = start
    while cursor < end:
        next_day = datetime.combine(
            cursor.date() + timedelta(days=1),
            datetime.min.time(),
            tzinfo=timezone.utc,
        )
        boundary = min(end, next_day)
        allocations[cursor.date().isoformat()] = int(
            (boundary - cursor).total_seconds()
        )
        cursor = boundary
    return allocations


def _adjust_daily_runtime(
    connection: sqlite3.Connection,
    allocations: Mapping[str, int],
    *,
    multiplier: int,
) -> set[int]:
    touched: set[int] = set()
    for day, seconds in allocations.items():
        bucket = _bucket_for_text(day)
        touched.add(bucket)
        row = connection.execute(
            "SELECT runtime_seconds FROM daily_runtime WHERE utc_date = ?",
            (day,),
        ).fetchone()
        adjusted = (
            (int(row["runtime_seconds"]) if row is not None else 0)
            + multiplier * int(seconds)
        )
        if adjusted < 0:
            raise _ControlIndexInvalid(
                "control index daily runtime became negative"
            )
        if row is None:
            connection.execute(
                """
                INSERT INTO daily_runtime(
                    utc_date, runtime_seconds, bucket
                ) VALUES (?, ?, ?)
                """,
                (day, adjusted, bucket),
            )
        else:
            connection.execute(
                """
                UPDATE daily_runtime
                SET runtime_seconds = ?
                WHERE utc_date = ?
                """,
                (adjusted, day),
            )
    return touched


def _project_control_event(
    connection: sqlite3.Connection,
    event: Mapping[str, Any],
    seal: Mapping[str, Any],
) -> dict[str, Any]:
    event_type = str(event.get("event_type") or "")
    sequence = int(event.get("sequence") or 0)
    recorded_at = str(event.get("recorded_at") or "")
    event_json = canonical_json(event).decode("ascii")
    successful_buckets: set[int] = set()
    daily_buckets: set[int] = set()
    effect_buckets: set[int] = set()
    refresh_active = False
    refresh_pending = False
    refresh_circuits = False

    if event_type == "run_started":
        lane = _validate_lane(str(event.get("lane") or ""))
        run_id = str(event.get("run_id") or "")
        key_digest = str(event.get("idempotency_key_sha256") or "")
        max_run = int(event.get("max_run_seconds") or 0)
        allowed_run = int(event.get("allowed_run_seconds") or 0)
        if (
            not run_id
            or not SHA256_RE.fullmatch(key_digest)
            or max_run < 1
            or allowed_run < 1
            or allowed_run > max_run
        ):
            raise _ControlIndexInvalid(
                "control index run-start event is invalid"
            )
        try:
            connection.execute(
                """
                INSERT INTO active_runs(
                    run_id, lane, idempotency_key_sha256, recorded_at,
                    max_run_seconds, allowed_run_seconds, start_sequence,
                    event_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    lane,
                    key_digest,
                    recorded_at,
                    max_run,
                    allowed_run,
                    sequence,
                    event_json,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise _ControlIndexInvalid(
                "control index run start is duplicated"
            ) from exc
        day = parse_utc(recorded_at).date().isoformat()
        bucket = _bucket_for_text(day)
        connection.execute(
            """
            INSERT INTO daily_lane_runs(
                utc_date, lane, run_count, bucket
            ) VALUES (?, ?, 1, ?)
            ON CONFLICT(utc_date, lane) DO UPDATE SET
                run_count = run_count + 1
            """,
            (day, lane, bucket),
        )
        daily_buckets.add(bucket)
        daily_buckets.update(
            _adjust_daily_runtime(
                connection,
                _runtime_allocations(recorded_at, allowed_run),
                multiplier=1,
            )
        )
        refresh_active = True
    elif event_type in TERMINAL_EVENT_TYPES:
        run_id = str(event.get("run_id") or "")
        active = connection.execute(
            """
            SELECT lane, idempotency_key_sha256, recorded_at,
                   allowed_run_seconds
            FROM active_runs
            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()
        if active is None:
            raise _ControlIndexInvalid(
                "control index terminal run has no active start"
            )
        lane = str(active["lane"])
        key_digest = str(active["idempotency_key_sha256"])
        status = str(event.get("status") or "")
        exit_code = int(event.get("exit_code") or 0)
        duration = int(event.get("duration_seconds") or 0)
        connection.execute(
            """
            INSERT INTO terminal_runs(
                run_id, lane, idempotency_key_sha256, status, exit_code,
                duration_seconds, terminal_sequence, event_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                lane,
                key_digest,
                status,
                exit_code,
                duration,
                sequence,
                event_json,
            ),
        )
        connection.execute(
            "DELETE FROM active_runs WHERE run_id = ?",
            (run_id,),
        )
        refresh_active = True
        reserved = int(active["allowed_run_seconds"])
        daily_buckets.update(
            _adjust_daily_runtime(
                connection,
                _runtime_allocations(str(active["recorded_at"]), reserved),
                multiplier=-1,
            )
        )
        daily_buckets.update(
            _adjust_daily_runtime(
                connection,
                _runtime_allocations(
                    str(active["recorded_at"]),
                    duration or reserved,
                ),
                multiplier=1,
            )
        )
        if status in IDEMPOTENT_SUCCESS_STATUSES:
            bucket = _bucket_for_key_digest(key_digest)
            connection.execute(
                """
                INSERT INTO successful_runs(
                    lane, idempotency_key_sha256, run_id,
                    terminal_sequence, bucket
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(lane, idempotency_key_sha256) DO UPDATE SET
                    run_id = excluded.run_id,
                    terminal_sequence = excluded.terminal_sequence,
                    bucket = excluded.bucket
                """,
                (lane, key_digest, run_id, sequence, bucket),
            )
            successful_buckets.add(bucket)
        circuit = connection.execute(
            """
            SELECT consecutive_failures
            FROM lane_circuits
            WHERE lane = ?
            """,
            (lane,),
        ).fetchone()
        if circuit is None:
            raise _ControlIndexInvalid(
                "control index lane circuit is missing"
            )
        if status in FAILURE_STATUSES or exit_code != 0:
            connection.execute(
                """
                UPDATE lane_circuits
                SET consecutive_failures = consecutive_failures + 1,
                    latest_failure_at = ?,
                    terminal_sequence = ?
                WHERE lane = ?
                """,
                (recorded_at, sequence, lane),
            )
            refresh_circuits = True
        elif status in SUCCESS_STATUSES:
            connection.execute(
                """
                UPDATE lane_circuits
                SET consecutive_failures = 0,
                    latest_failure_at = NULL,
                    terminal_sequence = ?
                WHERE lane = ?
                """,
                (sequence, lane),
            )
            refresh_circuits = True
    elif event_type == "effect_pending":
        effect_id = str(event.get("effect_id") or "")
        lane = _validate_lane(str(event.get("lane") or ""))
        run_id = str(event.get("run_id") or "")
        effect_kind = str(event.get("effect_kind") or "")
        key_digest = str(event.get("idempotency_key_sha256") or "")
        if (
            not effect_id
            or effect_kind not in EFFECT_KINDS
            or not SHA256_RE.fullmatch(key_digest)
        ):
            raise _ControlIndexInvalid(
                "control index pending effect is invalid"
            )
        run = connection.execute(
            "SELECT lane FROM active_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if run is None or str(run["lane"]) != lane:
            raise _ControlIndexInvalid(
                "control index pending effect run is invalid"
            )
        connection.execute(
            """
            INSERT INTO pending_effects(
                effect_id, lane, run_id, effect_kind,
                idempotency_key_sha256, before_sha256, recorded_at,
                pending_sequence, event_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                effect_id,
                lane,
                run_id,
                effect_kind,
                key_digest,
                event.get("before_sha256"),
                recorded_at,
                sequence,
                event_json,
            ),
        )
        effect_bucket = _bucket_for_text(
            f"{effect_kind}:{key_digest}"
        )
        connection.execute(
            """
            INSERT INTO latest_effects(
                effect_kind, idempotency_key_sha256, effect_id,
                event_type, receipt_json, latest_sequence, bucket,
                event_json
            ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?)
            ON CONFLICT(effect_kind, idempotency_key_sha256) DO UPDATE SET
                effect_id = excluded.effect_id,
                event_type = excluded.event_type,
                receipt_json = excluded.receipt_json,
                latest_sequence = excluded.latest_sequence,
                bucket = excluded.bucket,
                event_json = excluded.event_json
            """,
            (
                effect_kind,
                key_digest,
                effect_id,
                event_type,
                sequence,
                effect_bucket,
                event_json,
            ),
        )
        day = parse_utc(recorded_at).date().isoformat()
        daily_bucket = _bucket_for_text(day)
        connection.execute(
            """
            INSERT INTO daily_effects(
                utc_date, effect_kind, effect_count, bucket
            ) VALUES (?, ?, 1, ?)
            ON CONFLICT(utc_date, effect_kind) DO UPDATE SET
                effect_count = effect_count + 1
            """,
            (day, effect_kind, daily_bucket),
        )
        effect_buckets.add(effect_bucket)
        daily_buckets.add(daily_bucket)
        refresh_pending = True
    elif event_type in EFFECT_TERMINAL_EVENT_TYPES:
        effect_id = str(event.get("effect_id") or "")
        pending = connection.execute(
            """
            SELECT lane, run_id, effect_kind, idempotency_key_sha256
            FROM pending_effects
            WHERE effect_id = ?
            """,
            (effect_id,),
        ).fetchone()
        if pending is None:
            failed = connection.execute(
                """
                SELECT lane, run_id, effect_kind,
                       idempotency_key_sha256
                FROM terminal_effects
                WHERE effect_id = ? AND event_type = 'effect_failed'
                """,
                (effect_id,),
            ).fetchone()
            if (
                failed is None
                or event_type
                not in {
                    "effect_reconciled_completed",
                    "effect_reconciled_absent",
                }
            ):
                raise _ControlIndexInvalid(
                    "control index terminal effect has no pending start"
                )
            pending = failed
        lane = str(pending["lane"])
        run_id = str(pending["run_id"])
        effect_kind = str(pending["effect_kind"])
        key_digest = str(pending["idempotency_key_sha256"])
        receipt = event.get("receipt")
        receipt_json = (
            canonical_json(receipt).decode("ascii")
            if receipt is not None
            else None
        )
        connection.execute(
            """
            INSERT INTO terminal_effects(
                effect_id, lane, run_id, effect_kind,
                idempotency_key_sha256, event_type, receipt_json,
                terminal_sequence, first_event_json, event_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(effect_id) DO UPDATE SET
                lane = excluded.lane,
                run_id = excluded.run_id,
                effect_kind = excluded.effect_kind,
                idempotency_key_sha256 =
                    excluded.idempotency_key_sha256,
                event_type = excluded.event_type,
                receipt_json = excluded.receipt_json,
                terminal_sequence = excluded.terminal_sequence,
                event_json = excluded.event_json
            """,
            (
                effect_id,
                lane,
                run_id,
                effect_kind,
                key_digest,
                event_type,
                receipt_json,
                sequence,
                event_json,
                event_json,
            ),
        )
        connection.execute(
            "DELETE FROM pending_effects WHERE effect_id = ?",
            (effect_id,),
        )
        effect_bucket = _bucket_for_text(
            f"{effect_kind}:{key_digest}"
        )
        connection.execute(
            """
            UPDATE latest_effects
            SET event_type = ?,
                receipt_json = ?,
                latest_sequence = ?,
                event_json = ?
            WHERE effect_kind = ?
              AND idempotency_key_sha256 = ?
              AND effect_id = ?
            """,
            (
                event_type,
                receipt_json,
                sequence,
                event_json,
                effect_kind,
                key_digest,
                effect_id,
            ),
        )
        if connection.execute("SELECT changes()").fetchone()[0] != 1:
            raise _ControlIndexInvalid(
                "control index latest effect does not match terminal"
            )
        effect_buckets.add(effect_bucket)
        refresh_pending = True
    else:
        raise _ControlIndexInvalid(
            f"control index cannot project event type: {event_type}"
        )

    return _refresh_control_seal(
        connection,
        seal,
        successful_buckets=successful_buckets,
        daily_buckets=daily_buckets,
        effect_buckets=effect_buckets,
        active_runs=refresh_active,
        pending_effects=refresh_pending,
        lane_circuits=refresh_circuits,
    )


def _configure_control_connection(
    connection: sqlite3.Connection,
    *,
    memory: bool = False,
) -> None:
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA trusted_schema = OFF")
    connection.execute("PRAGMA foreign_keys = ON")
    mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()[0]
    expected_modes = {"memory"} if memory else {"delete"}
    if str(mode).lower() not in expected_modes:
        raise _ControlIndexUnsafe(
            "control index could not enable rollback journaling"
        )
    connection.execute("PRAGMA synchronous = FULL")
    connection.execute("PRAGMA fullfsync = ON")
    connection.execute("PRAGMA checkpoint_fullfsync = ON")
    connection.execute("PRAGMA temp_store = MEMORY")
    connection.execute("PRAGMA secure_delete = ON")
    connection.execute("PRAGMA busy_timeout = 5000")


def _initialize_control_schema(
    connection: sqlite3.Connection,
) -> None:
    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if version != 0:
        raise _ControlIndexInvalid(
            "new control index has a nonzero schema version"
        )
    seal = _empty_control_seal()
    try:
        connection.executescript(
            "BEGIN IMMEDIATE;\n"
            + _CONTROL_INDEX_SCHEMA
            + "\n"
            + f"PRAGMA user_version = {CONTROL_INDEX_SCHEMA_VERSION};\n"
        )
        for lane in LANES:
            connection.execute(
                """
                INSERT INTO lane_circuits(
                    lane, consecutive_failures, latest_failure_at,
                    terminal_sequence
                ) VALUES (?, 0, NULL, 0)
                """,
                (lane,),
            )
        seal["lane_circuits"] = _lane_circuits_digest(connection)
        seal_digest = _control_seal_digest(seal)
        connection.execute(
            """
            INSERT INTO control_meta(
                singleton, last_sequence, chain_head, archive_generation,
                archived_through_sequence, archived_chain_head,
                archive_manifest_hash, authority_seal_json,
                authority_seal_sha256
            ) VALUES (1, 0, ?, 0, 0, ?, ?, ?, ?)
            """,
            (
                ZERO_HASH,
                ZERO_HASH,
                ZERO_HASH,
                canonical_json(seal).decode("ascii"),
                seal_digest,
            ),
        )
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


def _validate_control_database(
    connection: sqlite3.Connection,
) -> None:
    if int(connection.execute("PRAGMA user_version").fetchone()[0]) != (
        CONTROL_INDEX_SCHEMA_VERSION
    ):
        raise _ControlIndexInvalid(
            "control index schema version mismatch"
        )
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
        "fullfsync": int(
            connection.execute("PRAGMA fullfsync").fetchone()[0]
        ),
        "journal_mode": str(
            connection.execute("PRAGMA journal_mode").fetchone()[0]
        ).lower(),
    }
    if settings != {
        "foreign_keys": 1,
        "trusted_schema": 0,
        "synchronous": 2,
        "fullfsync": 1,
        "journal_mode": (
            "memory"
            if connection.execute("PRAGMA database_list").fetchone()[2]
            == ""
            else "delete"
        ),
    }:
        raise _ControlIndexUnsafe(
            "control index durability settings are not active"
        )
    if [
        row[0]
        for row in connection.execute("PRAGMA quick_check").fetchall()
    ] != ["ok"]:
        raise _ControlIndexInvalid(
            "control index integrity check failed"
        )
    if connection.execute("PRAGMA foreign_key_check").fetchall():
        raise _ControlIndexInvalid(
            "control index foreign-key check failed"
        )
    _control_meta(connection)


def _validate_control_file(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise
    if stat.S_ISLNK(info.st_mode):
        raise _ControlIndexUnsafe("control index is a symlink")
    if not stat.S_ISREG(info.st_mode):
        raise _ControlIndexUnsafe(
            "control index has the wrong file type"
        )
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise _ControlIndexUnsafe("control index has an unsafe owner")
    if info.st_mode & 0o077:
        raise _ControlIndexUnsafe(
            "control index grants group/world permissions"
        )
    if info.st_nlink != 1:
        raise _ControlIndexUnsafe(
            "control index must not be hard-linked"
        )
    return info


def _validate_control_sidecars(path: Path) -> None:
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(str(path) + suffix)
        if not sidecar.exists() and not sidecar.is_symlink():
            continue
        info = sidecar.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or (
                hasattr(os, "geteuid")
                and info.st_uid != os.geteuid()
            )
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            raise _ControlIndexUnsafe(
                "control index sidecar is unsafe"
            )


class _ControlIndexHandle:
    def __init__(self, path: Path):
        _validate_control_sidecars(path)
        before = _validate_control_file(path)
        flags = os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        self.fd = os.open(path, flags)
        self.connection: sqlite3.Connection | None = None
        try:
            opened = os.fstat(self.fd)
            if (opened.st_dev, opened.st_ino) != (
                before.st_dev,
                before.st_ino,
            ):
                raise _ControlIndexUnsafe(
                    "control index changed while opening"
                )
            uri = "file:" + quote(str(path), safe="/") + "?mode=rw"
            connection = sqlite3.connect(
                uri,
                uri=True,
                timeout=5.0,
                isolation_level=None,
            )
            self.connection = connection
            after = _validate_control_file(path)
            if (opened.st_dev, opened.st_ino) != (
                after.st_dev,
                after.st_ino,
            ):
                raise _ControlIndexUnsafe(
                    "control index path was replaced while opening"
                )
            _configure_control_connection(connection)
            _validate_control_database(connection)
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        if getattr(self, "fd", -1) >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> sqlite3.Connection:
        if self.connection is None:
            raise _ControlIndexInvalid("control index handle is closed")
        return self.connection

    def __exit__(self, *_: object) -> None:
        self.close()


def _create_control_database(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise _ControlIndexUnsafe(
            "new control index path already exists"
        )
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    os.close(fd)
    try:
        uri = "file:" + quote(str(path), safe="/") + "?mode=rw"
        connection = sqlite3.connect(
            uri,
            uri=True,
            timeout=5.0,
            isolation_level=None,
        )
        try:
            _configure_control_connection(connection)
            _initialize_control_schema(connection)
            _validate_control_database(connection)
        finally:
            connection.close()
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _default_checkpoint() -> dict[str, Any]:
    return {
        "schema_version": CHECKPOINT_SCHEMA,
        "generation": 0,
        "archived_through_sequence": 0,
        "archived_chain_head": ZERO_HASH,
        "archive_manifest_hash": ZERO_HASH,
        CONTROL_INDEX_FIELD: None,
        "created_at": None,
    }


def _load_archive_manifest_path(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise AutonomyError("autonomy archive manifest is a symlink")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AutonomyError("autonomy archive manifest is missing") from exc
    if len(raw) > MAX_ARCHIVE_MANIFEST_BYTES:
        raise AutonomyError("autonomy archive manifest is too large")
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AutonomyError("autonomy archive manifest is unreadable") from exc
    if not isinstance(manifest, dict):
        raise AutonomyError("autonomy archive manifest is not an object")
    if manifest.get("schema_version") != ARCHIVE_MANIFEST_SCHEMA:
        raise AutonomyError("autonomy archive manifest schema mismatch")
    if set(manifest) != {
        "schema_version",
        "generation",
        "created_at",
        "previous_manifest_hash",
        "first_sequence",
        "last_sequence",
        "starting_previous_hash",
        "chain_head",
        "event_count",
        "byte_count",
        "files",
        "manifest_hash",
    }:
        raise AutonomyError("autonomy archive manifest fields are invalid")
    observed_hash = str(manifest.get("manifest_hash") or "")
    if not SHA256_RE.fullmatch(observed_hash):
        raise AutonomyError("autonomy archive manifest hash invalid")
    if observed_hash != _object_digest(manifest, "manifest_hash"):
        raise AutonomyError("autonomy archive manifest was modified")
    generation = manifest.get("generation")
    if type(generation) is not int or generation < 1:
        raise AutonomyError("autonomy archive generation is invalid")
    for field in (
        "previous_manifest_hash",
        "starting_previous_hash",
        "chain_head",
    ):
        if not SHA256_RE.fullmatch(str(manifest.get(field) or "")):
            raise AutonomyError(
                f"autonomy archive manifest {field} is invalid"
            )
    first_sequence = manifest.get("first_sequence")
    last_sequence = manifest.get("last_sequence")
    event_count = manifest.get("event_count")
    byte_count = manifest.get("byte_count")
    if (
        type(first_sequence) is not int
        or type(last_sequence) is not int
        or type(event_count) is not int
        or type(byte_count) is not int
        or first_sequence < 1
        or last_sequence < first_sequence
        or event_count != last_sequence - first_sequence + 1
        or byte_count < 1
    ):
        raise AutonomyError("autonomy archive manifest range is invalid")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise AutonomyError("autonomy archive manifest files are invalid")
    seen_names: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {
            "name",
            "sha256",
            "size",
        }:
            raise AutonomyError(
                "autonomy archive manifest file entry is invalid"
            )
        name = str(entry.get("name") or "")
        digest = str(entry.get("sha256") or "")
        size = entry.get("size")
        if (
            not JOURNAL_NAME_RE.fullmatch(name)
            or name in seen_names
            or not SHA256_RE.fullmatch(digest)
            or type(size) is not int
            or size < 1
        ):
            raise AutonomyError(
                "autonomy archive manifest file entry is unsafe"
            )
        seen_names.add(name)
    return manifest


def _load_archive_manifest(
    runtime_home: str | Path,
    generation: int,
) -> dict[str, Any]:
    archive = _archive_root(runtime_home, create=False)
    directory = archive / f"{generation:08d}"
    if directory.is_symlink() or not directory.is_dir():
        raise AutonomyError("autonomy archive generation is unsafe")
    path = directory / "manifest.json"
    return _load_archive_manifest_path(path)


def _load_checkpoint_unlocked(
    runtime_home: str | Path,
) -> dict[str, Any]:
    path = _checkpoint_path(runtime_home)
    if path.is_symlink():
        raise AutonomyError("autonomy checkpoint is a symlink")
    if not path.exists():
        return _default_checkpoint()
    try:
        checkpoint = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AutonomyError("autonomy checkpoint is unreadable") from exc
    if not isinstance(checkpoint, dict):
        raise AutonomyError("autonomy checkpoint is not an object")
    schema = checkpoint.get("schema_version")
    if schema not in {CHECKPOINT_SCHEMA, LEGACY_CHECKPOINT_SCHEMA}:
        raise AutonomyError("autonomy checkpoint schema mismatch")
    expected_fields = {
        "schema_version",
        "generation",
        "archived_through_sequence",
        "archived_chain_head",
        "archive_manifest_hash",
        "created_at",
        "checkpoint_hash",
    }
    expected_fields.add(
        "retained_events"
        if schema == LEGACY_CHECKPOINT_SCHEMA
        else CONTROL_INDEX_FIELD
    )
    if set(checkpoint) != expected_fields:
        raise AutonomyError("autonomy checkpoint fields are invalid")
    observed_hash = str(checkpoint.get("checkpoint_hash") or "")
    if not SHA256_RE.fullmatch(observed_hash):
        raise AutonomyError("autonomy checkpoint hash invalid")
    if observed_hash != _object_digest(checkpoint, "checkpoint_hash"):
        raise AutonomyError("autonomy checkpoint was modified")
    generation = checkpoint.get("generation")
    archived_sequence = checkpoint.get("archived_through_sequence")
    archived_head = str(checkpoint.get("archived_chain_head") or "")
    manifest_hash = str(checkpoint.get("archive_manifest_hash") or "")
    if (
        type(generation) is not int
        or generation < 1
        or type(archived_sequence) is not int
        or archived_sequence < 1
        or not SHA256_RE.fullmatch(archived_head)
        or not SHA256_RE.fullmatch(manifest_hash)
    ):
        raise AutonomyError("autonomy checkpoint anchor is invalid")
    if schema == LEGACY_CHECKPOINT_SCHEMA:
        retained = checkpoint.get("retained_events")
        if not isinstance(retained, list):
            raise AutonomyError(
                "autonomy checkpoint retained events are invalid"
            )
        previous_sequence = 0
        for raw_event in retained:
            event = _validate_event(raw_event)
            sequence = int(event["sequence"])
            if sequence <= previous_sequence or sequence > archived_sequence:
                raise AutonomyError(
                    "autonomy checkpoint retained event order is invalid"
                )
            previous_sequence = sequence
    else:
        control_digest = str(checkpoint.get(CONTROL_INDEX_FIELD) or "")
        if not SHA256_RE.fullmatch(control_digest):
            raise AutonomyError(
                "autonomy checkpoint control index anchor is invalid"
            )
    manifest = _load_archive_manifest(runtime_home, generation)
    if (
        manifest["generation"] != generation
        or manifest["manifest_hash"] != manifest_hash
        or manifest["last_sequence"] != archived_sequence
        or manifest["chain_head"] != archived_head
    ):
        raise AutonomyError("autonomy checkpoint archive anchor mismatch")
    return checkpoint


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _latest_manifest_file_map(
    runtime_home: str | Path,
    checkpoint: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    generation = int(checkpoint.get("generation") or 0)
    if generation == 0:
        return {}
    manifest = _load_archive_manifest(runtime_home, generation)
    return {
        str(entry["name"]): entry
        for entry in manifest["files"]
    }


def _partition_active_files(
    runtime_home: str | Path,
    checkpoint: Mapping[str, Any],
) -> tuple[list[Path], list[Path]]:
    archived_files = _latest_manifest_file_map(runtime_home, checkpoint)
    generation = int(checkpoint.get("generation") or 0)
    archive_directory = (
        _archive_root(runtime_home, create=False) / f"{generation:08d}"
        if generation
        else None
    )
    residual: list[Path] = []
    active: list[Path] = []
    for path in _journal_files(runtime_home):
        entry = archived_files.get(path.name)
        if (
            entry
            and path.stat().st_size == int(entry["size"])
            and _sha256_path(path) == entry["sha256"]
        ):
            archived = archive_directory / path.name
            if (
                archived.is_symlink()
                or not archived.is_file()
                or archived.stat().st_size != int(entry["size"])
                or _sha256_path(archived) != entry["sha256"]
            ):
                raise AutonomyError(
                    "autonomy archived journal was modified"
                )
            residual.append(path)
        else:
            active.append(path)
    return residual, active


def _cleanup_archived_residuals_unlocked(
    runtime_home: str | Path,
    checkpoint: Mapping[str, Any],
) -> None:
    residual, _active = _partition_active_files(runtime_home, checkpoint)
    if not residual:
        return
    for path in residual:
        path.unlink()
    _fsync_directory(_journal_root(runtime_home))


def _read_journal_context_unlocked(
    runtime_home: str | Path,
) -> dict[str, Any]:
    checkpoint = _load_checkpoint_unlocked(runtime_home)
    _residual, paths = _partition_active_files(runtime_home, checkpoint)
    archived_sequence = int(
        checkpoint.get("archived_through_sequence") or 0
    )
    archived_head = str(
        checkpoint.get("archived_chain_head") or ZERO_HASH
    )
    active, next_sequence, chain_head, byte_count = _read_event_files(
        paths,
        expected_sequence=archived_sequence + 1,
        previous_hash=archived_head,
        active_limits=True,
    )
    return {
        "checkpoint": checkpoint,
        "active_events": active,
        "active_paths": paths,
        "active_bytes": byte_count,
        "next_sequence": next_sequence,
        "chain_head": chain_head,
    }


def _compact_control_events(
    events: list[dict[str, Any]],
    *,
    now: datetime,
) -> list[dict[str, Any]]:
    ordered = sorted(events, key=lambda event: int(event["sequence"]))
    by_sequence: dict[int, dict[str, Any]] = {}
    for event in ordered:
        sequence = int(event["sequence"])
        existing = by_sequence.get(sequence)
        if existing and existing.get("event_hash") != event.get("event_hash"):
            raise AutonomyError(
                "autonomy control state has a sequence collision"
            )
        by_sequence[sequence] = event
    ordered = list(by_sequence.values())
    keep: set[int] = set()
    terminal = _terminal_by_run(ordered)
    starts = {
        str(event.get("run_id") or ""): event
        for event in ordered
        if event.get("event_type") == "run_started"
    }

    for event in terminal.values():
        if event.get("status") in IDEMPOTENT_SUCCESS_STATUSES:
            keep.add(int(event["sequence"]))

    for start in _active_starts(ordered):
        keep.add(int(start["sequence"]))

    day_start = datetime.combine(
        now.astimezone(timezone.utc).date(),
        datetime.min.time(),
        tzinfo=timezone.utc,
    )
    for run_id, start in starts.items():
        start_at = parse_utc(str(start["recorded_at"]))
        terminal_event = terminal.get(run_id)
        reserved = int(
            start.get("allowed_run_seconds")
            or start.get("max_run_seconds")
            or 0
        )
        duration = min(
            reserved,
            int(
                (
                    terminal_event.get("duration_seconds")
                    if terminal_event
                    else reserved
                )
                or reserved
            ),
        )
        if start_at.date() == day_start.date() or (
            start_at + timedelta(seconds=max(0, duration)) > day_start
        ):
            keep.add(int(start["sequence"]))
            if terminal_event:
                keep.add(int(terminal_event["sequence"]))

    for lane in LANES:
        for event in reversed(_run_finished_events(ordered, lane)):
            status = str(event.get("status") or "")
            if (
                status in FAILURE_STATUSES
                or int(event.get("exit_code") or 0) != 0
            ):
                keep.add(int(event["sequence"]))
                continue
            if status in SUCCESS_STATUSES:
                keep.add(int(event["sequence"]))
                break

    pending_by_effect = {
        str(event.get("effect_id") or ""): event
        for event in ordered
        if event.get("event_type") == "effect_pending"
    }
    latest_effect_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for event in ordered:
        if event.get("event_type") not in EFFECT_EVENT_TYPES:
            continue
        key = (
            str(event.get("effect_kind") or ""),
            str(event.get("idempotency_key_sha256") or ""),
        )
        latest_effect_by_key[key] = event
    for event in latest_effect_by_key.values():
        keep.add(int(event["sequence"]))
        pending = pending_by_effect.get(str(event.get("effect_id") or ""))
        if pending:
            keep.add(int(pending["sequence"]))

    day = day_start.date().isoformat()
    for event in ordered:
        if (
            event.get("event_type") == "effect_pending"
            and str(event.get("recorded_at") or "").startswith(day)
        ):
            keep.add(int(event["sequence"]))

    return [
        event
        for event in ordered
        if int(event["sequence"]) in keep
    ]


def _copy_archive_file(source: Path, target: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(target, flags, 0o400)
    size = 0
    try:
        with source.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                _write_all(fd, chunk)
                size += len(chunk)
        os.fsync(fd)
    finally:
        os.close(fd)
    return {
        "name": source.name,
        "sha256": digest.hexdigest(),
        "size": size,
    }


def _remove_archive_staging(path: Path) -> None:
    if path.is_symlink():
        raise AutonomyError("autonomy archive staging is a symlink")
    if not path.exists():
        return
    if not path.is_dir():
        raise AutonomyError("autonomy archive staging is not a directory")
    for child in path.iterdir():
        if child.is_symlink() or not child.is_file():
            raise AutonomyError(
                "autonomy archive staging contains an unsafe entry"
            )
        child.unlink()
    path.rmdir()


def _cleanup_archive_staging_unlocked(archive_root: Path) -> None:
    for path in archive_root.iterdir():
        if ARCHIVE_STAGING_RE.fullmatch(path.name):
            _remove_archive_staging(path)


def _validate_archive_segment_copy(
    directory: Path,
    *,
    generation: int,
    old_checkpoint: Mapping[str, Any],
    active: list[dict[str, Any]],
    sources: list[Path],
) -> dict[str, Any]:
    if directory.is_symlink() or not directory.is_dir():
        raise AutonomyError("autonomy archive generation is unsafe")
    manifest = _load_archive_manifest_path(directory / "manifest.json")
    expected_previous_manifest = str(
        old_checkpoint.get("archive_manifest_hash") or ZERO_HASH
    )
    if (
        manifest["generation"] != generation
        or manifest["previous_manifest_hash"] != expected_previous_manifest
        or manifest["first_sequence"] != int(active[0]["sequence"])
        or manifest["last_sequence"] != int(active[-1]["sequence"])
        or manifest["starting_previous_hash"]
        != str(active[0]["previous_hash"])
        or manifest["chain_head"] != str(active[-1]["event_hash"])
        or manifest["event_count"] != len(active)
    ):
        raise AutonomyError("autonomy archive generation collision")
    declared = {
        str(entry["name"]): entry
        for entry in manifest["files"]
    }
    source_names = {path.name for path in sources}
    actual_names = {path.name for path in directory.iterdir()}
    if (
        set(declared) != source_names
        or actual_names != source_names | {"manifest.json"}
    ):
        raise AutonomyError("autonomy archive generation files mismatch")
    archive_paths: list[Path] = []
    for source in sorted(sources):
        entry = declared[source.name]
        archived = directory / source.name
        if archived.is_symlink() or not archived.is_file():
            raise AutonomyError("autonomy archive file is unsafe")
        source_size = source.stat().st_size
        source_digest = _sha256_path(source)
        if (
            int(entry["size"]) != source_size
            or entry["sha256"] != source_digest
            or archived.stat().st_size != source_size
            or _sha256_path(archived) != source_digest
        ):
            raise AutonomyError("autonomy archive generation collision")
        archive_paths.append(archived)
    copied, _next, copied_head, byte_count = _read_event_files(
        archive_paths,
        expected_sequence=int(active[0]["sequence"]),
        previous_hash=str(active[0]["previous_hash"]),
        active_limits=False,
    )
    if (
        [event["event_hash"] for event in copied]
        != [event["event_hash"] for event in active]
        or copied_head != str(active[-1]["event_hash"])
        or byte_count != int(manifest["byte_count"])
    ):
        raise AutonomyError("autonomy archive generation content mismatch")
    return manifest


# Rotation is ordered for crash recovery:
#   1. copy and fsync the complete active segment into generation N;
#   2. atomically replace and fsync the checkpoint anchored at generation N;
#   3. unlink and fsync the now-redundant active files.
# A crash before step 2 leaves an orphan generation that is validated and
# reused on retry. A crash after step 2 leaves active-file duplicates that are
# ignored by readers and removed only after the archived copies are verified.
def _archive_active_segment_unlocked(
    runtime_home: str | Path,
    context: Mapping[str, Any],
    *,
    now: datetime,
) -> dict[str, Any]:
    active = list(context["active_events"])
    paths = list(context["active_paths"])
    if not active or not paths:
        return dict(context["checkpoint"])
    old_checkpoint = context["checkpoint"]
    generation = int(old_checkpoint.get("generation") or 0) + 1
    archive_root = _archive_root(runtime_home)
    _cleanup_archive_staging_unlocked(archive_root)
    final = archive_root / f"{generation:08d}"
    if final.is_symlink():
        raise AutonomyError("autonomy archive generation is a symlink")
    staging: Path | None = None
    try:
        if final.exists():
            manifest = _validate_archive_segment_copy(
                final,
                generation=generation,
                old_checkpoint=old_checkpoint,
                active=active,
                sources=paths,
            )
        else:
            staging = archive_root / (
                f".tmp-{generation:08d}-{uuid.uuid4().hex}"
            )
            staging.mkdir(mode=0o700)
            file_entries = [
                _copy_archive_file(path, staging / path.name)
                for path in paths
            ]
            manifest = {
                "schema_version": ARCHIVE_MANIFEST_SCHEMA,
                "generation": generation,
                "created_at": utc_text(now),
                "previous_manifest_hash": str(
                    old_checkpoint.get("archive_manifest_hash") or ZERO_HASH
                ),
                "first_sequence": int(active[0]["sequence"]),
                "last_sequence": int(active[-1]["sequence"]),
                "starting_previous_hash": str(active[0]["previous_hash"]),
                "chain_head": str(active[-1]["event_hash"]),
                "event_count": len(active),
                "byte_count": sum(
                    int(entry["size"]) for entry in file_entries
                ),
                "files": file_entries,
            }
            manifest["manifest_hash"] = _object_digest(
                manifest,
                "manifest_hash",
            )
            _atomic_write_json(staging / "manifest.json", manifest)
            _fsync_directory(staging)
            manifest = _validate_archive_segment_copy(
                staging,
                generation=generation,
                old_checkpoint=old_checkpoint,
                active=active,
                sources=paths,
            )
            os.rename(staging, final)
            staging = None
            _fsync_directory(archive_root)

        control_digest = str(
            context.get(CONTROL_INDEX_FIELD)
            or active[-1].get(CONTROL_INDEX_FIELD)
            or ""
        )
        if not SHA256_RE.fullmatch(control_digest):
            raise AutonomyError(
                "autonomy control index anchor is unavailable for rotation"
            )
        checkpoint: dict[str, Any] = {
            "schema_version": CHECKPOINT_SCHEMA,
            "generation": generation,
            "archived_through_sequence": int(active[-1]["sequence"]),
            "archived_chain_head": str(active[-1]["event_hash"]),
            "archive_manifest_hash": str(manifest["manifest_hash"]),
            CONTROL_INDEX_FIELD: control_digest,
            "created_at": utc_text(now),
        }
        checkpoint["checkpoint_hash"] = _object_digest(
            checkpoint,
            "checkpoint_hash",
        )
        _atomic_write_json(_checkpoint_path(runtime_home), checkpoint)
        for path in paths:
            path.unlink()
        _fsync_directory(_journal_root(runtime_home))
        return checkpoint
    except BaseException:
        if staging is not None:
            _remove_archive_staging(staging)
        raise


def _validate_uncommitted_archive_generation(
    directory: Path,
    *,
    generation: int,
    checkpoint: Mapping[str, Any],
) -> None:
    if directory.is_symlink() or not directory.is_dir():
        raise AutonomyError("autonomy orphan archive generation is unsafe")
    manifest = _load_archive_manifest_path(directory / "manifest.json")
    expected_sequence = int(
        checkpoint.get("archived_through_sequence") or 0
    ) + 1
    previous_hash = str(
        checkpoint.get("archived_chain_head") or ZERO_HASH
    )
    if (
        manifest["generation"] != generation
        or manifest["previous_manifest_hash"]
        != str(checkpoint.get("archive_manifest_hash") or ZERO_HASH)
        or manifest["first_sequence"] != expected_sequence
        or manifest["starting_previous_hash"] != previous_hash
    ):
        raise AutonomyError(
            "autonomy orphan archive generation does not extend checkpoint"
        )
    declared = {
        str(entry["name"]): entry
        for entry in manifest["files"]
    }
    actual_names = {path.name for path in directory.iterdir()}
    if actual_names != set(declared) | {"manifest.json"}:
        raise AutonomyError(
            "autonomy orphan archive generation files mismatch"
        )
    paths: list[Path] = []
    for name in sorted(declared):
        path = directory / name
        entry = declared[name]
        if path.is_symlink() or not path.is_file():
            raise AutonomyError("autonomy orphan archive file is unsafe")
        if (
            path.stat().st_size != int(entry["size"])
            or _sha256_path(path) != entry["sha256"]
        ):
            raise AutonomyError(
                "autonomy orphan archived journal was modified"
            )
        paths.append(path)
    segment, next_sequence, chain_head, byte_count = _read_event_files(
        paths,
        expected_sequence=expected_sequence,
        previous_hash=previous_hash,
        active_limits=False,
    )
    if (
        not segment
        or len(segment) != int(manifest["event_count"])
        or byte_count != int(manifest["byte_count"])
        or next_sequence - 1 != int(manifest["last_sequence"])
        or chain_head != manifest["chain_head"]
    ):
        raise AutonomyError(
            "autonomy orphan archive generation content mismatch"
        )


def _read_archived_events_unlocked(
    runtime_home: str | Path,
    checkpoint: Mapping[str, Any],
) -> list[dict[str, Any]]:
    generation_count = int(checkpoint.get("generation") or 0)
    archive_root = _archive_root(runtime_home, create=False)
    if generation_count == 0:
        if not archive_root.exists():
            return []
        _cleanup_archive_staging_unlocked(archive_root)
        observed = {path.name for path in archive_root.iterdir()}
        if not observed:
            return []
        if observed == {"00000001"}:
            _validate_uncommitted_archive_generation(
                archive_root / "00000001",
                generation=1,
                checkpoint=checkpoint,
            )
            return []
        if observed:
            raise AutonomyError(
                "autonomy archive exists without a checkpoint"
            )
    if not archive_root.exists():
        raise AutonomyError("autonomy archive root is missing")
    _cleanup_archive_staging_unlocked(archive_root)
    entries = sorted(archive_root.iterdir())
    expected_names = {
        f"{generation:08d}"
        for generation in range(1, generation_count + 1)
    }
    observed_names = {path.name for path in entries}
    orphan_name = f"{generation_count + 1:08d}"
    extras = observed_names - expected_names
    if extras not in (set(), {orphan_name}) or not expected_names.issubset(
        observed_names
    ):
        raise AutonomyError(
            "autonomy archive generations are incomplete or unexpected"
        )
    if extras:
        _validate_uncommitted_archive_generation(
            archive_root / orphan_name,
            generation=generation_count + 1,
            checkpoint=checkpoint,
        )
    events: list[dict[str, Any]] = []
    next_sequence = 1
    chain_head = ZERO_HASH
    manifest_head = ZERO_HASH
    for generation in range(1, generation_count + 1):
        directory = archive_root / f"{generation:08d}"
        if directory.is_symlink() or not directory.is_dir():
            raise AutonomyError("autonomy archive generation is unsafe")
        manifest = _load_archive_manifest_path(
            directory / "manifest.json"
        )
        if (
            manifest["generation"] != generation
            or manifest["previous_manifest_hash"] != manifest_head
            or manifest["first_sequence"] != next_sequence
            or manifest["starting_previous_hash"] != chain_head
        ):
            raise AutonomyError("autonomy archive manifest chain mismatch")
        declared = {
            str(entry["name"]): entry
            for entry in manifest["files"]
        }
        actual_names = {path.name for path in directory.iterdir()}
        if actual_names != set(declared) | {"manifest.json"}:
            raise AutonomyError(
                "autonomy archive generation files mismatch"
            )
        paths: list[Path] = []
        for name in sorted(declared):
            path = directory / name
            if path.is_symlink() or not path.is_file():
                raise AutonomyError("autonomy archive file is unsafe")
            entry = declared[name]
            if (
                path.stat().st_size != int(entry["size"])
                or _sha256_path(path) != entry["sha256"]
            ):
                raise AutonomyError("autonomy archived journal was modified")
            paths.append(path)
        segment, next_sequence, chain_head, byte_count = _read_event_files(
            paths,
            expected_sequence=next_sequence,
            previous_hash=chain_head,
            active_limits=False,
        )
        if (
            len(segment) != int(manifest["event_count"])
            or byte_count != int(manifest["byte_count"])
            or int(segment[-1]["sequence"]) != manifest["last_sequence"]
            or chain_head != manifest["chain_head"]
        ):
            raise AutonomyError(
                "autonomy archive manifest content mismatch"
            )
        events.extend(segment)
        manifest_head = str(manifest["manifest_hash"])
    if (
        next_sequence - 1
        != int(checkpoint["archived_through_sequence"])
        or chain_head != checkpoint["archived_chain_head"]
        or manifest_head != checkpoint["archive_manifest_hash"]
    ):
        raise AutonomyError("autonomy archive checkpoint mismatch")
    if checkpoint.get("schema_version") == LEGACY_CHECKPOINT_SCHEMA:
        archived_hashes = {
            int(event["sequence"]): str(event["event_hash"])
            for event in events
        }
        for retained in checkpoint.get("retained_events") or []:
            if archived_hashes.get(int(retained["sequence"])) != str(
                retained["event_hash"]
            ):
                raise AutonomyError(
                    "autonomy checkpoint retained event is not archived"
                )
        created_at = checkpoint.get("created_at")
        if not isinstance(created_at, str):
            raise AutonomyError(
                "autonomy checkpoint timestamp is invalid"
            )
        expected_retained = _compact_control_events(
            events,
            now=parse_utc(created_at),
        )
        if [
            (int(event["sequence"]), str(event["event_hash"]))
            for event in checkpoint.get("retained_events") or []
        ] != [
            (int(event["sequence"]), str(event["event_hash"]))
            for event in expected_retained
        ]:
            raise AutonomyError(
                "autonomy checkpoint compact control state is incomplete"
            )
    return events


def _read_events_unlocked(runtime_home: str | Path) -> list[dict[str, Any]]:
    checkpoint = _load_checkpoint_unlocked(runtime_home)
    archived = _read_archived_events_unlocked(runtime_home, checkpoint)
    _residual, paths = _partition_active_files(runtime_home, checkpoint)
    active, _next_sequence, _chain_head, _byte_count = _read_event_files(
        paths,
        expected_sequence=int(
            checkpoint.get("archived_through_sequence") or 0
        )
        + 1,
        previous_hash=str(
            checkpoint.get("archived_chain_head") or ZERO_HASH
        ),
        active_limits=True,
    )
    return archived + active


def _seal_from_meta(connection: sqlite3.Connection) -> dict[str, Any]:
    return _validate_control_seal(
        json.loads(str(_control_meta(connection)["authority_seal_json"]))
    )


def _preview_control_event(
    connection: sqlite3.Connection,
    event: Mapping[str, Any],
) -> str:
    connection.execute("SAVEPOINT control_preview")
    try:
        seal = _project_control_event(
            connection,
            event,
            _seal_from_meta(connection),
        )
        return _control_seal_digest(seal)
    finally:
        connection.execute("ROLLBACK TO control_preview")
        connection.execute("RELEASE control_preview")


def _apply_control_event(
    connection: sqlite3.Connection,
    event: Mapping[str, Any],
    *,
    require_embedded_digest: bool,
) -> str:
    event = _validate_event(dict(event))
    connection.execute("BEGIN IMMEDIATE")
    try:
        meta = _control_meta(connection)
        expected_sequence = int(meta["last_sequence"]) + 1
        if (
            int(event["sequence"]) != expected_sequence
            or str(event["previous_hash"]) != str(meta["chain_head"])
        ):
            raise _ControlIndexInvalid(
                "control index event anchor mismatch"
            )
        seal = _project_control_event(
            connection,
            event,
            _seal_from_meta(connection),
        )
        seal_json = canonical_json(seal).decode("ascii")
        seal_digest = _control_seal_digest(seal)
        embedded = event.get(CONTROL_INDEX_FIELD)
        if require_embedded_digest and embedded is None:
            raise _ControlIndexInvalid(
                "journal event lacks a control index digest"
            )
        if embedded is not None and str(embedded) != seal_digest:
            raise AutonomyError(
                "autonomy journal control projection mismatch"
            )
        connection.execute(
            """
            UPDATE control_meta
            SET last_sequence = ?,
                chain_head = ?,
                authority_seal_json = ?,
                authority_seal_sha256 = ?
            WHERE singleton = 1
            """,
            (
                int(event["sequence"]),
                str(event["event_hash"]),
                seal_json,
                seal_digest,
            ),
        )
        connection.execute("COMMIT")
        return seal_digest
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


def _update_control_archive_anchor(
    connection: sqlite3.Connection,
    checkpoint: Mapping[str, Any],
) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            """
            UPDATE control_meta
            SET archive_generation = ?,
                archived_through_sequence = ?,
                archived_chain_head = ?,
                archive_manifest_hash = ?
            WHERE singleton = 1
            """,
            (
                int(checkpoint.get("generation") or 0),
                int(checkpoint.get("archived_through_sequence") or 0),
                str(
                    checkpoint.get("archived_chain_head")
                    or ZERO_HASH
                ),
                str(
                    checkpoint.get("archive_manifest_hash")
                    or ZERO_HASH
                ),
            ),
        )
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


_PROJECTION_TABLES = (
    "successful_runs",
    "active_runs",
    "terminal_runs",
    "daily_runtime",
    "daily_lane_runs",
    "daily_effects",
    "lane_circuits",
    "latest_effects",
    "pending_effects",
    "terminal_effects",
)


def _control_projection_digest(
    connection: sqlite3.Connection,
) -> str:
    projection: dict[str, list[dict[str, Any]]] = {}
    for table in _PROJECTION_TABLES:
        columns = [
            str(row["name"])
            for row in connection.execute(
                f"PRAGMA table_info({table})"
            ).fetchall()
        ]
        if not columns:
            raise _ControlIndexInvalid(
                f"control index table is missing: {table}"
            )
        rows = [
            {column: row[column] for column in columns}
            for row in connection.execute(
                f"SELECT * FROM {table}"
            ).fetchall()
        ]
        rows.sort(key=canonical_json)
        projection[table] = rows
    meta = _control_meta(connection)
    projection["control_anchor"] = [
        {
            "last_sequence": int(meta["last_sequence"]),
            "chain_head": str(meta["chain_head"]),
            "authority_seal_sha256": str(
                meta["authority_seal_sha256"]
            ),
        }
    ]
    return sha256_json(projection)


def _remove_safe_control_sidecars(path: Path) -> None:
    _validate_control_sidecars(path)
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists():
            sidecar.unlink()


def _write_upgraded_checkpoint(
    runtime_home: str | Path,
    checkpoint: Mapping[str, Any],
    control_digest: str,
) -> dict[str, Any]:
    upgraded: dict[str, Any] = {
        "schema_version": CHECKPOINT_SCHEMA,
        "generation": int(checkpoint["generation"]),
        "archived_through_sequence": int(
            checkpoint["archived_through_sequence"]
        ),
        "archived_chain_head": str(
            checkpoint["archived_chain_head"]
        ),
        "archive_manifest_hash": str(
            checkpoint["archive_manifest_hash"]
        ),
        CONTROL_INDEX_FIELD: control_digest,
        "created_at": str(checkpoint["created_at"]),
    }
    upgraded["checkpoint_hash"] = _object_digest(
        upgraded,
        "checkpoint_hash",
    )
    _atomic_write_json(_checkpoint_path(runtime_home), upgraded)
    return upgraded


def _rebuild_control_index_unlocked(
    runtime_home: str | Path,
    *,
    events: list[dict[str, Any]] | None = None,
    checkpoint: Mapping[str, Any] | None = None,
) -> None:
    if checkpoint is None:
        checkpoint = _load_checkpoint_unlocked(runtime_home)
    if events is None:
        events = _read_events_unlocked(runtime_home)
    root = autonomy_root(runtime_home)
    target = _control_index_path(runtime_home)
    if target.exists() or target.is_symlink():
        _validate_control_file(target)
        _validate_control_sidecars(target)
    temporary = root / (
        f".{CONTROL_INDEX_FILENAME}.{uuid.uuid4().hex}.tmp"
    )
    _create_control_database(temporary)
    archived_sequence = int(
        checkpoint.get("archived_through_sequence") or 0
    )
    archive_projection_digest = (
        _control_seal_digest(_empty_control_seal())
        if archived_sequence == 0
        else None
    )
    try:
        with _ControlIndexHandle(temporary) as connection:
            for event in events:
                digest = _apply_control_event(
                    connection,
                    event,
                    require_embedded_digest=False,
                )
                if int(event["sequence"]) == archived_sequence:
                    archive_projection_digest = digest
            if archived_sequence and archive_projection_digest is None:
                raise AutonomyError(
                    "autonomy checkpoint sequence is absent from journal"
                )
            if (
                archived_sequence > 0
                and checkpoint.get("schema_version") == CHECKPOINT_SCHEMA
            ):
                if str(checkpoint.get(CONTROL_INDEX_FIELD)) != str(
                    archive_projection_digest
                ):
                    raise AutonomyError(
                        "autonomy checkpoint control projection mismatch"
                    )
            _update_control_archive_anchor(connection, checkpoint)
        _remove_safe_control_sidecars(target)
        os.replace(temporary, target)
        os.chmod(target, 0o600)
        _fsync_directory(root)
    except BaseException:
        temporary.unlink(missing_ok=True)
        _remove_safe_control_sidecars(temporary)
        raise
    if (
        checkpoint.get("schema_version") == LEGACY_CHECKPOINT_SCHEMA
        and archived_sequence > 0
    ):
        _write_upgraded_checkpoint(
            runtime_home,
            checkpoint,
            str(archive_projection_digest),
        )


def _trusted_control_digest(
    checkpoint: Mapping[str, Any],
    active: list[dict[str, Any]],
    sequence: int,
) -> str | None:
    archived_sequence = int(
        checkpoint.get("archived_through_sequence") or 0
    )
    if sequence == 0:
        return _control_seal_digest(_empty_control_seal())
    if sequence == archived_sequence:
        value = checkpoint.get(CONTROL_INDEX_FIELD)
        return str(value) if value is not None else None
    for event in active:
        if int(event["sequence"]) == sequence:
            value = event.get(CONTROL_INDEX_FIELD)
            return str(value) if value is not None else None
    return None


def _index_matches_archive_anchor(
    meta: sqlite3.Row,
    checkpoint: Mapping[str, Any],
) -> bool:
    return (
        int(meta["archive_generation"])
        == int(checkpoint.get("generation") or 0)
        and int(meta["archived_through_sequence"])
        == int(checkpoint.get("archived_through_sequence") or 0)
        and str(meta["archived_chain_head"])
        == str(checkpoint.get("archived_chain_head") or ZERO_HASH)
        and str(meta["archive_manifest_hash"])
        == str(checkpoint.get("archive_manifest_hash") or ZERO_HASH)
    )


def _open_current_control_index_unlocked(
    runtime_home: str | Path,
    *,
    rebuilt: bool = False,
) -> _ControlIndexHandle:
    checkpoint = _load_checkpoint_unlocked(runtime_home)
    _cleanup_archived_residuals_unlocked(runtime_home, checkpoint)
    context = _read_journal_context_unlocked(runtime_home)
    active = list(context["active_events"])
    current_sequence = int(context["next_sequence"]) - 1
    current_head = str(context["chain_head"])
    path = _control_index_path(runtime_home)
    try:
        handle = _ControlIndexHandle(path)
    except FileNotFoundError:
        _rebuild_control_index_unlocked(runtime_home)
        return _open_current_control_index_unlocked(
            runtime_home,
            rebuilt=True,
        )
    except _ControlIndexUnsafe:
        raise
    except (sqlite3.DatabaseError, _ControlIndexInvalid):
        _rebuild_control_index_unlocked(runtime_home)
        return _open_current_control_index_unlocked(
            runtime_home,
            rebuilt=True,
        )
    try:
        connection = handle.connection
        if connection is None:
            raise _ControlIndexInvalid("control index is closed")
        meta = _control_meta(connection)
        index_sequence = int(meta["last_sequence"])
        archived_sequence = int(
            checkpoint.get("archived_through_sequence") or 0
        )
        if index_sequence < archived_sequence or index_sequence > (
            current_sequence
        ):
            raise _ControlIndexInvalid(
                "control index sequence anchor is stale"
            )
        if index_sequence == archived_sequence:
            expected_head = str(
                checkpoint.get("archived_chain_head") or ZERO_HASH
            )
        else:
            anchored = next(
                (
                    event
                    for event in active
                    if int(event["sequence"]) == index_sequence
                ),
                None,
            )
            expected_head = (
                str(anchored["event_hash"]) if anchored else ""
            )
        if str(meta["chain_head"]) != expected_head:
            raise _ControlIndexInvalid(
                "control index chain anchor is stale"
            )
        trusted = _trusted_control_digest(
            checkpoint,
            active,
            index_sequence,
        )
        if trusted is None and not rebuilt:
            raise _ControlIndexInvalid(
                "control index lacks a trusted projection anchor"
            )
        if trusted is not None and str(
            meta["authority_seal_sha256"]
        ) != trusted:
            raise _ControlIndexInvalid(
                "control index projection anchor mismatch"
            )
        if not _index_matches_archive_anchor(meta, checkpoint):
            raise _ControlIndexInvalid(
                "control index archive anchor mismatch"
            )
        if index_sequence < current_sequence:
            suffix = [
                event
                for event in active
                if int(event["sequence"]) > index_sequence
            ]
            if (
                not suffix
                or int(suffix[0]["sequence"]) != index_sequence + 1
            ):
                raise _ControlIndexInvalid(
                    "control index catch-up segment is unavailable"
                )
            for event in suffix:
                _apply_control_event(
                    connection,
                    event,
                    require_embedded_digest=True,
                )
        meta = _control_meta(connection)
        if (
            int(meta["last_sequence"]) != current_sequence
            or str(meta["chain_head"]) != current_head
        ):
            raise _ControlIndexInvalid(
                "control index did not reach the journal head"
            )
        final_trusted = _trusted_control_digest(
            checkpoint,
            active,
            current_sequence,
        )
        if final_trusted is not None and str(
            meta["authority_seal_sha256"]
        ) != final_trusted:
            raise _ControlIndexInvalid(
                "control index final projection mismatch"
            )
        return handle
    except _ControlIndexUnsafe:
        handle.close()
        raise
    except (
        sqlite3.DatabaseError,
        _ControlIndexInvalid,
    ):
        handle.close()
        if rebuilt:
            raise AutonomyError(
                "autonomy control index rebuild did not stabilize"
            )
        _rebuild_control_index_unlocked(runtime_home)
        return _open_current_control_index_unlocked(
            runtime_home,
            rebuilt=True,
        )


def _verify_or_rebuild_control_components_unlocked(
    runtime_home: str | Path,
    *,
    successful_buckets: set[int] | None = None,
    daily_buckets: set[int] | None = None,
    effect_buckets: set[int] | None = None,
    active_runs: bool = False,
    pending_effects: bool = False,
    lane_circuits: bool = False,
) -> _ControlIndexHandle:
    handle = _open_current_control_index_unlocked(runtime_home)
    try:
        if handle.connection is None:
            raise _ControlIndexInvalid("control index is closed")
        _verify_control_components(
            handle.connection,
            successful_buckets=successful_buckets,
            daily_buckets=daily_buckets,
            effect_buckets=effect_buckets,
            active_runs=active_runs,
            pending_effects=pending_effects,
            lane_circuits=lane_circuits,
        )
        return handle
    except _ControlIndexUnsafe:
        handle.close()
        raise
    except (sqlite3.DatabaseError, _ControlIndexInvalid):
        handle.close()
        _rebuild_control_index_unlocked(runtime_home)
        rebuilt = _open_current_control_index_unlocked(
            runtime_home,
            rebuilt=True,
        )
        try:
            if rebuilt.connection is None:
                raise _ControlIndexInvalid("control index is closed")
            _verify_control_components(
                rebuilt.connection,
                successful_buckets=successful_buckets,
                daily_buckets=daily_buckets,
                effect_buckets=effect_buckets,
                active_runs=active_runs,
                pending_effects=pending_effects,
                lane_circuits=lane_circuits,
            )
            return rebuilt
        except BaseException:
            rebuilt.close()
            raise


def _projection_digest_from_events(
    events: list[dict[str, Any]],
) -> str:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    try:
        _configure_control_connection(connection, memory=True)
        _initialize_control_schema(connection)
        for event in events:
            _apply_control_event(
                connection,
                event,
                require_embedded_digest=False,
            )
        return _control_projection_digest(connection)
    finally:
        connection.close()


def _verify_control_projection_unlocked(
    runtime_home: str | Path,
    events: list[dict[str, Any]],
) -> None:
    expected = _projection_digest_from_events(events)
    try:
        handle = _open_current_control_index_unlocked(runtime_home)
        try:
            if handle.connection is None:
                raise _ControlIndexInvalid("control index is closed")
            observed = _control_projection_digest(handle.connection)
        finally:
            handle.close()
    except (
        sqlite3.DatabaseError,
        _ControlIndexInvalid,
    ):
        observed = ""
    if observed != expected:
        _rebuild_control_index_unlocked(
            runtime_home,
            events=events,
            checkpoint=_load_checkpoint_unlocked(runtime_home),
        )
        handle = _open_current_control_index_unlocked(
            runtime_home,
            rebuilt=True,
        )
        try:
            if handle.connection is None:
                raise _ControlIndexInvalid("control index is closed")
            observed = _control_projection_digest(handle.connection)
        finally:
            handle.close()
        if observed != expected:
            raise AutonomyError(
                "autonomy control index projection is not equivalent"
            )


def read_events(runtime_home: str | Path) -> list[dict[str, Any]]:
    with autonomy_lock(runtime_home):
        events = _read_events_unlocked(runtime_home)
        _verify_control_projection_unlocked(runtime_home, events)
        return events


def _event_projection_requirements(
    connection: sqlite3.Connection,
    event: Mapping[str, Any],
) -> dict[str, Any]:
    event_type = str(event.get("event_type") or "")
    requirements: dict[str, Any] = {
        "successful_buckets": set(),
        "daily_buckets": set(),
        "effect_buckets": set(),
        "active_runs": False,
        "pending_effects": False,
        "lane_circuits": False,
    }
    recorded_at = str(event.get("recorded_at") or "")
    if event_type == "run_started":
        requirements["active_runs"] = True
        for day in _runtime_allocations(
            recorded_at,
            int(event.get("allowed_run_seconds") or 0),
        ):
            requirements["daily_buckets"].add(_bucket_for_text(day))
        requirements["daily_buckets"].add(
            _bucket_for_text(parse_utc(recorded_at).date().isoformat())
        )
    elif event_type in TERMINAL_EVENT_TYPES:
        requirements["active_runs"] = True
        requirements["lane_circuits"] = True
        active = connection.execute(
            """
            SELECT recorded_at, allowed_run_seconds,
                   idempotency_key_sha256
            FROM active_runs
            WHERE run_id = ?
            """,
            (str(event.get("run_id") or ""),),
        ).fetchone()
        if active is None:
            raise _ControlIndexInvalid(
                "control index terminal run start is missing"
            )
        for duration in (
            int(active["allowed_run_seconds"]),
            int(event.get("duration_seconds") or 0),
        ):
            for day in _runtime_allocations(
                str(active["recorded_at"]),
                duration,
            ):
                requirements["daily_buckets"].add(
                    _bucket_for_text(day)
                )
        if str(event.get("status") or "") in (
            IDEMPOTENT_SUCCESS_STATUSES
        ):
            requirements["successful_buckets"].add(
                _bucket_for_key_digest(
                    str(active["idempotency_key_sha256"])
                )
            )
    elif event_type == "effect_pending":
        requirements["active_runs"] = True
        requirements["pending_effects"] = True
        effect_kind = str(event.get("effect_kind") or "")
        key_digest = str(event.get("idempotency_key_sha256") or "")
        requirements["effect_buckets"].add(
            _bucket_for_text(f"{effect_kind}:{key_digest}")
        )
        requirements["daily_buckets"].add(
            _bucket_for_text(parse_utc(recorded_at).date().isoformat())
        )
    elif event_type in EFFECT_TERMINAL_EVENT_TYPES:
        requirements["pending_effects"] = True
        pending = connection.execute(
            """
            SELECT effect_kind, idempotency_key_sha256
            FROM pending_effects
            WHERE effect_id = ?
            """,
            (str(event.get("effect_id") or ""),),
        ).fetchone()
        if pending is None:
            pending = connection.execute(
                """
                SELECT effect_kind, idempotency_key_sha256
                FROM terminal_effects
                WHERE effect_id = ? AND event_type = 'effect_failed'
                """,
                (str(event.get("effect_id") or ""),),
            ).fetchone()
            if (
                pending is None
                or event_type
                not in {
                    "effect_reconciled_completed",
                    "effect_reconciled_absent",
                }
            ):
                raise _ControlIndexInvalid(
                    "control index pending effect is missing"
                )
        requirements["effect_buckets"].add(
            _bucket_for_text(
                f"{pending['effect_kind']}:"
                f"{pending['idempotency_key_sha256']}"
            )
        )
    return requirements


def _append_event_unlocked(
    runtime_home: str | Path,
    event_type: str,
    *,
    now: datetime,
    fields: Mapping[str, Any],
) -> dict[str, Any]:
    checkpoint = _load_checkpoint_unlocked(runtime_home)
    _cleanup_archived_residuals_unlocked(runtime_home, checkpoint)
    context = _read_journal_context_unlocked(runtime_home)
    event: dict[str, Any] = {
        "schema_version": EVENT_SCHEMA,
        "sequence": int(context["next_sequence"]),
        "event_id": str(uuid.uuid4()),
        "recorded_at": utc_text(now),
        "event_type": event_type,
        "previous_hash": str(context["chain_head"]),
    }
    event.update(fields)
    initial = _open_current_control_index_unlocked(runtime_home)
    try:
        if initial.connection is None:
            raise _ControlIndexInvalid("control index is closed")
        requirements = _event_projection_requirements(
            initial.connection,
            event,
        )
    finally:
        initial.close()
    handle = _verify_or_rebuild_control_components_unlocked(
        runtime_home,
        **requirements,
    )
    connection = handle.connection
    if connection is None:
        handle.close()
        raise _ControlIndexInvalid("control index is closed")
    try:
        event[CONTROL_INDEX_FIELD] = _preview_control_event(
            connection,
            event,
        )
        event["event_hash"] = _event_hash(event)
        raw = canonical_json(event) + b"\n"
        if len(raw) > MAX_LINE_BYTES:
            raise AutonomyError("autonomy event exceeds line limit")
        context[CONTROL_INDEX_FIELD] = str(
            _control_meta(connection)["authority_seal_sha256"]
        )
        active_count = len(context["active_events"])
        active_bytes = int(context["active_bytes"])
        active_files = len(context["active_paths"])
        rotate_for_target = bool(context["active_events"]) and (
            active_count >= CHECKPOINT_EVENT_TARGET
            or active_bytes + len(raw) > CHECKPOINT_BYTE_TARGET
            or active_files >= CHECKPOINT_FILE_TARGET
        )
        rotate_for_hard_limit = bool(context["active_events"]) and (
            active_count >= MAX_EVENTS
            or active_bytes + len(raw) > MAX_JOURNAL_BYTES
        )
        if rotate_for_target or rotate_for_hard_limit:
            checkpoint = _archive_active_segment_unlocked(
                runtime_home,
                context,
                now=now,
            )
            _update_control_archive_anchor(connection, checkpoint)
            context = _read_journal_context_unlocked(runtime_home)
            active_count = len(context["active_events"])
            active_bytes = int(context["active_bytes"])
            active_files = len(context["active_paths"])
        if active_count >= MAX_EVENTS:
            raise AutonomyError(
                "autonomy active journal event limit reached"
            )
        if active_bytes + len(raw) > MAX_JOURNAL_BYTES:
            raise AutonomyError(
                "autonomy active journal size limit reached"
            )
        journal = _journal_root(runtime_home)
        path = (
            journal
            / f"{now.astimezone(timezone.utc).date().isoformat()}.jsonl"
        )
        if path.is_symlink():
            raise AutonomyError("autonomy journal file is a symlink")
        flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        original_size = os.fstat(fd).st_size
        try:
            try:
                written = os.write(fd, raw)
                if written != len(raw):
                    raise AutonomyError("autonomy journal short write")
                os.fsync(fd)
            except BaseException:
                try:
                    os.ftruncate(fd, original_size)
                    os.fsync(fd)
                except OSError as exc:
                    raise AutonomyError(
                        "autonomy journal append rollback failed"
                    ) from exc
                raise
        finally:
            os.close(fd)
        _apply_control_event(
            connection,
            event,
            require_embedded_digest=True,
        )
        return event
    finally:
        handle.close()


def _validate_lane(lane: str) -> str:
    if lane not in LANES:
        raise AutonomyError(f"unknown autonomy lane: {lane}")
    return lane


def _key_digest(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not SAFE_KEY_RE.fullmatch(value):
        raise AutonomyError(f"unsafe autonomy {field}")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _effect_receipt(
    value: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise AutonomyError("autonomy effect receipt must be an object")
    allowed = {
        "action",
        "branch",
        "label",
        "number",
        "oid",
        "repo",
        "stdout",
        "target",
        "url",
        "verified",
    }
    if not set(value) <= allowed:
        raise AutonomyError("autonomy effect receipt has unknown fields")
    receipt: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key)
        if raw_value is None or type(raw_value) in {bool, int}:
            receipt[key] = raw_value
            continue
        if not isinstance(raw_value, str):
            raise AutonomyError(
                "autonomy effect receipt values must be scalar"
            )
        limit = 2_048 if key == "stdout" else 512
        if len(raw_value.encode("utf-8")) > limit:
            raise AutonomyError(
                f"autonomy effect receipt field {key} is too large"
            )
        receipt[key] = raw_value
    if len(canonical_json(receipt)) > MAX_EFFECT_RECEIPT_BYTES:
        raise AutonomyError("autonomy effect receipt is too large")
    return receipt


def _run_finished_events(
    events: list[dict[str, Any]],
    lane: str,
) -> list[dict[str, Any]]:
    return [
        event
        for event in events
        if event.get("lane") == lane
        and event.get("event_type") in TERMINAL_EVENT_TYPES
    ]


def _terminal_by_run(
    events: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    terminal: dict[str, dict[str, Any]] = {}
    for event in events:
        if event.get("event_type") in TERMINAL_EVENT_TYPES:
            terminal[str(event.get("run_id") or "")] = event
    return terminal


def _active_starts(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    terminal = _terminal_by_run(events)
    return [
        event
        for event in events
        if event.get("event_type") == "run_started"
        and str(event.get("run_id") or "") not in terminal
    ]


def _event_from_index(
    raw: Any,
    *,
    event_types: set[str] | frozenset[str],
    identity_field: str,
    identity: str,
) -> dict[str, Any]:
    if not isinstance(raw, str):
        raise _ControlIndexInvalid(
            "control index event record is invalid"
        )
    try:
        event = _validate_event(json.loads(raw))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _ControlIndexInvalid(
            "control index event record is unreadable"
        ) from exc
    if (
        str(event.get("event_type") or "") not in event_types
        or str(event.get(identity_field) or "") != identity
    ):
        raise _ControlIndexInvalid(
            "control index event record identity mismatch"
        )
    return event


def _index_circuit_view(
    connection: sqlite3.Connection,
    policy: Mapping[str, Any],
    lane: str,
    now: datetime,
) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT consecutive_failures, latest_failure_at
        FROM lane_circuits
        WHERE lane = ?
        """,
        (lane,),
    ).fetchone()
    if row is None:
        raise _ControlIndexInvalid(
            "control index lane circuit is missing"
        )
    threshold = int(policy["circuit_breaker"]["failure_threshold"])
    cooldown = int(policy["circuit_breaker"]["cooldown_seconds"])
    consecutive = int(row["consecutive_failures"])
    latest_failure = (
        parse_utc(str(row["latest_failure_at"]))
        if row["latest_failure_at"] is not None
        else None
    )
    open_until = (
        latest_failure + timedelta(seconds=cooldown)
        if consecutive >= threshold and latest_failure is not None
        else None
    )
    return {
        "failure_threshold": threshold,
        "consecutive_failures": consecutive,
        "open": bool(open_until and now < open_until),
        "open_until": utc_text(open_until) if open_until else None,
    }


def _index_daily_view(
    connection: sqlite3.Connection,
    policy: Mapping[str, Any],
    lane: str,
    now: datetime,
) -> dict[str, Any]:
    day = now.astimezone(timezone.utc).date().isoformat()
    lane_row = connection.execute(
        """
        SELECT run_count
        FROM daily_lane_runs
        WHERE utc_date = ? AND lane = ?
        """,
        (day, lane),
    ).fetchone()
    runtime_row = connection.execute(
        """
        SELECT runtime_seconds
        FROM daily_runtime
        WHERE utc_date = ?
        """,
        (day,),
    ).fetchone()
    effect_rows = {
        str(row["effect_kind"]): int(row["effect_count"])
        for row in connection.execute(
            """
            SELECT effect_kind, effect_count
            FROM daily_effects
            WHERE utc_date = ?
            """,
            (day,),
        ).fetchall()
    }
    return {
        "utc_date": day,
        "lane_runs": int(lane_row["run_count"]) if lane_row else 0,
        "lane_run_limit": int(
            policy["budgets"]["max_daily_runs"][lane]
        ),
        "runtime_seconds": (
            int(runtime_row["runtime_seconds"]) if runtime_row else 0
        ),
        "runtime_limit_seconds": int(
            policy["budgets"]["max_daily_runtime_seconds"]
        ),
        "effect_counts": {
            effect: effect_rows.get(effect, 0)
            for effect in EFFECT_KINDS
        },
        "effect_limits": dict(policy["budgets"]["max_daily_effects"]),
    }


def _recover_stale_runs_unlocked(
    runtime_home: str | Path,
    policy: Mapping[str, Any],
    now: datetime,
) -> None:
    handle = _verify_or_rebuild_control_components_unlocked(
        runtime_home,
        active_runs=True,
    )
    try:
        if handle.connection is None:
            raise _ControlIndexInvalid("control index is closed")
        starts = handle.connection.execute(
            """
            SELECT run_id, lane, idempotency_key_sha256, recorded_at,
                   max_run_seconds, allowed_run_seconds
            FROM active_runs
            ORDER BY start_sequence
            """
        ).fetchall()
    finally:
        handle.close()
    for start in starts:
        start_lane = _validate_lane(str(start["lane"]))
        elapsed = int(
            now.timestamp()
            - parse_utc(str(start["recorded_at"])).timestamp()
        )
        max_run = int(
            start["allowed_run_seconds"]
            or start["max_run_seconds"]
            or policy["budgets"]["max_run_seconds"][start_lane]
        )
        if elapsed <= max_run + 300:
            continue
        _append_event_unlocked(
            runtime_home,
            "run_abandoned",
            now=now,
            fields={
                "lane": start_lane,
                "run_id": str(start["run_id"]),
                "idempotency_key_sha256": str(
                    start["idempotency_key_sha256"]
                ),
                "status": "abandoned",
                "exit_code": 124,
                "duration_seconds": max_run,
                "observed_elapsed_seconds": max(0, elapsed),
                "duration_clamped": elapsed > max_run,
            },
        )


def begin_run(
    runtime_home: str | Path,
    policy: Mapping[str, Any],
    lane: str,
    *,
    idempotency_key: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    lane = _validate_lane(lane)
    policy = normalize_policy(policy)
    now = now or utc_now()
    if idempotency_key is None:
        idempotency_key = f"manual:{lane}:{uuid.uuid4()}"
    key_digest = _key_digest(
        idempotency_key,
        field="idempotency key",
    )
    with autonomy_lock(runtime_home):
        _recover_stale_runs_unlocked(runtime_home, policy, now)
        max_run = int(policy["budgets"]["max_run_seconds"][lane])
        day = now.astimezone(timezone.utc).date().isoformat()
        handle = _verify_or_rebuild_control_components_unlocked(
            runtime_home,
            successful_buckets={
                _bucket_for_key_digest(key_digest)
            },
            daily_buckets={_bucket_for_text(day)},
            active_runs=True,
            lane_circuits=True,
        )
        try:
            if handle.connection is None:
                raise _ControlIndexInvalid("control index is closed")
            connection = handle.connection
            start = connection.execute(
                """
                SELECT run_id
                FROM active_runs
                WHERE lane = ? AND idempotency_key_sha256 = ?
                """,
                (lane, key_digest),
            ).fetchone()
            if start is not None:
                return {
                    "allowed": False,
                    "reason": "idempotency_in_progress",
                    "run_id": str(start["run_id"]),
                    "idempotency_key_sha256": key_digest,
                }
            successful = connection.execute(
                """
                SELECT run_id
                FROM successful_runs
                WHERE lane = ? AND idempotency_key_sha256 = ?
                """,
                (lane, key_digest),
            ).fetchone()
            if successful is not None:
                return {
                    "allowed": False,
                    "reason": "idempotency_completed",
                    "run_id": str(successful["run_id"]),
                    "idempotency_key_sha256": key_digest,
                }
            circuit = _index_circuit_view(
                connection,
                policy,
                lane,
                now,
            )
            daily = _index_daily_view(
                connection,
                policy,
                lane,
                now,
            )
        finally:
            handle.close()
        if circuit["open"]:
            return {
                "allowed": False,
                "reason": "circuit_open",
                "run_id": None,
                "idempotency_key_sha256": key_digest,
                "circuit": circuit,
            }
        if daily["lane_runs"] >= daily["lane_run_limit"]:
            return {
                "allowed": False,
                "reason": "daily_run_budget_exhausted",
                "run_id": None,
                "idempotency_key_sha256": key_digest,
                "daily": daily,
            }
        if daily["runtime_seconds"] >= daily["runtime_limit_seconds"]:
            return {
                "allowed": False,
                "reason": "daily_runtime_budget_exhausted",
                "run_id": None,
                "idempotency_key_sha256": key_digest,
                "daily": daily,
            }
        remaining_runtime = (
            daily["runtime_limit_seconds"] - daily["runtime_seconds"]
        )
        if remaining_runtime < MIN_RUN_RESERVATION_SECONDS:
            return {
                "allowed": False,
                "reason": "daily_runtime_budget_exhausted",
                "run_id": None,
                "idempotency_key_sha256": key_digest,
                "daily": daily,
            }
        allowed_run_seconds = min(max_run, remaining_runtime)
        run_id = str(uuid.uuid4())
        event = _append_event_unlocked(
            runtime_home,
            "run_started",
            now=now,
            fields={
                "lane": lane,
                "run_id": run_id,
                "idempotency_key_sha256": key_digest,
                "max_run_seconds": max_run,
                "allowed_run_seconds": allowed_run_seconds,
            },
        )
        return {
            "allowed": True,
            "reason": "allowed",
            "run_id": run_id,
            "idempotency_key_sha256": key_digest,
            "max_run_seconds": max_run,
            "allowed_run_seconds": allowed_run_seconds,
            "event_hash": event["event_hash"],
            "circuit": circuit,
            "daily": daily,
        }


def finish_run(
    runtime_home: str | Path,
    run_id: str,
    *,
    status: str,
    exit_code: int,
    duration_seconds: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(run_id, str) or not run_id:
        raise AutonomyError("missing autonomy run id")
    if not isinstance(status, str) or not SAFE_KEY_RE.fullmatch(status):
        raise AutonomyError("unsafe autonomy run status")
    if type(exit_code) is not int or exit_code < 0 or exit_code > 255:
        raise AutonomyError("invalid autonomy exit code")
    if (
        type(duration_seconds) is not int
        or duration_seconds < 0
        or duration_seconds > 7 * 24 * 60 * 60
    ):
        raise AutonomyError("invalid autonomy run duration")
    now = now or utc_now()
    with autonomy_lock(runtime_home):
        handle = _verify_or_rebuild_control_components_unlocked(
            runtime_home,
            active_runs=True,
        )
        try:
            if handle.connection is None:
                raise _ControlIndexInvalid("control index is closed")
            connection = handle.connection
            terminal = connection.execute(
                """
                SELECT event_json
                FROM terminal_runs
                WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
            if terminal is not None:
                return _event_from_index(
                    terminal["event_json"],
                    event_types=TERMINAL_EVENT_TYPES,
                    identity_field="run_id",
                    identity=run_id,
                )
            start = connection.execute(
                """
                SELECT lane, idempotency_key_sha256,
                       allowed_run_seconds, max_run_seconds
                FROM active_runs
                WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
        finally:
            handle.close()
        if start is None:
            raise AutonomyError("autonomy run start missing or duplicated")
        reserved_duration = int(
            start["allowed_run_seconds"]
            or start["max_run_seconds"]
            or 0
        )
        if reserved_duration <= 0:
            raise AutonomyError(
                "autonomy run lacks a valid duration reservation"
            )
        recorded_duration = min(
            duration_seconds,
            reserved_duration,
        )
        return _append_event_unlocked(
            runtime_home,
            "run_finished",
            now=now,
            fields={
                "lane": str(start["lane"]),
                "run_id": run_id,
                "idempotency_key_sha256": str(
                    start["idempotency_key_sha256"]
                ),
                "status": status,
                "exit_code": exit_code,
                "duration_seconds": recorded_duration,
                "reported_duration_seconds": duration_seconds,
                "duration_clamped": (
                    duration_seconds > reserved_duration
                ),
            },
        )


def begin_effect(
    runtime_home: str | Path,
    policy: Mapping[str, Any],
    lane: str,
    run_id: str,
    effect_kind: str,
    *,
    idempotency_key: str,
    before_sha256: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    lane = _validate_lane(lane)
    if effect_kind not in EFFECT_KINDS:
        raise AutonomyError(f"unknown autonomy effect kind: {effect_kind}")
    if before_sha256 not in (None, "") and not SHA256_RE.fullmatch(
        str(before_sha256)
    ):
        raise AutonomyError("invalid autonomy before digest")
    policy = normalize_policy(policy)
    key_digest = _key_digest(
        idempotency_key,
        field="effect idempotency key",
    )
    now = now or utc_now()
    with autonomy_lock(runtime_home):
        day = now.astimezone(timezone.utc).date().isoformat()
        effect_bucket = _bucket_for_text(
            f"{effect_kind}:{key_digest}"
        )
        handle = _verify_or_rebuild_control_components_unlocked(
            runtime_home,
            daily_buckets={_bucket_for_text(day)},
            effect_buckets={effect_bucket},
            active_runs=True,
            pending_effects=True,
        )
        try:
            if handle.connection is None:
                raise _ControlIndexInvalid("control index is closed")
            connection = handle.connection
            start = connection.execute(
                """
                SELECT lane
                FROM active_runs
                WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
            if start is None:
                terminal = connection.execute(
                    "SELECT 1 FROM terminal_runs WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                if terminal is not None:
                    raise AutonomyError(
                        "effect cannot start after its run finished"
                    )
                raise AutonomyError(
                    "effect does not belong to a journaled run"
                )
            if str(start["lane"]) != lane:
                raise AutonomyError(
                    "effect lane does not match its journaled run"
                )
            latest = connection.execute(
                """
                SELECT effect_id, event_type, receipt_json
                FROM latest_effects
                WHERE effect_kind = ?
                  AND idempotency_key_sha256 = ?
                """,
                (effect_kind, key_digest),
            ).fetchone()
            daily = _index_daily_view(
                connection,
                policy,
                lane,
                now,
            )
        finally:
            handle.close()
        if latest is not None:
            event_type = str(latest["event_type"])
            if event_type != "effect_reconciled_absent":
                state = event_type.removeprefix("effect_")
                if state == "reconciled_completed":
                    state = "completed"
                receipt = (
                    json.loads(str(latest["receipt_json"]))
                    if latest["receipt_json"] is not None
                    else None
                )
                return {
                    "allowed": False,
                    "reason": f"effect_idempotency_{state}",
                    "effect_id": str(latest["effect_id"]),
                    "receipt": receipt,
                }
        limit = int(daily["effect_limits"][effect_kind])
        used = int(daily["effect_counts"][effect_kind])
        if used >= limit:
            return {
                "allowed": False,
                "reason": "daily_effect_budget_exhausted",
                "effect_kind": effect_kind,
                "used": used,
                "limit": limit,
            }
        effect_id = str(uuid.uuid4())
        _append_event_unlocked(
            runtime_home,
            "effect_pending",
            now=now,
            fields={
                "lane": lane,
                "run_id": run_id,
                "effect_id": effect_id,
                "effect_kind": effect_kind,
                "idempotency_key_sha256": key_digest,
                "before_sha256": before_sha256 or None,
            },
        )
        return {
            "allowed": True,
            "reason": "allowed",
            "effect_id": effect_id,
            "effect_kind": effect_kind,
            "used": used,
            "limit": limit,
        }


def finish_effect(
    runtime_home: str | Path,
    effect_id: str,
    *,
    after_sha256: str | None = None,
    success: bool = True,
    receipt: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(effect_id, str) or not effect_id:
        raise AutonomyError("missing autonomy effect id")
    if type(success) is not bool:
        raise AutonomyError("autonomy effect success must be boolean")
    if after_sha256 not in (None, "") and not SHA256_RE.fullmatch(
        str(after_sha256)
    ):
        raise AutonomyError("invalid autonomy after digest")
    normalized_receipt = _effect_receipt(receipt)
    now = now or utc_now()
    with autonomy_lock(runtime_home):
        handle = _verify_or_rebuild_control_components_unlocked(
            runtime_home,
            pending_effects=True,
        )
        try:
            if handle.connection is None:
                raise _ControlIndexInvalid("control index is closed")
            connection = handle.connection
            terminal = connection.execute(
                """
                SELECT first_event_json
                FROM terminal_effects
                WHERE effect_id = ?
                """,
                (effect_id,),
            ).fetchone()
            if terminal is not None:
                return _event_from_index(
                    terminal["first_event_json"],
                    event_types=EFFECT_TERMINAL_EVENT_TYPES,
                    identity_field="effect_id",
                    identity=effect_id,
                )
            start = connection.execute(
                """
                SELECT lane, run_id, effect_kind,
                       idempotency_key_sha256, before_sha256
                FROM pending_effects
                WHERE effect_id = ?
                """,
                (effect_id,),
            ).fetchone()
        finally:
            handle.close()
        if start is None:
            raise AutonomyError("autonomy effect start missing or duplicated")
        return _append_event_unlocked(
            runtime_home,
            "effect_completed" if success else "effect_failed",
            now=now,
            fields={
                "lane": str(start["lane"]),
                "run_id": str(start["run_id"]),
                "effect_id": effect_id,
                "effect_kind": str(start["effect_kind"]),
                "idempotency_key_sha256": str(
                    start["idempotency_key_sha256"]
                ),
                "before_sha256": start["before_sha256"],
                "after_sha256": after_sha256 or None,
                "receipt": normalized_receipt,
            },
        )


def reconcile_effect(
    runtime_home: str | Path,
    effect_id: str,
    *,
    observed: str,
    receipt: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(effect_id, str) or not effect_id:
        raise AutonomyError("missing autonomy effect id")
    if observed not in {"completed", "absent"}:
        raise AutonomyError(
            "effect reconciliation must be completed or absent"
        )
    normalized_receipt = _effect_receipt(receipt)
    if observed == "absent" and normalized_receipt:
        raise AutonomyError(
            "absent effect reconciliation cannot carry a receipt"
        )
    now = now or utc_now()
    with autonomy_lock(runtime_home):
        handle = _verify_or_rebuild_control_components_unlocked(
            runtime_home,
            pending_effects=True,
        )
        try:
            if handle.connection is None:
                raise _ControlIndexInvalid("control index is closed")
            connection = handle.connection
            terminal = connection.execute(
                """
                SELECT event_json
                FROM terminal_effects
                WHERE effect_id = ?
                """,
                (effect_id,),
            ).fetchone()
            if terminal is not None:
                terminal_event = _event_from_index(
                    terminal["event_json"],
                    event_types=EFFECT_TERMINAL_EVENT_TYPES,
                    identity_field="effect_id",
                    identity=effect_id,
                )
                if terminal_event["event_type"] != "effect_failed":
                    return terminal_event
                start: Mapping[str, Any] | None = terminal_event
            else:
                start = connection.execute(
                    """
                    SELECT lane, run_id, effect_kind,
                           idempotency_key_sha256, before_sha256
                    FROM pending_effects
                    WHERE effect_id = ?
                    """,
                    (effect_id,),
                ).fetchone()
        finally:
            handle.close()
        if start is None:
            raise AutonomyError(
                "autonomy effect start missing or duplicated"
            )
        return _append_event_unlocked(
            runtime_home,
            (
                "effect_reconciled_completed"
                if observed == "completed"
                else "effect_reconciled_absent"
            ),
            now=now,
            fields={
                "lane": str(start["lane"]),
                "run_id": str(start["run_id"]),
                "effect_id": effect_id,
                "effect_kind": str(start["effect_kind"]),
                "idempotency_key_sha256": str(
                    start["idempotency_key_sha256"]
                ),
                "before_sha256": start["before_sha256"],
                "receipt": normalized_receipt,
            },
        )


def autonomy_status(
    runtime_home: str | Path,
    policy: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    policy = normalize_policy(policy)
    now = now or utc_now()
    with autonomy_lock(runtime_home):
        day = now.astimezone(timezone.utc).date().isoformat()
        handle = _verify_or_rebuild_control_components_unlocked(
            runtime_home,
            daily_buckets={_bucket_for_text(day)},
            active_runs=True,
            pending_effects=True,
            lane_circuits=True,
        )
        try:
            if handle.connection is None:
                raise _ControlIndexInvalid("control index is closed")
            connection = handle.connection
            meta = _control_meta(connection)
            active = connection.execute(
                """
                SELECT lane, run_id, recorded_at, max_run_seconds,
                       allowed_run_seconds
                FROM active_runs
                ORDER BY start_sequence
                """
            ).fetchall()
            pending_count = int(
                connection.execute(
                    "SELECT count(*) FROM pending_effects"
                ).fetchone()[0]
            )
            lanes = {
                lane: {
                    "circuit": _index_circuit_view(
                        connection,
                        policy,
                        lane,
                        now,
                    ),
                    "daily": _index_daily_view(
                        connection,
                        policy,
                        lane,
                        now,
                    ),
                }
                for lane in LANES
            }
            return {
                "schema_version": STATUS_SCHEMA,
                "journal_valid": True,
                "event_count": int(meta["last_sequence"]),
                "chain_head": str(meta["chain_head"]),
                "policy_sha256": sha256_json(policy),
                "active_runs": [
                    {
                        "lane": row["lane"],
                        "run_id": row["run_id"],
                        "recorded_at": row["recorded_at"],
                        "max_run_seconds": row["max_run_seconds"],
                        "allowed_run_seconds": row[
                            "allowed_run_seconds"
                        ],
                    }
                    for row in active
                ],
                "pending_effects": pending_count,
                "lanes": lanes,
            }
        finally:
            handle.close()


def _load_policy_argument(raw: str | None) -> dict[str, Any]:
    if not raw:
        raise AutonomyError("autonomy policy path is required")
    path = Path(raw).expanduser()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AutonomyError(f"cannot load autonomy policy: {path}") from exc
    if (
        isinstance(value, Mapping)
        and value.get("schema_version")
        == "john-lomein.autonomy-deployment.v1"
    ):
        policy = normalize_policy(value.get("policy"))
        if value.get("policy_sha256") != sha256_json(policy):
            raise AutonomyError("autonomy policy stamp digest mismatch")
        return policy
    return normalize_policy(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-home", required=True)
    parser.add_argument("--policy-json")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            events = read_events(args.runtime_home)
            result = {
                "ok": True,
                "event_count": len(events),
                "chain_head": (
                    events[-1]["event_hash"] if events else "0" * 64
                ),
            }
            if not args.quiet:
                print(json.dumps(result, sort_keys=True))
            return 0
        policy = (
            _load_policy_argument(args.policy_json)
            if args.policy_json
            else policy_from_runtime(args.runtime_home)
        )
        print(
            json.dumps(
                autonomy_status(args.runtime_home, policy),
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except (AutonomyError, ValueError) as exc:
        print(f"john-lomein autonomy blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
