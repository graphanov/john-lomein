#!/usr/bin/env python3
"""Fail-closed local Honcho pilot operations.

Read-only inspection and planning are the defaults. Destructive retention requires
an exact plan digest. Participant deletion additionally requires isolated sessions,
service quiescence, a verified backup, exact candidate digests, pgvector, cache
invalidation, and a replay-blocking tombstone.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import plistlib
import re
import secrets
import subprocess
import stat
import sys
import tempfile
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlparse
import yaml
from john_lomein_honcho_contract import honcho_settings
from john_lomein_manifest_contract import validate_manifest_contract
from john_lomein_profile_contract import canonical_role_profiles
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

PAUSE_SCHEMA = "john-lomein.honcho-pause.v1"
RETENTION_SCHEMA = "john-lomein.honcho-retention-plan.v1"
BACKUP_SCHEMA = "john-lomein.honcho-backup.v1"
DELETION_SCHEMA = "john-lomein.honcho-participant-deletion-plan.v1"
RECOVERY_SCHEMA = "john-lomein.honcho-embedding-recovery-plan.v1"
HONCHO_SERVICE_LABELS = ("ai.hermes.honcho.api", "ai.hermes.honcho.deriver")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SCRIPT_DIR = Path(__file__).resolve().parent
PARTICIPANT_CANDIDATE_SQL = SCRIPT_DIR / "honcho-participant-candidates.sql"
DELETION_CANDIDATE_KEYS = frozenset({
    "peer_ids", "session_ids", "session_names", "session_peer_link_keys",
    "message_ids", "message_public_ids", "embedding_ids", "document_ids",
    "collection_ids", "queue_ids", "work_unit_keys", "active_work_unit_keys",
    "conflicting_peers", "unknown_touching_queue_ids", "malformed_lineage_ids",
})
PLAN_FIELDS = (
    "database_oid",
    "workspace",
    "cutoff",
    "retention_days",
    "message_count",
    "queue_count",
    "embedding_count",
    "document_count",
    "schema_fingerprint",
)


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def strict_nonnegative_int(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def evaluate_health(metrics: Mapping[str, Any], thresholds: Mapping[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    if metrics.get("api_healthy") is not True:
        reasons.append("api_unhealthy")
    pairs = (
        ("queue_pending", "queue_pending_max", "queue_pending_exceeded"),
        ("queue_oldest_seconds", "queue_oldest_seconds_max", "queue_oldest_seconds_exceeded"),
        ("embedding_pending", "embedding_pending_max", "embedding_pending_exceeded"),
        (
            "embedding_oldest_pending_seconds",
            "embedding_oldest_seconds_max",
            "embedding_oldest_seconds_exceeded",
        ),
        (
            "embedding_recent_failed",
            "embedding_recent_failed_max",
            "embedding_recent_failed_exceeded",
        ),
        ("database_size_bytes", "database_size_bytes_max", "database_size_exceeded"),
        ("model_error_rows", "model_error_rows_max", "model_errors_present"),
        ("embedding_error_rows", "embedding_error_rows_max", "embedding_errors_present"),
        ("derivation_latency_p95_seconds", "derivation_latency_p95_seconds_max", "derivation_latency_exceeded"),
        ("embedding_latency_p95_seconds", "embedding_latency_p95_seconds_max", "embedding_latency_exceeded"),
    )
    for metric_name, threshold_name, reason in pairs:
        if threshold_name not in thresholds:
            continue
        try:
            observed = int(metrics.get(metric_name) or 0)
            limit = int(thresholds[threshold_name])
        except (KeyError, TypeError, ValueError):
            reasons.append(f"invalid_threshold:{threshold_name}")
            continue
        if observed > limit:
            reasons.append(reason)
    if int(metrics.get("queue_error_rows") or 0) > 0:
        reasons.append("queue_errors_present")
    return {"healthy": not reasons, "reasons": sorted(set(reasons))}


def make_retention_plan(values: Mapping[str, Any]) -> dict[str, Any]:
    if set(values) != set(PLAN_FIELDS):
        missing = sorted(set(PLAN_FIELDS) - set(values))
        extra = sorted(set(values) - set(PLAN_FIELDS))
        raise ValueError(f"retention plan fields invalid: missing={missing} extra={extra}")
    workspace = str(values["workspace"] or "").strip()
    if not SAFE_NAME_RE.fullmatch(workspace):
        raise ValueError("workspace must be a safe Honcho name")
    cutoff = str(values["cutoff"] or "").strip()
    try:
        parsed_cutoff = datetime.fromisoformat(cutoff.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("cutoff must be an ISO-8601 timestamp") from exc
    if parsed_cutoff.tzinfo is None:
        raise ValueError("cutoff must include a timezone")
    schema_fingerprint = str(values["schema_fingerprint"] or "")
    if not re.fullmatch(r"[0-9a-f]{64}", schema_fingerprint):
        raise ValueError("schema_fingerprint must be sha256 hex")
    body = {
        "schema_version": RETENTION_SCHEMA,
        "database_oid": strict_nonnegative_int(values["database_oid"], "database_oid"),
        "workspace": workspace,
        "cutoff": parsed_cutoff.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "retention_days": strict_nonnegative_int(values["retention_days"], "retention_days"),
        "message_count": strict_nonnegative_int(values["message_count"], "message_count"),
        "queue_count": strict_nonnegative_int(values["queue_count"], "queue_count"),
        "embedding_count": strict_nonnegative_int(values["embedding_count"], "embedding_count"),
        "document_count": strict_nonnegative_int(values["document_count"], "document_count"),
        "schema_fingerprint": schema_fingerprint,
        "apply_supported": False,
    }
    body["plan_digest"] = sha256_json(body)
    return body


def validate_retention_plan(plan: Mapping[str, Any]) -> bool:
    try:
        digest = str(plan.get("plan_digest") or "")
        values = {field: plan[field] for field in PLAN_FIELDS}
        rebuilt = make_retention_plan(values)
    except (KeyError, TypeError, ValueError):
        return False
    return plan.get("schema_version") == RETENTION_SCHEMA and plan.get("apply_supported") is False and digest == rebuilt["plan_digest"]


def make_participant_deletion_plan(
    *,
    database_oid: int,
    workspace: str,
    peer: str,
    candidate_sets: Mapping[str, Sequence[Any]],
    allowed_service_peers: Sequence[str],
    schema_fingerprint: str,
    generated_at: str,
) -> dict[str, Any]:
    if not SAFE_NAME_RE.fullmatch(workspace or "") or not SAFE_NAME_RE.fullmatch(peer or ""):
        raise ValueError("workspace and peer must be safe Honcho names")
    if set(candidate_sets) != set(DELETION_CANDIDATE_KEYS):
        raise ValueError("participant deletion candidate sets are incomplete")
    normalized_sets = {key: list(candidate_sets[key]) for key in sorted(DELETION_CANDIDATE_KEYS)}
    service_peers = sorted({str(item).strip() for item in allowed_service_peers if str(item).strip()})
    if any(SAFE_NAME_RE.fullmatch(name) is None for name in service_peers) or peer in service_peers:
        raise ValueError("allowed service peer registry is invalid")
    if len(normalized_sets["peer_ids"]) != 1:
        raise ValueError("participant peer must exist exactly once")
    for blocker in ("conflicting_peers", "unknown_touching_queue_ids", "malformed_lineage_ids"):
        if normalized_sets[blocker]:
            raise ValueError(f"participant deletion is blocked by {blocker}")
    counts = {key.removesuffix("_ids").removesuffix("_keys") + "_count": len(value) for key, value in normalized_sets.items() if key not in {"conflicting_peers", "unknown_touching_queue_ids", "malformed_lineage_ids", "message_public_ids", "session_names"}}
    id_set_digests = {key: sha256_json(value) for key, value in normalized_sets.items()}
    if re.fullmatch(r"sha256:[0-9a-f]{64}", schema_fingerprint or "") is None:
        raise ValueError("participant deletion schema fingerprint is invalid")
    payload = {
        "schema_version": DELETION_SCHEMA,
        "generated_at": generated_at,
        "database_oid": strict_nonnegative_int(database_oid, "database_oid"),
        "workspace": workspace,
        "peer": peer,
        "vector_store": "pgvector",
        "apply_supported": False,
        "allowed_service_peers": service_peers,
        "counts": counts,
        "candidate_sets_digest": sha256_json(normalized_sets),
        "id_set_digests": id_set_digests,
        "schema_fingerprint": schema_fingerprint,
        "scope": ["participant_peer", "participant_sessions", "all_session_messages", "message_embeddings", "queue", "active_queue_sessions", "session_links", "collections_observing_or_observed", "recursive_derived_documents"],
        "authority": {"can_delete": False, "can_delete_workspace": False, "requires_quiescence_receipt": True},
    }
    payload["plan_digest"] = sha256_json(payload)
    return payload


def validate_participant_deletion_plan(plan: Mapping[str, Any]) -> bool:
    expected = {"schema_version", "generated_at", "database_oid", "workspace", "peer", "vector_store", "apply_supported", "allowed_service_peers", "counts", "candidate_sets_digest", "id_set_digests", "schema_fingerprint", "scope", "authority", "plan_digest"}
    if set(plan) != expected or plan.get("schema_version") != DELETION_SCHEMA:
        return False
    if plan.get("vector_store") != "pgvector":
        return False
    if plan.get("apply_supported") is not False:
        return False
    if plan.get("authority") != {"can_delete": False, "can_delete_workspace": False, "requires_quiescence_receipt": True}:
        return False
    if set(plan.get("id_set_digests") or {}) != set(DELETION_CANDIDATE_KEYS):
        return False
    unsigned = dict(plan)
    digest = unsigned.pop("plan_digest", "")
    return digest == sha256_json(unsigned)


def retention_apply_sql() -> str:
    return r"""\set ON_ERROR_STOP on
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';
CREATE TEMP TABLE jl_purge_messages ON COMMIT DROP AS
SELECT id, public_id
FROM messages
WHERE workspace_name = :'workspace'
  AND created_at < :'cutoff'::timestamptz;
CREATE TEMP TABLE jl_purge_documents ON COMMIT DROP AS
WITH RECURSIVE impacted(id) AS (
  SELECT d.id FROM documents d
  WHERE d.workspace_name=:'workspace' AND d.deleted_at IS NULL
    AND d.internal_metadata ? 'message_created_at'
    AND (d.internal_metadata->>'message_created_at')::timestamptz < :'cutoff'::timestamptz
  UNION
  SELECT d.id FROM documents d JOIN impacted i ON EXISTS (
      SELECT 1 FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(d.source_ids)='array' THEN d.source_ids ELSE '[]'::jsonb END) sid
      WHERE sid = i.id
    )
  WHERE d.workspace_name=:'workspace' AND d.deleted_at IS NULL
)
SELECT id FROM impacted;
SELECT set_config('john_lomein.expected_message_count', :'expected_message_count', true);
SELECT set_config('john_lomein.expected_document_count', :'expected_document_count', true);
DO $$
DECLARE actual_count bigint; actual_document_count bigint;
BEGIN
  SELECT count(*) INTO actual_count FROM jl_purge_messages;
  SELECT count(*) INTO actual_document_count FROM jl_purge_documents;
  IF actual_count <> current_setting('john_lomein.expected_message_count')::bigint THEN
    RAISE EXCEPTION 'retention plan is stale: expected %, observed %',
      current_setting('john_lomein.expected_message_count'), actual_count;
  END IF;
  IF actual_document_count <> current_setting('john_lomein.expected_document_count')::bigint THEN
    RAISE EXCEPTION 'retention document plan is stale: expected %, observed %',
      current_setting('john_lomein.expected_document_count'), actual_document_count;
  END IF;
END $$;
WITH RECURSIVE impacted AS (SELECT id FROM jl_purge_documents)
UPDATE documents
SET deleted_at=clock_timestamp(), sync_state='pending'
WHERE id IN (SELECT id FROM impacted);
DELETE FROM queue
WHERE message_id IN (SELECT id FROM jl_purge_messages);
DELETE FROM messages
WHERE id IN (SELECT id FROM jl_purge_messages);
COMMIT;
"""


def participant_deletion_apply_sql() -> str:
    path = SCRIPT_DIR / "honcho-participant-delete.sql"
    return _safe_capability_source(path)


def applied_deletion_tombstones(directory: Path) -> list[dict[str, Any]]:
    raw = Path(directory).expanduser()
    if not raw.is_absolute():
        raise ValueError("deletion tombstone directory must be absolute")
    info = raw.lstat()
    if raw.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("deletion tombstone directory is missing or unsafe")
    _private_target(raw / ".tombstone-scan")
    root = raw
    results: list[dict[str, Any]] = []
    entries = sorted(root.iterdir())
    if any(path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode) or path.suffix != ".json" for path in entries):
        raise ValueError("deletion tombstone directory contains an unsupported entry")
    for path in entries:
        data = json.loads(_safe_capability_source(path, private=True))
        unsigned = dict(data)
        digest = str(unsigned.pop("tombstone_digest", ""))
        if digest != sha256_json(unsigned) or data.get("schema_version") != "john-lomein.honcho-deletion-tombstone.v1":
            raise ValueError("deletion tombstone is invalid")
        if data.get("state") not in {"pending", "applied"}:
            raise ValueError("deletion tombstone state is invalid")
        descriptor = data.get("replay_descriptor")
        if not isinstance(descriptor, Mapping) or not SAFE_NAME_RE.fullmatch(str(descriptor.get("workspace") or "")) or not SAFE_NAME_RE.fullmatch(str(descriptor.get("peer") or "")):
            raise ValueError("deletion tombstone replay descriptor is invalid")
        if data["state"] in {"pending", "applied"}:
            results.append({"tombstone_digest": digest, "plan_digest": data.get("plan_digest"), "state": data["state"]})
    return results


def write_pause_receipt(
    path: Path,
    health: Mapping[str, Any],
    *,
    observed_at: str | None = None,
) -> dict[str, Any]:
    target = Path(path)
    if health.get("healthy") is True:
        if target.is_file():
            try:
                return json.loads(target.read_text(encoding="utf-8"))
            except Exception:
                return {"schema_version": PAUSE_SCHEMA, "unchanged": True}
        return {"schema_version": PAUSE_SCHEMA, "unchanged": True}
    receipt = {
        "schema_version": PAUSE_SCHEMA,
        "observed_at": observed_at or utc_now(),
        "reasons": sorted({str(x) for x in health.get("reasons") or []}),
        "manual_clear_required": True,
    }
    receipt["receipt_digest"] = sha256_json(receipt)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(target.parent, 0o700)
    fd, tmp_name = tempfile.mkstemp(prefix=target.name + ".", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(receipt, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, target)
        os.chmod(target, 0o600)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
    return receipt


def backup_commands(database: str, destination: Path) -> list[list[str]]:
    if not SAFE_NAME_RE.fullmatch(str(database or "")):
        raise ValueError("database must be a safe PostgreSQL database name")
    dest = str(Path(destination))
    return [
        [
            "pg_dump",
            "--dbname",
            database,
            "--format=custom",
            "--compress=9",
            "--no-owner",
            "--no-acl",
            "--file",
            dest,
        ],
        ["pg_restore", "--list", dest],
    ]


def run_checked(
    command: Sequence[str],
    *,
    capture: bool = False,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        text=True,
        input=input_text,
        capture_output=capture,
        check=True,
        timeout=600,
    )


def psql_json(database: str, sql: str, *, variables: Mapping[str, object] | None = None) -> Any:
    command = ["psql", "-X", "--dbname", database, "-At", "-v", "ON_ERROR_STOP=1"]
    for key, value in sorted((variables or {}).items()):
        if not re.fullmatch(r"[a-z_][a-z0-9_]*", key):
            raise ValueError("unsafe psql variable name")
        command.extend(["-v", f"{key}={value}"])
    result = run_checked(command, capture=True, input_text=sql)
    text = result.stdout.strip()
    return json.loads(text) if text else None


def participant_deletion_candidate_sets(
    database: str,
    workspace: str,
    peer: str,
    allowed_service_peers: Sequence[str],
) -> dict[str, list[Any]]:
    names = sorted({str(item).strip() for item in allowed_service_peers if str(item).strip()})
    if not SAFE_NAME_RE.fullmatch(workspace or "") or not SAFE_NAME_RE.fullmatch(peer or ""):
        raise ValueError("workspace and peer must be safe Honcho names")
    if any(SAFE_NAME_RE.fullmatch(name) is None for name in names):
        raise ValueError("allowed service peers must be safe Honcho names")
    sql = PARTICIPANT_CANDIDATE_SQL.read_text(encoding="utf-8")
    raw = psql_json(
        database,
        sql,
        variables={"workspace": workspace, "peer": peer, "service_peers": canonical_json(names)},
    )
    expected = set(DELETION_CANDIDATE_KEYS)
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise ValueError("participant deletion candidate payload is invalid")
    normalized: dict[str, list[Any]] = {}
    for key in sorted(expected):
        value = raw[key]
        if not isinstance(value, list):
            raise ValueError("participant deletion candidate set is invalid")
        normalized[key] = sorted(set(value), key=lambda item: (str(type(item)), str(item)))
    return normalized


def _safe_capability_source(path: Path, *, private: bool = False) -> str:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError("required Honcho capability file is missing") from exc
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_uid != os.geteuid():
        raise ValueError("Honcho capability file metadata is unsafe")
    if private and info.st_mode & 0o077:
        raise ValueError("Honcho environment file must be private")
    return path.read_text(encoding="utf-8")


def _honcho_settings_python(root: Path) -> Path:
    python = root / ".venv" / "bin" / "python"
    try:
        executable = python.resolve(strict=True)
        info = executable.stat()
    except OSError as exc:
        raise ValueError("Honcho virtual environment is missing or unsafe") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022:
        raise ValueError("Honcho virtual environment is missing or unsafe")
    return python


def inspect_honcho_model_config(server_root: Path, expected_model: str) -> dict[str, Any]:
    root = Path(server_root).expanduser().resolve()
    python = _honcho_settings_python(root)
    code = (
        "import json;from src.config import settings;"
        "models={settings.DERIVER.MODEL_CONFIG.model};"
        "models.update(v.MODEL_CONFIG.model for v in settings.DIALECTIC.LEVELS.values());"
        "print(json.dumps({'configured_memory_models':sorted(models),'embedding_model':settings.EMBEDDING.MODEL_CONFIG.model,'embedding_max_input_tokens':settings.EMBEDDING.MAX_INPUT_TOKENS}))"
    )
    result = subprocess.run(
        [str(python), "-c", code], cwd=str(root), text=True, capture_output=True,
        timeout=30, check=True, env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home())},
    )
    data = json.loads(result.stdout)
    models = set(data.get("configured_memory_models") or [])
    payload = {
        "schema_version": "john-lomein.honcho-model-config.v1",
        "expected_memory_model": expected_model,
        **data,
        "model_config_matches": models == {expected_model},
    }
    payload["config_digest"] = sha256_json(payload)
    return payload


def verify_honcho_launch_targets(server_root: Path, base_url: str) -> None:
    root = Path(server_root).expanduser().resolve()
    port = urlparse(base_url).port
    for label in HONCHO_SERVICE_LABELS:
        path = Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o022:
            raise ValueError("Honcho LaunchAgent metadata is unsafe")
        data = plistlib.loads(path.read_bytes())
        if Path(str(data.get("WorkingDirectory") or "")).resolve() != root:
            raise ValueError("Honcho LaunchAgent server root does not match the instance manifest")
        launch_env = data.get("EnvironmentVariables") or {}
        if any(str(key).startswith(("DB_", "CACHE_")) for key in launch_env):
            raise ValueError("Honcho LaunchAgent overrides database or cache settings")
        arguments = [str(item) for item in data.get("ProgramArguments") or []]
        api_port_matches = any(item == "--port" and index + 1 < len(arguments) and arguments[index + 1] == str(port) for index, item in enumerate(arguments))
        if label.endswith(".api") and not api_port_matches:
            raise ValueError("Honcho API port does not match the instance manifest")


def inspect_honcho_database_name(server_root: Path) -> str:
    root = Path(server_root).expanduser().resolve()
    python = _honcho_settings_python(root)
    code = "from urllib.parse import urlparse;from src.config import settings;u=settings.DB.CONNECTION_URI;r=u.get_secret_value() if hasattr(u,'get_secret_value') else str(u);print(urlparse(r).path.lstrip('/'))"
    result = subprocess.run([str(python), "-c", code], cwd=str(root), text=True, capture_output=True, timeout=30, check=True)
    value = result.stdout.strip()
    if SAFE_NAME_RE.fullmatch(value) is None:
        raise ValueError("effective Honcho database name is invalid")
    return value


def inspect_honcho_cache_url(server_root: Path) -> str:
    root = Path(server_root).expanduser().resolve()
    python = _honcho_settings_python(root)
    code = "from src.config import settings;print(str(settings.CACHE.URL))"
    result = subprocess.run([str(python), "-c", code], cwd=str(root), text=True, capture_output=True, timeout=30, check=True)
    value = result.stdout.strip()
    parsed = urlparse(value)
    if parse_qs(parsed.query, keep_blank_values=True) not in ({}, {"suppress": ["true"]}):
        raise ValueError("effective Honcho cache URL options are unsupported")
    normalized = parsed._replace(query="", fragment="").geturl()
    if re.fullmatch(r"redis://127\.0\.0\.1:[0-9]{2,5}/[0-9]+", normalized) is None:
        raise ValueError("effective Honcho cache URL is unsupported")
    return normalized


def inspect_honcho_vector_store(server_root: Path) -> dict[str, Any]:
    root = Path(server_root).expanduser().resolve()
    python = _honcho_settings_python(root)
    code = "import json;from src.config import settings;print(json.dumps({'type':str(settings.VECTOR_STORE.TYPE),'migrated':bool(settings.VECTOR_STORE.MIGRATED)}))"
    result = subprocess.run(
        [str(python), "-c", code], cwd=str(root), text=True, capture_output=True,
        timeout=30, check=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home())},
    )
    payload = json.loads(result.stdout)
    payload["config_digest"] = sha256_json(payload)
    return payload


def inspect_chunking_capability(
    server_root: Path,
    env_path: Path,
    *,
    expected_cap: int = 1000,
) -> dict[str, Any]:
    root = Path(server_root).expanduser().resolve()
    client_text = _safe_capability_source(root / "src" / "embedding_client.py")
    message_text = _safe_capability_source(root / "src" / "crud" / "message.py")
    env_text = _safe_capability_source(Path(env_path).expanduser().resolve(), private=True)
    matches = re.findall(r"(?m)^EMBEDDING_MAX_INPUT_TOKENS=(\d+)\s*$", env_text)
    observed = int(matches[0]) if len(matches) == 1 else -1
    client_tree = ast.parse(client_text)
    message_tree = ast.parse(message_text)
    has_prepare = any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "prepare_chunks"
        for node in ast.walk(client_tree)
    )
    persists_chunks = any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "prepare_chunks"
        for node in ast.walk(message_tree)
    )
    verified = observed == expected_cap and has_prepare and persists_chunks
    payload = {
        "schema_version": "john-lomein.honcho-chunking-capability.v1",
        "expected_cap": expected_cap,
        "observed_cap": observed,
        "prepare_chunks_present": has_prepare,
        "persistence_wiring_present": persists_chunks,
        "capability_verified": verified,
    }
    payload["capability_digest"] = sha256_json(payload)
    return payload


def api_health(base_url: str) -> bool:
    url = base_url.rstrip("/") + "/health"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            payload = json.load(response)
        return response.status == 200 and str(payload.get("status") or "").lower() in {
            "ok",
            "healthy",
        }
    except (OSError, ValueError, urllib.error.URLError):
        return False


def collect_metrics(database: str, base_url: str, workspace: str) -> dict[str, Any]:
    if not SAFE_NAME_RE.fullmatch(workspace):
        raise ValueError("workspace must be a safe Honcho name")
    sql = r"""SELECT json_build_object(
'database_oid', (SELECT oid FROM pg_database WHERE datname=current_database()),
'database_size_bytes', pg_database_size(current_database()),
'workspace_messages', (SELECT count(*) FROM messages WHERE workspace_name=:'workspace'),
'workspace_sessions', (SELECT count(*) FROM sessions WHERE workspace_name=:'workspace'),
'workspace_peers', (SELECT count(*) FROM peers WHERE workspace_name=:'workspace'),
'queue_pending', (SELECT count(*) FROM queue WHERE processed=false),
'queue_error_rows', (SELECT count(*) FROM queue WHERE COALESCE(error,'')<>''),
'queue_oldest_seconds', COALESCE((SELECT extract(epoch FROM now()-min(created_at))::bigint FROM queue WHERE processed=false),0),
'embedding_pending', (SELECT count(*) FROM message_embeddings WHERE workspace_name=:'workspace' AND sync_state='pending'),
'embedding_oldest_pending_seconds', COALESCE((SELECT extract(epoch FROM now()-min(created_at))::bigint FROM message_embeddings WHERE workspace_name=:'workspace' AND sync_state='pending'),0),
'embedding_recent_failed', (SELECT count(*) FROM message_embeddings WHERE workspace_name=:'workspace' AND sync_state='failed' AND created_at > now()-interval '24 hours'),
'model_error_rows', (SELECT count(*) FROM queue WHERE workspace_name=:'workspace' AND task_type='representation' AND COALESCE(error,'')<>''),
'embedding_error_rows', (SELECT count(*) FROM message_embeddings WHERE workspace_name=:'workspace' AND sync_state='failed'),
'derivation_latency_p95_seconds', COALESCE((SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM d.created_at-(d.internal_metadata->>'message_created_at')::timestamptz))::bigint FROM documents d WHERE d.workspace_name=:'workspace' AND d.created_at>now()-interval '24 hours' AND d.internal_metadata ? 'message_created_at'),0),
'embedding_latency_p95_seconds', COALESCE((SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM e.last_sync_at-m.created_at))::bigint FROM message_embeddings e JOIN messages m ON m.workspace_name=e.workspace_name AND m.public_id=e.message_id WHERE e.workspace_name=:'workspace' AND m.created_at>now()-interval '24 hours' AND e.sync_state='synced' AND e.last_sync_at IS NOT NULL),0),
'max_message_tokens', COALESCE((SELECT max(token_count) FROM messages WHERE workspace_name=:'workspace'),0)
)::text;"""
    metrics = dict(psql_json(database, sql, variables={"workspace": workspace}) or {})
    metrics["api_healthy"] = api_health(base_url)
    return metrics


def database_oid(database: str) -> int:
    value = psql_json(
        database,
        "SELECT json_build_object('database_oid',oid)::text FROM pg_database WHERE datname=current_database();",
    ) or {}
    return int(value.get("database_oid") or 0)


def schema_fingerprint(database: str) -> str:
    sql = r"""SELECT json_agg(row_to_json(x) ORDER BY x.table_name,x.ordinal_position)::text
FROM (
 SELECT table_name,column_name,data_type,ordinal_position
 FROM information_schema.columns
 WHERE table_schema='public'
   AND table_name IN ('messages','message_embeddings','queue','documents','peers','collections','session_peers','sessions','active_queue_sessions')
) x;"""
    structure = psql_json(database, sql)
    return sha256_json(structure)


def retention_counts(database: str, workspace: str, cutoff: str) -> dict[str, int]:
    sql = r"""SELECT json_build_object(
'message_count', (SELECT count(*) FROM messages WHERE workspace_name=:'workspace' AND created_at < :'cutoff'::timestamptz),
'queue_count', (SELECT count(*) FROM queue WHERE message_id IN (SELECT id FROM messages WHERE workspace_name=:'workspace' AND created_at < :'cutoff'::timestamptz)),
'embedding_count', (SELECT count(*) FROM message_embeddings WHERE message_id IN (SELECT public_id FROM messages WHERE workspace_name=:'workspace' AND created_at < :'cutoff'::timestamptz)),
'document_count', (
  WITH RECURSIVE impacted(id) AS (
    SELECT d.id FROM documents d
    WHERE d.workspace_name=:'workspace' AND d.deleted_at IS NULL
      AND d.internal_metadata ? 'message_created_at'
      AND (d.internal_metadata->>'message_created_at')::timestamptz < :'cutoff'::timestamptz
    UNION
    SELECT d.id FROM documents d JOIN impacted i ON EXISTS (
      SELECT 1 FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(d.source_ids)='array' THEN d.source_ids ELSE '[]'::jsonb END) sid
      WHERE sid = i.id
    )
    WHERE d.workspace_name=:'workspace' AND d.deleted_at IS NULL
  )
  SELECT count(*) FROM impacted
)
)::text;"""
    data = psql_json(database, sql, variables={"workspace": workspace, "cutoff": cutoff}) or {}
    return {key: int(data.get(key) or 0) for key in ("message_count", "queue_count", "embedding_count", "document_count")}


def workspace_counts(database: str, workspace: str) -> dict[str, int]:
    if SAFE_NAME_RE.fullmatch(workspace or "") is None:
        raise ValueError("workspace must be a safe Honcho name")
    sql = r"""SELECT json_build_object(
'workspaces', (SELECT count(*) FROM workspaces WHERE name=:'workspace'),
'peers', (SELECT count(*) FROM peers WHERE workspace_name=:'workspace'),
'sessions', (SELECT count(*) FROM sessions WHERE workspace_name=:'workspace'),
'messages', (SELECT count(*) FROM messages WHERE workspace_name=:'workspace'),
'documents', (SELECT count(*) FROM documents WHERE workspace_name=:'workspace'),
'collections', (SELECT count(*) FROM collections WHERE workspace_name=:'workspace'),
'message_embeddings', (SELECT count(*) FROM message_embeddings WHERE workspace_name=:'workspace'),
'queue', (SELECT count(*) FROM queue WHERE workspace_name=:'workspace')
)::text;"""
    data = psql_json(database, sql, variables={"workspace": workspace}) or {}
    keys = ("workspaces", "peers", "sessions", "messages", "documents", "collections", "message_embeddings", "queue")
    return {key: int(data.get(key) or 0) for key in keys}


def participant_deletion_counts(
    database: str,
    workspace: str,
    peer: str,
    allowed_service_peers: Sequence[str] = (),
) -> dict[str, int]:
    sets = participant_deletion_candidate_sets(
        database, workspace, peer, allowed_service_peers
    )
    return {
        "peer_count": len(sets["peer_ids"]),
        "session_count": len(sets["session_ids"]),
        "session_peer_link_count": len(sets["session_peer_link_keys"]),
        "message_count": len(sets["message_ids"]),
        "embedding_count": len(sets["embedding_ids"]),
        "document_count": len(sets["document_ids"]),
        "collection_count": len(sets["collection_ids"]),
        "queue_count": len(sets["queue_ids"]),
        "active_work_unit_count": len(sets["active_work_unit_keys"]),
    }


def chunking_metrics(database: str, workspace: str, expected_cap: int) -> dict[str, int]:
    if not SAFE_NAME_RE.fullmatch(workspace or "") or expected_cap <= 0:
        raise ValueError("chunking metric inputs are invalid")
    sql = r"""WITH per_message AS (
 SELECT m.id,m.token_count,count(e.id)::int AS embedding_rows
 FROM messages m LEFT JOIN message_embeddings e
  ON e.workspace_name=m.workspace_name AND e.message_id=m.public_id
 WHERE m.workspace_name=:'workspace'
 GROUP BY m.id,m.token_count
)
SELECT json_build_object(
 'source_messages',count(*),
 'missing_embedding_sources',count(*) FILTER (WHERE embedding_rows=0),
 'long_sources',count(*) FILTER (WHERE token_count>:'cap'::int),
 'long_single_row_sources',count(*) FILTER (WHERE token_count>:'cap'::int AND embedding_rows=1),
 'chunked_sources',count(*) FILTER (WHERE embedding_rows>1),
 'max_source_tokens',COALESCE(max(token_count),0),
 'max_embedding_rows',COALESCE(max(embedding_rows),0)
)::text FROM per_message;"""
    data = psql_json(database, sql, variables={"workspace": workspace, "cap": expected_cap}) or {}
    return {key: int(value or 0) for key, value in data.items()}


def evaluate_chunking_preflight(
    capability: Mapping[str, Any], metrics: Mapping[str, Any]
) -> dict[str, Any]:
    reasons: list[str] = []
    if capability.get("capability_verified") is not True:
        reasons.append("chunking_capability_unverified")
    if int(metrics.get("missing_embedding_sources") or 0) > 0:
        reasons.append("message_embeddings_missing")
    if int(metrics.get("long_single_row_sources") or 0) > 0:
        reasons.append("legacy_or_unpersisted_long_message_chunks")
    payload = {"ready": not reasons, "reasons": sorted(reasons)}
    payload["preflight_digest"] = sha256_json(
        {"capability": capability, "metrics": metrics, **payload}
    )
    return payload


def embedding_recovery_candidates(
    database: str, workspace: str, expected_cap: int
) -> dict[str, list[str]]:
    if not SAFE_NAME_RE.fullmatch(workspace or "") or expected_cap <= 0:
        raise ValueError("embedding recovery inputs are invalid")
    sql = _safe_capability_source(SCRIPT_DIR / "honcho-embedding-recovery-candidates.sql")
    data = psql_json(database, sql, variables={"workspace": workspace, "cap": expected_cap}) or {}
    expected = {"missing", "failed", "legacy_long_single"}
    if set(data) != expected:
        raise ValueError("embedding recovery candidate query returned unexpected fields")
    normalized = {key: sorted({str(item) for item in (data[key] or [])}) for key in expected}
    return normalized


def make_embedding_recovery_plan(
    *, workspace: str, expected_cap: int, candidates: Mapping[str, Sequence[str]],
    capability_digest: str, schema_fingerprint_value: str, generated_at: str,
) -> dict[str, Any]:
    expected = {"missing", "failed", "legacy_long_single"}
    if set(candidates) != expected or not SAFE_NAME_RE.fullmatch(workspace or ""):
        raise ValueError("embedding recovery candidates are invalid")
    normalized = {key: sorted({str(item) for item in candidates[key]}) for key in expected}
    all_ids = sorted(set().union(*normalized.values()))
    payload = {
        "schema_version": RECOVERY_SCHEMA, "generated_at": generated_at,
        "workspace": workspace, "expected_cap": expected_cap,
        "candidate_counts": {key: len(value) for key, value in normalized.items()},
        "message_public_ids_digest": sha256_json(all_ids),
        "capability_digest": capability_digest,
        "schema_fingerprint": schema_fingerprint_value,
        "apply_supported": False,
        "authority": {"can_requeue": False, "owner_approval_required": True},
    }
    return {**payload, "plan_digest": sha256_json(payload)}


def create_backup(database: str, destination: Path) -> dict[str, Any]:
    dest = Path(destination).expanduser().resolve()
    if dest.exists():
        raise FileExistsError(f"backup destination already exists: {dest}")
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(dest.parent, 0o700)
    temp = dest.with_name(dest.name + ".partial")
    if temp.exists():
        raise FileExistsError(f"partial backup already exists: {temp}")
    commands = backup_commands(database, temp)
    try:
        run_checked(commands[0])
        os.chmod(temp, 0o600)
        listing = run_checked(commands[1], capture=True).stdout
        if not listing.strip():
            raise RuntimeError("pg_restore --list returned empty output")
        os.replace(temp, dest)
        os.chmod(dest, 0o600)
    finally:
        if temp.exists():
            temp.unlink()
    digest = hashlib.sha256(dest.read_bytes()).hexdigest()
    manifest = {
        "schema_version": BACKUP_SCHEMA,
        "database": database,
        "created_at": utc_now(),
        "path": str(dest),
        "size_bytes": dest.stat().st_size,
        "sha256": digest,
    }
    manifest["manifest_digest"] = sha256_json(manifest)
    manifest_path = dest.with_suffix(dest.suffix + ".json")
    fd, tmp_name = tempfile.mkstemp(prefix=manifest_path.name + ".", dir=dest.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, manifest_path)
        os.chmod(manifest_path, 0o600)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
    return manifest


def restore_verify(backup: Path) -> dict[str, Any]:
    source = Path(backup).expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(source)
    manifest_path = source.with_suffix(source.suffix + ".json")
    if not manifest_path.is_file():
        raise FileNotFoundError(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != BACKUP_SCHEMA:
        raise ValueError("unsupported backup manifest schema")
    manifest_digest = str(manifest.get("manifest_digest") or "")
    unsigned_manifest = {
        key: value for key, value in manifest.items() if key != "manifest_digest"
    }
    if manifest_digest != sha256_json(unsigned_manifest):
        raise ValueError("backup manifest digest mismatch")
    backup_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    if backup_digest != manifest.get("sha256"):
        raise ValueError("backup checksum mismatch")
    database = str(manifest.get("database") or "")
    if not SAFE_NAME_RE.fullmatch(database):
        raise ValueError("backup manifest database name is unsafe")
    name = f"jl_restore_verify_{os.getpid()}_{secrets.token_hex(4)}"
    if not SAFE_NAME_RE.fullmatch(name):
        raise RuntimeError("generated unsafe restore database name")
    run_checked(["createdb", name])
    try:
        run_checked(
            [
                "pg_restore",
                "--dbname",
                name,
                "--no-owner",
                "--no-acl",
                "--exit-on-error",
                str(source),
            ]
        )
        counts = psql_json(
            name,
            "SELECT json_build_object('workspaces',(SELECT count(*) FROM workspaces),'messages',(SELECT count(*) FROM messages),'documents',(SELECT count(*) FROM documents))::text;",
        )
        result = {
            "verified": True,
            "source_database": database,
            "restore_database": name,
            "counts": counts,
        }
    finally:
        run_checked(["dropdb", "--if-exists", name])
    result["restore_database_dropped"] = True
    return result


def _private_target(path: Path) -> Path:
    target = Path(path).expanduser()
    if not target.is_absolute():
        raise ValueError("private output path must be absolute")
    current = Path(target.anchor)
    for part in target.parent.parts[1:]:
        current = current / part
        info = current.lstat()
        if current.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise ValueError("private output path traverses an unsafe directory")
    parent_info = target.parent.lstat()
    if parent_info.st_uid != os.geteuid() or parent_info.st_mode & 0o077:
        raise ValueError("private output directory metadata is unsafe")
    return target


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_private_json(path: Path, payload: Mapping[str, Any]) -> None:
    raw = Path(path).expanduser()
    raw.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(raw.parent, 0o700)
    target = _private_target(raw)
    fd, temp_name = tempfile.mkstemp(prefix=target.name + ".", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, target)
        _fsync_directory(target.parent)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def reserve_private_json(path: Path, payload: Mapping[str, Any]) -> None:
    raw = Path(path).expanduser()
    raw.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(raw.parent, 0o700)
    target = _private_target(raw)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(target, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    _fsync_directory(target.parent)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def verified_backup_metadata(path: Path, *, expected_database: str) -> dict[str, Any]:
    backup = Path(path).expanduser().resolve()
    info = backup.lstat()
    if not stat.S_ISREG(info.st_mode) or backup.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError("verified backup file metadata is unsafe")
    manifest_path = backup.with_suffix(backup.suffix + ".json")
    manifest = json.loads(_safe_capability_source(manifest_path, private=True))
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_digest"}
    if manifest.get("schema_version") != BACKUP_SCHEMA or manifest.get("manifest_digest") != sha256_json(unsigned):
        raise ValueError("backup manifest is invalid")
    if manifest.get("database") != expected_database:
        raise ValueError("backup database does not match deletion target")
    backup_digest = file_sha256(backup)
    if manifest.get("sha256") != backup_digest.removeprefix("sha256:"):
        raise ValueError("backup checksum mismatch")
    listing = run_checked(["pg_restore", "--list", str(backup)], capture=True).stdout
    if not listing.strip():
        raise ValueError("verified backup is unreadable")
    return {"path": str(backup), "sha256": backup_digest, "size_bytes": info.st_size}


def build_honcho_quiescence_receipt(
    *,
    database_oid_value: int,
    schema_fingerprint_value: str,
    service_labels: Sequence[str],
    observed_at: str,
    expires_at: str,
    nonce: str,
    vector_store_config_digest: str,
) -> dict[str, Any]:
    labels = sorted({str(item).strip() for item in service_labels if str(item).strip()})
    if not labels or any(re.fullmatch(r"[A-Za-z0-9._-]{1,128}", item) is None for item in labels):
        raise ValueError("quiescence service labels are invalid")
    payload = {
        "schema_version": "john-lomein.honcho-quiescence.v1",
        "database_oid": strict_nonnegative_int(database_oid_value, "database_oid"),
        "schema_fingerprint": schema_fingerprint_value,
        "service_labels": labels,
        "observed_at": observed_at,
        "expires_at": expires_at,
        "api_unreachable": True,
        "services_absent": True,
        "vector_store": "pgvector",
        "vector_store_config_digest": vector_store_config_digest,
        "nonce": nonce,
    }
    payload["receipt_digest"] = sha256_json(payload)
    return payload


def validate_honcho_quiescence_receipt(receipt: Mapping[str, Any], *, now: datetime) -> bool:
    unsigned = dict(receipt)
    digest = unsigned.pop("receipt_digest", "")
    if digest != sha256_json(unsigned):
        return False
    if receipt.get("schema_version") != "john-lomein.honcho-quiescence.v1":
        return False
    if receipt.get("api_unreachable") is not True or receipt.get("services_absent") is not True:
        return False
    if tuple(receipt.get("service_labels") or ()) != HONCHO_SERVICE_LABELS:
        return False
    if receipt.get("vector_store") != "pgvector" or re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("vector_store_config_digest") or "")) is None:
        return False
    try:
        expires = datetime.fromisoformat(str(receipt["expires_at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError):
        return False
    return now.astimezone(timezone.utc) < expires.astimezone(timezone.utc)


def assert_honcho_quiescent(base_url: str, service_labels: Sequence[str]) -> None:
    if api_health(base_url):
        raise RuntimeError("Honcho API is still reachable")
    uid = str(os.getuid())
    for label in service_labels:
        result = subprocess.run(
            ["/bin/launchctl", "print", f"gui/{uid}/{label}"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode == 0:
            raise RuntimeError(f"Honcho service is still loaded: {label}")


def create_honcho_quiescence_receipt(
    database: str,
    base_url: str,
    service_labels: Sequence[str],
    server_root: Path,
) -> dict[str, Any]:
    assert_honcho_quiescent(base_url, service_labels)
    vector_store = inspect_honcho_vector_store(server_root)
    if vector_store.get("type") != "pgvector" or vector_store.get("migrated") is not False:
        raise ValueError("participant deletion supports only non-migrated pgvector")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return build_honcho_quiescence_receipt(
        database_oid_value=database_oid(database),
        schema_fingerprint_value="sha256:" + schema_fingerprint(database),
        service_labels=service_labels,
        observed_at=now.isoformat().replace("+00:00", "Z"),
        expires_at=(now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        nonce=secrets.token_hex(32),
        vector_store_config_digest=vector_store["config_digest"],
    )



def invalidate_honcho_workspace_cache(redis_url: str, workspace: str) -> dict[str, Any]:
    if re.fullmatch(r"redis://127\.0\.0\.1:[0-9]{2,5}/[0-9]+", redis_url or "") is None:
        raise ValueError("only local unauthenticated Redis URLs are supported")
    pattern = f"*{workspace}*"
    scan = run_checked(
        ["redis-cli", "-u", redis_url, "--scan", "--pattern", pattern],
        capture=True,
    )
    keys = sorted({line.strip() for line in scan.stdout.splitlines() if line.strip()})
    for start in range(0, len(keys), 100):
        run_checked(["redis-cli", "-u", redis_url, "UNLINK", *keys[start : start + 100]], capture=True)
    verify = run_checked(
        ["redis-cli", "-u", redis_url, "--scan", "--pattern", f"*{workspace}*"],
        capture=True,
    )
    remaining = [line for line in verify.stdout.splitlines() if line.strip()]
    if remaining:
        raise RuntimeError("workspace cache invalidation did not remove every workspace-namespaced key")
    return {"scope_digest": sha256_json(pattern), "redis_target_sha256": "sha256:" + hashlib.sha256(redis_url.encode("utf-8")).hexdigest(), "keys_unlinked": len(keys), "remaining": 0}


def _prototype_apply_participant_deletion(
    *,
    database: str,
    plan: Mapping[str, Any],
    backup_path: Path,
    quiescence_receipt: Mapping[str, Any],
    base_url: str,
    redis_url: str,
    server_root: Path,
    tombstone_path: Path,
) -> dict[str, Any]:
    if not validate_participant_deletion_plan(plan):
        raise ValueError("participant deletion plan is invalid")
    now = datetime.now(timezone.utc)
    if not validate_honcho_quiescence_receipt(quiescence_receipt, now=now):
        raise ValueError("Honcho quiescence receipt is invalid or expired")
    if database_oid(database) != plan["database_oid"]:
        raise ValueError("participant deletion database changed")
    current_schema = "sha256:" + schema_fingerprint(database)
    if current_schema != plan["schema_fingerprint"] or quiescence_receipt.get("schema_fingerprint") != current_schema:
        raise ValueError("participant deletion schema changed")
    if quiescence_receipt.get("database_oid") != plan["database_oid"]:
        raise ValueError("quiescence receipt database mismatch")
    labels = list(quiescence_receipt.get("service_labels") or [])
    assert_honcho_quiescent(base_url, labels)
    verify_honcho_launch_targets(server_root, base_url)
    if inspect_honcho_database_name(server_root) != database:
        raise ValueError("Honcho database target does not match the instance manifest")
    if inspect_honcho_cache_url(server_root) != redis_url:
        raise ValueError("Honcho cache target does not match the instance manifest")
    vector_store = inspect_honcho_vector_store(server_root)
    if vector_store.get("type") != "pgvector" or vector_store.get("migrated") is not False:
        raise ValueError("participant deletion supports only non-migrated pgvector")
    if vector_store.get("config_digest") != quiescence_receipt.get("vector_store_config_digest"):
        raise ValueError("vector store configuration changed after quiescence")
    candidates = participant_deletion_candidate_sets(
        database, plan["workspace"], plan["peer"], plan["allowed_service_peers"]
    )
    if sha256_json(candidates) != plan["candidate_sets_digest"]:
        raise ValueError("participant deletion candidate sets changed")
    for key, value in candidates.items():
        if sha256_json(value) != plan["id_set_digests"][key]:
            raise ValueError("participant deletion candidate digest changed")
    backup_metadata = verified_backup_metadata(backup_path, expected_database=database)
    tombstone = {
        "schema_version": "john-lomein.honcho-deletion-tombstone.v1",
        "state": "pending",
        "created_at": utc_now(),
        "plan_digest": plan["plan_digest"],
        "candidate_sets_digest": plan["candidate_sets_digest"],
        "backup_sha256": backup_metadata["sha256"],
        "quiescence_receipt_digest": quiescence_receipt["receipt_digest"],
        "workspace_sha256": sha256_json(plan["workspace"]),
        "peer_sha256": sha256_json(plan["peer"]),
        "replay_descriptor": {
            "workspace": plan["workspace"],
            "peer": plan["peer"],
            "allowed_service_peers": plan["allowed_service_peers"],
        },
        "restore_replay_required": True,
    }
    tombstone["tombstone_digest"] = sha256_json(tombstone)
    try:
        reserve_private_json(tombstone_path, tombstone)
    except FileExistsError as exc:
        raise ValueError("participant deletion tombstone path already exists") from exc
    command = ["psql", "-X", "--dbname", database, "-v", "ON_ERROR_STOP=1", "-v", f"workspace={plan['workspace']}", "-v", f"peer={plan['peer']}"]
    for key in ("peer_ids", "session_ids", "session_names", "message_ids", "embedding_ids", "document_ids", "collection_ids", "queue_ids", "work_unit_keys"):
        command.extend(["-v", f"{key}={canonical_json(candidates[key])}"])
    run_checked(command, input_text=participant_deletion_apply_sql())
    cache = invalidate_honcho_workspace_cache(redis_url, plan["workspace"])
    assert_honcho_quiescent(base_url, labels)
    post = participant_deletion_candidate_sets(
        database, plan["workspace"], plan["peer"], plan["allowed_service_peers"]
    )
    if any(post.values()):
        raise RuntimeError("participant deletion post-verification failed")
    tombstone["state"] = "applied"
    tombstone["applied_at"] = utc_now()
    tombstone["cache"] = cache
    tombstone["post_candidate_sets_digest"] = sha256_json(post)
    tombstone.pop("tombstone_digest", None)
    tombstone["tombstone_digest"] = sha256_json(tombstone)
    write_private_json(tombstone_path, tombstone)
    return {
        "applied": True,
        "plan_digest": plan["plan_digest"],
        "candidate_sets_digest": plan["candidate_sets_digest"],
        "post_candidate_sets_digest": sha256_json(post),
        "tombstone_digest": tombstone["tombstone_digest"],
        "restore_replay_required": True,
        "cache": cache,
    }


def apply_participant_deletion(**_kwargs: Any) -> dict[str, Any]:
    raise ValueError("participant deletion apply is disabled until crash-safe startup enforcement and replay qualification are complete")


def manifest_payload(path: Path) -> dict[str, Any]:
    manifest = yaml.safe_load(_safe_capability_source(Path(path).expanduser().resolve())) or {}
    if not isinstance(manifest, dict):
        raise ValueError("instance manifest is invalid")
    validate_manifest_contract(manifest)
    return manifest


def manifest_service_peers(path: Path) -> list[str]:
    return sorted(canonical_role_profiles(manifest_payload(path)).values())


def manifest_honcho_targets(path: Path) -> dict[str, Any]:
    manifest = manifest_payload(path)
    slug = str((manifest.get("instance") or {}).get("slug") or "")
    settings = honcho_settings(manifest, instance_slug=slug)
    runtime_home_value = str((manifest.get("runtime") or {}).get("hermes_home") or "")
    if not runtime_home_value or not Path(runtime_home_value).expanduser().is_absolute():
        raise ValueError("instance runtime home is invalid")
    runtime_home = Path(runtime_home_value).expanduser().resolve()
    return {**settings, "tombstone_dir": runtime_home / "private" / "honcho-deletion-tombstones"}


def canonical_tombstone_path(targets: Mapping[str, Any], plan: Mapping[str, Any]) -> Path:
    digest = str(plan.get("plan_digest") or "")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise ValueError("participant deletion plan digest is invalid")
    return Path(targets["tombstone_dir"]) / f"{digest.removeprefix('sha256:')}.json"

def build_workspace_migration_plan(
    *,
    source_workspace: str,
    target_workspace: str,
    source_counts: Mapping[str, Any],
    target_counts: Mapping[str, Any],
    profiles: list[str],
    schema_fingerprint: str,
    generated_at: str,
) -> dict[str, Any]:
    if not SAFE_NAME_RE.fullmatch(source_workspace or ""):
        raise ValueError("source workspace must be a safe Honcho name")
    if not SAFE_NAME_RE.fullmatch(target_workspace or ""):
        raise ValueError("target workspace must be a safe Honcho name")
    if source_workspace == target_workspace:
        raise ValueError("source and target workspaces must differ")
    source = {str(key): int(value) for key, value in source_counts.items()}
    target = {str(key): int(value) for key, value in target_counts.items()}
    if source.get("workspaces") != 1:
        raise ValueError("source workspace must exist exactly once")
    if target.get("workspaces", 0) not in {0, 1}:
        raise ValueError("target workspace count is invalid")
    if any(value != 0 for key, value in target.items() if key != "workspaces"):
        raise ValueError("target workspace must be absent or empty")
    normalized_profiles = sorted({str(item).strip() for item in profiles if str(item).strip()})
    if not normalized_profiles or any(SAFE_NAME_RE.fullmatch(item) is None for item in normalized_profiles):
        raise ValueError("profiles must be non-empty safe names")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", schema_fingerprint or "") is None:
        raise ValueError("schema fingerprint is invalid")
    payload = {
        "schema_version": "john-lomein.honcho-workspace-migration-plan.v1",
        "generated_at": generated_at,
        "source_workspace": source_workspace,
        "target_workspace": target_workspace,
        "continuity": "fresh_empty_target",
        "applied": False,
        "schema_fingerprint": schema_fingerprint,
        "source_snapshot": source,
        "target_snapshot": target,
        "profiles": normalized_profiles,
        "preconditions": [
            "fresh_verified_backup",
            "honcho_health_green",
            "ingestion_paused",
            "target_absent_or_empty",
            "owner_confirms_memory_continuity_break",
        ],
        "cutover": {
            "change_instance_manifest_only": True,
            "deploy_after_owner_confirmation": True,
            "copy_source_memory": False,
        },
        "rollback": {"workspace": source_workspace, "source_untouched": True},
        "authority": {"can_migrate": False, "can_activate_public_traffic": False},
    }
    payload["plan_digest"] = sha256_json(payload)
    return payload


def validate_workspace_migration_plan(plan: Mapping[str, Any]) -> bool:
    expected = {
        "schema_version", "generated_at", "source_workspace", "target_workspace",
        "continuity", "applied", "schema_fingerprint", "source_snapshot",
        "target_snapshot", "profiles", "preconditions", "cutover", "rollback",
        "authority", "plan_digest",
    }
    if set(plan) != expected:
        return False
    if plan.get("schema_version") != "john-lomein.honcho-workspace-migration-plan.v1":
        return False
    if plan.get("continuity") != "fresh_empty_target" or plan.get("applied") is not False:
        return False
    if plan.get("source_workspace") == plan.get("target_workspace"):
        return False
    target = plan.get("target_snapshot")
    if not isinstance(target, Mapping):
        return False
    if any(int(value) != 0 for key, value in target.items() if key != "workspaces"):
        return False
    if plan.get("authority") != {"can_migrate": False, "can_activate_public_traffic": False}:
        return False
    unsigned = dict(plan)
    digest = unsigned.pop("plan_digest", "")
    return digest == sha256_json(unsigned)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    health = sub.add_parser("health")
    health.add_argument("--database", required=True)
    health.add_argument("--base-url", default="http://127.0.0.1:8000")
    health.add_argument("--workspace", required=True)
    health.add_argument("--queue-pending-max", type=int, default=25)
    health.add_argument("--queue-oldest-seconds-max", type=int, default=900)
    health.add_argument("--embedding-pending-max", type=int, default=10)
    health.add_argument("--embedding-oldest-seconds-max", type=int, default=900)
    health.add_argument("--embedding-recent-failed-max", type=int, default=0)
    health.add_argument("--database-size-bytes-max", type=int, default=1_073_741_824)
    health.add_argument("--model-error-rows-max", type=int, default=0)
    health.add_argument("--embedding-error-rows-max", type=int, default=0)
    health.add_argument("--derivation-latency-p95-seconds-max", type=int, default=900)
    health.add_argument("--embedding-latency-p95-seconds-max", type=int, default=900)
    health.add_argument("--write-pause-file")

    chunking = sub.add_parser("chunking-preflight")
    chunking.add_argument("--database", required=True)
    chunking.add_argument("--workspace", required=True)
    chunking.add_argument("--server-root", required=True)
    chunking.add_argument("--env-file", required=True)
    chunking.add_argument("--expected-cap", type=int, default=1000)

    recovery = sub.add_parser("chunking-recovery-plan")
    recovery.add_argument("--database", required=True)
    recovery.add_argument("--workspace", required=True)
    recovery.add_argument("--server-root", required=True)
    recovery.add_argument("--env-file", required=True)
    recovery.add_argument("--expected-cap", type=int, default=1000)
    recovery.add_argument("--output", required=True)

    migration = sub.add_parser("workspace-migration-plan")
    migration.add_argument("--database", required=True)
    migration.add_argument("--source-workspace", required=True)
    migration.add_argument("--target-workspace", required=True)
    migration.add_argument("--profile", action="append", required=True)
    migration.add_argument("--output", required=True)

    plan = sub.add_parser("retention-plan")
    plan.add_argument("--database", required=True)
    plan.add_argument("--workspace", required=True)
    plan.add_argument("--days", type=int, default=30)
    plan.add_argument("--output")

    apply = sub.add_parser("retention-apply")
    apply.add_argument("--database", required=True)
    apply.add_argument("--plan", required=True)
    apply.add_argument("--confirm-digest", required=True)
    apply.add_argument("--backup", required=True)

    backup = sub.add_parser("backup")
    backup.add_argument("--database", required=True)
    backup.add_argument("--output", required=True)

    restore = sub.add_parser("restore-verify")
    restore.add_argument("--backup", required=True)
    restore.add_argument("--for-service-restore", action="store_true")
    restore.add_argument("--manifest")

    delete = sub.add_parser("deletion-request-plan")
    delete.add_argument("--database", required=True)
    delete.add_argument("--workspace", required=True)
    delete.add_argument("--peer", required=True)
    delete.add_argument("--manifest", required=True)
    delete.add_argument("--allowed-service-peer", action="append", default=[])
    delete.add_argument("--output", required=True)
    delete_apply = sub.add_parser("deletion-request-apply")
    delete_apply.add_argument("--database", required=True)
    delete_apply.add_argument("--manifest", required=True)
    delete_apply.add_argument("--plan", required=True)
    delete_apply.add_argument("--confirm-digest", required=True)
    delete_apply.add_argument("--backup", required=True)
    delete_apply.add_argument("--quiescence-receipt", required=True)
    quiescence = sub.add_parser("deletion-quiescence-receipt")
    quiescence.add_argument("--database", required=True)
    quiescence.add_argument("--manifest", required=True)
    quiescence.add_argument("--output", required=True)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "health":
        metrics = collect_metrics(args.database, args.base_url, args.workspace)
        thresholds = {
            "queue_pending_max": args.queue_pending_max,
            "queue_oldest_seconds_max": args.queue_oldest_seconds_max,
            "embedding_pending_max": args.embedding_pending_max,
            "embedding_oldest_seconds_max": args.embedding_oldest_seconds_max,
            "embedding_recent_failed_max": args.embedding_recent_failed_max,
            "database_size_bytes_max": args.database_size_bytes_max,
            "model_error_rows_max": args.model_error_rows_max,
            "embedding_error_rows_max": args.embedding_error_rows_max,
            "derivation_latency_p95_seconds_max": args.derivation_latency_p95_seconds_max,
            "embedding_latency_p95_seconds_max": args.embedding_latency_p95_seconds_max,
        }
        health = evaluate_health(metrics, thresholds)
        payload = {"metrics": metrics, "thresholds": thresholds, **health}
        if args.write_pause_file and not health["healthy"]:
            payload["pause_receipt"] = write_pause_receipt(Path(args.write_pause_file), health)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if health["healthy"] else 2

    if args.command == "chunking-preflight":
        capability = inspect_chunking_capability(
            Path(args.server_root), Path(args.env_file), expected_cap=args.expected_cap
        )
        metrics = chunking_metrics(args.database, args.workspace, args.expected_cap)
        verdict = evaluate_chunking_preflight(capability, metrics)
        print(json.dumps({"capability": capability, "metrics": metrics, **verdict}, indent=2, sort_keys=True))
        return 0 if verdict["ready"] else 2

    if args.command == "chunking-recovery-plan":
        capability = inspect_chunking_capability(
            Path(args.server_root), Path(args.env_file), expected_cap=args.expected_cap
        )
        if capability["capability_verified"] is not True:
            raise ValueError("chunking capability must verify before recovery planning")
        candidates = embedding_recovery_candidates(args.database, args.workspace, args.expected_cap)
        plan = make_embedding_recovery_plan(
            workspace=args.workspace, expected_cap=args.expected_cap, candidates=candidates,
            capability_digest=capability["capability_digest"],
            schema_fingerprint_value="sha256:" + schema_fingerprint(args.database),
            generated_at=utc_now(),
        )
        write_private_json(Path(args.output), plan)
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0

    if args.command == "workspace-migration-plan":
        plan = build_workspace_migration_plan(
            source_workspace=args.source_workspace,
            target_workspace=args.target_workspace,
            source_counts=workspace_counts(args.database, args.source_workspace),
            target_counts=workspace_counts(args.database, args.target_workspace),
            profiles=args.profile,
            schema_fingerprint="sha256:" + schema_fingerprint(args.database),
            generated_at=utc_now(),
        )
        write_private_json(Path(args.output), plan)
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0

    if args.command == "retention-plan":
        if args.days != 30:
            raise ValueError("pilot retention is fixed at 30 days")
        cutoff = (datetime.now(timezone.utc) - timedelta(days=args.days)).replace(microsecond=0)
        cutoff_text = cutoff.isoformat().replace("+00:00", "Z")
        metrics = collect_metrics(args.database, "http://127.0.0.1:8000", args.workspace)
        counts = retention_counts(args.database, args.workspace, cutoff_text)
        plan = make_retention_plan(
            {
                "database_oid": int(metrics["database_oid"]),
                "workspace": args.workspace,
                "cutoff": cutoff_text,
                "retention_days": args.days,
                **counts,
                "schema_fingerprint": schema_fingerprint(args.database),
            }
        )
        if args.output:
            write_private_json(Path(args.output), plan)
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0

    if args.command == "retention-apply":
        raise ValueError("retention apply is disabled until exact lineage ID sets and replay tombstones are implemented")
    if args.command == "backup":
        print(json.dumps(create_backup(args.database, Path(args.output)), indent=2, sort_keys=True))
        return 0

    if args.command == "restore-verify":
        result = restore_verify(Path(args.backup))
        result["mechanical_restore_verified"] = True
        if args.for_service_restore:
            if not args.manifest:
                raise ValueError("service restore verification requires --manifest")
            targets = manifest_honcho_targets(Path(args.manifest))
            applied = applied_deletion_tombstones(Path(targets["tombstone_dir"]))
            result["blocking_tombstone_count"] = len(applied)
            result["tombstone_set_digest"] = sha256_json(applied)
            result["serve_safe"] = not applied
            result["reason"] = "deletion_tombstone_replay_required" if applied else "no_blocking_deletion_tombstones"
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["serve_safe"] else 2
        result["serve_safe"] = False
        result["reason"] = "mechanical_restore_only_tombstone_gate_not_evaluated"
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if args.command == "deletion-quiescence-receipt":
        targets = manifest_honcho_targets(Path(args.manifest))
        if args.database != targets["database"]:
            raise ValueError("quiescence database does not match the instance manifest")
        receipt = create_honcho_quiescence_receipt(
            args.database, targets["base_url"], HONCHO_SERVICE_LABELS, Path(targets["server_root"])
        )
        write_private_json(Path(args.output), receipt)
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0

    if args.command == "deletion-request-plan":
        targets = manifest_honcho_targets(Path(args.manifest))
        if args.database != targets["database"] or args.workspace != targets["workspace"]:
            raise ValueError("participant deletion target does not match the instance manifest")
        service_peers = manifest_service_peers(Path(args.manifest))
        if args.allowed_service_peer and sorted(set(args.allowed_service_peer)) != service_peers:
            raise ValueError("allowed service peers do not match the instance manifest")
        candidate_sets = participant_deletion_candidate_sets(
            args.database,
            args.workspace,
            args.peer,
            service_peers,
        )
        payload = make_participant_deletion_plan(
            database_oid=database_oid(args.database),
            workspace=args.workspace,
            peer=args.peer,
            candidate_sets=candidate_sets,
            allowed_service_peers=service_peers,
            schema_fingerprint="sha256:" + schema_fingerprint(args.database),
            generated_at=utc_now(),
        )
        write_private_json(Path(args.output), payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    if args.command == "deletion-request-apply":
        raise ValueError("participant deletion apply is disabled until crash-safe API/deriver startup tombstone enforcement and replay qualification are complete")
        targets = manifest_honcho_targets(Path(args.manifest))
        plan = json.loads(_safe_capability_source(Path(args.plan).expanduser().resolve(), private=True))
        if not validate_participant_deletion_plan(plan) or args.confirm_digest != plan.get("plan_digest"):
            raise ValueError("participant deletion plan or confirmation digest is invalid")
        if plan.get("allowed_service_peers") != manifest_service_peers(Path(args.manifest)):
            raise ValueError("participant deletion service peer policy changed")
        if args.database != targets["database"] or plan.get("workspace") != targets["workspace"]:
            raise ValueError("participant deletion target does not match the instance manifest")
        if database_oid(args.database) != plan["database_oid"] or "sha256:" + schema_fingerprint(args.database) != plan["schema_fingerprint"]:
            raise ValueError("participant deletion database or schema changed")
        quiescence_text = _safe_capability_source(
            Path(args.quiescence_receipt).expanduser().resolve(), private=True
        )
        quiescence = json.loads(quiescence_text)
        result = apply_participant_deletion(
            database=args.database,
            plan=plan,
            backup_path=Path(args.backup),
            quiescence_receipt=quiescence,
            base_url=targets["base_url"],
            redis_url=targets["redis_url"],
            server_root=Path(targets["server_root"]),
            tombstone_path=canonical_tombstone_path(targets, plan),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    raise AssertionError("unreachable")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"honcho-pilot error: {exc}", file=sys.stderr)
        raise SystemExit(1)
