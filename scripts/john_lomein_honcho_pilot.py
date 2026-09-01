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
RETENTION_SCHEMA = "john-lomein.honcho-retention-plan.v2"
BACKUP_SCHEMA = "john-lomein.honcho-backup.v1"
DELETION_SCHEMA = "john-lomein.honcho-participant-deletion-plan.v2"
RECOVERY_SCHEMA = "john-lomein.honcho-embedding-recovery-plan.v1"
DELETION_TOMBSTONE_SCHEMA = "john-lomein.honcho-deletion-tombstone.v2"
RETENTION_TOMBSTONE_SCHEMA = "john-lomein.honcho-retention-tombstone.v2"
RETENTION_BACKUP_COVERAGE_SCHEMA = (
    "john-lomein.honcho-retention-backup-coverage.v1"
)
PUBLIC_BACKUP_MAX_COUNT = 32
PUBLIC_BACKUP_MAX_BYTES = 64 * 1024 * 1024 * 1024
PUBLIC_BACKUP_REUSE_MAX_AGE_SECONDS = 24 * 60 * 60
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SCRIPT_DIR = Path(__file__).resolve().parent
PARTICIPANT_CANDIDATE_SQL = SCRIPT_DIR / "honcho-participant-candidates.sql"
RETENTION_CANDIDATE_SQL = SCRIPT_DIR / "honcho-retention-candidates.sql"
DELETION_CANDIDATE_KEYS = frozenset({
    "peer_ids", "session_ids", "session_names", "session_peer_link_keys",
    "message_ids", "message_public_ids", "embedding_ids", "document_ids",
    "collection_ids", "queue_ids", "work_unit_keys", "active_work_unit_keys",
    "active_queue_session_ids",
    "conflicting_peers", "unknown_touching_queue_ids", "malformed_lineage_ids",
})
RETENTION_CANDIDATE_KEYS = frozenset({
    "message_ids", "message_public_ids", "embedding_ids", "document_ids",
    "queue_ids", "work_unit_keys", "active_work_unit_keys",
    "active_queue_session_ids",
    "mixed_work_unit_keys", "unknown_touching_queue_ids",
    "malformed_lineage_ids",
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
        (
            "workspace_storage_bytes",
            "workspace_storage_bytes_max",
            "workspace_storage_exceeded",
        ),
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


def make_retention_plan(
    values: Mapping[str, Any],
    *,
    candidate_sets: Mapping[str, Sequence[Any]],
) -> dict[str, Any]:
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
    if set(candidate_sets) != set(RETENTION_CANDIDATE_KEYS):
        raise ValueError("retention candidate sets are incomplete")
    normalized_sets = {
        key: sorted(
            set(candidate_sets[key]),
            key=lambda item: (str(type(item)), str(item)),
        )
        for key in sorted(RETENTION_CANDIDATE_KEYS)
    }
    if normalized_sets["mixed_work_unit_keys"]:
        raise ValueError("retention is blocked by mixed-age work units")
    if normalized_sets["unknown_touching_queue_ids"]:
        raise ValueError("retention is blocked by unknown touching queue rows")
    if normalized_sets["malformed_lineage_ids"]:
        raise ValueError("retention is blocked by malformed lineage")
    count_bindings = {
        "message_count": "message_ids",
        "queue_count": "queue_ids",
        "embedding_count": "embedding_ids",
        "document_count": "document_ids",
    }
    for count_key, candidate_key in count_bindings.items():
        if strict_nonnegative_int(values[count_key], count_key) != len(
            normalized_sets[candidate_key]
        ):
            raise ValueError(f"{count_key} does not match exact retention candidates")
    retention_days = strict_nonnegative_int(
        values["retention_days"],
        "retention_days",
    )
    if retention_days != 30:
        raise ValueError("retention_days must remain exactly 30")
    body = {
        "schema_version": RETENTION_SCHEMA,
        "database_oid": strict_nonnegative_int(values["database_oid"], "database_oid"),
        "workspace": workspace,
        "cutoff": parsed_cutoff.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "retention_days": retention_days,
        "message_count": len(normalized_sets["message_ids"]),
        "queue_count": len(normalized_sets["queue_ids"]),
        "embedding_count": len(normalized_sets["embedding_ids"]),
        "document_count": len(normalized_sets["document_ids"]),
        "schema_fingerprint": schema_fingerprint,
        "apply_supported": True,
        "candidate_sets_digest": sha256_json(normalized_sets),
        "id_set_digests": {
            key: sha256_json(value) for key, value in normalized_sets.items()
        },
        "authority": {
            "can_delete_raw_public_messages": True,
            "can_delete_workspace": False,
            "requires_verified_backup": True,
            "requires_quiescence_receipt": True,
        },
    }
    body["plan_digest"] = sha256_json(body)
    return body


def validate_retention_plan(plan: Mapping[str, Any]) -> bool:
    expected = {
        "schema_version", *PLAN_FIELDS, "apply_supported",
        "candidate_sets_digest", "id_set_digests", "authority", "plan_digest",
    }
    if set(plan) != expected or plan.get("schema_version") != RETENTION_SCHEMA:
        return False
    if plan.get("apply_supported") is not True:
        return False
    if plan.get("retention_days") != 30:
        return False
    if SAFE_NAME_RE.fullmatch(str(plan.get("workspace") or "")) is None:
        return False
    if re.fullmatch(r"[0-9a-f]{64}", str(plan.get("schema_fingerprint") or "")) is None:
        return False
    if any(
        type(plan.get(field)) is not int or int(plan[field]) < 0
        for field in (
            "database_oid", "message_count", "queue_count",
            "embedding_count", "document_count",
        )
    ):
        return False
    if set(plan.get("id_set_digests") or {}) != set(RETENTION_CANDIDATE_KEYS):
        return False
    if re.fullmatch(r"[0-9a-f]{64}", str(plan.get("candidate_sets_digest") or "")) is None:
        return False
    if any(
        re.fullmatch(r"[0-9a-f]{64}", str(value or "")) is None
        for value in (plan.get("id_set_digests") or {}).values()
    ):
        return False
    try:
        cutoff = datetime.fromisoformat(
            str(plan.get("cutoff") or "").replace("Z", "+00:00")
        )
    except ValueError:
        return False
    if cutoff.tzinfo is None:
        return False
    if plan.get("authority") != {
        "can_delete_raw_public_messages": True,
        "can_delete_workspace": False,
        "requires_verified_backup": True,
        "requires_quiescence_receipt": True,
    }:
        return False
    unsigned = dict(plan)
    digest = unsigned.pop("plan_digest", "")
    return digest == sha256_json(unsigned)


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
        "apply_supported": True,
        "allowed_service_peers": service_peers,
        "counts": counts,
        "candidate_sets_digest": sha256_json(normalized_sets),
        "id_set_digests": id_set_digests,
        "schema_fingerprint": schema_fingerprint,
        "scope": ["participant_peer", "participant_sessions", "all_session_messages", "message_embeddings", "queue", "active_queue_sessions", "session_links", "collections_observing_or_observed", "recursive_derived_documents"],
        "authority": {
            "can_delete": True,
            "can_delete_workspace": False,
            "requires_verified_backup": True,
            "requires_quiescence_receipt": True,
        },
    }
    payload["plan_digest"] = sha256_json(payload)
    return payload


def validate_participant_deletion_plan(plan: Mapping[str, Any]) -> bool:
    expected = {"schema_version", "generated_at", "database_oid", "workspace", "peer", "vector_store", "apply_supported", "allowed_service_peers", "counts", "candidate_sets_digest", "id_set_digests", "schema_fingerprint", "scope", "authority", "plan_digest"}
    if set(plan) != expected or plan.get("schema_version") != DELETION_SCHEMA:
        return False
    if plan.get("vector_store") != "pgvector":
        return False
    if plan.get("apply_supported") is not True:
        return False
    if plan.get("authority") != {
        "can_delete": True,
        "can_delete_workspace": False,
        "requires_verified_backup": True,
        "requires_quiescence_receipt": True,
    }:
        return False
    if set(plan.get("id_set_digests") or {}) != set(DELETION_CANDIDATE_KEYS):
        return False
    unsigned = dict(plan)
    digest = unsigned.pop("plan_digest", "")
    return digest == sha256_json(unsigned)


def retention_apply_sql() -> str:
    return _safe_capability_source(SCRIPT_DIR / "honcho-retention-delete.sql")


def participant_deletion_apply_sql() -> str:
    path = SCRIPT_DIR / "honcho-participant-delete.sql"
    return _safe_capability_source(path)


def applied_deletion_tombstones(directory: Path) -> list[dict[str, Any]]:
    records = _load_tombstone_records(directory)
    return [
        {
            "tombstone_digest": data["tombstone_digest"],
            "plan_digest": data.get("plan_digest"),
            "state": data["state"],
        }
        for data in records
        if data.get("operation") == "participant_deletion"
        and data["state"] in {"pending", "applied"}
    ]


def _load_tombstone_records(directory: Path) -> list[dict[str, Any]]:
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
        operation = str(data.get("operation") or "")
        expected_schema = (
            DELETION_TOMBSTONE_SCHEMA
            if operation == "participant_deletion"
            else RETENTION_TOMBSTONE_SCHEMA
            if operation == "retention"
            else ""
        )
        if digest != sha256_json(unsigned) or data.get("schema_version") != expected_schema:
            raise ValueError("deletion tombstone is invalid")
        if data.get("state") not in {"pending", "applied"}:
            raise ValueError("deletion tombstone state is invalid")
        workspace = str(data.get("workspace") or "")
        if SAFE_NAME_RE.fullmatch(workspace) is None:
            raise ValueError("deletion tombstone workspace is invalid")
        identity = data.get("database_identity")
        if (
            not isinstance(identity, Mapping)
            or not str(identity.get("database") or "")
            or type(identity.get("database_oid")) is not int
            or re.fullmatch(
                r"[0-9]+", str(identity.get("system_identifier") or "")
            )
            is None
            or re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                str(identity.get("schema_fingerprint") or data.get("schema_fingerprint") or ""),
            )
            is None
        ):
            raise ValueError("deletion tombstone database identity is invalid")
        backup = data.get("backup")
        if (
            not isinstance(backup, Mapping)
            or backup.get("verified") is not True
            or re.fullmatch(
                r"sha256:[0-9a-f]{64}", str(backup.get("sha256") or "")
            )
            is None
        ):
            raise ValueError("deletion tombstone backup evidence is invalid")
        exact_ids = data.get("exact_candidate_ids")
        expected_keys = (
            DELETION_CANDIDATE_KEYS
            if operation == "participant_deletion"
            else RETENTION_CANDIDATE_KEYS
        )
        if (
            not isinstance(exact_ids, Mapping)
            or set(exact_ids) != set(expected_keys)
            or any(not isinstance(value, list) for value in exact_ids.values())
        ):
            raise ValueError("deletion tombstone exact ID sets are invalid")
        if sha256_json(exact_ids) != data.get("candidate_sets_digest"):
            raise ValueError("deletion tombstone exact candidate digest is invalid")
        id_set_digests = data.get("id_set_digests")
        if (
            not isinstance(id_set_digests, Mapping)
            or set(id_set_digests) != set(expected_keys)
            or any(
                id_set_digests[key] != sha256_json(exact_ids[key])
                for key in expected_keys
            )
        ):
            raise ValueError("deletion tombstone exact ID digests are invalid")
        if re.fullmatch(
            r"(?:sha256:)?[0-9a-f]{64}", str(data.get("plan_digest") or "")
        ) is None:
            raise ValueError("deletion tombstone plan digest is invalid")
        if re.fullmatch(
            r"sha256:[0-9a-f]{64}", str(data.get("manifest_digest") or "")
        ) is None:
            raise ValueError("deletion tombstone manifest digest is invalid")
        server_identity = data.get("server_identity")
        if (
            not isinstance(server_identity, Mapping)
            or server_identity.get("clean") is not True
            or server_identity.get("remote")
            != "https://github.com/plastic-labs/honcho.git"
            or re.fullmatch(
                r"[0-9a-f]{40}", str(server_identity.get("head") or "")
            )
            is None
        ):
            raise ValueError("deletion tombstone server identity is invalid")
        try:
            datetime.fromisoformat(
                str(data["request_cutoff"]).replace("Z", "+00:00")
            )
            backup_created = datetime.fromisoformat(
                str(backup["created_at"]).replace("Z", "+00:00")
            )
            backup_expires = datetime.fromisoformat(
                str(backup["expires_at"]).replace("Z", "+00:00")
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("deletion tombstone time evidence is invalid") from exc
        if (
            backup_created.tzinfo is None
            or backup_expires.tzinfo is None
            or backup_expires <= backup_created
            or backup_expires - backup_created > timedelta(days=30)
        ):
            raise ValueError("deletion tombstone backup expiry is invalid")
        if any(
            exact_ids[key]
            for key in (
                "conflicting_peers",
                "unknown_touching_queue_ids",
                "malformed_lineage_ids",
                *(('mixed_work_unit_keys',) if operation == 'retention' else ()),
            )
        ):
            raise ValueError("deletion tombstone contains blocked candidates")
        if operation == "participant_deletion" and SAFE_NAME_RE.fullmatch(
            str(data.get("participant_peer") or "")
        ) is None:
            raise ValueError("deletion tombstone participant is invalid")
        results.append(dict(data))
    return results


def exact_tombstone_residue(
    database: str,
    workspace: str,
    exact_ids: Mapping[str, Sequence[Any]],
) -> dict[str, list[Any]]:
    if SAFE_NAME_RE.fullmatch(workspace or "") is None:
        raise ValueError("tombstone residue workspace is invalid")
    variables = {
        key: canonical_json(list(exact_ids.get(key) or []))
        for key in (
            "peer_ids",
            "session_ids",
            "session_names",
            "session_peer_link_keys",
            "message_ids",
            "message_public_ids",
            "embedding_ids",
            "document_ids",
            "collection_ids",
            "queue_ids",
            "active_queue_session_ids",
        )
    }
    variables["workspace"] = workspace
    sql = r"""
WITH
peer_ids(id) AS (SELECT value FROM jsonb_array_elements_text(:'peer_ids'::jsonb)),
session_ids(id) AS (SELECT value FROM jsonb_array_elements_text(:'session_ids'::jsonb)),
session_names(name) AS (SELECT value FROM jsonb_array_elements_text(:'session_names'::jsonb)),
session_links(link_key) AS (SELECT value FROM jsonb_array_elements_text(:'session_peer_link_keys'::jsonb)),
message_ids(id) AS (SELECT value::bigint FROM jsonb_array_elements_text(:'message_ids'::jsonb)),
message_public_ids(id) AS (SELECT value FROM jsonb_array_elements_text(:'message_public_ids'::jsonb)),
embedding_ids(id) AS (SELECT value::bigint FROM jsonb_array_elements_text(:'embedding_ids'::jsonb)),
document_ids(id) AS (SELECT value FROM jsonb_array_elements_text(:'document_ids'::jsonb)),
collection_ids(id) AS (SELECT value FROM jsonb_array_elements_text(:'collection_ids'::jsonb)),
queue_ids(id) AS (SELECT value::bigint FROM jsonb_array_elements_text(:'queue_ids'::jsonb)),
active_ids(id) AS (SELECT value FROM jsonb_array_elements_text(:'active_queue_session_ids'::jsonb))
SELECT json_build_object(
  'peer_ids', COALESCE((SELECT json_agg(p.id ORDER BY p.id) FROM peers p JOIN peer_ids j ON j.id=p.id WHERE p.workspace_name=:'workspace'
    AND NOT EXISTS (SELECT 1 FROM messages m WHERE m.workspace_name=p.workspace_name AND m.peer_name=p.name AND m.id NOT IN (SELECT id FROM message_ids))
    AND NOT EXISTS (SELECT 1 FROM session_peers sp WHERE sp.workspace_name=p.workspace_name AND sp.peer_name=p.name AND sp.session_name || '|' || sp.peer_name NOT IN (SELECT link_key FROM session_links))
    AND NOT EXISTS (SELECT 1 FROM collections c WHERE c.workspace_name=p.workspace_name AND (c.observer=p.name OR c.observed=p.name) AND c.id NOT IN (SELECT id FROM collection_ids))
    AND NOT EXISTS (SELECT 1 FROM documents d WHERE d.workspace_name=p.workspace_name AND (d.observer=p.name OR d.observed=p.name) AND d.id NOT IN (SELECT id FROM document_ids))),'[]'::json),
  'session_ids', COALESCE((SELECT json_agg(s.id ORDER BY s.id) FROM sessions s JOIN session_ids j ON j.id=s.id WHERE s.workspace_name=:'workspace'),'[]'::json),
  'session_names', COALESCE((SELECT json_agg(s.name ORDER BY s.name) FROM sessions s JOIN session_names j ON j.name=s.name WHERE s.workspace_name=:'workspace'),'[]'::json),
  'session_peer_link_keys', COALESCE((SELECT json_agg(sp.session_name || '|' || sp.peer_name ORDER BY sp.session_name,sp.peer_name) FROM session_peers sp JOIN session_links j ON j.link_key=sp.session_name || '|' || sp.peer_name WHERE sp.workspace_name=:'workspace'),'[]'::json),
  'message_ids', COALESCE((SELECT json_agg(m.id ORDER BY m.id) FROM messages m JOIN message_ids j ON j.id=m.id WHERE m.workspace_name=:'workspace'),'[]'::json),
  'message_public_ids', COALESCE((SELECT json_agg(m.public_id ORDER BY m.public_id) FROM messages m JOIN message_public_ids j ON j.id=m.public_id WHERE m.workspace_name=:'workspace'),'[]'::json),
  'embedding_ids', COALESCE((SELECT json_agg(e.id ORDER BY e.id) FROM message_embeddings e JOIN embedding_ids j ON j.id=e.id WHERE e.workspace_name=:'workspace'),'[]'::json),
  'document_ids', COALESCE((SELECT json_agg(d.id ORDER BY d.id) FROM documents d JOIN document_ids j ON j.id=d.id WHERE d.workspace_name=:'workspace'),'[]'::json),
  'collection_ids', COALESCE((SELECT json_agg(c.id ORDER BY c.id) FROM collections c JOIN collection_ids j ON j.id=c.id WHERE c.workspace_name=:'workspace'),'[]'::json),
  'queue_ids', COALESCE((SELECT json_agg(q.id ORDER BY q.id) FROM queue q JOIN queue_ids j ON j.id=q.id WHERE q.workspace_name=:'workspace'),'[]'::json),
  'active_queue_session_ids', COALESCE((SELECT json_agg(a.id ORDER BY a.id) FROM active_queue_sessions a JOIN active_ids j ON j.id=a.id),'[]'::json)
)::text;
"""
    payload = psql_json(database, sql, variables=variables)
    if not isinstance(payload, Mapping):
        raise ValueError("tombstone exact residue query failed")
    return {
        str(key): list(value)
        for key, value in payload.items()
        if isinstance(value, list) and value
    }


def honcho_startup_blockers(
    directory: Path,
    *,
    database: str,
    workspace: str,
) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    for data in _load_tombstone_records(directory):
        state = str(data["state"])
        if data["workspace"] != workspace:
            raise ValueError("deletion tombstone workspace does not match public service")
        if data["database_identity"].get("database") != database:
            raise ValueError("deletion tombstone database does not match public service")
        if state == "pending":
            reason = "pending_tombstone"
        elif exact_tombstone_residue(
            database,
            workspace,
            data["exact_candidate_ids"],
        ):
            reason = "deletion_replay_required"
        else:
            continue
        blockers.append(
            {
                "operation": str(data.get("operation") or "participant_deletion"),
                "state": state,
                "reason": reason,
                "plan_digest": data.get("plan_digest"),
                "tombstone_digest": data["tombstone_digest"],
            }
        )
    return blockers


def tombstone_state_summary(directory: Path) -> dict[str, Any]:
    records = _load_tombstone_records(directory)
    states = {
        state: sum(1 for item in records if item["state"] == state)
        for state in ("pending", "applied")
    }
    public_records = [
        {
            "operation": str(item.get("operation") or "participant_deletion"),
            "state": item["state"],
            "tombstone_digest": item["tombstone_digest"],
        }
        for item in records
    ]
    return {
        "total": len(records),
        "states": states,
        "blocking_without_database_check": states["pending"],
        "tombstone_set_digest": sha256_json(public_records),
    }


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


def retention_candidate_sets(
    database: str,
    workspace: str,
    cutoff: str,
) -> dict[str, list[Any]]:
    if SAFE_NAME_RE.fullmatch(workspace or "") is None:
        raise ValueError("workspace must be a safe Honcho name")
    try:
        parsed = datetime.fromisoformat(str(cutoff).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("retention cutoff must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("retention cutoff must include a timezone")
    raw = psql_json(
        database,
        _safe_capability_source(RETENTION_CANDIDATE_SQL),
        variables={"workspace": workspace, "cutoff": cutoff},
    )
    if not isinstance(raw, Mapping) or set(raw) != set(RETENTION_CANDIDATE_KEYS):
        raise ValueError("retention candidate payload is invalid")
    normalized: dict[str, list[Any]] = {}
    for key in sorted(RETENTION_CANDIDATE_KEYS):
        value = raw[key]
        if not isinstance(value, list):
            raise ValueError("retention candidate set is invalid")
        normalized[key] = sorted(
            set(value),
            key=lambda item: (str(type(item)), str(item)),
        )
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


def verify_honcho_runtime_targets(
    server_root: Path,
    base_url: str,
    *,
    database: str,
    redis_url: str,
) -> dict[str, Any]:
    root = Path(server_root).expanduser().resolve()
    port = urlparse(base_url).port
    if port in {None, 8000}:
        raise ValueError("public Honcho API port is not dedicated")
    if inspect_honcho_database_name(root) != database:
        raise ValueError("public Honcho database target changed")
    if inspect_honcho_cache_url(root) != redis_url:
        raise ValueError("public Honcho cache target changed")
    remote = run_checked(
        ["git", "-C", str(root), "remote", "get-url", "origin"], capture=True
    ).stdout.strip()
    head = run_checked(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture=True
    ).stdout.strip()
    dirty = run_checked(
        ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
        capture=True,
    ).stdout.strip()
    if remote != "https://github.com/plastic-labs/honcho.git":
        raise ValueError("public Honcho checkout remote changed")
    if head != "9379c634ed240d0225b63443606e5304a4e261c5":
        raise ValueError("public Honcho checkout does not match the supported pin")
    if dirty:
        raise ValueError("public Honcho checkout is dirty")
    return {
        "remote": remote,
        "head": head,
        "clean": True,
        "api_port": port,
        "runtime_identity_digest": sha256_json(
            {"remote": remote, "head": head, "database": database, "redis_url": redis_url}
        ),
    }


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
'workspace_storage_bytes',
  COALESCE((SELECT sum(pg_column_size(m)) FROM messages m WHERE workspace_name=:'workspace'),0)+
  COALESCE((SELECT sum(pg_column_size(e)) FROM message_embeddings e WHERE workspace_name=:'workspace'),0)+
  COALESCE((SELECT sum(pg_column_size(d)) FROM documents d WHERE workspace_name=:'workspace'),0)+
  COALESCE((SELECT sum(pg_column_size(q)) FROM queue q WHERE workspace_name=:'workspace'),0)+
  COALESCE((SELECT sum(pg_column_size(s)) FROM sessions s WHERE workspace_name=:'workspace'),0)+
  COALESCE((SELECT sum(pg_column_size(p)) FROM peers p WHERE workspace_name=:'workspace'),0)+
  COALESCE((SELECT sum(pg_column_size(c)) FROM collections c WHERE workspace_name=:'workspace'),0),
'workspace_messages', (SELECT count(*) FROM messages WHERE workspace_name=:'workspace'),
'workspace_sessions', (SELECT count(*) FROM sessions WHERE workspace_name=:'workspace'),
'workspace_peers', (SELECT count(*) FROM peers WHERE workspace_name=:'workspace'),
'queue_pending', (SELECT count(*) FROM queue WHERE workspace_name=:'workspace' AND processed=false),
'queue_error_rows', (SELECT count(*) FROM queue WHERE workspace_name=:'workspace' AND COALESCE(error,'')<>''),
'queue_oldest_seconds', COALESCE((SELECT extract(epoch FROM now()-min(created_at))::bigint FROM queue WHERE workspace_name=:'workspace' AND processed=false),0),
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


def create_backup(
    database: str,
    destination: Path,
    *,
    maximum_bytes: int | None = None,
    retention_coverage: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    dest = Path(destination).expanduser().resolve()
    if maximum_bytes is not None and (
        type(maximum_bytes) is not int or maximum_bytes < 0
    ):
        raise ValueError("backup maximum_bytes must be a non-negative integer")
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
        if maximum_bytes is not None and temp.stat().st_size > maximum_bytes:
            raise RuntimeError("public Honcho backup byte quota exceeded")
        listing = run_checked(commands[1], capture=True).stdout
        if not listing.strip():
            raise RuntimeError("pg_restore --list returned empty output")
        archive_fd = os.open(temp, os.O_RDONLY)
        try:
            os.fsync(archive_fd)
        finally:
            os.close(archive_fd)
        os.replace(temp, dest)
        os.chmod(dest, 0o600)
        _fsync_directory(dest.parent)
    finally:
        if temp.exists():
            temp.unlink()
    digest = file_sha256(dest).removeprefix("sha256:")
    manifest = {
        "schema_version": BACKUP_SCHEMA,
        "database": database,
        "created_at": utc_now(),
        "path": str(dest),
        "size_bytes": dest.stat().st_size,
        "sha256": digest,
    }
    if retention_coverage is not None:
        manifest["retention_coverage"] = dict(retention_coverage)
    manifest["manifest_digest"] = sha256_json(manifest)
    manifest_path = dest.with_suffix(dest.suffix + ".json")
    fd, tmp_name = tempfile.mkstemp(prefix=manifest_path.name + ".", dir=dest.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, manifest_path)
        os.chmod(manifest_path, 0o600)
        _fsync_directory(manifest_path.parent)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
    if maximum_bytes is not None:
        total_size = dest.stat().st_size + manifest_path.stat().st_size
        if total_size > maximum_bytes:
            dest.unlink()
            manifest_path.unlink()
            _fsync_directory(dest.parent)
            raise RuntimeError("public Honcho backup byte quota exceeded")
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
    backup_digest = file_sha256(source).removeprefix("sha256:")
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
            "restore_database_oid": database_oid(name),
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
    try:
        manifest_archive = Path(str(manifest["path"])).expanduser().resolve()
    except (KeyError, OSError, RuntimeError, ValueError) as exc:
        raise ValueError("backup manifest archive identity is invalid") from exc
    if manifest_archive != backup or manifest.get("size_bytes") != info.st_size:
        raise ValueError("backup manifest archive identity is invalid")
    backup_digest = file_sha256(backup)
    if manifest.get("sha256") != backup_digest.removeprefix("sha256:"):
        raise ValueError("backup checksum mismatch")
    listing = run_checked(["pg_restore", "--list", str(backup)], capture=True).stdout
    if not listing.strip():
        raise ValueError("verified backup is unreadable")
    result = {
        "path": str(backup),
        "sha256": backup_digest,
        "size_bytes": info.st_size,
        "database": expected_database,
        "created_at": manifest.get("created_at"),
        "manifest_digest": manifest["manifest_digest"],
        "verified": True,
    }
    if "retention_coverage" in manifest:
        result["retention_coverage"] = manifest["retention_coverage"]
    return result


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
    if not labels or any(
        re.fullmatch(r"ai\.john-lomein\.[A-Za-z0-9._-]{1,120}", item) is None
        for item in labels
    ):
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
    labels = receipt.get("service_labels") or ()
    if (
        not isinstance(labels, list)
        or len(labels) != 2
        or labels != sorted(set(labels))
        or any(
            re.fullmatch(r"ai\.john-lomein\.[A-Za-z0-9._-]{1,120}", str(label))
            is None
            for label in labels
        )
    ):
        return False
    if receipt.get("vector_store") != "pgvector" or re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("vector_store_config_digest") or "")) is None:
        return False
    try:
        observed = datetime.fromisoformat(
            str(receipt["observed_at"]).replace("Z", "+00:00")
        )
        expires = datetime.fromisoformat(str(receipt["expires_at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError):
        return False
    if observed.tzinfo is None or expires.tzinfo is None:
        return False
    observed_utc = observed.astimezone(timezone.utc)
    expires_utc = expires.astimezone(timezone.utc)
    current = now.astimezone(timezone.utc)
    return (
        observed_utc <= current < expires_utc
        and timedelta(0) < expires_utc - observed_utc <= timedelta(minutes=5)
    )


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



def flush_dedicated_honcho_cache(redis_url: str) -> dict[str, Any]:
    parsed = urlparse(redis_url or "")
    if (
        parsed.scheme != "redis"
        or parsed.hostname != "127.0.0.1"
        or parsed.port in {None, 6379}
        or parsed.path != "/0"
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("cache flush requires the dedicated public Redis instance")
    run_checked(
        ["redis-cli", "-u", redis_url, "FLUSHDB", "SYNC"],
        capture=True,
    )
    size = run_checked(
        ["redis-cli", "-u", redis_url, "DBSIZE"],
        capture=True,
    )
    try:
        remaining = int(size.stdout.strip())
    except ValueError as exc:
        raise RuntimeError("dedicated Redis post-flush size is invalid") from exc
    if remaining != 0:
        raise RuntimeError("dedicated Redis flush left cached keys")
    return {
        "scope": "dedicated_redis_database",
        "redis_target_sha256": "sha256:"
        + hashlib.sha256(redis_url.encode("utf-8")).hexdigest(),
        "remaining": 0,
    }


def honcho_database_identity(database: str) -> dict[str, Any]:
    payload = psql_json(
        database,
        "SELECT json_build_object('database',current_database(),'database_oid',(SELECT oid FROM pg_database WHERE datname=current_database()),'system_identifier',(SELECT system_identifier::text FROM pg_control_system()),'server_port',inet_server_port())::text;",
    )
    if (
        not isinstance(payload, Mapping)
        or payload.get("database") != database
        or type(payload.get("database_oid")) is not int
        or re.fullmatch(r"[0-9]+", str(payload.get("system_identifier") or "")) is None
    ):
        raise ValueError("public Honcho database identity is invalid")
    identity = dict(payload)
    identity["schema_fingerprint"] = "sha256:" + schema_fingerprint(database)
    identity["identity_digest"] = sha256_json(identity)
    return identity


def assert_public_database_isolation(database: str, workspace: str) -> dict[str, Any]:
    payload = psql_json(
        database,
        r"""WITH workspace_names(name) AS (
SELECT name FROM workspaces
UNION SELECT workspace_name FROM peers
UNION SELECT workspace_name FROM sessions
UNION SELECT workspace_name FROM session_peers
UNION SELECT workspace_name FROM messages
UNION SELECT workspace_name FROM message_embeddings
UNION SELECT workspace_name FROM documents
UNION SELECT workspace_name FROM collections
UNION SELECT workspace_name FROM queue WHERE workspace_name IS NOT NULL)
SELECT json_build_object('database',current_database(),'database_oid',(SELECT oid FROM pg_database WHERE datname=current_database()),'system_identifier',(SELECT system_identifier::text FROM pg_control_system()),'server_port',inet_server_port(),'workspace_names',COALESCE((SELECT json_agg(name ORDER BY name) FROM workspace_names),'[]'::json))::text;""",
    )
    if (
        not isinstance(payload, Mapping)
        or payload.get("database") != database
        or re.fullmatch(r"[0-9]+", str(payload.get("system_identifier") or "")) is None
    ):
        raise ValueError("public Honcho database identity is invalid")
    names = payload.get("workspace_names")
    if (
        not isinstance(names, list)
        or any(not isinstance(name, str) for name in names)
        or any(name != workspace for name in names)
        or len(set(names)) > 1
    ):
        raise ValueError("public Honcho database is shared or multi-workspace")
    identity = dict(payload)
    identity["workspace_names"] = sorted(set(names))
    identity["database_identity_digest"] = sha256_json(identity)
    return identity


def validate_public_retention_receipt(
    receipt: Mapping[str, Any],
    *,
    database_identity_digest: str,
    workspace: str,
    now: datetime,
) -> bool:
    unsigned = dict(receipt)
    digest = unsigned.pop("receipt_digest", "")
    if digest != sha256_json(unsigned):
        return False
    if receipt.get("schema_version") != "john-lomein.honcho-retention-receipt.v2":
        return False
    if receipt.get("database_identity_digest") != database_identity_digest.removeprefix("sha256:"):
        return False
    if receipt.get("workspace") != workspace:
        return False
    if receipt.get("retention_days") != 30 or receipt.get("maximum_active_store_lag_seconds") != 300:
        return False
    try:
        completed_raw = datetime.fromisoformat(
            str(receipt["completed_at"]).replace("Z", "+00:00")
        )
        cutoff_raw = datetime.fromisoformat(
            str(receipt["cutoff"]).replace("Z", "+00:00")
        )
    except (KeyError, TypeError, ValueError):
        return False
    if completed_raw.tzinfo is None or cutoff_raw.tzinfo is None or now.tzinfo is None:
        return False
    completed = completed_raw.astimezone(timezone.utc)
    cutoff = cutoff_raw.astimezone(timezone.utc)
    current = now.astimezone(timezone.utc)
    age = current - completed
    return (
        timedelta(0) <= age <= timedelta(seconds=300)
        and _retention_receipt_times_bounded(cutoff, completed, current)
    )


def _backup_tombstone_evidence(metadata: Mapping[str, Any]) -> dict[str, Any]:
    try:
        created = datetime.fromisoformat(
            str(metadata["created_at"]).replace("Z", "+00:00")
        ).astimezone(timezone.utc)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("verified backup creation time is invalid") from exc
    return {
        "sha256": metadata["sha256"],
        "manifest_digest": metadata["manifest_digest"],
        "database": metadata["database"],
        "created_at": created.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "expires_at": (created + timedelta(days=30))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "verified": True,
    }


def _pending_exact_tombstone(
    *,
    schema_version: str,
    operation: str,
    plan: Mapping[str, Any],
    candidates: Mapping[str, Sequence[Any]],
    database_identity: Mapping[str, Any],
    backup_metadata: Mapping[str, Any],
    quiescence_receipt: Mapping[str, Any],
    runtime_identity: Mapping[str, Any],
    manifest_digest: str,
    request_cutoff: str,
) -> dict[str, Any]:
    if re.fullmatch(r"sha256:[0-9a-f]{64}", manifest_digest or "") is None:
        raise ValueError("instance manifest digest is invalid")
    tombstone = {
        "schema_version": schema_version,
        "operation": operation,
        "state": "pending",
        "created_at": utc_now(),
        "request_cutoff": request_cutoff,
        "plan_digest": plan["plan_digest"],
        "candidate_sets_digest": sha256_json(candidates),
        "id_set_digests": {
            key: sha256_json(value) for key, value in sorted(candidates.items())
        },
        "exact_candidate_ids": {
            key: list(value) for key, value in sorted(candidates.items())
        },
        "workspace": plan["workspace"],
        "database_identity": dict(database_identity),
        "schema_fingerprint": database_identity["schema_fingerprint"],
        "server_identity": dict(runtime_identity),
        "manifest_digest": manifest_digest,
        "backup": _backup_tombstone_evidence(backup_metadata),
        "quiescence_receipt_digest": quiescence_receipt["receipt_digest"],
    }
    tombstone["tombstone_digest"] = sha256_json(tombstone)
    return tombstone


def _mark_exact_tombstone_applied(
    tombstone: Mapping[str, Any],
    *,
    tombstone_path: Path,
    cache: Mapping[str, Any],
    replay_backup: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    applied = dict(tombstone)
    applied["state"] = "applied"
    applied["applied_at"] = utc_now()
    applied["cache"] = dict(cache)
    if replay_backup is not None:
        applied["replay_backup"] = _backup_tombstone_evidence(replay_backup)
    applied.pop("tombstone_digest", None)
    applied["tombstone_digest"] = sha256_json(applied)
    write_private_json(tombstone_path, applied)
    return applied


def _apply_participant_deletion(
    *,
    database: str,
    plan: Mapping[str, Any],
    backup_path: Path,
    quiescence_receipt: Mapping[str, Any],
    base_url: str,
    redis_url: str,
    server_root: Path,
    tombstone_path: Path,
    manifest_digest: str,
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
    runtime_identity = verify_honcho_runtime_targets(
        server_root, base_url, database=database, redis_url=redis_url
    )
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
    tombstone = _pending_exact_tombstone(
        schema_version=DELETION_TOMBSTONE_SCHEMA,
        operation="participant_deletion",
        plan=plan,
        candidates=candidates,
        database_identity=honcho_database_identity(database),
        backup_metadata=backup_metadata,
        quiescence_receipt=quiescence_receipt,
        runtime_identity=runtime_identity,
        manifest_digest=manifest_digest,
        request_cutoff=str(plan["generated_at"]),
    )
    tombstone["participant_peer"] = plan["peer"]
    tombstone["allowed_service_peers"] = list(plan["allowed_service_peers"])
    tombstone.pop("tombstone_digest", None)
    tombstone["tombstone_digest"] = sha256_json(tombstone)
    try:
        reserve_private_json(tombstone_path, tombstone)
    except FileExistsError as exc:
        raise ValueError("participant deletion tombstone path already exists") from exc
    run_checked(
        _participant_psql_command(
            database, str(plan["workspace"]), str(plan["peer"]), candidates
        ),
        input_text=participant_deletion_apply_sql(),
    )
    residue = exact_tombstone_residue(database, str(plan["workspace"]), candidates)
    if residue:
        raise RuntimeError("participant deletion exact-ID verification failed")
    cache = flush_dedicated_honcho_cache(redis_url)
    assert_honcho_quiescent(base_url, labels)
    applied = _mark_exact_tombstone_applied(
        tombstone, tombstone_path=tombstone_path, cache=cache
    )
    return {
        "applied": True,
        "plan_digest": plan["plan_digest"],
        "candidate_sets_digest": plan["candidate_sets_digest"],
        "post_candidate_sets_digest": sha256_json(residue),
        "tombstone_digest": applied["tombstone_digest"],
        "restore_replay_required": True,
        "cache": cache,
    }


def apply_participant_deletion(
    *,
    plan: Mapping[str, Any],
    confirm_digest: str,
    **kwargs: Any,
) -> dict[str, Any]:
    if confirm_digest != str(plan.get("plan_digest") or ""):
        raise ValueError("participant deletion confirmation digest is invalid")
    return _apply_participant_deletion(plan=plan, **kwargs)


def _retention_psql_command(
    database: str,
    plan: Mapping[str, Any],
    candidates: Mapping[str, Sequence[Any]],
) -> list[str]:
    command = [
        "psql", "-X", "--dbname", database, "-v", "ON_ERROR_STOP=1",
        "-v", f"workspace={plan['workspace']}",
        "-v", f"cutoff={plan['cutoff']}",
        "-v", f"expected_message_count={plan['message_count']}",
        "-v", f"expected_document_count={plan['document_count']}",
        "-v", f"expected_embedding_count={plan['embedding_count']}",
        "-v", f"expected_queue_count={plan['queue_count']}",
        "-v", f"expected_active_count={plan.get('active_count', len(candidates['active_queue_session_ids']))}",
    ]
    for key in (
        "message_ids",
        "embedding_ids",
        "document_ids",
        "queue_ids",
        "active_queue_session_ids",
    ):
        command.extend(["-v", f"{key}={canonical_json(candidates[key])}"])
    return command


def _apply_retention(
    *,
    database: str,
    plan: Mapping[str, Any],
    backup_path: Path,
    quiescence_receipt: Mapping[str, Any],
    base_url: str,
    redis_url: str,
    server_root: Path,
    tombstone_path: Path,
    manifest_digest: str,
) -> dict[str, Any]:
    if not validate_retention_plan(plan):
        raise ValueError("retention plan is invalid")
    now = datetime.now(timezone.utc)
    if not validate_honcho_quiescence_receipt(quiescence_receipt, now=now):
        raise ValueError("Honcho quiescence receipt is invalid or expired")
    cutoff = datetime.fromisoformat(str(plan["cutoff"]).replace("Z", "+00:00"))
    if (
        cutoff.tzinfo is None
        or cutoff.astimezone(timezone.utc) > now - timedelta(days=30)
    ):
        raise ValueError("retention cutoff is newer than the fixed 30-day boundary")
    oid = database_oid(database)
    if oid != plan["database_oid"] or quiescence_receipt.get("database_oid") != oid:
        raise ValueError("retention database changed")
    current_schema = "sha256:" + schema_fingerprint(database)
    if (
        current_schema != "sha256:" + plan["schema_fingerprint"]
        or quiescence_receipt.get("schema_fingerprint") != current_schema
    ):
        raise ValueError("retention schema changed")
    labels = list(quiescence_receipt.get("service_labels") or [])
    assert_honcho_quiescent(base_url, labels)
    runtime_identity = verify_honcho_runtime_targets(
        server_root, base_url, database=database, redis_url=redis_url
    )
    vector_store = inspect_honcho_vector_store(server_root)
    if vector_store.get("type") != "pgvector" or vector_store.get("migrated") is not False:
        raise ValueError("retention supports only non-migrated pgvector")
    if vector_store.get("config_digest") != quiescence_receipt.get(
        "vector_store_config_digest"
    ):
        raise ValueError("vector store configuration changed after quiescence")

    candidates = retention_candidate_sets(
        database,
        str(plan["workspace"]),
        str(plan["cutoff"]),
    )
    if sha256_json(candidates) != plan["candidate_sets_digest"]:
        raise ValueError("retention candidate sets changed")
    for key, value in candidates.items():
        if sha256_json(value) != plan["id_set_digests"][key]:
            raise ValueError("retention candidate digest changed")
    backup_metadata = verified_backup_metadata(backup_path, expected_database=database)
    tombstone = _pending_exact_tombstone(
        schema_version=RETENTION_TOMBSTONE_SCHEMA,
        operation="retention",
        plan=plan,
        candidates=candidates,
        database_identity=honcho_database_identity(database),
        backup_metadata=backup_metadata,
        quiescence_receipt=quiescence_receipt,
        runtime_identity=runtime_identity,
        manifest_digest=manifest_digest,
        request_cutoff=str(plan["cutoff"]),
    )
    try:
        reserve_private_json(tombstone_path, tombstone)
    except FileExistsError as exc:
        raise ValueError("retention tombstone path already exists") from exc
    run_checked(
        _retention_psql_command(database, plan, candidates),
        input_text=retention_apply_sql(),
    )
    residue = exact_tombstone_residue(database, str(plan["workspace"]), candidates)
    if residue:
        raise RuntimeError("retention exact-ID verification failed")
    cache = flush_dedicated_honcho_cache(redis_url)
    assert_honcho_quiescent(base_url, labels)
    applied = _mark_exact_tombstone_applied(
        tombstone, tombstone_path=tombstone_path, cache=cache
    )
    return {
        "applied": True,
        "plan_digest": plan["plan_digest"],
        "candidate_sets_digest": plan["candidate_sets_digest"],
        "post_candidate_sets_digest": sha256_json(residue),
        "tombstone_digest": applied["tombstone_digest"],
        "restore_replay_required": True,
        "cache": cache,
    }


def apply_retention(
    *,
    plan: Mapping[str, Any],
    confirm_digest: str,
    **kwargs: Any,
) -> dict[str, Any]:
    if confirm_digest != str(plan.get("plan_digest") or ""):
        raise ValueError("retention confirmation digest is invalid")
    return _apply_retention(plan=plan, **kwargs)


def _participant_psql_command(
    database: str,
    workspace: str,
    peer: str,
    candidates: Mapping[str, Sequence[Any]],
    *,
    expected_candidates: Mapping[str, Sequence[Any]] | None = None,
) -> list[str]:
    command = [
        "psql", "-X", "--dbname", database, "-v", "ON_ERROR_STOP=1",
        "-v", f"workspace={workspace}", "-v", f"peer={peer}",
    ]
    for key in (
        "peer_ids", "session_ids", "session_names", "session_peer_link_keys", "message_ids",
        "embedding_ids", "document_ids", "collection_ids", "queue_ids",
        "work_unit_keys", "active_queue_session_ids",
    ):
        command.extend(["-v", f"{key}={canonical_json(candidates[key])}"])
    expected = expected_candidates or candidates
    count_keys = {
        "peer": "peer_ids",
        "session": "session_ids",
        "session_link": "session_peer_link_keys",
        "message": "message_ids",
        "embedding": "embedding_ids",
        "document": "document_ids",
        "collection": "collection_ids",
        "queue": "queue_ids",
        "active": "active_queue_session_ids",
    }
    for name, key in count_keys.items():
        command.extend(["-v", f"expected_{name}_count={len(expected.get(key) or [])}"])
    return command


def _replay_tombstone(
    *,
    database: str,
    tombstone: Mapping[str, Any],
    tombstone_path: Path,
    backup_path: Path,
    quiescence_receipt: Mapping[str, Any],
    base_url: str,
    redis_url: str,
    server_root: Path,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    if not validate_honcho_quiescence_receipt(quiescence_receipt, now=now):
        raise ValueError("Honcho quiescence receipt is invalid or expired")
    oid = database_oid(database)
    current_schema = "sha256:" + schema_fingerprint(database)
    if quiescence_receipt.get("database_oid") != oid:
        raise ValueError("replay quiescence database mismatch")
    if quiescence_receipt.get("schema_fingerprint") != current_schema:
        raise ValueError("replay schema changed after quiescence")
    recorded_schema = str(tombstone.get("schema_fingerprint") or current_schema)
    if recorded_schema != current_schema:
        raise ValueError("tombstone schema does not match replay database")
    labels = list(quiescence_receipt.get("service_labels") or [])
    assert_honcho_quiescent(base_url, labels)
    verify_honcho_runtime_targets(
        server_root, base_url, database=database, redis_url=redis_url
    )
    vector_store = inspect_honcho_vector_store(server_root)
    if vector_store.get("type") != "pgvector" or vector_store.get("migrated") is not False:
        raise ValueError("tombstone replay supports only non-migrated pgvector")
    if vector_store.get("config_digest") != quiescence_receipt.get(
        "vector_store_config_digest"
    ):
        raise ValueError("vector store configuration changed after quiescence")
    source_identity = tombstone.get("database_identity")
    if not isinstance(source_identity, Mapping):
        raise ValueError("tombstone replay database identity is invalid")
    backup = verified_backup_metadata(
        backup_path, expected_database=str(source_identity.get("database") or "")
    )
    workspace = str(tombstone.get("workspace") or "")
    operation = str(tombstone.get("operation") or "")
    exact = tombstone.get("exact_candidate_ids")
    if not isinstance(exact, Mapping):
        raise ValueError("tombstone replay exact IDs are invalid")
    candidates = {str(key): list(value) for key, value in exact.items()}
    before = exact_tombstone_residue(database, workspace, candidates)
    if not before:
        cache = flush_dedicated_honcho_cache(redis_url)
        if tombstone.get("state") == "applied":
            return {
                "applied": True,
                "already_applied": True,
                "database_oid": oid,
                "tombstone_digest": tombstone["tombstone_digest"],
                "cache": cache,
            }
        applied = _mark_exact_tombstone_applied(
            tombstone,
            tombstone_path=tombstone_path,
            cache=cache,
            replay_backup=backup,
        )
        return {
            "applied": True,
            "already_applied": False,
            "database_oid": oid,
            "tombstone_digest": applied["tombstone_digest"],
            "cache": cache,
        }

    if operation == "participant_deletion":
        run_checked(
            _participant_psql_command(
                database,
                workspace,
                str(tombstone.get("participant_peer") or ""),
                candidates,
                expected_candidates=before,
            ),
            input_text=participant_deletion_apply_sql(),
        )
    elif operation == "retention":
        replay_plan = {
            "workspace": workspace,
            "cutoff": str(tombstone.get("request_cutoff") or ""),
            "message_count": len(before.get("message_ids") or []),
            "embedding_count": len(before.get("embedding_ids") or []),
            "document_count": len(before.get("document_ids") or []),
            "queue_count": len(before.get("queue_ids") or []),
            "active_count": len(before.get("active_queue_session_ids") or []),
        }
        run_checked(
            _retention_psql_command(database, replay_plan, candidates),
            input_text=retention_apply_sql(),
        )
    else:
        raise ValueError("unsupported tombstone replay operation")
    residue = exact_tombstone_residue(database, workspace, candidates)
    if residue:
        raise RuntimeError("tombstone exact-ID replay verification failed")
    cache = flush_dedicated_honcho_cache(redis_url)
    assert_honcho_quiescent(base_url, labels)
    updated = _mark_exact_tombstone_applied(
        tombstone,
        tombstone_path=tombstone_path,
        cache=cache,
        replay_backup=backup,
    )
    return {
        "applied": True,
        "already_applied": False,
        "database_oid": oid,
        "operation": operation,
        "replay_candidate_sets_digest": sha256_json(before),
        "post_candidate_sets_digest": sha256_json(residue),
        "tombstone_digest": updated["tombstone_digest"],
        "cache": cache,
    }


def replay_tombstone(
    *,
    tombstone: Mapping[str, Any],
    confirm_tombstone_digest: str,
    **kwargs: Any,
) -> dict[str, Any]:
    if confirm_tombstone_digest != str(tombstone.get("tombstone_digest") or ""):
        raise ValueError("tombstone replay confirmation digest is invalid")
    return _replay_tombstone(tombstone=tombstone, **kwargs)


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
    return {
        **settings,
        "runtime_home": runtime_home,
        "tombstone_dir": runtime_home / "private" / "honcho-deletion-tombstones",
    }


def canonical_tombstone_path(targets: Mapping[str, Any], plan: Mapping[str, Any]) -> Path:
    digest = str(plan.get("plan_digest") or "")
    if re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", digest) is None:
        raise ValueError("Honcho destructive plan digest is invalid")
    operation = (
        "retention"
        if plan.get("schema_version") == RETENTION_SCHEMA
        else "participant-deletion"
    )
    return (
        Path(targets["tombstone_dir"])
        / f"{operation}-{digest.removeprefix('sha256:')}.json"
    )


def _public_child_service_names(instance_slug: str) -> tuple[str, str]:
    prefix = f"ai.john-lomein.{instance_slug}.public-honcho.child"
    return (f"{prefix}.api", f"{prefix}.deriver")


def _database_retention_boundary(database: str) -> dict[str, str]:
    payload = psql_json(
        database,
        "SELECT json_build_object('database_now',date_trunc('second',clock_timestamp()),'cutoff',date_trunc('second',clock_timestamp()-interval '30 days'))::text;",
    )
    if not isinstance(payload, Mapping):
        raise ValueError("PostgreSQL retention clock query failed")
    return {key: str(payload[key]).replace("+00:00", "Z") for key in ("database_now", "cutoff")}


def _retention_receipt_times_bounded(
    cutoff: str | datetime,
    completed_at: str | datetime,
    current: str | datetime,
) -> bool:
    try:
        parsed = []
        for value in (cutoff, completed_at, current):
            timestamp = (
                value
                if isinstance(value, datetime)
                else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            )
            if timestamp.tzinfo is None:
                return False
            parsed.append(timestamp.astimezone(timezone.utc))
    except (TypeError, ValueError):
        return False
    cutoff_utc, completed_utc, current_utc = parsed
    minimum_age = timedelta(days=30)
    maximum_age = minimum_age + timedelta(seconds=300)
    return (
        minimum_age <= completed_utc - cutoff_utc <= maximum_age
        and minimum_age <= current_utc - cutoff_utc <= maximum_age
    )


def _write_retention_receipt(
    *,
    runtime_home: Path,
    database_identity_digest: str,
    workspace: str,
    cutoff: str,
    completed_at: str,
    deleted_counts: Mapping[str, int],
) -> dict[str, Any]:
    if not _retention_receipt_times_bounded(cutoff, completed_at, completed_at):
        raise RuntimeError("retention cutoff is not bound to completion time")
    receipt = {
        "schema_version": "john-lomein.honcho-retention-receipt.v2",
        "database_identity_digest": database_identity_digest.removeprefix("sha256:"),
        "workspace": workspace,
        "cutoff": cutoff,
        "completed_at": completed_at,
        "retention_days": 30,
        "maximum_active_store_lag_seconds": 300,
        "deleted_counts": {str(k): int(v) for k, v in sorted(deleted_counts.items())},
    }
    receipt["receipt_digest"] = sha256_json(receipt)
    write_private_json(runtime_home / "state" / "honcho" / "retention-latest.json", receipt)
    return receipt


def _public_backup_root(backup_root: Path) -> Path:
    raw = Path(backup_root).expanduser()
    if raw.is_symlink():
        raise ValueError("public Honcho backup directory is unsafe")
    raw.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = raw.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise ValueError("public Honcho backup directory is unsafe")
    os.chmod(raw, 0o700)
    return raw.resolve()


def _private_backup_artifact(path: Path) -> os.stat_result:
    info = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_mode & 0o077
    ):
        raise ValueError("public Honcho backup directory contains an unsafe entry")
    return info


def _public_backup_archives(root: Path) -> dict[Path, os.stat_result]:
    archives: dict[Path, os.stat_result] = {}
    for entry in sorted(root.iterdir()):
        if entry.name.endswith(".dump") or entry.name.endswith(".dump.partial"):
            archives[entry] = _private_backup_artifact(entry)
    return archives


def enforce_public_backup_quota(
    backup_root: Path,
    *,
    additional_count: int = 0,
    additional_bytes: int = 0,
    maximum_count: int = PUBLIC_BACKUP_MAX_COUNT,
    maximum_bytes: int = PUBLIC_BACKUP_MAX_BYTES,
) -> dict[str, int]:
    for value, name in (
        (additional_count, "additional_count"),
        (additional_bytes, "additional_bytes"),
    ):
        if type(value) is not int or value < 0:
            raise ValueError(f"backup {name} must be a non-negative integer")
    if type(maximum_count) is not int or maximum_count < 1:
        raise ValueError("backup maximum_count must be a positive integer")
    if type(maximum_bytes) is not int or maximum_bytes < 1:
        raise ValueError("backup maximum_bytes must be a positive integer")
    root = _public_backup_root(backup_root)
    archives = _public_backup_archives(root)
    manifest_bytes = 0
    for manifest_path in sorted(root.glob("*.dump.json")):
        manifest_bytes += _private_backup_artifact(manifest_path).st_size
    usage = {
        "count": len(archives),
        "bytes": sum(info.st_size for info in archives.values()) + manifest_bytes,
    }
    if usage["count"] + additional_count > maximum_count:
        raise RuntimeError("public Honcho backup count quota exceeded")
    if usage["bytes"] + additional_bytes > maximum_bytes:
        raise RuntimeError("public Honcho backup byte quota exceeded")
    return usage


def _normalized_retention_candidate_sets(
    candidate_sets: Mapping[str, Sequence[Any]],
) -> dict[str, list[Any]]:
    if set(candidate_sets) != set(RETENTION_CANDIDATE_KEYS):
        raise ValueError("retention candidate sets are incomplete")
    return {
        key: sorted(
            set(candidate_sets[key]),
            key=lambda item: (str(type(item)), str(item)),
        )
        for key in sorted(RETENTION_CANDIDATE_KEYS)
    }


def build_retention_backup_coverage(
    *,
    database_identity_digest: str,
    workspace: str,
    coverage_cutoff: str,
    candidate_sets: Mapping[str, Sequence[Any]],
) -> dict[str, Any]:
    if re.fullmatch(
        r"(?:sha256:)?[0-9a-f]{64}", database_identity_digest or ""
    ) is None:
        raise ValueError("retention backup database identity is invalid")
    if SAFE_NAME_RE.fullmatch(workspace or "") is None:
        raise ValueError("retention backup workspace is invalid")
    try:
        parsed_cutoff = datetime.fromisoformat(coverage_cutoff.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("retention backup coverage cutoff is invalid") from exc
    if parsed_cutoff.tzinfo is None:
        raise ValueError("retention backup coverage cutoff must include a timezone")
    normalized = _normalized_retention_candidate_sets(candidate_sets)
    coverage = {
        "schema_version": RETENTION_BACKUP_COVERAGE_SCHEMA,
        "database_identity_digest": database_identity_digest.removeprefix("sha256:"),
        "workspace": workspace,
        "coverage_cutoff": parsed_cutoff.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "candidate_sets": normalized,
        "candidate_sets_digest": sha256_json(normalized),
    }
    return coverage


def retention_backup_covers(
    metadata: Mapping[str, Any],
    *,
    expected_database: str,
    database_identity_digest: str,
    workspace: str,
    cutoff: str,
    candidate_sets: Mapping[str, Sequence[Any]],
    now: datetime,
    maximum_age_seconds: int = PUBLIC_BACKUP_REUSE_MAX_AGE_SECONDS,
) -> bool:
    coverage = metadata.get("retention_coverage")
    if (
        metadata.get("verified") is not True
        or metadata.get("database") != expected_database
        or not isinstance(coverage, Mapping)
        or coverage.get("schema_version") != RETENTION_BACKUP_COVERAGE_SCHEMA
        or coverage.get("database_identity_digest")
        != database_identity_digest.removeprefix("sha256:")
        or coverage.get("workspace") != workspace
        or type(maximum_age_seconds) is not int
        or maximum_age_seconds < 1
    ):
        return False
    try:
        created_raw = datetime.fromisoformat(
            str(metadata["created_at"]).replace("Z", "+00:00")
        )
        requested_cutoff_raw = datetime.fromisoformat(cutoff.replace("Z", "+00:00"))
        coverage_cutoff_raw = datetime.fromisoformat(
            str(coverage["coverage_cutoff"]).replace("Z", "+00:00")
        )
        covered = _normalized_retention_candidate_sets(coverage["candidate_sets"])
        requested = _normalized_retention_candidate_sets(candidate_sets)
    except (KeyError, TypeError, ValueError):
        return False
    if (
        created_raw.tzinfo is None
        or requested_cutoff_raw.tzinfo is None
        or coverage_cutoff_raw.tzinfo is None
        or now.tzinfo is None
    ):
        return False
    created = created_raw.astimezone(timezone.utc)
    requested_cutoff = requested_cutoff_raw.astimezone(timezone.utc)
    coverage_cutoff = coverage_cutoff_raw.astimezone(timezone.utc)
    age = now.astimezone(timezone.utc) - created
    if not timedelta(0) <= age <= timedelta(seconds=maximum_age_seconds):
        return False
    if requested_cutoff > coverage_cutoff:
        return False
    if coverage.get("candidate_sets_digest") != sha256_json(covered):
        return False
    return all(set(requested[key]).issubset(set(covered[key])) for key in requested)


def find_reusable_public_backup(
    backup_root: Path,
    *,
    expected_database: str,
    database_identity_digest: str,
    workspace: str,
    cutoff: str,
    candidate_sets: Mapping[str, Sequence[Any]],
    now: datetime,
) -> dict[str, Any] | None:
    root = _public_backup_root(backup_root)
    for manifest_path in sorted(root.glob("*.dump.json"), reverse=True):
        _private_backup_artifact(manifest_path)
        archive = root / manifest_path.name.removesuffix(".json")
        metadata = verified_backup_metadata(
            archive,
            expected_database=expected_database,
        )
        if retention_backup_covers(
            metadata,
            expected_database=expected_database,
            database_identity_digest=database_identity_digest,
            workspace=workspace,
            cutoff=cutoff,
            candidate_sets=candidate_sets,
            now=now,
        ):
            return metadata
    return None


def expire_public_backups(backup_root: Path, *, now: datetime) -> int:
    root = _public_backup_root(backup_root)
    archives = _public_backup_archives(root)
    manifests: dict[Path, Mapping[str, Any]] = {}
    for manifest_path in sorted(root.glob("*.dump.json")):
        _private_backup_artifact(manifest_path)
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(data, Mapping):
            raise ValueError("public Honcho backup manifest is invalid")
        unsigned = {key: value for key, value in data.items() if key != "manifest_digest"}
        if (
            data.get("schema_version") != BACKUP_SCHEMA
            or data.get("manifest_digest") != sha256_json(unsigned)
        ):
            raise ValueError("public Honcho backup manifest is invalid")
        manifests[manifest_path] = data

    current = now.astimezone(timezone.utc)
    removed = 0
    for archive, info in archives.items():
        if archive.name.endswith(".dump.partial"):
            modified = datetime.fromtimestamp(info.st_mtime, tz=timezone.utc)
            if modified > current:
                raise ValueError("public Honcho backup artifact time is invalid")
            if current - modified >= timedelta(days=30):
                archive.unlink()
                removed += 1
            continue
        manifest_path = archive.with_suffix(archive.suffix + ".json")
        if manifest_path not in manifests:
            modified = datetime.fromtimestamp(info.st_mtime, tz=timezone.utc)
            if modified > current:
                raise ValueError("public Honcho backup artifact time is invalid")
            if current - modified >= timedelta(days=30):
                archive.unlink()
                removed += 1

    for manifest_path, data in manifests.items():
        try:
            created_raw = datetime.fromisoformat(
                str(data["created_at"]).replace("Z", "+00:00")
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("public Honcho backup manifest time is invalid") from exc
        if created_raw.tzinfo is None:
            raise ValueError("public Honcho backup manifest time is invalid")
        created = created_raw.astimezone(timezone.utc)
        age = current - created
        if age < timedelta(0):
            raise ValueError("public Honcho backup manifest time is invalid")
        archive = root / manifest_path.name.removesuffix(".json")
        if archive not in archives or archive.name.endswith(".partial"):
            raise ValueError("public Honcho backup archive is missing or unsafe")
        info = archives[archive]
        try:
            manifest_archive = Path(str(data["path"])).expanduser().resolve()
        except (KeyError, OSError, RuntimeError, ValueError) as exc:
            raise ValueError("public Honcho backup archive identity is invalid") from exc
        if manifest_archive != archive or data.get("size_bytes") != info.st_size:
            raise ValueError("public Honcho backup archive identity is invalid")
        if age < timedelta(days=30):
            continue
        archive.unlink()
        manifest_path.unlink()
        removed += 1
    if removed:
        _fsync_directory(root)
    return removed


def run_public_retention_cycle(
    manifest_path: Path,
    *,
    database_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    manifest_file = Path(manifest_path).expanduser().resolve()
    manifest = manifest_payload(manifest_file)
    targets = manifest_honcho_targets(manifest_file)
    runtime_home = Path(targets["runtime_home"])
    slug = str((manifest.get("instance") or {}).get("slug") or "")
    database = str(targets["database"])
    workspace = str(targets["workspace"])
    identity = dict(
        database_identity
        or assert_public_database_isolation(database, workspace)
    )
    identity_digest = str(
        identity.get("database_identity_digest")
        or identity.get("identity_digest")
        or sha256_json(identity)
    )
    blockers = honcho_startup_blockers(
        Path(targets["tombstone_dir"]), database=database, workspace=workspace
    )
    if blockers:
        raise RuntimeError("retention blocked by pending or resurrected exact IDs")
    verify_honcho_runtime_targets(
        Path(targets["server_root"]),
        str(targets["base_url"]),
        database=database,
        redis_url=str(targets["redis_url"]),
    )
    backup_root = runtime_home / "private" / "honcho-backups"
    expired_backup_count = expire_public_backups(
        backup_root,
        now=datetime.now(timezone.utc),
    )
    boundary = _database_retention_boundary(database)
    candidates = retention_candidate_sets(database, workspace, boundary["cutoff"])
    counts = {
        "messages": len(candidates["message_ids"]),
        "queue": len(candidates["queue_ids"]),
        "message_embeddings": len(candidates["embedding_ids"]),
        "documents": len(candidates["document_ids"]),
        "active_queue_sessions": len(candidates["active_queue_session_ids"]),
    }
    result: dict[str, Any] = {
        "schema_version": "john-lomein.honcho-retention-run.v2",
        "status": "no_expired_messages",
        "workspace": workspace,
        "retention_days": 30,
        "maximum_active_store_lag_seconds": 300,
        "deleted_counts": {key: 0 for key in counts},
        "expired_backup_count": expired_backup_count,
    }
    if candidates["message_ids"]:
        labels = _public_child_service_names(slug)
        quiescence = create_honcho_quiescence_receipt(
            database,
            str(targets["base_url"]),
            labels,
            Path(targets["server_root"]),
        )
        enforce_public_backup_quota(backup_root)
        backup_metadata = find_reusable_public_backup(
            backup_root,
            expected_database=database,
            database_identity_digest=identity_digest,
            workspace=workspace,
            cutoff=boundary["cutoff"],
            candidate_sets=candidates,
            now=datetime.now(timezone.utc),
        )
        backup_reused = backup_metadata is not None
        if backup_metadata is None:
            parsed_cutoff = datetime.fromisoformat(
                boundary["cutoff"].replace("Z", "+00:00")
            ).astimezone(timezone.utc)
            coverage_cutoff = (
                parsed_cutoff
                + timedelta(seconds=PUBLIC_BACKUP_REUSE_MAX_AGE_SECONDS)
            ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            coverage_candidates = retention_candidate_sets(
                database,
                workspace,
                coverage_cutoff,
            )
            coverage = build_retention_backup_coverage(
                database_identity_digest=identity_digest,
                workspace=workspace,
                coverage_cutoff=coverage_cutoff,
                candidate_sets=coverage_candidates,
            )
            usage = enforce_public_backup_quota(
                backup_root,
                additional_count=1,
                additional_bytes=1,
            )
            remaining_bytes = PUBLIC_BACKUP_MAX_BYTES - usage["bytes"]
            run_id = (
                f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-"
                f"{secrets.token_hex(4)}"
            )
            backup_path = backup_root / f"{run_id}.dump"
            backup_manifest = create_backup(
                database,
                backup_path,
                maximum_bytes=remaining_bytes,
                retention_coverage=coverage,
            )
            enforce_public_backup_quota(backup_root)
            backup_metadata = {
                "path": str(backup_path),
                "sha256": "sha256:" + str(backup_manifest["sha256"]),
                "size_bytes": int(backup_manifest["size_bytes"]),
                "database": database,
                "created_at": backup_manifest["created_at"],
                "manifest_digest": backup_manifest["manifest_digest"],
                "retention_coverage": coverage,
                "verified": True,
            }

        boundary = _database_retention_boundary(database)
        candidates = retention_candidate_sets(database, workspace, boundary["cutoff"])
        counts = {
            "messages": len(candidates["message_ids"]),
            "queue": len(candidates["queue_ids"]),
            "message_embeddings": len(candidates["embedding_ids"]),
            "documents": len(candidates["document_ids"]),
            "active_queue_sessions": len(candidates["active_queue_session_ids"]),
        }
        result["backup_reused"] = backup_reused
        if candidates["message_ids"]:
            if not retention_backup_covers(
                backup_metadata,
                expected_database=database,
                database_identity_digest=identity_digest,
                workspace=workspace,
                cutoff=boundary["cutoff"],
                candidate_sets=candidates,
                now=datetime.now(timezone.utc),
            ):
                raise RuntimeError(
                    "verified public backup does not cover final retention transaction"
                )
            oid = database_oid(database)
            plan = make_retention_plan(
                {
                    "database_oid": oid,
                    "workspace": workspace,
                    "cutoff": boundary["cutoff"],
                    "retention_days": 30,
                    "message_count": counts["messages"],
                    "queue_count": counts["queue"],
                    "embedding_count": counts["message_embeddings"],
                    "document_count": counts["documents"],
                    "schema_fingerprint": schema_fingerprint(database),
                },
                candidate_sets=candidates,
            )
            backup_path = Path(str(backup_metadata["path"]))
            applied = apply_retention(
                database=database,
                plan=plan,
                confirm_digest=str(plan["plan_digest"]),
                backup_path=backup_path,
                quiescence_receipt=quiescence,
                base_url=str(targets["base_url"]),
                redis_url=str(targets["redis_url"]),
                server_root=Path(targets["server_root"]),
                tombstone_path=canonical_tombstone_path(targets, plan),
                manifest_digest=file_sha256(manifest_file),
            )
            result.update(
                status="applied",
                deleted_counts=counts,
                tombstone_digest=applied["tombstone_digest"],
            )
    completed = _database_retention_boundary(database)["database_now"]
    receipt = _write_retention_receipt(
        runtime_home=runtime_home,
        database_identity_digest=identity_digest,
        workspace=workspace,
        cutoff=boundary["cutoff"],
        completed_at=completed,
        deleted_counts=result["deleted_counts"],
    )
    result["retention_receipt_digest"] = receipt["receipt_digest"]
    return result


def run_scheduled_retention(manifest_path: Path) -> dict[str, Any]:
    return run_public_retention_cycle(manifest_path)

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
    health.add_argument("--base-url", required=True)
    health.add_argument("--workspace", required=True)
    health.add_argument("--queue-pending-max", type=int, default=25)
    health.add_argument("--queue-oldest-seconds-max", type=int, default=900)
    health.add_argument("--embedding-pending-max", type=int, default=10)
    health.add_argument("--embedding-oldest-seconds-max", type=int, default=900)
    health.add_argument("--embedding-recent-failed-max", type=int, default=0)
    health.add_argument(
        "--workspace-storage-bytes-max",
        "--database-size-bytes-max",
        dest="workspace_storage_bytes_max",
        type=int,
        default=1_073_741_824,
    )
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
    apply.add_argument("--manifest", required=True)
    apply.add_argument("--quiescence-receipt", required=True)

    backup = sub.add_parser("backup")
    backup.add_argument("--database", required=True)
    backup.add_argument("--manifest", required=True)
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
    startup = sub.add_parser("startup-gate")
    startup.add_argument("--database", required=True)
    startup.add_argument("--manifest", required=True)
    startup.add_argument("--service", choices=("api", "deriver", "guide"), required=True)
    scheduled = sub.add_parser("retention-scheduled-run")
    scheduled.add_argument("--manifest", required=True)
    replay = sub.add_parser("tombstone-replay")
    replay.add_argument("--database", required=True)
    replay.add_argument("--manifest", required=True)
    replay.add_argument("--tombstone", required=True)
    replay.add_argument("--confirm-tombstone-digest", required=True)
    replay.add_argument("--backup", required=True)
    replay.add_argument("--quiescence-receipt", required=True)
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
            "workspace_storage_bytes_max": args.workspace_storage_bytes_max,
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

    if args.command == "startup-gate":
        targets = manifest_honcho_targets(Path(args.manifest))
        if args.database != targets["database"]:
            raise ValueError("startup database does not match the instance manifest")
        if not targets["server_root"]:
            raise ValueError("Honcho startup gate requires a configured server root")
        runtime_identity = verify_honcho_runtime_targets(
            Path(targets["server_root"]),
            str(targets["base_url"]),
            database=args.database,
            redis_url=str(targets["redis_url"]),
        )
        if runtime_identity["head"] != targets["checkout_commit"]:
            raise ValueError("public Honcho checkout does not match manifest pin")
        database_identity = assert_public_database_isolation(
            args.database, str(targets["workspace"])
        )
        blockers = honcho_startup_blockers(
            Path(targets["tombstone_dir"]),
            database=args.database,
            workspace=str(targets["workspace"]),
        )
        retention_path = Path(targets["runtime_home"]) / "state" / "honcho" / "retention-latest.json"
        retention = json.loads(_safe_capability_source(retention_path, private=True))
        retention_fresh = validate_public_retention_receipt(
            retention,
            database_identity_digest=str(database_identity["database_identity_digest"]),
            workspace=str(targets["workspace"]),
            now=datetime.now(timezone.utc),
        )
        if not blockers and retention_fresh:
            flush_dedicated_honcho_cache(str(targets["redis_url"]))
        result = {
            "schema_version": "john-lomein.honcho-startup-gate.v2",
            "service": args.service,
            "database_oid": database_identity["database_oid"],
            "workspace": targets["workspace"],
            "blocking_tombstone_count": len(blockers),
            "blocking_tombstone_set_digest": sha256_json(blockers),
            "retention_receipt_fresh": retention_fresh,
            "startup_safe": not blockers and retention_fresh,
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["startup_safe"] else 2

    if args.command == "retention-scheduled-run":
        result = run_scheduled_retention(Path(args.manifest))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if args.command == "tombstone-replay":
        targets = manifest_honcho_targets(Path(args.manifest))
        if args.database != targets["database"]:
            raise ValueError("replay database does not match the instance manifest")
        tombstone_path = Path(args.tombstone).expanduser().resolve()
        tombstone_root = Path(targets["tombstone_dir"]).resolve()
        if tombstone_path.parent != tombstone_root:
            raise ValueError("tombstone replay path is outside the canonical directory")
        known = _load_tombstone_records(tombstone_root)
        tombstone = json.loads(_safe_capability_source(tombstone_path, private=True))
        if not isinstance(tombstone, Mapping) or not any(
            item.get("tombstone_digest") == tombstone.get("tombstone_digest")
            for item in known
        ):
            raise ValueError("tombstone replay target is invalid")
        if tombstone.get("workspace") != targets["workspace"]:
            raise ValueError("tombstone replay workspace changed")
        quiescence = json.loads(
            _safe_capability_source(
                Path(args.quiescence_receipt).expanduser().resolve(),
                private=True,
            )
        )
        result = replay_tombstone(
            database=args.database,
            tombstone=tombstone,
            confirm_tombstone_digest=args.confirm_tombstone_digest,
            tombstone_path=tombstone_path,
            backup_path=Path(args.backup),
            quiescence_receipt=quiescence,
            base_url=str(targets["base_url"]),
            redis_url=str(targets["redis_url"]),
            server_root=Path(targets["server_root"]),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if args.command == "retention-plan":
        if args.days != 30:
            raise ValueError("pilot retention is fixed at 30 days")
        cutoff_text = _database_retention_boundary(args.database)["cutoff"]
        candidates = retention_candidate_sets(
            args.database,
            args.workspace,
            cutoff_text,
        )
        counts = {
            "message_count": len(candidates["message_ids"]),
            "queue_count": len(candidates["queue_ids"]),
            "embedding_count": len(candidates["embedding_ids"]),
            "document_count": len(candidates["document_ids"]),
        }
        plan = make_retention_plan(
            {
                "database_oid": database_oid(args.database),
                "workspace": args.workspace,
                "cutoff": cutoff_text,
                "retention_days": args.days,
                **counts,
                "schema_fingerprint": schema_fingerprint(args.database),
            },
            candidate_sets=candidates,
        )
        if args.output:
            write_private_json(Path(args.output), plan)
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0

    if args.command == "retention-apply":
        targets = manifest_honcho_targets(Path(args.manifest))
        if args.database != targets["database"]:
            raise ValueError("retention database does not match the instance manifest")
        plan = json.loads(
            _safe_capability_source(Path(args.plan).expanduser().resolve(), private=True)
        )
        if (
            not validate_retention_plan(plan)
            or args.confirm_digest != plan.get("plan_digest")
        ):
            raise ValueError("retention plan or confirmation digest is invalid")
        if plan.get("workspace") != targets["workspace"]:
            raise ValueError("retention workspace does not match the instance manifest")
        if (
            database_oid(args.database) != plan["database_oid"]
            or schema_fingerprint(args.database) != plan["schema_fingerprint"]
        ):
            raise ValueError("retention database or schema changed")
        quiescence = json.loads(
            _safe_capability_source(
                Path(args.quiescence_receipt).expanduser().resolve(), private=True
            )
        )
        result = apply_retention(
            database=args.database,
            plan=plan,
            confirm_digest=args.confirm_digest,
            backup_path=Path(args.backup),
            quiescence_receipt=quiescence,
            base_url=targets["base_url"],
            redis_url=targets["redis_url"],
            server_root=Path(targets["server_root"]),
            tombstone_path=canonical_tombstone_path(targets, plan),
            manifest_digest=file_sha256(Path(args.manifest).expanduser().resolve()),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "backup":
        targets = manifest_honcho_targets(Path(args.manifest))
        if args.database != targets["database"]:
            raise ValueError("backup database does not match the dedicated public service")
        assert_public_database_isolation(
            args.database, str(targets["workspace"])
        )
        print(json.dumps(create_backup(args.database, Path(args.output)), indent=2, sort_keys=True))
        return 0

    if args.command == "restore-verify":
        result = restore_verify(Path(args.backup))
        result["mechanical_restore_verified"] = True
        if args.for_service_restore:
            if not args.manifest:
                raise ValueError("service restore verification requires --manifest")
            targets = manifest_honcho_targets(Path(args.manifest))
            tombstones = _load_tombstone_records(Path(targets["tombstone_dir"]))
            result["blocking_tombstone_count"] = len(tombstones)
            result["tombstone_set_digest"] = sha256_json(tombstones)
            result["serve_safe"] = False
            result["reason"] = "exact_replay_must_run_on_the_restored_service_database"
            print(json.dumps(result, indent=2, sort_keys=True))
            return 2
        result["serve_safe"] = False
        result["reason"] = "mechanical_restore_only_tombstone_gate_not_evaluated"
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if args.command == "deletion-quiescence-receipt":
        targets = manifest_honcho_targets(Path(args.manifest))
        if args.database != targets["database"]:
            raise ValueError("quiescence database does not match the instance manifest")
        receipt = create_honcho_quiescence_receipt(
            args.database,
            targets["base_url"],
            _public_child_service_names(
                str((manifest_payload(Path(args.manifest)).get("instance") or {}).get("slug") or "")
            ),
            Path(targets["server_root"]),
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
            confirm_digest=args.confirm_digest,
            backup_path=Path(args.backup),
            quiescence_receipt=quiescence,
            base_url=targets["base_url"],
            redis_url=targets["redis_url"],
            server_root=Path(targets["server_root"]),
            tombstone_path=canonical_tombstone_path(targets, plan),
            manifest_digest=file_sha256(Path(args.manifest).expanduser().resolve()),
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
