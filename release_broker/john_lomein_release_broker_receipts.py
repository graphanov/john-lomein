#!/usr/bin/env python3
"""Signed, append-chained receipts for the protected release broker.

The release broker is the only John Lomein component allowed to hold a
GitHub credential with ``contents:write``.  Its receipts are therefore a
security boundary, not ordinary diagnostic output.  This module:

* independently normalizes every receipt field;
* binds the receipt to the exact packet, owner authorization, repository,
  GitHub App installation, bundle order, and merge evidence;
* signs only canonical JSON with an in-process Ed25519 key;
* loads signing and verification keys without following the final symlink and
  rejects unsafe owners, modes, hard links, and parent directories; and
* verifies individual receipts and append-only receipt chains offline.

Receipt payloads deliberately contain digests of the owner actor and nonce,
not the raw nonce or approval text.  The durable broker store remains the
authoritative replay-control boundary; the receipt proves what that boundary
authorized and observed.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import os
import re
import stat
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from release_broker.john_lomein_release_broker_protocol import (
    BRANCH_RE,
    INSTANCE_SLUG_RE,
    KEY_ID_RE,
    MAX_CLOCK_SKEW_SECONDS,
    MAX_SAFE_JSON_INTEGER,
    OID_RE,
    PACKET_ID_RE,
    REPOSITORY_RE,
    SHA256_RE,
    TOKEN_RE,
    ReleaseBrokerProtocolError,
    canonical_json,
    changed_paths_digest,
    config_digest,
    normalize_config,
    normalize_release_packet,
    ordered_prs_digest,
    owner_assertion_digest,
    parse_json_bytes,
    sha256_bytes,
    sha256_json,
    sha256_text,
)


RECEIPT_PAYLOAD_SCHEMA = (
    "john-lomein.protected-release-broker-receipt.v1"
)
RECEIPT_ENVELOPE_SCHEMA = (
    "john-lomein.protected-release-broker-signed-receipt.v1"
)
SIGNATURE_ALGORITHM = "ed25519"
MERGE_METHOD = "squash"
ZERO_DIGEST = "sha256:" + ("0" * 64)

MAX_RECEIPT_BYTES = 1024 * 1024
MAX_KEY_BYTES = 64 * 1024
MAX_STEPS = 50
MAX_RECEIPT_DURATION_SECONDS = 24 * 60 * 60

RECEIPT_ID_RE = re.compile(r"^jlrrc-[0-9a-f]{24}$")
APP_SLUG_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$"
)
ATTEMPT_ID_RE = re.compile(
    r"^jlra-[A-Za-z0-9._:@+~-]{1,120}$"
)
REASON_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")
LOGIN_OR_ACTOR_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._:@/+~-]{0,250}(?:\[bot\])?)?$"
)

TERMINAL_OUTCOMES = frozenset(
    {"succeeded", "rejected", "partial", "indeterminate"}
)
STEP_OUTCOMES = frozenset(
    {"merged", "rejected", "not_attempted", "indeterminate"}
)


class ReleaseBrokerReceiptError(ReleaseBrokerProtocolError):
    """A malformed, unauthenticated, or context-mismatched receipt."""


def _mapping(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseBrokerReceiptError(f"{field} must be an object")
    return value


def _strict_keys(
    value: Mapping[str, Any],
    *,
    field: str,
    required: set[str],
) -> None:
    unknown = sorted(set(value) - required)
    missing = sorted(required - set(value))
    if unknown:
        raise ReleaseBrokerReceiptError(f"{field} contains unknown fields")
    if missing:
        raise ReleaseBrokerReceiptError(
            f"{field} is missing required fields"
        )


def _positive_int(
    value: Any,
    *,
    field: str,
    maximum: int = MAX_SAFE_JSON_INTEGER,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReleaseBrokerReceiptError(f"{field} must be an integer")
    if value <= 0 or value > maximum:
        raise ReleaseBrokerReceiptError(
            f"{field} is outside the allowed range"
        )
    return value


def _nonnegative_int(
    value: Any,
    *,
    field: str,
    maximum: int = MAX_SAFE_JSON_INTEGER,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReleaseBrokerReceiptError(f"{field} must be an integer")
    if value < 0 or value > maximum:
        raise ReleaseBrokerReceiptError(
            f"{field} is outside the allowed range"
        )
    return value


def _uid(value: Any, *, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 2**31 - 1
    ):
        raise ReleaseBrokerReceiptError(f"{field} must be a UID")
    return value


def _gid(value: Any, *, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 2**31 - 1
    ):
        raise ReleaseBrokerReceiptError(f"{field} must be a GID")
    return value


def _token(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        raise ReleaseBrokerReceiptError(f"{field} is invalid")
    return value


def _key_id(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not KEY_ID_RE.fullmatch(value):
        raise ReleaseBrokerReceiptError(f"{field} is invalid")
    return value


def _digest(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ReleaseBrokerReceiptError(
            f"{field} must be a SHA-256 digest"
        )
    return value


def _oid(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not OID_RE.fullmatch(value):
        raise ReleaseBrokerReceiptError(f"{field} must be a full Git OID")
    return value


def _optional_oid(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    return _oid(value, field=field)


def _optional_attempt_id(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not ATTEMPT_ID_RE.fullmatch(value):
        raise ReleaseBrokerReceiptError(f"{field} is invalid")
    return value


def _actor(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not LOGIN_OR_ACTOR_RE.fullmatch(value):
        raise ReleaseBrokerReceiptError(f"{field} is invalid")
    return value


def _reason(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not REASON_CODE_RE.fullmatch(value):
        raise ReleaseBrokerReceiptError(f"{field} is invalid")
    return value


def _timestamp(value: Any, *, field: str) -> tuple[str, datetime]:
    if not isinstance(value, str):
        raise ReleaseBrokerReceiptError(f"{field} must be a UTC timestamp")
    try:
        parsed = datetime.strptime(
            value, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ReleaseBrokerReceiptError(
            f"{field} must be a canonical UTC timestamp"
        ) from exc
    if parsed.year < 2020:
        raise ReleaseBrokerReceiptError(
            f"{field} is outside the allowed range"
        )
    return value, parsed


def _optional_timestamp(
    value: Any,
    *,
    field: str,
) -> tuple[str | None, datetime | None]:
    if value is None:
        return None, None
    return _timestamp(value, field=field)


def _utc_text(value: datetime | str, *, field: str) -> str:
    if isinstance(value, str):
        return _timestamp(value, field=field)[0]
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ReleaseBrokerReceiptError(
            f"{field} must be timezone-aware"
        )
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _optional_utc_text(
    value: datetime | str | None,
    *,
    field: str,
) -> str | None:
    if value is None:
        return None
    return _utc_text(value, field=field)


def _payload_id_material(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in payload.items()
        if key != "receipt_id"
    }


def _normalize_broker(raw: Any) -> dict[str, Any]:
    broker = _mapping(raw, field="release receipt broker binding")
    _strict_keys(
        broker,
        field="release receipt broker binding",
        required={"id", "uid", "config_sha256", "signing_key"},
    )
    signing_key = _mapping(
        broker.get("signing_key"),
        field="release receipt signing-key binding",
    )
    _strict_keys(
        signing_key,
        field="release receipt signing-key binding",
        required={"key_id", "public_key_sha256"},
    )
    return {
        "id": _token(broker.get("id"), field="release receipt broker ID"),
        "uid": _uid(broker.get("uid"), field="release receipt broker UID"),
        "config_sha256": _digest(
            broker.get("config_sha256"),
            field="release receipt config digest",
        ),
        "signing_key": {
            "key_id": _key_id(
                signing_key.get("key_id"),
                field="release receipt signing key ID",
            ),
            "public_key_sha256": _digest(
                signing_key.get("public_key_sha256"),
                field="release receipt signing public-key fingerprint",
            ),
        },
    }


def _normalize_packet_binding(raw: Any) -> dict[str, Any]:
    packet = _mapping(raw, field="release receipt packet binding")
    _strict_keys(
        packet,
        field="release receipt packet binding",
        required={
            "packet_id",
            "packet_digest",
            "request_digest",
            "owner_assertion_digest",
            "owner_key_id",
            "owner_actor_digest",
            "owner_nonce_digest",
        },
    )
    packet_id = packet.get("packet_id")
    if not isinstance(packet_id, str) or not PACKET_ID_RE.fullmatch(
        packet_id
    ):
        raise ReleaseBrokerReceiptError(
            "release receipt packet ID is invalid"
        )
    return {
        "packet_id": packet_id,
        "packet_digest": _digest(
            packet.get("packet_digest"),
            field="release receipt packet digest",
        ),
        "request_digest": _digest(
            packet.get("request_digest"),
            field="release receipt request digest",
        ),
        "owner_assertion_digest": _digest(
            packet.get("owner_assertion_digest"),
            field="release receipt owner assertion digest",
        ),
        "owner_key_id": _key_id(
            packet.get("owner_key_id"),
            field="release receipt owner key ID",
        ),
        "owner_actor_digest": _digest(
            packet.get("owner_actor_digest"),
            field="release receipt owner actor digest",
        ),
        "owner_nonce_digest": _digest(
            packet.get("owner_nonce_digest"),
            field="release receipt owner nonce digest",
        ),
    }


def _normalize_repository(raw: Any) -> dict[str, Any]:
    repository = _mapping(raw, field="release receipt repository binding")
    _strict_keys(
        repository,
        field="release receipt repository binding",
        required={"id", "full_name", "default_branch"},
    )
    full_name = repository.get("full_name")
    if not isinstance(full_name, str) or not REPOSITORY_RE.fullmatch(
        full_name
    ):
        raise ReleaseBrokerReceiptError(
            "release receipt repository name is invalid"
        )
    default_branch = repository.get("default_branch")
    if not isinstance(default_branch, str) or not BRANCH_RE.fullmatch(
        default_branch
    ):
        raise ReleaseBrokerReceiptError(
            "release receipt default branch is invalid"
        )
    return {
        "id": _positive_int(
            repository.get("id"),
            field="release receipt repository ID",
        ),
        "full_name": full_name,
        "default_branch": default_branch,
    }


def _normalize_github_app(raw: Any) -> dict[str, Any]:
    app = _mapping(raw, field="release receipt GitHub App binding")
    _strict_keys(
        app,
        field="release receipt GitHub App binding",
        required={"app_id", "app_slug", "installation_id"},
    )
    app_slug = app.get("app_slug")
    if not isinstance(app_slug, str) or not APP_SLUG_RE.fullmatch(app_slug):
        raise ReleaseBrokerReceiptError(
            "release receipt GitHub App slug is invalid"
        )
    return {
        "app_id": _positive_int(
            app.get("app_id"),
            field="release receipt GitHub App ID",
        ),
        "app_slug": app_slug,
        "installation_id": _positive_int(
            app.get("installation_id"),
            field="release receipt GitHub installation ID",
        ),
    }


def _normalize_bundle_binding(raw: Any) -> dict[str, Any]:
    bundle = _mapping(raw, field="release receipt bundle binding")
    _strict_keys(
        bundle,
        field="release receipt bundle binding",
        required={
            "bundle_id",
            "bundle_digest",
            "pr_count",
            "ordered_prs_digest",
            "changed_paths_digest",
            "initial_base_sha",
            "merge_method",
            "publish",
            "train_attestation_digest",
        },
    )
    bundle_id = bundle.get("bundle_id")
    if (
        not isinstance(bundle_id, str)
        or not re.fullmatch(r"^jlb-[0-9a-f]{24}$", bundle_id)
    ):
        raise ReleaseBrokerReceiptError(
            "release receipt bundle ID is invalid"
        )
    if bundle.get("merge_method") != MERGE_METHOD:
        raise ReleaseBrokerReceiptError(
            "release receipt merge method must be squash"
        )
    if bundle.get("publish") is not False:
        raise ReleaseBrokerReceiptError(
            "release receipt may not claim publishing authority"
        )
    train_digest = bundle.get("train_attestation_digest")
    if train_digest is not None:
        train_digest = _digest(
            train_digest,
            field="release receipt train attestation digest",
        )
    return {
        "bundle_id": bundle_id,
        "bundle_digest": _digest(
            bundle.get("bundle_digest"),
            field="release receipt bundle digest",
        ),
        "pr_count": _positive_int(
            bundle.get("pr_count"),
            field="release receipt PR count",
            maximum=MAX_STEPS,
        ),
        "ordered_prs_digest": _digest(
            bundle.get("ordered_prs_digest"),
            field="release receipt ordered PR digest",
        ),
        "changed_paths_digest": _digest(
            bundle.get("changed_paths_digest"),
            field="release receipt changed-path digest",
        ),
        "initial_base_sha": _oid(
            bundle.get("initial_base_sha"),
            field="release receipt initial base SHA",
        ),
        "merge_method": MERGE_METHOD,
        "publish": False,
        "train_attestation_digest": train_digest,
    }


def _normalize_step(
    raw: Any,
    *,
    position: int,
    receipt_started: datetime,
    receipt_completed: datetime,
) -> tuple[dict[str, Any], datetime, datetime | None, datetime]:
    step = _mapping(raw, field=f"release receipt step {position}")
    _strict_keys(
        step,
        field=f"release receipt step {position}",
        required={
            "position",
            "pr_number",
            "authorized_head_sha",
            "expected_base_sha",
            "precondition_digest",
            "attempt_id",
            "outcome",
            "reason_code",
            "merge_sha",
            "parent_sha",
            "tree_sha",
            "merged_by",
            "started_at",
            "attempted_at",
            "completed_at",
        },
    )
    normalized_position = _nonnegative_int(
        step.get("position"),
        field=f"release receipt step {position} position",
        maximum=MAX_STEPS - 1,
    )
    if normalized_position != position:
        raise ReleaseBrokerReceiptError(
            "release receipt step positions must be contiguous and ordered"
        )
    outcome = step.get("outcome")
    if outcome not in STEP_OUTCOMES:
        raise ReleaseBrokerReceiptError(
            f"release receipt step {position} outcome is invalid"
        )
    reason_code = _reason(
        step.get("reason_code"),
        field=f"release receipt step {position} reason code",
    )
    attempt_id = _optional_attempt_id(
        step.get("attempt_id"),
        field=f"release receipt step {position} attempt ID",
    )
    merge_sha = _optional_oid(
        step.get("merge_sha"),
        field=f"release receipt step {position} merge SHA",
    )
    parent_sha = _optional_oid(
        step.get("parent_sha"),
        field=f"release receipt step {position} parent SHA",
    )
    tree_sha = _optional_oid(
        step.get("tree_sha"),
        field=f"release receipt step {position} tree SHA",
    )
    merged_by = _actor(
        step.get("merged_by"),
        field=f"release receipt step {position} merge actor",
    )
    evidence = (merge_sha, parent_sha, tree_sha, merged_by)
    if any(value is None for value in evidence) != all(
        value is None for value in evidence
    ):
        raise ReleaseBrokerReceiptError(
            f"release receipt step {position} merge evidence is incomplete"
        )
    started_at, started = _timestamp(
        step.get("started_at"),
        field=f"release receipt step {position} started_at",
    )
    attempted_at, attempted = _optional_timestamp(
        step.get("attempted_at"),
        field=f"release receipt step {position} attempted_at",
    )
    completed_at, completed = _timestamp(
        step.get("completed_at"),
        field=f"release receipt step {position} completed_at",
    )
    if not receipt_started <= started <= completed <= receipt_completed:
        raise ReleaseBrokerReceiptError(
            f"release receipt step {position} timestamps are inconsistent"
        )
    if attempted is not None and not started <= attempted <= completed:
        raise ReleaseBrokerReceiptError(
            f"release receipt step {position} attempt time is inconsistent"
        )
    expected_base = _oid(
        step.get("expected_base_sha"),
        field=f"release receipt step {position} expected base SHA",
    )
    if outcome == "merged":
        if (
            attempt_id is None
            or attempted is None
            or merge_sha is None
            or parent_sha != expected_base
            or reason_code != "merge_confirmed"
        ):
            raise ReleaseBrokerReceiptError(
                f"release receipt step {position} lacks confirmed merge evidence"
            )
    elif outcome in {"rejected", "not_attempted"}:
        if (
            attempt_id is not None
            or attempted is not None
            or any(value is not None for value in evidence)
        ):
            raise ReleaseBrokerReceiptError(
                f"release receipt step {position} claims an unapproved mutation"
            )
        if outcome == "not_attempted" and reason_code != "not_reached":
            raise ReleaseBrokerReceiptError(
                f"release receipt step {position} not-attempted reason is invalid"
            )
    else:
        if (
            attempt_id is None
            or attempted is None
            or not reason_code.startswith("indeterminate_")
        ):
            raise ReleaseBrokerReceiptError(
                f"release receipt step {position} indeterminate evidence is invalid"
            )
        if parent_sha is not None and parent_sha != expected_base:
            raise ReleaseBrokerReceiptError(
                f"release receipt step {position} parent does not match its base"
            )
    return (
        {
            "position": normalized_position,
            "pr_number": _positive_int(
                step.get("pr_number"),
                field=f"release receipt step {position} PR number",
                maximum=2**31 - 1,
            ),
            "authorized_head_sha": _oid(
                step.get("authorized_head_sha"),
                field=f"release receipt step {position} authorized head",
            ),
            "expected_base_sha": expected_base,
            "precondition_digest": _digest(
                step.get("precondition_digest"),
                field=f"release receipt step {position} precondition digest",
            ),
            "attempt_id": attempt_id,
            "outcome": outcome,
            "reason_code": reason_code,
            "merge_sha": merge_sha,
            "parent_sha": parent_sha,
            "tree_sha": tree_sha,
            "merged_by": merged_by,
            "started_at": started_at,
            "attempted_at": attempted_at,
            "completed_at": completed_at,
        },
        started,
        attempted,
        completed,
    )


def _normalize_final_branch(
    raw: Any,
    *,
    repository: Mapping[str, Any],
    receipt_started: datetime,
    receipt_completed: datetime,
) -> tuple[dict[str, Any], datetime | None]:
    branch = _mapping(raw, field="release receipt final branch")
    _strict_keys(
        branch,
        field="release receipt final branch",
        required={"name", "head_sha", "tree_sha", "observed_at"},
    )
    name = branch.get("name")
    if name != repository["default_branch"]:
        raise ReleaseBrokerReceiptError(
            "release receipt final branch is not the bound default branch"
        )
    head_sha = _optional_oid(
        branch.get("head_sha"),
        field="release receipt final branch head",
    )
    tree_sha = _optional_oid(
        branch.get("tree_sha"),
        field="release receipt final branch tree",
    )
    observed_at, observed = _optional_timestamp(
        branch.get("observed_at"),
        field="release receipt final branch observed_at",
    )
    present = (head_sha is not None, tree_sha is not None, observed is not None)
    if any(present) and not all(present):
        raise ReleaseBrokerReceiptError(
            "release receipt final branch evidence is incomplete"
        )
    if observed is not None and not (
        receipt_started <= observed <= receipt_completed
    ):
        raise ReleaseBrokerReceiptError(
            "release receipt final branch time is inconsistent"
        )
    return {
        "name": name,
        "head_sha": head_sha,
        "tree_sha": tree_sha,
        "observed_at": observed_at,
    }, observed


def normalize_receipt_payload(raw: Any) -> dict[str, Any]:
    """Normalize and cross-check one release receipt payload."""

    payload = _mapping(raw, field="release broker receipt payload")
    _strict_keys(
        payload,
        field="release broker receipt payload",
        required={
            "schema_version",
            "receipt_id",
            "broker",
            "instance_slug",
            "packet",
            "repository",
            "github_app",
            "bundle",
            "steps",
            "final_branch",
            "outcome",
            "reason_code",
            "started_at",
            "completed_at",
            "previous_receipt_sha256",
        },
    )
    if payload.get("schema_version") != RECEIPT_PAYLOAD_SCHEMA:
        raise ReleaseBrokerReceiptError(
            "release broker receipt payload schema is unsupported"
        )
    broker = _normalize_broker(payload.get("broker"))
    instance_slug = payload.get("instance_slug")
    if (
        not isinstance(instance_slug, str)
        or not INSTANCE_SLUG_RE.fullmatch(instance_slug)
    ):
        raise ReleaseBrokerReceiptError(
            "release receipt instance slug is invalid"
        )
    packet = _normalize_packet_binding(payload.get("packet"))
    repository = _normalize_repository(payload.get("repository"))
    github_app = _normalize_github_app(payload.get("github_app"))
    bundle = _normalize_bundle_binding(payload.get("bundle"))
    started_at, started = _timestamp(
        payload.get("started_at"),
        field="release receipt started_at",
    )
    completed_at, completed = _timestamp(
        payload.get("completed_at"),
        field="release receipt completed_at",
    )
    duration = int((completed - started).total_seconds())
    if duration < 0 or duration > MAX_RECEIPT_DURATION_SECONDS:
        raise ReleaseBrokerReceiptError(
            "release receipt lifetime is invalid"
        )
    raw_steps = payload.get("steps")
    if (
        not isinstance(raw_steps, list)
        or not raw_steps
        or len(raw_steps) > MAX_STEPS
    ):
        raise ReleaseBrokerReceiptError(
            "release receipt steps are invalid"
        )
    steps: list[dict[str, Any]] = []
    step_times: list[tuple[datetime, datetime | None, datetime]] = []
    seen_prs: set[int] = set()
    seen_attempts: set[str] = set()
    for position, raw_step in enumerate(raw_steps):
        normalized_step, step_started, attempted, step_completed = (
            _normalize_step(
                raw_step,
                position=position,
                receipt_started=started,
                receipt_completed=completed,
            )
        )
        if normalized_step["pr_number"] in seen_prs:
            raise ReleaseBrokerReceiptError(
                "release receipt PR numbers must be unique"
            )
        seen_prs.add(normalized_step["pr_number"])
        attempt_id = normalized_step["attempt_id"]
        if attempt_id is not None:
            if attempt_id in seen_attempts:
                raise ReleaseBrokerReceiptError(
                    "release receipt attempt IDs must be unique"
                )
            seen_attempts.add(attempt_id)
        steps.append(normalized_step)
        step_times.append((step_started, attempted, step_completed))
    if len(steps) != bundle["pr_count"]:
        raise ReleaseBrokerReceiptError(
            "release receipt step count does not match the bundle"
        )
    if steps[0]["expected_base_sha"] != bundle["initial_base_sha"]:
        raise ReleaseBrokerReceiptError(
            "release receipt first step does not use the initial base"
        )
    for position in range(1, len(steps)):
        previous = steps[position - 1]
        current = steps[position]
        if previous["outcome"] == "merged":
            required_base = previous["merge_sha"]
        else:
            required_base = previous["expected_base_sha"]
        if current["expected_base_sha"] != required_base:
            raise ReleaseBrokerReceiptError(
                "release receipt step base chain is inconsistent"
            )
        if step_times[position][0] < step_times[position - 1][2]:
            raise ReleaseBrokerReceiptError(
                "release receipt step execution overlaps or is out of order"
            )

    encountered_stop = False
    for step in steps:
        if encountered_stop and step["outcome"] != "not_attempted":
            raise ReleaseBrokerReceiptError(
                "release receipt cannot execute steps after a stopped step"
            )
        if step["outcome"] != "merged":
            encountered_stop = True

    final_branch, final_observed = _normalize_final_branch(
        payload.get("final_branch"),
        repository=repository,
        receipt_started=started,
        receipt_completed=completed,
    )
    outcome = payload.get("outcome")
    if outcome not in TERMINAL_OUTCOMES:
        raise ReleaseBrokerReceiptError(
            "release receipt terminal outcome is invalid"
        )
    reason_code = _reason(
        payload.get("reason_code"),
        field="release receipt terminal reason code",
    )
    step_outcomes = [step["outcome"] for step in steps]
    merged_steps = [step for step in steps if step["outcome"] == "merged"]
    if outcome == "succeeded":
        if (
            any(value != "merged" for value in step_outcomes)
            or reason_code != "release_merged"
        ):
            raise ReleaseBrokerReceiptError(
                "successful release receipt does not prove every merge"
            )
    elif outcome == "rejected":
        if (
            merged_steps
            or "indeterminate" in step_outcomes
            or "rejected" not in step_outcomes
        ):
            raise ReleaseBrokerReceiptError(
                "rejected release receipt has inconsistent step outcomes"
            )
        if not reason_code.startswith(
            (
                "request_",
                "owner_",
                "policy_",
                "precondition_",
                "budget_",
                "circuit_",
                "config_",
            )
        ):
            raise ReleaseBrokerReceiptError(
                "rejected release receipt reason is inconsistent"
            )
    elif outcome == "partial":
        if (
            not merged_steps
            or len(merged_steps) == len(steps)
            or "rejected" not in step_outcomes
            or "indeterminate" in step_outcomes
            or not reason_code.startswith("partial_")
        ):
            raise ReleaseBrokerReceiptError(
                "partial release receipt has inconsistent step outcomes"
            )
    else:
        if (
            "indeterminate" not in step_outcomes
            or not reason_code.startswith("indeterminate_")
        ):
            raise ReleaseBrokerReceiptError(
                "indeterminate release receipt has inconsistent evidence"
            )

    if outcome in {"succeeded", "partial"}:
        last_merge = merged_steps[-1]
        if (
            final_branch["head_sha"] != last_merge["merge_sha"]
            or final_branch["tree_sha"] != last_merge["tree_sha"]
            or final_observed is None
            or final_observed
            < _timestamp(
                last_merge["completed_at"],
                field="release receipt last merge completed_at",
            )[1]
        ):
            raise ReleaseBrokerReceiptError(
                "release receipt final branch does not prove the terminal merge"
            )

    previous = _digest(
        payload.get("previous_receipt_sha256"),
        field="release receipt previous hash",
    )
    normalized = {
        "schema_version": RECEIPT_PAYLOAD_SCHEMA,
        "receipt_id": str(payload.get("receipt_id") or ""),
        "broker": broker,
        "instance_slug": instance_slug,
        "packet": packet,
        "repository": repository,
        "github_app": github_app,
        "bundle": bundle,
        "steps": steps,
        "final_branch": final_branch,
        "outcome": outcome,
        "reason_code": reason_code,
        "started_at": started_at,
        "completed_at": completed_at,
        "previous_receipt_sha256": previous,
    }
    expected_id = (
        "jlrrc-"
        + sha256_json(_payload_id_material(normalized)).removeprefix(
            "sha256:"
        )[:24]
    )
    if (
        not RECEIPT_ID_RE.fullmatch(normalized["receipt_id"])
        or normalized["receipt_id"] != expected_id
    ):
        raise ReleaseBrokerReceiptError(
            "release receipt ID does not match its payload"
        )
    if len(canonical_json(normalized)) > MAX_RECEIPT_BYTES:
        raise ReleaseBrokerReceiptError(
            "release receipt payload exceeds its size limit"
        )
    return normalized


def _actor_digest(assertion_payload: Mapping[str, Any]) -> str:
    return sha256_json(
        {
            "issuer": assertion_payload["issuer"],
            "actor_id": assertion_payload["actor_id"],
            "actor_login": assertion_payload["actor_login"],
            "tier": assertion_payload["tier"],
        }
    )


def _packet_binding(packet: Mapping[str, Any]) -> dict[str, Any]:
    assertion = packet["request"]["owner_assertion"]
    assertion_payload = assertion["payload"]
    return {
        "packet_id": packet["packet_id"],
        "packet_digest": sha256_json(packet),
        "request_digest": packet["request_digest"],
        "owner_assertion_digest": owner_assertion_digest(assertion),
        "owner_key_id": assertion["key_id"],
        "owner_actor_digest": _actor_digest(assertion_payload),
        "owner_nonce_digest": sha256_text(assertion_payload["nonce"]),
    }


def assert_receipt_packet_binding(
    payload: Any,
    packet: Any,
) -> dict[str, Any]:
    """Bind a normalized receipt back to the complete release packet."""

    normalized_payload = normalize_receipt_payload(payload)
    started = _timestamp(
        normalized_payload["started_at"],
        field="release receipt started_at",
    )[1]
    try:
        normalized_packet = normalize_release_packet(
            packet,
            now=started,
            allow_expired=True,
            allow_expired_assertion=True,
        )
    except ReleaseBrokerProtocolError as exc:
        raise ReleaseBrokerReceiptError(str(exc)) from exc
    bundle = normalized_packet["request"]["bundle"]
    expected_repository = bundle["repository"]
    expected_bundle = {
        "bundle_id": bundle["bundle_id"],
        "bundle_digest": bundle["bundle_digest"],
        "pr_count": len(bundle["ordered_prs"]),
        "ordered_prs_digest": ordered_prs_digest(bundle),
        "changed_paths_digest": changed_paths_digest(bundle),
        "initial_base_sha": bundle["initial_base_sha"],
        "merge_method": MERGE_METHOD,
        "publish": False,
        "train_attestation_digest": bundle[
            "train_attestation_digest"
        ],
    }
    if normalized_payload["packet"] != _packet_binding(normalized_packet):
        raise ReleaseBrokerReceiptError(
            "release receipt packet binding does not match"
        )
    if normalized_payload["repository"] != expected_repository:
        raise ReleaseBrokerReceiptError(
            "release receipt repository binding does not match"
        )
    if normalized_payload["instance_slug"] != bundle["instance_slug"]:
        raise ReleaseBrokerReceiptError(
            "release receipt instance binding does not match"
        )
    if normalized_payload["bundle"] != expected_bundle:
        raise ReleaseBrokerReceiptError(
            "release receipt bundle binding does not match"
        )
    for receipt_step, authorized in zip(
        normalized_payload["steps"],
        bundle["ordered_prs"],
        strict=True,
    ):
        expected_step = (
            authorized["position"],
            authorized["number"],
            authorized["head_sha"],
        )
        observed_step = (
            receipt_step["position"],
            receipt_step["pr_number"],
            receipt_step["authorized_head_sha"],
        )
        if observed_step != expected_step:
            raise ReleaseBrokerReceiptError(
                "release receipt step authorization does not match"
            )
    packet_created = _timestamp(
        normalized_packet["created_at"],
        field="release packet created_at",
    )[1]
    packet_expires = _timestamp(
        normalized_packet["expires_at"],
        field="release packet expires_at",
    )[1]
    if (
        started < packet_created - timedelta(seconds=MAX_CLOCK_SKEW_SECONDS)
        or started >= packet_expires
    ):
        raise ReleaseBrokerReceiptError(
            "release receipt started outside packet authority"
        )
    return normalized_payload


def build_receipt_payload(
    packet: Any,
    *,
    broker_id: str,
    broker_uid: int,
    config_sha256: str,
    signing_key_id: str,
    signing_public_key_sha256: str,
    github_app: Mapping[str, Any],
    steps: Sequence[Mapping[str, Any]],
    final_branch: Mapping[str, Any],
    outcome: str,
    reason_code: str,
    started_at: datetime | str,
    completed_at: datetime | str,
    previous_receipt_sha256: str = ZERO_DIGEST,
) -> dict[str, Any]:
    """Build a strict payload from a historically valid release packet."""

    started_text = _utc_text(
        started_at, field="release receipt started_at"
    )
    completed_text = _utc_text(
        completed_at, field="release receipt completed_at"
    )
    started = _timestamp(
        started_text, field="release receipt started_at"
    )[1]
    try:
        normalized_packet = normalize_release_packet(
            packet,
            now=started,
            allow_expired=True,
            allow_expired_assertion=True,
        )
    except ReleaseBrokerProtocolError as exc:
        raise ReleaseBrokerReceiptError(str(exc)) from exc
    bundle = normalized_packet["request"]["bundle"]
    normalized_steps: list[dict[str, Any]] = []
    for index, step in enumerate(steps):
        copied = dict(step)
        copied["started_at"] = _utc_text(
            copied.get("started_at"),
            field=f"release receipt step {index} started_at",
        )
        copied["attempted_at"] = _optional_utc_text(
            copied.get("attempted_at"),
            field=f"release receipt step {index} attempted_at",
        )
        copied["completed_at"] = _utc_text(
            copied.get("completed_at"),
            field=f"release receipt step {index} completed_at",
        )
        normalized_steps.append(copied)
    normalized_final = dict(final_branch)
    normalized_final["observed_at"] = _optional_utc_text(
        normalized_final.get("observed_at"),
        field="release receipt final branch observed_at",
    )
    body = {
        "schema_version": RECEIPT_PAYLOAD_SCHEMA,
        "receipt_id": "",
        "broker": {
            "id": broker_id,
            "uid": broker_uid,
            "config_sha256": config_sha256,
            "signing_key": {
                "key_id": signing_key_id,
                "public_key_sha256": signing_public_key_sha256,
            },
        },
        "instance_slug": bundle["instance_slug"],
        "packet": _packet_binding(normalized_packet),
        "repository": bundle["repository"],
        "github_app": dict(github_app),
        "bundle": {
            "bundle_id": bundle["bundle_id"],
            "bundle_digest": bundle["bundle_digest"],
            "pr_count": len(bundle["ordered_prs"]),
            "ordered_prs_digest": ordered_prs_digest(bundle),
            "changed_paths_digest": changed_paths_digest(bundle),
            "initial_base_sha": bundle["initial_base_sha"],
            "merge_method": MERGE_METHOD,
            "publish": False,
            "train_attestation_digest": bundle[
                "train_attestation_digest"
            ],
        },
        "steps": normalized_steps,
        "final_branch": normalized_final,
        "outcome": outcome,
        "reason_code": reason_code,
        "started_at": started_text,
        "completed_at": completed_text,
        "previous_receipt_sha256": previous_receipt_sha256,
    }
    body["receipt_id"] = (
        "jlrrc-"
        + sha256_json(_payload_id_material(body)).removeprefix("sha256:")[
            :24
        ]
    )
    normalized = normalize_receipt_payload(body)
    return assert_receipt_packet_binding(normalized, normalized_packet)


def assert_receipt_config_binding(
    payload: Any,
    config: Any,
) -> dict[str, Any]:
    """Bind a receipt to the complete normalized root-owned configuration."""

    normalized_payload = normalize_receipt_payload(payload)
    try:
        normalized_config = normalize_config(config)
    except ReleaseBrokerProtocolError as exc:
        raise ReleaseBrokerReceiptError(str(exc)) from exc
    expected_app = {
        field: normalized_config["github_app"][field]
        for field in ("app_id", "app_slug", "installation_id")
    }
    expected = {
        "broker": {
            "id": normalized_config["broker_id"],
            "uid": normalized_config["broker_uid"],
            "config_sha256": config_digest(normalized_config),
            "signing_key": {
                "key_id": normalized_config["receipt_signing"]["key_id"],
                "public_key_sha256": normalized_config[
                    "receipt_signing"
                ]["public_key_sha256"],
            },
        },
        "instance_slug": normalized_config["instance"]["slug"],
        "repository": normalized_config["instance"]["repository"],
        "github_app": expected_app,
    }
    for field, value in expected.items():
        if normalized_payload[field] != value:
            raise ReleaseBrokerReceiptError(
                f"release receipt {field} config binding does not match"
            )
    return normalized_payload


def build_configured_receipt_payload(
    config: Any,
    packet: Any,
    *,
    steps: Sequence[Mapping[str, Any]],
    final_branch: Mapping[str, Any],
    outcome: str,
    reason_code: str,
    started_at: datetime | str,
    completed_at: datetime | str,
    previous_receipt_sha256: str = ZERO_DIGEST,
) -> dict[str, Any]:
    """Build a payload directly from the root-owned broker configuration."""

    try:
        normalized_config = normalize_config(config)
    except ReleaseBrokerProtocolError as exc:
        raise ReleaseBrokerReceiptError(str(exc)) from exc
    if normalized_config["enabled"] is not True:
        raise ReleaseBrokerReceiptError(
            "disabled release broker configuration cannot build receipts"
        )
    app = {
        field: normalized_config["github_app"][field]
        for field in ("app_id", "app_slug", "installation_id")
    }
    payload = build_receipt_payload(
        packet,
        broker_id=normalized_config["broker_id"],
        broker_uid=normalized_config["broker_uid"],
        config_sha256=config_digest(normalized_config),
        signing_key_id=normalized_config["receipt_signing"]["key_id"],
        signing_public_key_sha256=normalized_config[
            "receipt_signing"
        ]["public_key_sha256"],
        github_app=app,
        steps=steps,
        final_branch=final_branch,
        outcome=outcome,
        reason_code=reason_code,
        started_at=started_at,
        completed_at=completed_at,
        previous_receipt_sha256=previous_receipt_sha256,
    )
    return assert_receipt_config_binding(payload, normalized_config)


def _uid_set(
    values: int | Iterable[int] | None,
    *,
    default: Iterable[int],
) -> frozenset[int]:
    if values is None:
        values = default
    elif isinstance(values, int) and not isinstance(values, bool):
        values = (values,)
    normalized: set[int] = set()
    try:
        for value in values:
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                or value > 2**31 - 1
            ):
                raise ReleaseBrokerReceiptError(
                    "trusted key owner UID set is invalid"
                )
            normalized.add(value)
    except TypeError as exc:
        raise ReleaseBrokerReceiptError(
            "trusted key owner UID set is invalid"
        ) from exc
    if not normalized:
        raise ReleaseBrokerReceiptError(
            "trusted key owner UID set is empty"
        )
    return frozenset(normalized)


def _absolute_path(value: Path, *, field: str) -> Path:
    path = Path(value)
    text = str(path)
    if (
        not path.is_absolute()
        or "\x00" in text
        or ".." in path.parts
        or "." in path.parts
        or text != str(Path(text))
    ):
        raise ReleaseBrokerReceiptError(
            f"{field} must be a normalized absolute path"
        )
    return path


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _validate_parent_chain(
    path: Path,
    *,
    field: str,
    owner_uids: frozenset[int],
    trusted_path_root: Path | None,
) -> None:
    stop: Path | None = None
    if trusted_path_root is not None:
        stop = _absolute_path(
            Path(trusted_path_root), field="trusted key path root"
        )
        if not _is_within(path, stop):
            raise ReleaseBrokerReceiptError(
                f"{field} is outside the trusted key path root"
            )
    current = path
    while True:
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise ReleaseBrokerReceiptError(
                f"{field} parent directory is unreadable"
            ) from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ReleaseBrokerReceiptError(
                f"{field} parent directory is unsafe"
            )
        if info.st_uid not in owner_uids:
            raise ReleaseBrokerReceiptError(
                f"{field} parent directory owner is untrusted"
            )
        if info.st_mode & 0o022:
            raise ReleaseBrokerReceiptError(
                f"{field} parent directory is group/other writable"
            )
        if current == stop or current.parent == current:
            return
        current = current.parent


def _key_snapshot(info: os.stat_result) -> tuple[int, ...]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_uid),
        int(info.st_gid),
        int(info.st_nlink),
        int(info.st_size),
        int(
            getattr(
                info,
                "st_mtime_ns",
                round(float(info.st_mtime) * 1_000_000_000),
            )
        ),
        int(
            getattr(
                info,
                "st_ctime_ns",
                round(float(info.st_ctime) * 1_000_000_000),
            )
        ),
    )


def read_trusted_key(
    path: Path,
    *,
    field: str,
    private: bool,
    expected_owner_uids: int | Iterable[int] | None,
    parent_owner_uids: int | Iterable[int] | None,
    trusted_path_root: Path | None = None,
    expected_gid: int | None = None,
    expected_mode: int | None = None,
) -> bytes:
    """Read one bounded, stable key snapshot without following symlinks."""

    path = _absolute_path(Path(path), field=field)
    if private and (
        expected_owner_uids is None
        or expected_gid is None
        or expected_mode is None
    ):
        raise ReleaseBrokerReceiptError(
            f"{field} private-key trust policy must be explicit"
        )
    owners = _uid_set(expected_owner_uids, default=(0,))
    parent_owners = _uid_set(parent_owner_uids, default=(0,))
    normalized_gid = (
        _gid(expected_gid, field=f"{field} expected GID")
        if expected_gid is not None
        else None
    )
    if expected_mode is not None:
        if (
            isinstance(expected_mode, bool)
            or not isinstance(expected_mode, int)
            or expected_mode not in {0o600, 0o640}
        ):
            raise ReleaseBrokerReceiptError(
                f"{field} expected mode must be 0600 or 0640"
            )
    _validate_parent_chain(
        path.parent,
        field=field,
        owner_uids=parent_owners,
        trusted_path_root=trusted_path_root,
    )
    if not hasattr(os, "O_NOFOLLOW"):
        raise ReleaseBrokerReceiptError(
            f"{field} cannot be opened safely on this platform"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseBrokerReceiptError(f"{field} is unreadable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ReleaseBrokerReceiptError(
                f"{field} must be a regular non-symlink file"
            )
        if before.st_nlink != 1:
            raise ReleaseBrokerReceiptError(
                f"{field} must not have hard links"
            )
        if before.st_uid not in owners:
            raise ReleaseBrokerReceiptError(f"{field} owner is untrusted")
        if normalized_gid is not None and before.st_gid != normalized_gid:
            raise ReleaseBrokerReceiptError(
                f"{field} group is untrusted"
            )
        mode = stat.S_IMODE(before.st_mode)
        if expected_mode is not None and mode != expected_mode:
            raise ReleaseBrokerReceiptError(
                f"{field} mode must be exactly {expected_mode:04o}"
            )
        if private:
            if expected_mode is None:
                raise ReleaseBrokerReceiptError(
                    f"{field} private-key mode must be explicit"
                )
        elif mode & 0o022:
            raise ReleaseBrokerReceiptError(
                f"{field} must not be group/other writable"
            )
        if before.st_size <= 0 or before.st_size > MAX_KEY_BYTES:
            raise ReleaseBrokerReceiptError(
                f"{field} has an invalid size"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, MAX_KEY_BYTES + 1 - total),
            )
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_KEY_BYTES:
                raise ReleaseBrokerReceiptError(
                    f"{field} exceeds its size limit"
                )
            chunks.append(chunk)
        raw = b"".join(chunks)
        try:
            after = os.fstat(descriptor)
            named = os.lstat(path)
        except OSError as exc:
            raise ReleaseBrokerReceiptError(
                f"{field} changed while being read"
            ) from exc
        if (
            _key_snapshot(before) != _key_snapshot(after)
            or _key_snapshot(after) != _key_snapshot(named)
            or len(raw) != before.st_size
        ):
            raise ReleaseBrokerReceiptError(
                f"{field} changed while being read"
            )
        return raw
    except OSError as exc:
        raise ReleaseBrokerReceiptError(f"{field} is unreadable") from exc
    finally:
        os.close(descriptor)


def _load_public_key(raw: bytes) -> Ed25519PublicKey:
    if not isinstance(raw, bytes) or b"PUBLIC KEY" not in raw:
        raise ReleaseBrokerReceiptError(
            "release receipt public key is not PEM encoded"
        )
    try:
        key = serialization.load_pem_public_key(raw)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise ReleaseBrokerReceiptError(
            "release receipt public key is invalid"
        ) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ReleaseBrokerReceiptError(
            "release receipt public key is not Ed25519"
        )
    return key


def _load_private_key(raw: bytes) -> Ed25519PrivateKey:
    if not isinstance(raw, bytes) or b"PRIVATE KEY" not in raw:
        raise ReleaseBrokerReceiptError(
            "release receipt private key is not PEM encoded"
        )
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise ReleaseBrokerReceiptError(
            "release receipt private key is invalid"
        ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ReleaseBrokerReceiptError(
            "release receipt private key is not Ed25519"
        )
    return key


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str) or not SIGNATURE_RE.fullmatch(value):
        raise ReleaseBrokerReceiptError(
            "release receipt signature encoding is invalid"
        )
    try:
        decoded = base64.urlsafe_b64decode(value + "==")
    except (ValueError, TypeError, binascii.Error) as exc:
        raise ReleaseBrokerReceiptError(
            "release receipt signature encoding is invalid"
        ) from exc
    if len(decoded) != 64:
        raise ReleaseBrokerReceiptError(
            "release receipt signature size is invalid"
        )
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if not hmac.compare_digest(canonical, value):
        raise ReleaseBrokerReceiptError(
            "release receipt signature is not canonical base64url"
        )
    return decoded


def normalize_receipt_envelope(raw: Any) -> dict[str, Any]:
    envelope = _mapping(raw, field="signed release broker receipt")
    _strict_keys(
        envelope,
        field="signed release broker receipt",
        required={
            "schema_version",
            "algorithm",
            "key_id",
            "public_key_sha256",
            "payload_sha256",
            "payload",
            "signature",
        },
    )
    if envelope.get("schema_version") != RECEIPT_ENVELOPE_SCHEMA:
        raise ReleaseBrokerReceiptError(
            "signed release receipt schema is unsupported"
        )
    if envelope.get("algorithm") != SIGNATURE_ALGORITHM:
        raise ReleaseBrokerReceiptError(
            "signed release receipt algorithm is unsupported"
        )
    key_id = _key_id(
        envelope.get("key_id"),
        field="signed release receipt key ID",
    )
    public_fingerprint = _digest(
        envelope.get("public_key_sha256"),
        field="signed release receipt public-key fingerprint",
    )
    payload_digest = _digest(
        envelope.get("payload_sha256"),
        field="signed release receipt payload digest",
    )
    payload = normalize_receipt_payload(envelope.get("payload"))
    if payload["broker"]["signing_key"] != {
        "key_id": key_id,
        "public_key_sha256": public_fingerprint,
    }:
        raise ReleaseBrokerReceiptError(
            "signed release receipt key identity does not match its payload"
        )
    actual_payload_digest = sha256_bytes(canonical_json(payload))
    if payload_digest != actual_payload_digest:
        raise ReleaseBrokerReceiptError(
            "signed release receipt payload digest does not match"
        )
    signature = envelope.get("signature")
    _decode_signature(signature)
    normalized = {
        "schema_version": RECEIPT_ENVELOPE_SCHEMA,
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "public_key_sha256": public_fingerprint,
        "payload_sha256": actual_payload_digest,
        "payload": payload,
        "signature": signature,
    }
    if len(canonical_json(normalized)) > MAX_RECEIPT_BYTES:
        raise ReleaseBrokerReceiptError(
            "signed release receipt exceeds its size limit"
        )
    return normalized


def _read_receipt_file(path: Path) -> bytes:
    path = _absolute_path(Path(path), field="signed release receipt")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseBrokerReceiptError(
            "signed release receipt is unreadable"
        ) from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ReleaseBrokerReceiptError(
                "signed release receipt must be a regular file"
            )
        if info.st_size > MAX_RECEIPT_BYTES:
            raise ReleaseBrokerReceiptError(
                "signed release receipt exceeds its size limit"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, MAX_RECEIPT_BYTES + 1 - total),
            )
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_RECEIPT_BYTES:
                raise ReleaseBrokerReceiptError(
                    "signed release receipt exceeds its size limit"
                )
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as exc:
        raise ReleaseBrokerReceiptError(
            "signed release receipt is unreadable"
        ) from exc
    finally:
        os.close(descriptor)


def load_receipt(
    source: bytes | bytearray | memoryview | Path | os.PathLike[str],
) -> dict[str, Any]:
    if isinstance(source, (bytes, bytearray, memoryview)):
        raw = bytes(source)
    elif isinstance(source, (Path, os.PathLike)):
        raw = _read_receipt_file(Path(source))
    else:
        raise ReleaseBrokerReceiptError(
            "signed release receipt source must be bytes or a path"
        )
    try:
        value = parse_json_bytes(
            raw,
            field="signed release broker receipt",
            maximum_bytes=MAX_RECEIPT_BYTES,
        )
    except ReleaseBrokerProtocolError as exc:
        raise ReleaseBrokerReceiptError(str(exc)) from exc
    return normalize_receipt_envelope(value)


def _coerce_envelope(source: Any) -> dict[str, Any]:
    if isinstance(source, dict):
        return normalize_receipt_envelope(source)
    if isinstance(
        source, (bytes, bytearray, memoryview, Path, os.PathLike)
    ):
        return load_receipt(source)
    raise ReleaseBrokerReceiptError(
        "signed release receipt source is invalid"
    )


def _assert_expected_bindings(
    envelope: Mapping[str, Any],
    *,
    expected_key_id: str | None,
    expected_broker_id: str | None,
    expected_broker_uid: int | None,
    expected_config_sha256: str | None,
    expected_instance_slug: str | None,
    expected_repository_id: int | None,
    expected_repository_full_name: str | None,
    expected_github_app: Mapping[str, Any] | None,
    packet: Any | None,
) -> None:
    payload = envelope["payload"]
    if expected_key_id is not None:
        expected = _key_id(
            expected_key_id,
            field="pinned release receipt key ID",
        )
        if envelope["key_id"] != expected:
            raise ReleaseBrokerReceiptError(
                "signed release receipt key ID is not pinned"
            )
    if expected_broker_id is not None:
        expected = _token(
            expected_broker_id,
            field="pinned release broker ID",
        )
        if payload["broker"]["id"] != expected:
            raise ReleaseBrokerReceiptError(
                "release receipt broker ID binding does not match"
            )
    if expected_broker_uid is not None:
        expected = _uid(
            expected_broker_uid,
            field="pinned release broker UID",
        )
        if payload["broker"]["uid"] != expected:
            raise ReleaseBrokerReceiptError(
                "release receipt broker UID binding does not match"
            )
    if expected_config_sha256 is not None:
        expected = _digest(
            expected_config_sha256,
            field="pinned release broker config digest",
        )
        if payload["broker"]["config_sha256"] != expected:
            raise ReleaseBrokerReceiptError(
                "release receipt config binding does not match"
            )
    if expected_instance_slug is not None:
        if (
            not isinstance(expected_instance_slug, str)
            or not INSTANCE_SLUG_RE.fullmatch(expected_instance_slug)
            or payload["instance_slug"] != expected_instance_slug
        ):
            raise ReleaseBrokerReceiptError(
                "release receipt instance binding does not match"
            )
    if expected_repository_id is not None:
        expected = _positive_int(
            expected_repository_id,
            field="pinned release repository ID",
        )
        if payload["repository"]["id"] != expected:
            raise ReleaseBrokerReceiptError(
                "release receipt repository ID binding does not match"
            )
    if expected_repository_full_name is not None:
        if (
            not isinstance(expected_repository_full_name, str)
            or not REPOSITORY_RE.fullmatch(expected_repository_full_name)
            or payload["repository"]["full_name"]
            != expected_repository_full_name
        ):
            raise ReleaseBrokerReceiptError(
                "release receipt repository name binding does not match"
            )
    if expected_github_app is not None:
        if payload["github_app"] != _normalize_github_app(
            dict(expected_github_app)
        ):
            raise ReleaseBrokerReceiptError(
                "release receipt GitHub App binding does not match"
            )
    if packet is not None:
        assert_receipt_packet_binding(payload, packet)


def _verify_signature(
    envelope: Mapping[str, Any],
    *,
    public_key: bytes,
    expected_public_key_sha256: str,
) -> None:
    expected_fingerprint = _digest(
        expected_public_key_sha256,
        field="pinned release receipt public-key fingerprint",
    )
    actual_fingerprint = sha256_bytes(public_key)
    if not hmac.compare_digest(actual_fingerprint, expected_fingerprint):
        raise ReleaseBrokerReceiptError(
            "release receipt public-key fingerprint does not match"
        )
    if not hmac.compare_digest(
        envelope["public_key_sha256"], expected_fingerprint
    ):
        raise ReleaseBrokerReceiptError(
            "signed release receipt public-key fingerprint is not pinned"
        )
    key = _load_public_key(public_key)
    signature = _decode_signature(envelope["signature"])
    try:
        key.verify(signature, canonical_json(envelope["payload"]))
    except InvalidSignature as exc:
        raise ReleaseBrokerReceiptError(
            "release receipt signature verification failed"
        ) from exc


def verify_receipt_with_public_key(
    source: Any,
    *,
    public_key: bytes,
    expected_public_key_sha256: str,
    expected_key_id: str | None = None,
    expected_broker_id: str | None = None,
    expected_broker_uid: int | None = None,
    expected_config_sha256: str | None = None,
    expected_instance_slug: str | None = None,
    expected_repository_id: int | None = None,
    expected_repository_full_name: str | None = None,
    expected_github_app: Mapping[str, Any] | None = None,
    packet: Any | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify a receipt entirely offline using pinned public-key bytes."""

    envelope = _coerce_envelope(source)
    _verify_signature(
        envelope,
        public_key=public_key,
        expected_public_key_sha256=expected_public_key_sha256,
    )
    _assert_expected_bindings(
        envelope,
        expected_key_id=expected_key_id,
        expected_broker_id=expected_broker_id,
        expected_broker_uid=expected_broker_uid,
        expected_config_sha256=expected_config_sha256,
        expected_instance_slug=expected_instance_slug,
        expected_repository_id=expected_repository_id,
        expected_repository_full_name=expected_repository_full_name,
        expected_github_app=expected_github_app,
        packet=packet,
    )
    if now is not None:
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ReleaseBrokerReceiptError(
                "receipt verification clock must be timezone-aware"
            )
        completed = _timestamp(
            envelope["payload"]["completed_at"],
            field="release receipt completed_at",
        )[1]
        if completed > now.astimezone(timezone.utc) + timedelta(
            seconds=MAX_CLOCK_SKEW_SECONDS
        ):
            raise ReleaseBrokerReceiptError(
                "release receipt completion time is in the future"
            )
    return envelope


def verify_signed_receipt(
    source: Any,
    public_key_bytes: bytes,
    expected_key_id: str | None = None,
    *,
    expected_public_key_sha256: str | None = None,
) -> dict[str, Any]:
    """Small offline-verifier API used by the unprivileged submit client.

    ``public_key_bytes`` is itself trusted input (normally loaded from the
    root-published public descriptor).  Supplying an explicit fingerprint
    additionally pins the exact PEM encoding; otherwise the trusted bytes are
    deterministically fingerprinted here.
    """

    fingerprint = (
        sha256_bytes(public_key_bytes)
        if expected_public_key_sha256 is None
        else expected_public_key_sha256
    )
    return verify_receipt_with_public_key(
        source,
        public_key=public_key_bytes,
        expected_public_key_sha256=fingerprint,
        expected_key_id=expected_key_id,
    )


def verify_receipt(
    source: Any,
    *,
    public_key_path: Path,
    expected_public_key_sha256: str,
    expected_key_id: str | None = None,
    public_key_owner_uids: int | Iterable[int] | None = None,
    parent_owner_uids: int | Iterable[int] | None = None,
    trusted_path_root: Path | None = None,
    expected_broker_id: str | None = None,
    expected_broker_uid: int | None = None,
    expected_config_sha256: str | None = None,
    expected_instance_slug: str | None = None,
    expected_repository_id: int | None = None,
    expected_repository_full_name: str | None = None,
    expected_github_app: Mapping[str, Any] | None = None,
    packet: Any | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify a receipt using a no-follow, owner-checked public key file."""

    public_key = read_trusted_key(
        public_key_path,
        field="release receipt verification public key",
        private=False,
        expected_owner_uids=public_key_owner_uids,
        parent_owner_uids=parent_owner_uids,
        trusted_path_root=trusted_path_root,
    )
    return verify_receipt_with_public_key(
        source,
        public_key=public_key,
        expected_public_key_sha256=expected_public_key_sha256,
        expected_key_id=expected_key_id,
        expected_broker_id=expected_broker_id,
        expected_broker_uid=expected_broker_uid,
        expected_config_sha256=expected_config_sha256,
        expected_instance_slug=expected_instance_slug,
        expected_repository_id=expected_repository_id,
        expected_repository_full_name=expected_repository_full_name,
        expected_github_app=expected_github_app,
        packet=packet,
        now=now,
    )


def sign_receipt(
    payload: Any,
    *,
    private_key_path: Path,
    public_key_path: Path,
    expected_public_key_sha256: str,
    expected_key_id: str,
    key_owner_uids: int | Iterable[int] | None = None,
    parent_owner_uids: int | Iterable[int] | None = None,
    trusted_path_root: Path | None = None,
    private_key_owner_uid: int | None = None,
    private_key_gid: int | None = None,
    private_key_mode: int | None = None,
    packet: Any | None = None,
) -> dict[str, Any]:
    """Sign one normalized payload with the root-pinned Ed25519 key pair."""

    normalized_payload = normalize_receipt_payload(payload)
    expected_fingerprint = _digest(
        expected_public_key_sha256,
        field="pinned release receipt public-key fingerprint",
    )
    pinned_key_id = _key_id(
        expected_key_id, field="pinned release receipt key ID"
    )
    signing_identity = normalized_payload["broker"]["signing_key"]
    if signing_identity != {
        "key_id": pinned_key_id,
        "public_key_sha256": expected_fingerprint,
    }:
        raise ReleaseBrokerReceiptError(
            "release receipt signing identity is not root-pinned"
        )
    if packet is not None:
        assert_receipt_packet_binding(normalized_payload, packet)
    default_owners = (0, normalized_payload["broker"]["uid"])
    private_key_bytes = read_trusted_key(
        private_key_path,
        field="release receipt private signing key",
        private=True,
        expected_owner_uids=private_key_owner_uid,
        parent_owner_uids=(
            parent_owner_uids
            if parent_owner_uids is not None
            else default_owners
        ),
        trusted_path_root=trusted_path_root,
        expected_gid=private_key_gid,
        expected_mode=private_key_mode,
    )
    public_key_bytes = read_trusted_key(
        public_key_path,
        field="release receipt public signing key",
        private=False,
        expected_owner_uids=(
            key_owner_uids
            if key_owner_uids is not None
            else default_owners
        ),
        parent_owner_uids=(
            parent_owner_uids
            if parent_owner_uids is not None
            else default_owners
        ),
        trusted_path_root=trusted_path_root,
    )
    if not hmac.compare_digest(
        sha256_bytes(public_key_bytes), expected_fingerprint
    ):
        raise ReleaseBrokerReceiptError(
            "release receipt signing public-key fingerprint does not match"
        )
    private_key = _load_private_key(private_key_bytes)
    public_key = _load_public_key(public_key_bytes)
    derived_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    configured_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if not hmac.compare_digest(derived_public, configured_public):
        raise ReleaseBrokerReceiptError(
            "release receipt private and public keys do not match"
        )
    payload_bytes = canonical_json(normalized_payload)
    try:
        signature = private_key.sign(payload_bytes)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise ReleaseBrokerReceiptError(
            "release receipt signing failed"
        ) from exc
    signature_text = (
        base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    )
    envelope = {
        "schema_version": RECEIPT_ENVELOPE_SCHEMA,
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": pinned_key_id,
        "public_key_sha256": expected_fingerprint,
        "payload_sha256": sha256_bytes(payload_bytes),
        "payload": normalized_payload,
        "signature": signature_text,
    }
    normalized_envelope = normalize_receipt_envelope(envelope)
    _verify_signature(
        normalized_envelope,
        public_key=public_key_bytes,
        expected_public_key_sha256=expected_fingerprint,
    )
    return normalized_envelope


def sign_configured_receipt(
    payload: Any,
    config: Any,
    *,
    key_owner_uids: int | Iterable[int] | None = None,
    parent_owner_uids: int | Iterable[int] | None = None,
    trusted_path_root: Path | None = None,
    packet: Any | None = None,
) -> dict[str, Any]:
    """Sign only after the payload matches the enabled root configuration."""

    try:
        normalized_config = normalize_config(config)
    except ReleaseBrokerProtocolError as exc:
        raise ReleaseBrokerReceiptError(str(exc)) from exc
    if normalized_config["enabled"] is not True:
        raise ReleaseBrokerReceiptError(
            "disabled release broker configuration cannot sign receipts"
        )
    normalized_payload = assert_receipt_config_binding(
        payload, normalized_config
    )
    signing = normalized_config["receipt_signing"]
    return sign_receipt(
        normalized_payload,
        private_key_path=Path(signing["private_key_path"]),
        public_key_path=Path(signing["public_key_path"]),
        expected_public_key_sha256=signing["public_key_sha256"],
        expected_key_id=signing["key_id"],
        key_owner_uids=key_owner_uids,
        parent_owner_uids=parent_owner_uids,
        trusted_path_root=trusted_path_root,
        private_key_owner_uid=0,
        private_key_gid=normalized_config["broker_private_gid"],
        private_key_mode=0o640,
        packet=packet,
    )


def verify_configured_receipt(
    source: Any,
    config: Any,
    *,
    public_key_owner_uids: int | Iterable[int] | None = None,
    parent_owner_uids: int | Iterable[int] | None = None,
    trusted_path_root: Path | None = None,
    packet: Any | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify a receipt against a normalized historical broker config."""

    try:
        normalized_config = normalize_config(config)
    except ReleaseBrokerProtocolError as exc:
        raise ReleaseBrokerReceiptError(str(exc)) from exc
    signing = normalized_config["receipt_signing"]
    repository = normalized_config["instance"]["repository"]
    app = {
        field: normalized_config["github_app"][field]
        for field in ("app_id", "app_slug", "installation_id")
    }
    verified = verify_receipt(
        source,
        public_key_path=Path(signing["public_key_path"]),
        expected_public_key_sha256=signing["public_key_sha256"],
        expected_key_id=signing["key_id"],
        public_key_owner_uids=public_key_owner_uids,
        parent_owner_uids=parent_owner_uids,
        trusted_path_root=trusted_path_root,
        expected_broker_id=normalized_config["broker_id"],
        expected_broker_uid=normalized_config["broker_uid"],
        expected_config_sha256=config_digest(normalized_config),
        expected_instance_slug=normalized_config["instance"]["slug"],
        expected_repository_id=repository["id"],
        expected_repository_full_name=repository["full_name"],
        expected_github_app=app,
        packet=packet,
        now=now,
    )
    assert_receipt_config_binding(verified["payload"], normalized_config)
    return verified


def receipt_digest(source: Any) -> str:
    """Return the canonical digest used by the append-only receipt chain."""

    return sha256_json(_coerce_envelope(source))


def assert_append_binding(
    previous: Any,
    current: Any,
) -> dict[str, Any]:
    """Prove that ``current`` is the next receipt after ``previous``."""

    previous_envelope = _coerce_envelope(previous)
    current_envelope = _coerce_envelope(current)
    expected_previous = receipt_digest(previous_envelope)
    if (
        current_envelope["payload"]["previous_receipt_sha256"]
        != expected_previous
    ):
        raise ReleaseBrokerReceiptError(
            "release receipt append-chain hash does not match"
        )
    previous_payload = previous_envelope["payload"]
    current_payload = current_envelope["payload"]
    if (
        current_payload["broker"]["id"] != previous_payload["broker"]["id"]
        or current_payload["broker"]["uid"]
        != previous_payload["broker"]["uid"]
        or current_payload["instance_slug"]
        != previous_payload["instance_slug"]
        or current_payload["repository"] != previous_payload["repository"]
    ):
        raise ReleaseBrokerReceiptError(
            "release receipt append-chain identity changed"
        )
    previous_completed = _timestamp(
        previous_payload["completed_at"],
        field="previous release receipt completed_at",
    )[1]
    current_started = _timestamp(
        current_payload["started_at"],
        field="current release receipt started_at",
    )[1]
    if current_started < previous_completed:
        raise ReleaseBrokerReceiptError(
            "release receipt append-chain time moved backwards"
        )
    return current_envelope


def verify_receipt_chain(
    sources: Sequence[Any],
    *,
    public_keys: Mapping[str, bytes],
    expected_previous_receipt_sha256: str = ZERO_DIGEST,
    expected_broker_id: str | None = None,
    expected_broker_uid: int | None = None,
    expected_instance_slug: str | None = None,
    expected_repository_id: int | None = None,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Verify signatures, key IDs, fingerprints, order, and chain hashes."""

    if not isinstance(sources, Sequence) or isinstance(
        sources, (str, bytes, bytearray, memoryview)
    ):
        raise ReleaseBrokerReceiptError(
            "release receipt chain must be a sequence"
        )
    if not sources:
        raise ReleaseBrokerReceiptError(
            "release receipt chain must not be empty"
        )
    expected_previous = _digest(
        expected_previous_receipt_sha256,
        field="expected release receipt chain predecessor",
    )
    verified: list[dict[str, Any]] = []
    seen_receipt_ids: set[str] = set()
    seen_packet_ids: set[str] = set()
    for index, source in enumerate(sources):
        envelope = _coerce_envelope(source)
        key_id = envelope["key_id"]
        public_key = public_keys.get(key_id)
        if not isinstance(public_key, bytes) or not public_key:
            raise ReleaseBrokerReceiptError(
                f"release receipt chain key {key_id!r} is not trusted"
            )
        envelope = verify_receipt_with_public_key(
            envelope,
            public_key=public_key,
            expected_public_key_sha256=sha256_bytes(public_key),
            expected_key_id=key_id,
            expected_broker_id=expected_broker_id,
            expected_broker_uid=expected_broker_uid,
            expected_instance_slug=expected_instance_slug,
            expected_repository_id=expected_repository_id,
            now=now,
        )
        if (
            envelope["payload"]["previous_receipt_sha256"]
            != expected_previous
        ):
            raise ReleaseBrokerReceiptError(
                f"release receipt chain entry {index} has the wrong predecessor"
            )
        receipt_id = envelope["payload"]["receipt_id"]
        packet_id = envelope["payload"]["packet"]["packet_id"]
        if receipt_id in seen_receipt_ids or packet_id in seen_packet_ids:
            raise ReleaseBrokerReceiptError(
                "release receipt chain repeats a receipt or packet identity"
            )
        seen_receipt_ids.add(receipt_id)
        seen_packet_ids.add(packet_id)
        if verified:
            assert_append_binding(verified[-1], envelope)
        verified.append(envelope)
        expected_previous = receipt_digest(envelope)
    return verified


def is_completion_receipt(
    source: Any,
    **verification: Any,
) -> bool:
    """Return true only for a verified, fully successful release receipt."""

    try:
        receipt = verify_receipt(source, **verification)
    except ReleaseBrokerProtocolError:
        return False
    return receipt["payload"]["outcome"] == "succeeded"


# Short compatibility names for service/client code.
BrokerReceiptError = ReleaseBrokerReceiptError
RECEIPT_SCHEMA = RECEIPT_PAYLOAD_SCHEMA
SIGNED_RECEIPT_SCHEMA = RECEIPT_ENVELOPE_SCHEMA
