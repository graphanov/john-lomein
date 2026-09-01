#!/usr/bin/env python3
"""Signed, independently verifiable receipts for protected broker effects."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from broker.john_lomein_broker_protocol import (
    ALLOWED_ACTIONS,
    APP_SLUG_RE,
    BRANCH_RE,
    BrokerProtocolError,
    INSTANCE_SLUG_RE,
    MAX_CLOCK_SKEW_SECONDS,
    MAX_KEY_BYTES,
    OID_RE,
    PACKET_ID_RE,
    REPO_RE,
    SHA256_RE,
    TOKEN_RE,
    canonical_json,
    config_digest,
    normalize_config,
    normalize_submission,
    parse_json_bytes,
    read_stable_file,
    read_trusted_file,
    sha256_json,
)


RECEIPT_PAYLOAD_SCHEMA = "john-lomein.protected-broker-receipt.v1"
RECEIPT_ENVELOPE_SCHEMA = (
    "john-lomein.protected-broker-signed-receipt.v1"
)
SIGNATURE_ALGORITHM = "Ed25519"
ZERO_HASH = "0" * 64
MAX_RECEIPT_BYTES = 512 * 1024

RECEIPT_ID_RE = re.compile(r"^jlbr-[0-9a-f]{24}$")
REASON_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
OUTCOMES = frozenset(
    {"succeeded", "rejected", "failed", "indeterminate"}
)
MUTATION_STATUSES = frozenset(
    {
        "not_attempted",
        "already_satisfied",
        "applied",
        "reconciled",
        "failed",
        "indeterminate",
    }
)
READBACK_STATUSES = frozenset(
    {
        "not_attempted",
        "confirmed",
        "not_confirmed",
        "indeterminate",
    }
)


class BrokerReceiptError(BrokerProtocolError):
    """A malformed, unauthenticated, or context-mismatched receipt."""


def _mapping(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BrokerReceiptError(f"{field} must be an object")
    return value


def _strict_keys(
    value: dict[str, Any],
    *,
    field: str,
    allowed: set[str],
) -> None:
    unknown = sorted(set(value) - allowed)
    missing = sorted(allowed - set(value))
    if unknown:
        raise BrokerReceiptError(f"{field} contains unknown fields")
    if missing:
        raise BrokerReceiptError(f"{field} is missing required fields")


def _positive_int(
    value: Any,
    *,
    field: str,
    maximum: int = 2**63 - 1,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BrokerReceiptError(f"{field} must be an integer")
    if value <= 0 or value > maximum:
        raise BrokerReceiptError(f"{field} is outside the allowed range")
    return value


def _timestamp(value: Any, *, field: str) -> tuple[str, datetime]:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise BrokerReceiptError(
                f"{field} must be timezone-aware"
            )
        parsed = value.astimezone(timezone.utc)
        text = parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
        return text, datetime.strptime(
            text, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    if not isinstance(value, str):
        raise BrokerReceiptError(f"{field} must be a UTC timestamp")
    try:
        parsed = datetime.strptime(
            value, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise BrokerReceiptError(
            f"{field} must be a UTC timestamp"
        ) from exc
    if parsed.year < 2020:
        raise BrokerReceiptError(f"{field} is outside the allowed range")
    return value, parsed


def _optional_timestamp(
    value: Any,
    *,
    field: str,
) -> tuple[str | None, datetime | None]:
    if value is None:
        return None, None
    return _timestamp(value, field=field)


def _oid_or_none(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise BrokerReceiptError(f"{field} is invalid")
    normalized = value.lower()
    if not OID_RE.fullmatch(normalized):
        raise BrokerReceiptError(f"{field} is invalid")
    return normalized


def _bool_or_none(value: Any, *, field: str) -> bool | None:
    if value is None:
        return None
    if type(value) is not bool:
        raise BrokerReceiptError(f"{field} must be boolean or null")
    return value


def _thread_ids(value: Any, *, field: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 1:
        raise BrokerReceiptError(
            f"{field} must contain at most one thread ID"
        )
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str) or not TOKEN_RE.fullmatch(item):
            raise BrokerReceiptError(f"{field} contains an invalid ID")
        normalized.append(item)
    if len(set(normalized)) != len(normalized):
        raise BrokerReceiptError(f"{field} contains duplicate IDs")
    return normalized


def _optional_operation_id(value: Any) -> str:
    if value == "":
        return ""
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        raise BrokerReceiptError("receipt mutation operation_id is invalid")
    return value


def _reason_has_prefix(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and len(value) > len(prefix)


def _payload_id_material(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in payload.items()
        if key != "receipt_id"
    }


def normalize_receipt_payload(raw: Any) -> dict[str, Any]:
    payload = _mapping(raw, field="broker receipt payload")
    _strict_keys(
        payload,
        field="broker receipt payload",
        allowed={
            "schema_version",
            "receipt_id",
            "broker_id",
            "broker_uid",
            "broker_config_sha256",
            "signing_key_id",
            "packet",
            "request",
            "github_app",
            "precondition_digest",
            "mutation",
            "readback",
            "outcome",
            "reason_code",
            "started_at",
            "completed_at",
            "previous_receipt_sha256",
        },
    )
    if payload.get("schema_version") != RECEIPT_PAYLOAD_SCHEMA:
        raise BrokerReceiptError("broker receipt schema is unsupported")
    broker_id = str(payload.get("broker_id") or "")
    if not TOKEN_RE.fullmatch(broker_id):
        raise BrokerReceiptError("broker receipt broker_id is invalid")
    broker_uid = payload.get("broker_uid")
    if (
        isinstance(broker_uid, bool)
        or not isinstance(broker_uid, int)
        or broker_uid < 0
        or broker_uid > 2**31 - 1
    ):
        raise BrokerReceiptError("broker receipt broker_uid is invalid")
    broker_config_sha256 = str(
        payload.get("broker_config_sha256") or ""
    )
    if not SHA256_RE.fullmatch(broker_config_sha256):
        raise BrokerReceiptError(
            "broker receipt config digest is invalid"
        )
    signing_key_id = str(payload.get("signing_key_id") or "")
    if not TOKEN_RE.fullmatch(signing_key_id):
        raise BrokerReceiptError(
            "broker receipt signing_key_id is invalid"
        )

    packet = _mapping(
        payload.get("packet"), field="broker receipt packet binding"
    )
    _strict_keys(
        packet,
        field="broker receipt packet binding",
        allowed={"packet_id", "request_digest"},
    )
    packet_id = str(packet.get("packet_id") or "")
    request_digest = str(packet.get("request_digest") or "")
    if not PACKET_ID_RE.fullmatch(packet_id):
        raise BrokerReceiptError("broker receipt packet ID is invalid")
    if not SHA256_RE.fullmatch(request_digest):
        raise BrokerReceiptError(
            "broker receipt request digest is invalid"
        )

    request = _mapping(
        payload.get("request"), field="broker receipt request binding"
    )
    _strict_keys(
        request,
        field="broker receipt request binding",
        allowed={
            "instance_slug",
            "action",
            "repository_full_name",
            "repository_id",
            "default_branch",
            "pr_number",
            "head_sha",
            "thread_node_ids",
        },
    )
    instance_slug = str(request.get("instance_slug") or "")
    if not INSTANCE_SLUG_RE.fullmatch(instance_slug):
        raise BrokerReceiptError(
            "broker receipt instance slug is invalid"
        )
    action = str(request.get("action") or "")
    if action not in ALLOWED_ACTIONS:
        raise BrokerReceiptError("broker receipt action is unsupported")
    repository_full_name = str(
        request.get("repository_full_name") or ""
    )
    if not REPO_RE.fullmatch(repository_full_name):
        raise BrokerReceiptError(
            "broker receipt repository name is invalid"
        )
    repository_id = _positive_int(
        request.get("repository_id"),
        field="broker receipt repository_id",
    )
    default_branch = str(request.get("default_branch") or "")
    if not BRANCH_RE.fullmatch(default_branch):
        raise BrokerReceiptError(
            "broker receipt default branch is invalid"
        )
    pr_number = _positive_int(
        request.get("pr_number"),
        field="broker receipt PR number",
        maximum=2**31 - 1,
    )
    head_sha = _oid_or_none(
        request.get("head_sha"), field="broker receipt head SHA"
    )
    if head_sha is None:
        raise BrokerReceiptError("broker receipt head SHA is required")
    target_thread_ids = _thread_ids(
        request.get("thread_node_ids"),
        field="broker receipt target thread IDs",
    )
    if action == "mark_pr_ready" and target_thread_ids:
        raise BrokerReceiptError(
            "mark_pr_ready receipt cannot target review threads"
        )
    if action == "resolve_review_thread" and len(target_thread_ids) != 1:
        raise BrokerReceiptError(
            "review-thread receipt must target exactly one thread"
        )

    github_app = _mapping(
        payload.get("github_app"),
        field="broker receipt GitHub App binding",
    )
    _strict_keys(
        github_app,
        field="broker receipt GitHub App binding",
        allowed={"app_id", "app_slug", "installation_id"},
    )
    app_id = _positive_int(
        github_app.get("app_id"),
        field="broker receipt GitHub App ID",
    )
    app_slug = str(github_app.get("app_slug") or "")
    if not APP_SLUG_RE.fullmatch(app_slug):
        raise BrokerReceiptError(
            "broker receipt GitHub App slug is invalid"
        )
    installation_id = _positive_int(
        github_app.get("installation_id"),
        field="broker receipt GitHub installation ID",
    )

    precondition_digest = str(
        payload.get("precondition_digest") or ""
    )
    if not SHA256_RE.fullmatch(precondition_digest):
        raise BrokerReceiptError(
            "broker receipt precondition digest is invalid"
        )

    mutation = _mapping(
        payload.get("mutation"), field="broker receipt mutation"
    )
    _strict_keys(
        mutation,
        field="broker receipt mutation",
        allowed={"status", "attempted_at", "operation_id"},
    )
    mutation_status = str(mutation.get("status") or "")
    if mutation_status not in MUTATION_STATUSES:
        raise BrokerReceiptError(
            "broker receipt mutation status is unsupported"
        )
    attempted_at, attempted = _optional_timestamp(
        mutation.get("attempted_at"),
        field="broker receipt mutation attempted_at",
    )
    operation_id = _optional_operation_id(
        mutation.get("operation_id")
    )
    if mutation_status in {"not_attempted", "already_satisfied"}:
        if attempted_at is not None or operation_id:
            raise BrokerReceiptError(
                "unattempted mutation cannot carry attempt evidence"
            )
    elif attempted_at is None:
        raise BrokerReceiptError(
            "attempted mutation requires an attempt timestamp"
        )
    if (
        mutation_status in {"applied", "reconciled"}
        and not operation_id
    ):
        raise BrokerReceiptError(
            "successful mutation requires an operation ID"
        )

    readback = _mapping(
        payload.get("readback"), field="broker receipt readback"
    )
    _strict_keys(
        readback,
        field="broker receipt readback",
        allowed={
            "status",
            "observed_at",
            "head_sha",
            "pr_is_draft",
            "resolved_thread_node_ids",
        },
    )
    readback_status = str(readback.get("status") or "")
    if readback_status not in READBACK_STATUSES:
        raise BrokerReceiptError(
            "broker receipt readback status is unsupported"
        )
    observed_at, observed = _optional_timestamp(
        readback.get("observed_at"),
        field="broker receipt readback observed_at",
    )
    readback_head_sha = _oid_or_none(
        readback.get("head_sha"),
        field="broker receipt readback head SHA",
    )
    pr_is_draft = _bool_or_none(
        readback.get("pr_is_draft"),
        field="broker receipt readback pr_is_draft",
    )
    resolved_thread_ids = _thread_ids(
        readback.get("resolved_thread_node_ids"),
        field="broker receipt resolved thread IDs",
    )
    if readback_status == "not_attempted":
        if (
            observed_at is not None
            or readback_head_sha is not None
            or pr_is_draft is not None
            or resolved_thread_ids
        ):
            raise BrokerReceiptError(
                "not-attempted readback cannot carry observations"
            )
    elif observed_at is None:
        raise BrokerReceiptError(
            "broker receipt readback requires an observation timestamp"
        )
    if readback_status == "confirmed":
        if readback_head_sha != head_sha or pr_is_draft is None:
            raise BrokerReceiptError(
                "confirmed readback must bind the exact head and draft state"
            )
        if action == "mark_pr_ready":
            if pr_is_draft is not False or resolved_thread_ids:
                raise BrokerReceiptError(
                    "mark-ready readback does not prove promotion"
                )
        elif resolved_thread_ids != target_thread_ids:
            raise BrokerReceiptError(
                "thread readback does not prove exact target resolution"
            )

    outcome = str(payload.get("outcome") or "")
    if outcome not in OUTCOMES:
        raise BrokerReceiptError("broker receipt outcome is unsupported")
    reason_code = str(payload.get("reason_code") or "")
    if not REASON_CODE_RE.fullmatch(reason_code):
        raise BrokerReceiptError(
            "broker receipt reason_code is invalid"
        )
    started_at, started = _timestamp(
        payload.get("started_at"),
        field="broker receipt started_at",
    )
    completed_at, completed = _timestamp(
        payload.get("completed_at"),
        field="broker receipt completed_at",
    )
    if completed < started:
        raise BrokerReceiptError(
            "broker receipt completion precedes its start"
        )
    if attempted is not None and not (
        started <= attempted <= completed
    ):
        raise BrokerReceiptError(
            "broker receipt mutation time is inconsistent"
        )
    if observed is not None and not (
        started <= observed <= completed
    ):
        raise BrokerReceiptError(
            "broker receipt readback time is inconsistent"
        )
    if (
        attempted is not None
        and observed is not None
        and observed < attempted
    ):
        raise BrokerReceiptError(
            "broker receipt readback precedes mutation"
        )

    if outcome == "succeeded":
        if (
            mutation_status
            not in {"applied", "reconciled", "already_satisfied"}
            or readback_status != "confirmed"
        ):
            raise BrokerReceiptError(
                "successful receipt requires a completed effect and "
                "confirmed readback"
            )
        expected_reasons = {
            "applied": "readback_verified",
            "reconciled": "reconciled_readback_verified",
            "already_satisfied": "already_satisfied",
        }
        if reason_code != expected_reasons[mutation_status]:
            raise BrokerReceiptError(
                "successful receipt reason_code is inconsistent"
            )
    elif outcome == "rejected":
        if (
            mutation_status != "not_attempted"
            or readback_status != "not_attempted"
        ):
            raise BrokerReceiptError(
                "rejected receipt cannot claim mutation or readback"
            )
        if not any(
            _reason_has_prefix(reason_code, prefix)
            for prefix in (
                "precondition_",
                "request_",
                "policy_",
                "budget_",
                "circuit_",
            )
        ):
            raise BrokerReceiptError(
                "rejected receipt reason_code is inconsistent"
            )
    elif outcome == "failed":
        if (
            mutation_status != "failed"
            or readback_status != "not_attempted"
        ):
            raise BrokerReceiptError(
                "failed receipt has inconsistent effect status"
            )
        if not _reason_has_prefix(reason_code, "mutation_"):
            raise BrokerReceiptError(
                "failed receipt reason_code is inconsistent"
            )
    elif (
        mutation_status not in {"applied", "reconciled", "indeterminate"}
        or readback_status
        not in {"not_confirmed", "indeterminate"}
    ):
        raise BrokerReceiptError(
            "indeterminate receipt has inconsistent effect status"
        )
    elif not _reason_has_prefix(reason_code, "indeterminate_"):
        raise BrokerReceiptError(
            "indeterminate receipt reason_code is inconsistent"
        )

    previous_receipt_sha256 = str(
        payload.get("previous_receipt_sha256") or ""
    )
    if not SHA256_RE.fullmatch(previous_receipt_sha256):
        raise BrokerReceiptError(
            "broker receipt previous hash is invalid"
        )

    normalized = {
        "schema_version": RECEIPT_PAYLOAD_SCHEMA,
        "receipt_id": str(payload.get("receipt_id") or ""),
        "broker_id": broker_id,
        "broker_uid": broker_uid,
        "broker_config_sha256": broker_config_sha256,
        "signing_key_id": signing_key_id,
        "packet": {
            "packet_id": packet_id,
            "request_digest": request_digest,
        },
        "request": {
            "instance_slug": instance_slug,
            "action": action,
            "repository_full_name": repository_full_name,
            "repository_id": repository_id,
            "default_branch": default_branch,
            "pr_number": pr_number,
            "head_sha": head_sha,
            "thread_node_ids": target_thread_ids,
        },
        "github_app": {
            "app_id": app_id,
            "app_slug": app_slug,
            "installation_id": installation_id,
        },
        "precondition_digest": precondition_digest,
        "mutation": {
            "status": mutation_status,
            "attempted_at": attempted_at,
            "operation_id": operation_id,
        },
        "readback": {
            "status": readback_status,
            "observed_at": observed_at,
            "head_sha": readback_head_sha,
            "pr_is_draft": pr_is_draft,
            "resolved_thread_node_ids": resolved_thread_ids,
        },
        "outcome": outcome,
        "reason_code": reason_code,
        "started_at": started_at,
        "completed_at": completed_at,
        "previous_receipt_sha256": previous_receipt_sha256,
    }
    expected_id = (
        f"jlbr-{sha256_json(_payload_id_material(normalized))[:24]}"
    )
    if not RECEIPT_ID_RE.fullmatch(normalized["receipt_id"]):
        raise BrokerReceiptError("broker receipt ID is invalid")
    if normalized["receipt_id"] != expected_id:
        raise BrokerReceiptError("broker receipt ID does not match")
    return normalized


def _historical_submission(
    submission: Any,
    config: Any,
) -> dict[str, Any]:
    try:
        packet = _mapping(
            submission, field="broker submission"
        ).get("packet")
        created_at = _mapping(
            packet, field="protected-action packet"
        ).get("created_at")
        _, created = _timestamp(
            created_at,
            field="protected-action packet created_at",
        )
    except BrokerReceiptError:
        raise
    except Exception as exc:
        raise BrokerReceiptError(
            "broker submission cannot be validated historically"
        ) from exc
    try:
        return normalize_submission(
            submission, config, now=created
        )
    except BrokerProtocolError as exc:
        raise BrokerReceiptError(str(exc)) from exc


def build_receipt_payload(
    config: Any,
    submission: Any,
    *,
    precondition_digest: str,
    outcome: str,
    reason_code: str,
    mutation_status: str,
    readback_status: str,
    started_at: datetime | str,
    completed_at: datetime | str,
    mutation_attempted_at: datetime | str | None = None,
    operation_id: str = "",
    readback_observed_at: datetime | str | None = None,
    readback_head_sha: str | None = None,
    readback_pr_is_draft: bool | None = None,
    resolved_thread_node_ids: Iterable[str] = (),
    previous_receipt_sha256: str = ZERO_HASH,
) -> dict[str, Any]:
    normalized_config = normalize_config(config)
    _, started = _timestamp(
        started_at, field="broker receipt started_at"
    )
    normalized_submission = normalize_submission(
        submission, normalized_config, now=started
    )
    packet = normalized_submission["packet"]
    request = packet["request"]
    body = {
        "schema_version": RECEIPT_PAYLOAD_SCHEMA,
        "receipt_id": "",
        "broker_id": normalized_config["broker_id"],
        "broker_uid": normalized_config["broker_uid"],
        "broker_config_sha256": config_digest(normalized_config),
        "signing_key_id": normalized_config["receipt_signing"][
            "key_id"
        ],
        "packet": {
            "packet_id": packet["packet_id"],
            "request_digest": packet["request_digest"],
        },
        "request": {
            "instance_slug": request["instance_slug"],
            "action": request["action"],
            "repository_full_name": normalized_config["instance"][
                "repository"
            ]["full_name"],
            "repository_id": normalized_config["instance"]["repository"][
                "id"
            ],
            "default_branch": normalized_config["instance"][
                "repository"
            ]["default_branch"],
            "pr_number": request["pr"]["number"],
            "head_sha": request["pr"]["head_sha"],
            "thread_node_ids": request["targets"][
                "thread_node_ids"
            ],
        },
        "github_app": {
            "app_id": normalized_config["github_app"]["app_id"],
            "app_slug": normalized_config["github_app"]["app_slug"],
            "installation_id": normalized_config["github_app"][
                "installation_id"
            ],
        },
        "precondition_digest": precondition_digest,
        "mutation": {
            "status": mutation_status,
            "attempted_at": (
                _timestamp(
                    mutation_attempted_at,
                    field="broker receipt mutation attempted_at",
                )[0]
                if mutation_attempted_at is not None
                else None
            ),
            "operation_id": operation_id,
        },
        "readback": {
            "status": readback_status,
            "observed_at": (
                _timestamp(
                    readback_observed_at,
                    field="broker receipt readback observed_at",
                )[0]
                if readback_observed_at is not None
                else None
            ),
            "head_sha": readback_head_sha,
            "pr_is_draft": readback_pr_is_draft,
            "resolved_thread_node_ids": list(
                resolved_thread_node_ids
            ),
        },
        "outcome": outcome,
        "reason_code": reason_code,
        "started_at": _timestamp(
            started_at, field="broker receipt started_at"
        )[0],
        "completed_at": _timestamp(
            completed_at, field="broker receipt completed_at"
        )[0],
        "previous_receipt_sha256": previous_receipt_sha256,
    }
    body["receipt_id"] = (
        f"jlbr-{sha256_json(_payload_id_material(body))[:24]}"
    )
    return normalize_receipt_payload(body)


def _verify_signature_bytes(
    *,
    public_key: bytes,
    payload: bytes,
    signature: bytes,
) -> None:
    if len(signature) != 64:
        raise BrokerReceiptError(
            "broker receipt Ed25519 signature size is invalid"
        )
    try:
        key = serialization.load_pem_public_key(public_key)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise BrokerReceiptError(
            "broker receipt verification key is invalid"
        ) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise BrokerReceiptError(
            "broker receipt verification key is not Ed25519"
        )
    try:
        key.verify(signature, payload)
    except InvalidSignature as exc:
        raise BrokerReceiptError(
            "broker receipt signature verification failed"
        ) from exc


def sign_receipt(
    payload: Any,
    config: Any,
    submission: Any,
    *,
    key_owner_uids: int | Iterable[int] | None = None,
    parent_owner_uids: int | Iterable[int] | None = None,
    trusted_path_root: Path | None = None,
) -> dict[str, Any]:
    normalized_config = normalize_config(config)
    normalized_payload = normalize_receipt_payload(payload)
    _assert_context_binding(
        normalized_payload,
        config=normalized_config,
        submission=submission,
    )
    signing = normalized_config["receipt_signing"]
    key_owners = (
        key_owner_uids
        if key_owner_uids is not None
        else (0, normalized_config["broker_uid"])
    )
    parent_owners = (
        parent_owner_uids
        if parent_owner_uids is not None
        else (0, normalized_config["broker_uid"])
    )
    try:
        private_key = read_trusted_file(
            Path(signing["private_key_path"]),
            field="broker receipt private key",
            maximum_bytes=MAX_KEY_BYTES,
            expected_owner_uids=key_owners,
            parent_owner_uids=parent_owners,
            trusted_path_root=trusted_path_root,
        )
        public_key = read_trusted_file(
            Path(signing["public_key_path"]),
            field="broker receipt public key",
            maximum_bytes=MAX_KEY_BYTES,
            expected_owner_uids=key_owners,
            parent_owner_uids=parent_owners,
            trusted_path_root=trusted_path_root,
        )
    except BrokerReceiptError:
        raise
    except BrokerProtocolError as exc:
        raise BrokerReceiptError(str(exc)) from exc
    expected_fingerprint = signing["public_key_sha256"]
    if hashlib.sha256(public_key).hexdigest() != expected_fingerprint:
        raise BrokerReceiptError(
            "broker receipt public-key fingerprint does not match"
        )
    if b"PRIVATE KEY" not in private_key or b"PUBLIC KEY" not in public_key:
        raise BrokerReceiptError("broker receipt key type is invalid")

    payload_bytes = canonical_json(normalized_payload)
    try:
        private = serialization.load_pem_private_key(
            private_key,
            password=None,
        )
        public = serialization.load_pem_public_key(public_key)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise BrokerReceiptError("broker receipt key is invalid") from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise BrokerReceiptError(
            "broker receipt signing key is not Ed25519"
        )
    if not isinstance(public, Ed25519PublicKey):
        raise BrokerReceiptError(
            "broker receipt verification key is not Ed25519"
        )
    derived_public = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    configured_public = public.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if not hmac.compare_digest(derived_public, configured_public):
        raise BrokerReceiptError(
            "broker receipt private and public keys do not match"
        )
    try:
        signature = private.sign(payload_bytes)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise BrokerReceiptError("broker receipt signing failed") from exc
    _verify_signature_bytes(
        public_key=public_key,
        payload=payload_bytes,
        signature=signature,
    )
    return {
        "schema_version": RECEIPT_ENVELOPE_SCHEMA,
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": signing["key_id"],
        "public_key_sha256": expected_fingerprint,
        "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
        "payload": normalized_payload,
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def normalize_receipt_envelope(raw: Any) -> dict[str, Any]:
    envelope = _mapping(raw, field="signed broker receipt")
    _strict_keys(
        envelope,
        field="signed broker receipt",
        allowed={
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
        raise BrokerReceiptError(
            "signed broker receipt schema is unsupported"
        )
    if envelope.get("algorithm") != SIGNATURE_ALGORITHM:
        raise BrokerReceiptError(
            "signed broker receipt algorithm is unsupported"
        )
    key_id = str(envelope.get("key_id") or "")
    if not TOKEN_RE.fullmatch(key_id):
        raise BrokerReceiptError(
            "signed broker receipt key_id is invalid"
        )
    public_key_sha256 = str(
        envelope.get("public_key_sha256") or ""
    )
    payload_sha256 = str(envelope.get("payload_sha256") or "")
    if not SHA256_RE.fullmatch(public_key_sha256):
        raise BrokerReceiptError(
            "signed broker receipt key fingerprint is invalid"
        )
    if not SHA256_RE.fullmatch(payload_sha256):
        raise BrokerReceiptError(
            "signed broker receipt payload digest is invalid"
        )
    payload = normalize_receipt_payload(envelope.get("payload"))
    if payload["signing_key_id"] != key_id:
        raise BrokerReceiptError(
            "signed broker receipt key ID does not match its payload"
        )
    actual_payload_digest = hashlib.sha256(
        canonical_json(payload)
    ).hexdigest()
    if payload_sha256 != actual_payload_digest:
        raise BrokerReceiptError(
            "signed broker receipt payload digest does not match"
        )
    signature_text = envelope.get("signature")
    if not isinstance(signature_text, str):
        raise BrokerReceiptError(
            "signed broker receipt signature is invalid"
        )
    try:
        signature = base64.b64decode(
            signature_text.encode("ascii"), validate=True
        )
    except (UnicodeError, ValueError, binascii.Error) as exc:
        raise BrokerReceiptError(
            "signed broker receipt signature is invalid base64"
        ) from exc
    if len(signature) != 64:
        raise BrokerReceiptError(
            "signed broker receipt Ed25519 signature size is invalid"
        )
    canonical_signature = base64.b64encode(signature).decode("ascii")
    if signature_text != canonical_signature:
        raise BrokerReceiptError(
            "signed broker receipt signature is not canonical base64"
        )
    return {
        "schema_version": RECEIPT_ENVELOPE_SCHEMA,
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "public_key_sha256": public_key_sha256,
        "payload_sha256": actual_payload_digest,
        "payload": payload,
        "signature": canonical_signature,
    }


def load_receipt(
    source: bytes | bytearray | memoryview | Path | os.PathLike[str],
) -> dict[str, Any]:
    if isinstance(source, (bytes, bytearray, memoryview)):
        raw = bytes(source)
    elif isinstance(source, (Path, os.PathLike)):
        raw = read_stable_file(
            Path(source),
            field="signed broker receipt",
            maximum_bytes=MAX_RECEIPT_BYTES,
        )
    else:
        raise BrokerReceiptError(
            "signed broker receipt source must be bytes or a path"
        )
    try:
        value = parse_json_bytes(
            raw,
            field="signed broker receipt",
            maximum_bytes=MAX_RECEIPT_BYTES,
        )
    except BrokerProtocolError as exc:
        raise BrokerReceiptError(str(exc)) from exc
    return normalize_receipt_envelope(value)


def _coerce_envelope(
    source: Any,
) -> dict[str, Any]:
    if isinstance(source, dict):
        return normalize_receipt_envelope(source)
    if isinstance(
        source, (bytes, bytearray, memoryview, Path, os.PathLike)
    ):
        return load_receipt(source)
    raise BrokerReceiptError("signed broker receipt source is invalid")


def _assert_config_binding(
    payload: dict[str, Any],
    config: dict[str, Any],
) -> None:
    repository = config["instance"]["repository"]
    expected = {
        "broker_id": config["broker_id"],
        "broker_uid": config["broker_uid"],
        "broker_config_sha256": config_digest(config),
        "signing_key_id": config["receipt_signing"]["key_id"],
        "instance_slug": config["instance"]["slug"],
        "repository_full_name": repository["full_name"],
        "repository_id": repository["id"],
        "default_branch": repository["default_branch"],
        "github_app": {
            "app_id": config["github_app"]["app_id"],
            "app_slug": config["github_app"]["app_slug"],
            "installation_id": config["github_app"][
                "installation_id"
            ],
        },
    }
    for field in (
        "broker_id",
        "broker_uid",
        "broker_config_sha256",
        "signing_key_id",
    ):
        if payload[field] != expected[field]:
            raise BrokerReceiptError(
                f"broker receipt {field} binding does not match"
            )
    for field in (
        "instance_slug",
        "repository_full_name",
        "repository_id",
        "default_branch",
    ):
        if payload["request"][field] != expected[field]:
            raise BrokerReceiptError(
                f"broker receipt {field} binding does not match"
            )
    if payload["github_app"] != expected["github_app"]:
        raise BrokerReceiptError(
            "broker receipt github_app binding does not match"
        )


def _assert_context_binding(
    payload: dict[str, Any],
    *,
    config: Any | None,
    submission: Any | None,
) -> None:
    if (config is None) != (submission is None):
        raise BrokerReceiptError(
            "receipt context requires both config and submission"
        )
    if config is None:
        return
    normalized_config = normalize_config(config)
    _assert_config_binding(payload, normalized_config)
    normalized_submission = _historical_submission(
        submission, normalized_config
    )
    packet = normalized_submission["packet"]
    request = packet["request"]
    expected = {
        "packet": {
            "packet_id": packet["packet_id"],
            "request_digest": packet["request_digest"],
        },
        "request": {
            "instance_slug": request["instance_slug"],
            "action": request["action"],
            "repository_full_name": normalized_config["instance"][
                "repository"
            ]["full_name"],
            "repository_id": normalized_config["instance"][
                "repository"
            ]["id"],
            "default_branch": normalized_config["instance"][
                "repository"
            ]["default_branch"],
            "pr_number": request["pr"]["number"],
            "head_sha": request["pr"]["head_sha"],
            "thread_node_ids": request["targets"][
                "thread_node_ids"
            ],
        },
    }
    for field in ("packet", "request"):
        if payload[field] != expected[field]:
            raise BrokerReceiptError(
                f"broker receipt {field} binding does not match"
            )
    _, started = _timestamp(
        payload["started_at"],
        field="broker receipt started_at",
    )
    _, packet_created = _timestamp(
        packet["created_at"],
        field="protected-action packet created_at",
    )
    _, packet_expires = _timestamp(
        packet["expires_at"],
        field="protected-action packet expires_at",
    )
    skew = timedelta(
        seconds=normalized_config["instance"]["policy"][
            "maximum_clock_skew_seconds"
        ]
    )
    if started < packet_created - skew or started >= packet_expires:
        raise BrokerReceiptError(
            "broker receipt started outside the packet authority window"
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
    config: Any | None = None,
    submission: Any | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not SHA256_RE.fullmatch(expected_public_key_sha256):
        raise BrokerReceiptError(
            "pinned broker public-key fingerprint is invalid"
        )
    envelope = _coerce_envelope(source)
    if expected_key_id is not None:
        if (
            not TOKEN_RE.fullmatch(expected_key_id)
            or envelope["key_id"] != expected_key_id
        ):
            raise BrokerReceiptError(
                "signed broker receipt key ID is not pinned"
            )
    if envelope["public_key_sha256"] != expected_public_key_sha256:
        raise BrokerReceiptError(
            "signed broker receipt key fingerprint is not pinned"
        )
    if config is not None:
        normalized_config = normalize_config(config)
        if (
            normalized_config["receipt_signing"][
                "public_key_sha256"
            ]
            != expected_public_key_sha256
        ):
            raise BrokerReceiptError(
                "pinned broker public key does not match config"
            )
        if (
            envelope["key_id"]
            != normalized_config["receipt_signing"]["key_id"]
        ):
            raise BrokerReceiptError(
                "signed broker receipt key ID does not match config"
            )
    try:
        key = read_trusted_file(
            public_key_path,
            field="broker receipt verification public key",
            maximum_bytes=MAX_KEY_BYTES,
            expected_owner_uids=public_key_owner_uids,
            parent_owner_uids=parent_owner_uids,
            trusted_path_root=trusted_path_root,
        )
    except BrokerReceiptError:
        raise
    except BrokerProtocolError as exc:
        raise BrokerReceiptError(str(exc)) from exc
    if b"PUBLIC KEY" not in key:
        raise BrokerReceiptError(
            "broker receipt verification key is not a public key"
        )
    if hashlib.sha256(key).hexdigest() != expected_public_key_sha256:
        raise BrokerReceiptError(
            "broker receipt verification key fingerprint does not match"
        )
    try:
        signature = base64.b64decode(
            envelope["signature"].encode("ascii"), validate=True
        )
    except (UnicodeError, ValueError, binascii.Error) as exc:
        raise BrokerReceiptError(
            "signed broker receipt signature is invalid"
        ) from exc
    _verify_signature_bytes(
        public_key=key,
        payload=canonical_json(envelope["payload"]),
        signature=signature,
    )
    _assert_context_binding(
        envelope["payload"],
        config=config,
        submission=submission,
    )
    if now is not None:
        _, completed = _timestamp(
            envelope["payload"]["completed_at"],
            field="broker receipt completed_at",
        )
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise BrokerReceiptError(
                "receipt verification clock must be timezone-aware"
            )
        current = now.astimezone(timezone.utc)
        if completed > current + timedelta(
            seconds=MAX_CLOCK_SKEW_SECONDS
        ):
            raise BrokerReceiptError(
                "broker receipt completion time is in the future"
            )
    return envelope


def _verified_receipt_is_completion(
    verified_envelope: Any,
) -> bool:
    try:
        payload = normalize_receipt_envelope(
            verified_envelope
        )["payload"]
    except BrokerProtocolError:
        return False
    return (
        payload["outcome"] == "succeeded"
        and payload["mutation"]["status"]
        in {"applied", "reconciled", "already_satisfied"}
        and payload["readback"]["status"] == "confirmed"
    )


def is_completion_receipt(
    source: Any,
    *,
    public_key_path: Path,
    expected_public_key_sha256: str,
    expected_key_id: str | None = None,
    config: Any,
    submission: Any,
    public_key_owner_uids: int | Iterable[int] | None = None,
    parent_owner_uids: int | Iterable[int] | None = None,
    trusted_path_root: Path | None = None,
    now: datetime | None = None,
) -> bool:
    """Count completion only after signature, pin, context, and readback checks."""

    try:
        verified = verify_receipt(
            source,
            public_key_path=public_key_path,
            expected_public_key_sha256=expected_public_key_sha256,
            expected_key_id=expected_key_id,
            public_key_owner_uids=public_key_owner_uids,
            parent_owner_uids=parent_owner_uids,
            trusted_path_root=trusted_path_root,
            config=config,
            submission=submission,
            now=now,
        )
    except BrokerProtocolError:
        return False
    return _verified_receipt_is_completion(verified)


def receipt_digest(source: Any) -> str:
    return sha256_json(_coerce_envelope(source))
