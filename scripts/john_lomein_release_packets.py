#!/usr/bin/env python3
"""Prepare credential-free requests for the isolated release broker.

This runtime module can package a bundle plus an externally signed owner
assertion, but it cannot sign the assertion or execute a merge.  The protected
broker contains an independent validator and must distrust this module's
result.  Keeping separate implementations is intentional: compromise of the
Hermes/model runtime must not redefine the broker's authorization contract.
"""

from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import unicodedata
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


BUNDLE_SCHEMA = "john-lomein.release-bundle.v6"
PACKET_SCHEMA = "john-lomein.protected-release-merge-packet.v1"
OWNER_ASSERTION_SCHEMA = "john-lomein.owner-assertion.v2"
SIGNED_ENVELOPE_SCHEMA = "john-lomein.signed-envelope.v1"
AUTHORITY = "request_only_no_execution_authority"
REQUEST_COMPONENT = "john-lomein-release-executor"
RELEASE_ACTION = "merge_release_bundle"
SIGNATURE_ALGORITHM = "ed25519"
MERGE_METHOD = "squash"

MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 3600
MAX_CLOCK_SKEW_SECONDS = 300
MAX_ASSERTION_TTL_SECONDS = 900
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_APPROVAL_BYTES = 4096
MAX_PATHS = 2000
MAX_PATH_BYTES = 1024
MAX_SAFE_INTEGER = 9_007_199_254_740_991
OUTBOX_LOCATOR_PREFIX = Path("state/protected-releases/outbox")

OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
BUNDLE_ID_RE = re.compile(r"^jlb-[0-9a-f]{24}$")
PACKET_ID_RE = re.compile(r"^jlrp-[0-9a-f]{24}$")
NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
INSTANCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
REPOSITORY_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
LOGIN_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,98}(?:\[bot\])?)?$"
)
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,255}$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$")
SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")
RISK_CLASSES = ("low", "medium", "high", "critical")
RISK_RANK = {name: index for index, name in enumerate(RISK_CLASSES)}


class ReleasePacketError(ValueError):
    """A public-safe release request preparation failure."""


def _validate_json(value: Any, *, field: str = "value") -> None:
    if value is None or type(value) is bool:
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ReleasePacketError(
                f"{field} integer is outside the canonical range"
            )
        return
    if isinstance(value, float):
        raise ReleasePacketError(f"{field} floats are forbidden")
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise ReleasePacketError(f"{field} is not NFC-normalized")
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ReleasePacketError(f"{field} is invalid Unicode") from exc
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json(item, field=f"{field}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ReleasePacketError(
                    f"{field} object key must be a string"
                )
            _validate_json(key, field=f"{field} object key")
            _validate_json(item, field=f"{field}.{key}")
        return
    raise ReleasePacketError(f"{field} contains an unsupported JSON type")


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
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(_canonical_text(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
        return (
            "{"
            + ",".join(
                f"{_canonical_text(key)}:{_canonical_text(value[key])}"
                for key in keys
            )
            + "}"
        )
    raise ReleasePacketError("value cannot be encoded as canonical JSON")


def canonical_json(value: Any) -> bytes:
    _validate_json(value)
    return _canonical_text(value).encode("utf-8")


def sha256_json(value: Any) -> str:
    return f"sha256:{hashlib.sha256(canonical_json(value)).hexdigest()}"


def sha256_text(value: str) -> str:
    _validate_json(value, field="text")
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleasePacketError("JSON object contains duplicate fields")
        result[key] = value
    return result


def _reject_float(_: str) -> None:
    raise ReleasePacketError("JSON floats are forbidden")


def _reject_nonfinite(_: str) -> None:
    raise ReleasePacketError("JSON non-finite numbers are forbidden")


def _mapping(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleasePacketError(f"{field} must be an object")
    return value


def _strict_keys(
    value: dict[str, Any],
    *,
    field: str,
    required: set[str],
) -> None:
    if set(value) - required:
        raise ReleasePacketError(f"{field} contains unknown fields")
    if required - set(value):
        raise ReleasePacketError(f"{field} is missing required fields")


def _positive_int(value: Any, *, field: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReleasePacketError(f"{field} must be an integer")
    if value <= 0 or value > maximum:
        raise ReleasePacketError(f"{field} is outside the allowed range")
    return value


def _nonnegative_int(value: Any, *, field: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReleasePacketError(f"{field} must be an integer")
    if value < 0 or value > maximum:
        raise ReleasePacketError(f"{field} is outside the allowed range")
    return value


def _parse_utc(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise ReleasePacketError(f"{field} must be a UTC timestamp")
    try:
        return datetime.strptime(
            value, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ReleasePacketError(
            f"{field} must be a canonical UTC timestamp"
        ) from exc


def utc_text(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ReleasePacketError("clock value must be timezone-aware")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ReleasePacketError("clock value must be timezone-aware")
    return value.astimezone(timezone.utc)


def _full_oid(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not OID_RE.fullmatch(value):
        raise ReleasePacketError(f"{field} must be a full Git OID")
    return value


def _digest(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
        raise ReleasePacketError(f"{field} must be a SHA-256 digest")
    return value


def _safe_text(value: Any, *, field: str, maximum_bytes: int) -> str:
    if not isinstance(value, str) or not value:
        raise ReleasePacketError(f"{field} is invalid")
    _validate_json(value, field=field)
    if len(value.encode("utf-8")) > maximum_bytes:
        raise ReleasePacketError(f"{field} exceeds its size limit")
    if "\x00" in value or any(ord(character) < 0x20 for character in value):
        raise ReleasePacketError(f"{field} contains control characters")
    return value


def _changed_path(value: Any, *, field: str) -> str:
    path = _safe_text(value, field=field, maximum_bytes=MAX_PATH_BYTES)
    if (
        path.startswith("/")
        or path.startswith("./")
        or path.endswith("/")
        or "\\" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        raise ReleasePacketError(f"{field} is unsafe")
    return path


def _github_pr_url(
    value: Any,
    *,
    repository: str,
    number: int,
    field: str,
) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ReleasePacketError(f"{field} must be a GitHub PR URL")
    parsed = urlparse(value)
    path = f"/{repository}/pull/{number}"
    if (
        parsed.scheme != "https"
        or parsed.netloc.lower() != "github.com"
        or parsed.path != path
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.params
        or parsed.fragment
    ):
        raise ReleasePacketError(f"{field} must target the bound GitHub PR")
    return f"https://github.com{path}"


def bundle_digest(bundle: dict[str, Any]) -> str:
    return sha256_json(
        {
            key: value
            for key, value in bundle.items()
            if key not in {"bundle_id", "bundle_digest"}
        }
    )


def bundle_id(bundle: dict[str, Any]) -> str:
    return f"jlb-{bundle_digest(bundle).removeprefix('sha256:')[:24]}"


def ordered_prs_digest(bundle: dict[str, Any]) -> str:
    return sha256_json(bundle["ordered_prs"])


def changed_paths_digest(bundle: dict[str, Any]) -> str:
    return sha256_json(
        [
            {
                "position": item["position"],
                "number": item["number"],
                "changed_paths": item["changed_paths"],
            }
            for item in bundle["ordered_prs"]
        ]
    )


def aggregate_risk_class(bundle: dict[str, Any]) -> str:
    return max(
        (item["risk_class"] for item in bundle["ordered_prs"]),
        key=RISK_RANK.__getitem__,
    )


def normalize_bundle(raw: Any) -> dict[str, Any]:
    bundle = _mapping(raw, field="release bundle")
    _strict_keys(
        bundle,
        field="release bundle",
        required={
            "schema_version",
            "bundle_id",
            "instance_slug",
            "repository",
            "created_at",
            "expires_at",
            "initial_base_sha",
            "merge_method",
            "publish",
            "ordered_prs",
            "train_attestation_digest",
            "actions",
            "bundle_digest",
        },
    )
    if bundle.get("schema_version") != BUNDLE_SCHEMA:
        raise ReleasePacketError("release bundle schema is unsupported")
    instance_slug = str(bundle.get("instance_slug") or "")
    if not INSTANCE_RE.fullmatch(instance_slug):
        raise ReleasePacketError("release bundle instance slug is invalid")
    repository = _mapping(
        bundle.get("repository"), field="release bundle repository"
    )
    _strict_keys(
        repository,
        field="release bundle repository",
        required={"id", "full_name", "default_branch"},
    )
    repository_id = _positive_int(
        repository.get("id"),
        field="release repository ID",
        maximum=MAX_SAFE_INTEGER,
    )
    full_name = str(repository.get("full_name") or "")
    default_branch = str(repository.get("default_branch") or "")
    if not REPOSITORY_RE.fullmatch(full_name):
        raise ReleasePacketError("release repository name is invalid")
    if not BRANCH_RE.fullmatch(default_branch):
        raise ReleasePacketError("release default branch is invalid")
    created = _parse_utc(
        bundle.get("created_at"), field="release bundle created_at"
    )
    expires = _parse_utc(
        bundle.get("expires_at"), field="release bundle expires_at"
    )
    if not 60 <= int((expires - created).total_seconds()) <= 86400:
        raise ReleasePacketError("release bundle lifetime is invalid")
    initial_base_sha = _full_oid(
        bundle.get("initial_base_sha"),
        field="release bundle initial base",
    )
    if bundle.get("merge_method") != MERGE_METHOD:
        raise ReleasePacketError("release merge method must be squash")
    if bundle.get("publish") is not False:
        raise ReleasePacketError("release bundle may not publish")
    raw_prs = bundle.get("ordered_prs")
    if not isinstance(raw_prs, list) or not 1 <= len(raw_prs) <= 50:
        raise ReleasePacketError("release ordered PR list is invalid")
    ordered_prs: list[dict[str, Any]] = []
    seen: set[int] = set()
    for index, raw_pr in enumerate(raw_prs):
        pr = _mapping(raw_pr, field=f"release PR {index}")
        _strict_keys(
            pr,
            field=f"release PR {index}",
            required={
                "position",
                "number",
                "url",
                "head_sha",
                "expected_merge_tree_sha",
                "base_branch",
                "author_login",
                "changed_paths",
                "changed_paths_digest",
                "changed_path_count",
                "risk_class",
                "review_quorum_sha256",
                "review_quorum_policy_sha256",
            },
        )
        position = _nonnegative_int(
            pr.get("position"),
            field=f"release PR {index} position",
            maximum=49,
        )
        if position != index:
            raise ReleasePacketError(
                "release PR positions must be contiguous and ordered"
            )
        number = _positive_int(
            pr.get("number"),
            field=f"release PR {index} number",
            maximum=2**31 - 1,
        )
        if number in seen:
            raise ReleasePacketError("release PR numbers must be unique")
        seen.add(number)
        url = _github_pr_url(
            pr.get("url"),
            repository=full_name,
            number=number,
            field=f"release PR {index} URL",
        )
        head_sha = _full_oid(
            pr.get("head_sha"),
            field=f"release PR {index} head SHA",
        )
        expected_merge_tree_sha = _full_oid(
            pr.get("expected_merge_tree_sha"),
            field=f"release PR {index} expected merge tree SHA",
        )
        if pr.get("base_branch") != default_branch:
            raise ReleasePacketError(
                "release PR base must be the default branch"
            )
        author_login = str(pr.get("author_login") or "")
        if not LOGIN_RE.fullmatch(author_login):
            raise ReleasePacketError(f"release PR {index} author is invalid")
        raw_paths = pr.get("changed_paths")
        if not isinstance(raw_paths, list) or len(raw_paths) > MAX_PATHS:
            raise ReleasePacketError(
                f"release PR {index} changed paths are invalid"
            )
        paths = [
            _changed_path(path, field=f"release PR {index} changed path")
            for path in raw_paths
        ]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ReleasePacketError(
                "release changed paths must be sorted and unique"
            )
        path_count = _nonnegative_int(
            pr.get("changed_path_count"),
            field=f"release PR {index} changed path count",
            maximum=MAX_PATHS,
        )
        if path_count != len(paths):
            raise ReleasePacketError(
                "release changed path count does not match"
            )
        expected_path_digest = sha256_json(paths)
        if pr.get("changed_paths_digest") != expected_path_digest:
            raise ReleasePacketError(
                "release changed paths digest does not match"
            )
        risk_class = str(pr.get("risk_class") or "")
        if risk_class not in RISK_RANK:
            raise ReleasePacketError("release PR risk class is invalid")
        review_quorum_sha256 = _digest(pr.get("review_quorum_sha256"), field=f"release PR {index} review quorum digest")
        review_quorum_policy_sha256 = _digest(pr.get("review_quorum_policy_sha256"), field=f"release PR {index} review policy digest")
        ordered_prs.append(
            {
                "position": position,
                "number": number,
                "url": url,
                "head_sha": head_sha,
                "expected_merge_tree_sha": expected_merge_tree_sha,
                "base_branch": default_branch,
                "author_login": author_login,
                "changed_paths": paths,
                "changed_paths_digest": expected_path_digest,
                "changed_path_count": path_count,
                "risk_class": risk_class,
                "review_quorum_sha256": review_quorum_sha256,
                "review_quorum_policy_sha256": review_quorum_policy_sha256,
            }
        )
    train_digest = bundle.get("train_attestation_digest")
    if train_digest is not None:
        train_digest = _digest(
            train_digest, field="release train attestation digest"
        )
    actions = _mapping(bundle.get("actions"), field="release actions")
    _strict_keys(
        actions,
        field="release actions",
        required={"merge", "publish"},
    )
    if actions != {"merge": True, "publish": False}:
        raise ReleasePacketError("release actions must authorize merge only")
    normalized = {
        "schema_version": BUNDLE_SCHEMA,
        "bundle_id": str(bundle.get("bundle_id") or ""),
        "instance_slug": instance_slug,
        "repository": {
            "id": repository_id,
            "full_name": full_name,
            "default_branch": default_branch,
        },
        "created_at": utc_text(created),
        "expires_at": utc_text(expires),
        "initial_base_sha": initial_base_sha,
        "merge_method": MERGE_METHOD,
        "publish": False,
        "ordered_prs": ordered_prs,
        "train_attestation_digest": train_digest,
        "actions": {"merge": True, "publish": False},
        "bundle_digest": str(bundle.get("bundle_digest") or ""),
    }
    if normalized["bundle_digest"] != bundle_digest(normalized):
        raise ReleasePacketError("release bundle digest does not match")
    if normalized["bundle_id"] != bundle_id(normalized):
        raise ReleasePacketError("release bundle ID does not match")
    return normalized


def normalize_owner_assertion(
    raw: Any,
    *,
    now: datetime,
    allow_expired: bool,
) -> dict[str, Any]:
    envelope = _mapping(raw, field="owner assertion")
    _strict_keys(
        envelope,
        field="owner assertion",
        required={
            "schema_version",
            "algorithm",
            "key_id",
            "payload",
            "signature",
        },
    )
    if envelope.get("schema_version") != SIGNED_ENVELOPE_SCHEMA:
        raise ReleasePacketError("owner assertion schema is unsupported")
    if envelope.get("algorithm") != SIGNATURE_ALGORITHM:
        raise ReleasePacketError("owner assertion algorithm is unsupported")
    key_id = str(envelope.get("key_id") or "")
    if not KEY_ID_RE.fullmatch(key_id):
        raise ReleasePacketError("owner assertion key ID is invalid")
    signature = str(envelope.get("signature") or "")
    if not SIGNATURE_RE.fullmatch(signature):
        raise ReleasePacketError("owner assertion signature is invalid")
    try:
        decoded = base64.urlsafe_b64decode(signature + "==")
    except (ValueError, TypeError) as exc:
        raise ReleasePacketError("owner assertion signature is invalid") from exc
    if len(decoded) != 64:
        raise ReleasePacketError("owner assertion signature is invalid")
    payload = _mapping(
        envelope.get("payload"), field="owner assertion payload"
    )
    required = {
        "schema_version",
        "purpose",
        "issuer",
        "actor_id",
        "actor_login",
        "tier",
        "issued_at",
        "expires_at",
        "nonce",
        "instance_slug",
        "repository_id",
        "repository_full_name",
        "bundle_id",
        "bundle_digest",
        "approval_text_sha256",
        "action",
        "merge_method",
        "publish",
        "ordered_prs_digest",
        "changed_paths_digest",
        "risk_class",
    }
    _strict_keys(payload, field="owner assertion payload", required=required)
    if payload.get("schema_version") != OWNER_ASSERTION_SCHEMA:
        raise ReleasePacketError(
            "owner assertion payload schema is unsupported"
        )
    if payload.get("purpose") != "release_merge":
        raise ReleasePacketError("owner assertion purpose is invalid")
    issuer = str(payload.get("issuer") or "")
    actor_id = str(payload.get("actor_id") or "")
    actor_login = str(payload.get("actor_login") or "")
    if not TOKEN_RE.fullmatch(issuer) or not TOKEN_RE.fullmatch(actor_id):
        raise ReleasePacketError("owner assertion identity is invalid")
    if not LOGIN_RE.fullmatch(actor_login):
        raise ReleasePacketError("owner assertion login is invalid")
    if payload.get("tier") != "owner":
        raise ReleasePacketError("owner assertion tier must be owner")
    issued = _parse_utc(
        payload.get("issued_at"), field="owner assertion issued_at"
    )
    expires = _parse_utc(
        payload.get("expires_at"), field="owner assertion expires_at"
    )
    if not 1 <= int((expires - issued).total_seconds()) <= MAX_ASSERTION_TTL_SECONDS:
        raise ReleasePacketError("owner assertion lifetime is invalid")
    if issued > now + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        raise ReleasePacketError("owner assertion is from the future")
    if not allow_expired and now >= expires:
        raise ReleasePacketError("owner assertion has expired")
    nonce = str(payload.get("nonce") or "")
    if not NONCE_RE.fullmatch(nonce):
        raise ReleasePacketError("owner assertion nonce is invalid")
    instance_slug = str(payload.get("instance_slug") or "")
    repository_full_name = str(
        payload.get("repository_full_name") or ""
    )
    if not INSTANCE_RE.fullmatch(instance_slug):
        raise ReleasePacketError("owner assertion instance is invalid")
    if not REPOSITORY_RE.fullmatch(repository_full_name):
        raise ReleasePacketError("owner assertion repository is invalid")
    normalized_payload = {
        "schema_version": OWNER_ASSERTION_SCHEMA,
        "purpose": "release_merge",
        "issuer": issuer,
        "actor_id": actor_id,
        "actor_login": actor_login,
        "tier": "owner",
        "issued_at": utc_text(issued),
        "expires_at": utc_text(expires),
        "nonce": nonce,
        "instance_slug": instance_slug,
        "repository_id": _positive_int(
            payload.get("repository_id"),
            field="owner assertion repository ID",
            maximum=MAX_SAFE_INTEGER,
        ),
        "repository_full_name": repository_full_name,
        "bundle_id": str(payload.get("bundle_id") or ""),
        "bundle_digest": _digest(
            payload.get("bundle_digest"),
            field="owner assertion bundle digest",
        ),
        "approval_text_sha256": _digest(
            payload.get("approval_text_sha256"),
            field="owner assertion approval digest",
        ),
        "action": str(payload.get("action") or ""),
        "merge_method": str(payload.get("merge_method") or ""),
        "publish": payload.get("publish"),
        "ordered_prs_digest": _digest(
            payload.get("ordered_prs_digest"),
            field="owner assertion ordered PR digest",
        ),
        "changed_paths_digest": _digest(
            payload.get("changed_paths_digest"),
            field="owner assertion changed paths digest",
        ),
        "risk_class": str(payload.get("risk_class") or ""),
    }
    if not BUNDLE_ID_RE.fullmatch(normalized_payload["bundle_id"]):
        raise ReleasePacketError("owner assertion bundle ID is invalid")
    if normalized_payload["action"] != RELEASE_ACTION:
        raise ReleasePacketError("owner assertion action is invalid")
    if normalized_payload["merge_method"] != MERGE_METHOD:
        raise ReleasePacketError("owner assertion merge method is invalid")
    if normalized_payload["publish"] is not False:
        raise ReleasePacketError("owner assertion may not publish")
    if normalized_payload["risk_class"] not in RISK_RANK:
        raise ReleasePacketError("owner assertion risk class is invalid")
    return {
        "schema_version": SIGNED_ENVELOPE_SCHEMA,
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "payload": normalized_payload,
        "signature": signature,
    }


def _approval(value: Any) -> dict[str, str]:
    approval = _mapping(value, field="release approval")
    _strict_keys(
        approval,
        field="release approval",
        required={"text", "text_sha256"},
    )
    text = _safe_text(
        approval.get("text"),
        field="release approval text",
        maximum_bytes=MAX_APPROVAL_BYTES,
    )
    expected = sha256_text(text)
    if approval.get("text_sha256") != expected:
        raise ReleasePacketError("release approval digest does not match")
    return {"text": text, "text_sha256": expected}


def _cross_bind(
    *,
    bundle: dict[str, Any],
    approval: dict[str, str],
    assertion: dict[str, Any],
) -> None:
    payload = assertion["payload"]
    expected = {
        "instance_slug": bundle["instance_slug"],
        "repository_id": bundle["repository"]["id"],
        "repository_full_name": bundle["repository"]["full_name"],
        "bundle_id": bundle["bundle_id"],
        "bundle_digest": bundle["bundle_digest"],
        "approval_text_sha256": approval["text_sha256"],
        "action": RELEASE_ACTION,
        "merge_method": MERGE_METHOD,
        "publish": False,
        "ordered_prs_digest": ordered_prs_digest(bundle),
        "changed_paths_digest": changed_paths_digest(bundle),
        "risk_class": aggregate_risk_class(bundle),
    }
    for field, value in expected.items():
        if payload.get(field) != value:
            raise ReleasePacketError(
                f"owner assertion {field} does not match the release"
            )


def prepare_packet(
    *,
    bundle: Any,
    approval_text: str,
    owner_assertion: Any,
    now: datetime | None = None,
    ttl_seconds: int = 300,
) -> dict[str, Any]:
    if (
        isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, int)
        or not MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS
    ):
        raise ReleasePacketError("release packet TTL is invalid")
    current = _now(now)
    normalized_bundle = normalize_bundle(bundle)
    if len(normalized_bundle["ordered_prs"]) != 1:
        raise ReleasePacketError(
            "live release v1 accepts exactly one PR per bundle"
        )
    if normalized_bundle["train_attestation_digest"] is not None:
        raise ReleasePacketError(
            "single-PR release may not carry a train attestation"
        )
    bundle_created = _parse_utc(
        normalized_bundle["created_at"],
        field="release bundle created_at",
    )
    bundle_expires = _parse_utc(
        normalized_bundle["expires_at"],
        field="release bundle expires_at",
    )
    if current < bundle_created - timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        raise ReleasePacketError("release bundle is from the future")
    if current >= bundle_expires:
        raise ReleasePacketError("release bundle has expired")
    packet_expires = current + timedelta(seconds=ttl_seconds)
    if packet_expires > bundle_expires:
        raise ReleasePacketError("release packet would outlive its bundle")
    approval = {
        "text": approval_text,
        "text_sha256": sha256_text(approval_text),
    }
    approval = _approval(approval)
    assertion = normalize_owner_assertion(
        owner_assertion,
        now=current,
        allow_expired=False,
    )
    _cross_bind(
        bundle=normalized_bundle,
        approval=approval,
        assertion=assertion,
    )
    request = {
        "action": RELEASE_ACTION,
        "bundle": normalized_bundle,
        "approval": approval,
        "owner_assertion": assertion,
        "train_attestation": None,
    }
    body = {
        "schema_version": PACKET_SCHEMA,
        "created_at": utc_text(current),
        "expires_at": utc_text(packet_expires),
        "authority": AUTHORITY,
        "requested_by": {
            "component": REQUEST_COMPONENT,
            "instance_slug": normalized_bundle["instance_slug"],
        },
        "request": request,
    }
    return {
        **body,
        "packet_id": (
            "jlrp-"
            + sha256_json(body).removeprefix("sha256:")[:24]
        ),
        "request_digest": sha256_json(request),
    }


def verify_packet(
    raw: Any,
    *,
    now: datetime | None = None,
    allow_expired: bool = False,
    allow_expired_assertion: bool = False,
) -> dict[str, Any]:
    packet = _mapping(raw, field="release packet")
    _strict_keys(
        packet,
        field="release packet",
        required={
            "schema_version",
            "packet_id",
            "created_at",
            "expires_at",
            "authority",
            "requested_by",
            "request",
            "request_digest",
        },
    )
    if packet.get("schema_version") != PACKET_SCHEMA:
        raise ReleasePacketError("release packet schema is unsupported")
    if packet.get("authority") != AUTHORITY:
        raise ReleasePacketError("release packet authority is invalid")
    requester = _mapping(
        packet.get("requested_by"), field="release packet requester"
    )
    _strict_keys(
        requester,
        field="release packet requester",
        required={"component", "instance_slug"},
    )
    if requester.get("component") != REQUEST_COMPONENT:
        raise ReleasePacketError("release packet requester is invalid")
    created = _parse_utc(
        packet.get("created_at"), field="release packet created_at"
    )
    expires = _parse_utc(
        packet.get("expires_at"), field="release packet expires_at"
    )
    if not MIN_TTL_SECONDS <= int(
        (expires - created).total_seconds()
    ) <= MAX_TTL_SECONDS:
        raise ReleasePacketError("release packet lifetime is invalid")
    current = _now(now)
    if created > current + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        raise ReleasePacketError("release packet is from the future")
    if not allow_expired and current >= expires:
        raise ReleasePacketError("release packet has expired")
    request = _mapping(packet.get("request"), field="release request")
    _strict_keys(
        request,
        field="release request",
        required={
            "action",
            "bundle",
            "approval",
            "owner_assertion",
            "train_attestation",
        },
    )
    if request.get("action") != RELEASE_ACTION:
        raise ReleasePacketError("release action is invalid")
    bundle = normalize_bundle(request.get("bundle"))
    if len(bundle["ordered_prs"]) != 1:
        raise ReleasePacketError(
            "live release v1 accepts exactly one PR per bundle"
        )
    approval = _approval(request.get("approval"))
    assertion = normalize_owner_assertion(
        request.get("owner_assertion"),
        now=current,
        allow_expired=allow_expired_assertion,
    )
    if request.get("train_attestation") is not None:
        raise ReleasePacketError(
            "release train attestations are not implemented"
        )
    if bundle["train_attestation_digest"] is not None:
        raise ReleasePacketError(
            "single-PR release may not carry a train attestation"
        )
    if requester.get("instance_slug") != bundle["instance_slug"]:
        raise ReleasePacketError("release requester instance does not match")
    _cross_bind(bundle=bundle, approval=approval, assertion=assertion)
    if created < _parse_utc(
        bundle["created_at"], field="release bundle created_at"
    ):
        raise ReleasePacketError("release packet predates its bundle")
    if expires > _parse_utc(
        bundle["expires_at"], field="release bundle expires_at"
    ):
        raise ReleasePacketError("release packet outlives its bundle")
    normalized_request = {
        "action": RELEASE_ACTION,
        "bundle": bundle,
        "approval": approval,
        "owner_assertion": assertion,
        "train_attestation": None,
    }
    body = {
        "schema_version": PACKET_SCHEMA,
        "created_at": utc_text(created),
        "expires_at": utc_text(expires),
        "authority": AUTHORITY,
        "requested_by": {
            "component": REQUEST_COMPONENT,
            "instance_slug": bundle["instance_slug"],
        },
        "request": normalized_request,
    }
    expected_digest = sha256_json(normalized_request)
    expected_id = (
        "jlrp-" + sha256_json(body).removeprefix("sha256:")[:24]
    )
    if packet.get("request_digest") != expected_digest:
        raise ReleasePacketError("release packet digest does not match")
    if packet.get("packet_id") != expected_id:
        raise ReleasePacketError("release packet ID does not match")
    return {
        **body,
        "packet_id": expected_id,
        "request_digest": expected_digest,
    }


def load_json(path: Path, *, field: str) -> Any:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ReleasePacketError(f"{field} is unreadable") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ReleasePacketError(
                f"{field} must be a regular non-symlink file"
            )
        if info.st_size > MAX_JSON_BYTES:
            raise ReleasePacketError(f"{field} exceeds its size limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                fd, min(64 * 1024, MAX_JSON_BYTES + 1 - total)
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_JSON_BYTES:
                raise ReleasePacketError(f"{field} exceeds its size limit")
        value = json.loads(
            b"".join(chunks),
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_nonfinite,
        )
        _validate_json(value, field=field)
        return value
    except ReleasePacketError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleasePacketError(f"{field} is invalid JSON") from exc
    finally:
        os.close(fd)


def load_text(
    path: Path,
    *,
    field: str,
    maximum_bytes: int,
) -> str:
    """Read one stable, bounded UTF-8 regular-file snapshot."""

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ReleasePacketError(f"{field} is unreadable") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ReleasePacketError(
                f"{field} must be a regular non-symlink file"
            )
        if info.st_size > maximum_bytes:
            raise ReleasePacketError(f"{field} exceeds its size limit")
        raw = bytearray()
        while len(raw) <= maximum_bytes:
            chunk = os.read(
                fd, min(16 * 1024, maximum_bytes + 1 - len(raw))
            )
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > maximum_bytes:
            raise ReleasePacketError(f"{field} exceeds its size limit")
        return bytes(raw).decode("utf-8", errors="strict")
    except ReleasePacketError:
        raise
    except (OSError, UnicodeError) as exc:
        raise ReleasePacketError(f"{field} is unreadable") from exc
    finally:
        os.close(fd)


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _open_directory(path: Path, *, field: str) -> int:
    try:
        fd = os.open(path, _directory_flags())
    except OSError as exc:
        raise ReleasePacketError(f"{field} directory is unsafe") from exc
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        os.close(fd)
        raise ReleasePacketError(f"{field} directory is unsafe")
    return fd


def _ensure_directory_at(parent_fd: int, name: str, *, field: str) -> int:
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileExistsError:
        pass
    try:
        fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise ReleasePacketError(f"{field} directory is unsafe") from exc
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        os.close(fd)
        raise ReleasePacketError(f"{field} directory is unsafe")
    os.fchmod(fd, 0o700)
    return fd


def _write_all(fd: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(fd, raw[offset:])
        if written <= 0:
            raise ReleasePacketError("release packet write made no progress")
        offset += written


def _read_json_at(directory_fd: int, name: str, *, field: str) -> Any:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise ReleasePacketError(f"{field} is unreadable") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JSON_BYTES:
            raise ReleasePacketError(f"{field} is unsafe")
        raw = bytearray()
        while len(raw) <= MAX_JSON_BYTES:
            chunk = os.read(fd, min(64 * 1024, MAX_JSON_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > MAX_JSON_BYTES:
            raise ReleasePacketError(f"{field} exceeds its size limit")
        value = json.loads(
            bytes(raw),
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_nonfinite,
        )
        _validate_json(value, field=field)
        return value
    except ReleasePacketError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleasePacketError(f"{field} is invalid JSON") from exc
    finally:
        os.close(fd)


def persist_packet(
    runtime_home: Path,
    packet: dict[str, Any],
    *,
    now: datetime | None = None,
) -> Path:
    verified = verify_packet(packet, now=now)
    packet_id = verified["packet_id"]
    if not PACKET_ID_RE.fullmatch(packet_id):
        raise ReleasePacketError("release packet ID is unsafe")
    raw = canonical_json(verified) + b"\n"
    if len(raw) > MAX_JSON_BYTES:
        raise ReleasePacketError("release packet exceeds its size limit")
    runtime = runtime_home.expanduser()
    runtime.mkdir(parents=True, exist_ok=True)
    runtime_fd = _open_directory(runtime, field="runtime")
    state_fd = protected_fd = outbox_fd = -1
    final_name = f"{packet_id}.json"
    temporary_name = (
        f".{packet_id}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    try:
        state_fd = _ensure_directory_at(runtime_fd, "state", field="state")
        protected_fd = _ensure_directory_at(
            state_fd,
            "protected-releases",
            field="protected releases",
        )
        outbox_fd = _ensure_directory_at(
            protected_fd,
            "outbox",
            field="protected release outbox",
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(
            temporary_name, flags, 0o600, dir_fd=outbox_fd
        )
        try:
            _write_all(fd, raw)
            os.fsync(fd)
        except BaseException:
            try:
                os.unlink(temporary_name, dir_fd=outbox_fd)
                os.fsync(outbox_fd)
            finally:
                raise
        finally:
            os.close(fd)
        try:
            os.link(
                temporary_name,
                final_name,
                src_dir_fd=outbox_fd,
                dst_dir_fd=outbox_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise ReleasePacketError(
                    "release packet could not be persisted"
                ) from exc
            existing = _read_json_at(
                outbox_fd,
                final_name,
                field="existing release packet",
            )
            if existing != verified:
                raise ReleasePacketError("release packet ID collision")
        finally:
            try:
                os.unlink(temporary_name, dir_fd=outbox_fd)
            except FileNotFoundError:
                pass
        os.fsync(outbox_fd)
    finally:
        for fd in (outbox_fd, protected_fd, state_fd, runtime_fd):
            if fd >= 0:
                os.close(fd)
    return runtime / OUTBOX_LOCATOR_PREFIX / final_name


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--bundle", required=True)
    prepare.add_argument("--approval-file", required=True)
    prepare.add_argument("--owner-assertion", required=True)
    prepare.add_argument("--runtime-home", required=True)
    prepare.add_argument("--ttl-seconds", type=int, default=300)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--packet", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            approval_text = load_text(
                Path(args.approval_file),
                field="release approval file",
                maximum_bytes=MAX_APPROVAL_BYTES + 1,
            )
            packet = prepare_packet(
                bundle=load_json(
                    Path(args.bundle), field="release bundle"
                ),
                approval_text=approval_text.rstrip("\n"),
                owner_assertion=load_json(
                    Path(args.owner_assertion),
                    field="owner assertion",
                ),
                ttl_seconds=args.ttl_seconds,
            )
            persist_packet(Path(args.runtime_home), packet)
            print(
                json.dumps(
                    {
                        "ok": True,
                        "authority": AUTHORITY,
                        "packet_id": packet["packet_id"],
                        "request_digest": packet["request_digest"],
                        "bundle_id": packet["request"]["bundle"]["bundle_id"],
                        "expires_at": packet["expires_at"],
                        "packet_locator": str(
                            OUTBOX_LOCATOR_PREFIX
                            / f"{packet['packet_id']}.json"
                        ),
                    },
                    sort_keys=True,
                )
            )
            return 0
        packet = verify_packet(
            load_json(Path(args.packet), field="release packet")
        )
        print(
            json.dumps(
                {
                    "ok": True,
                    "authority": packet["authority"],
                    "packet_id": packet["packet_id"],
                    "request_digest": packet["request_digest"],
                    "bundle_id": packet["request"]["bundle"]["bundle_id"],
                    "expires_at": packet["expires_at"],
                },
                sort_keys=True,
            )
        )
        return 0
    except ReleasePacketError as exc:
        print(
            json.dumps(
                {"ok": False, "error": str(exc)},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
