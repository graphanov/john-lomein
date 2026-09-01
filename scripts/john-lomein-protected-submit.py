#!/usr/bin/env python3
"""Submit one protected-action packet and verify the broker's signed receipt.

The client imports only John Lomein's unprivileged runtime-control contract.
No privileged broker package, private key, GitHub credential, or broker
configuration is imported.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from john_lomein_autonomy import (
    AutonomyError,
    anchored_runtime_home,
    deployed_runtime_control,
    require_effective_mutation,
)


CLIENT_CONFIG_SCHEMA = "john-lomein.protected-broker-client-config.v1"
SUBMISSION_SCHEMA = "john-lomein.protected-broker-submit.v1"
RESPONSE_SCHEMA = "john-lomein.protected-broker-response.v1"
PACKET_INPUT_SCHEMA = "john-lomein.protected-action-input.v1"
PACKET_SCHEMA = "john-lomein.protected-action-packet.v1"
PACKET_AUTHORITY = "request_only_no_execution_authority"
RECEIPT_PAYLOAD_SCHEMA = "john-lomein.protected-broker-receipt.v1"
RECEIPT_ENVELOPE_SCHEMA = (
    "john-lomein.protected-broker-signed-receipt.v1"
)
SIGNATURE_ALGORITHM = "Ed25519"
DEFAULT_CONFIG_ROOT = Path("/private/etc/john-lomein-broker-public")

ALLOWED_ACTIONS = frozenset(
    {"mark_pr_ready", "resolve_review_thread"}
)
DAEMON_ERROR_CODES = frozenset(
    {"request_rejected", "transport_rejected", "broker_failure"}
)
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

MAX_PACKET_BYTES = 256 * 1024
MAX_CONFIG_BYTES = 64 * 1024
MAX_KEY_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 512 * 1024
MAX_SIGNATURE_BYTES = 256
FRAME_HEADER_BYTES = 4
MIN_PACKET_TTL_SECONDS = 60
MAX_PACKET_TTL_SECONDS = 3600
MAX_PACKET_EVIDENCE_AGE_SECONDS = 3600
MAX_CLOCK_SKEW_SECONDS = 300
MAX_SOCKET_PATH_BYTES = 100

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
PACKET_ID_RE = re.compile(r"^jlpa-[0-9a-f]{24}$")
RECEIPT_ID_RE = re.compile(r"^jlbr-[0-9a-f]{24}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,255}$")
INSTANCE_SLUG_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
)
REPO_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
LOGIN_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9-]{0,98}(?:\[bot\])?$"
)
APP_SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$")
REASON_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")


class ProtectedSubmitError(ValueError):
    """A public-safe, fail-closed client error."""


class BrokerDeniedError(ProtectedSubmitError):
    """The authenticated transport returned a strict negative response."""

    def __init__(
        self,
        reason_code: str,
        *,
        receipt: dict[str, Any] | None = None,
    ) -> None:
        if not REASON_CODE_RE.fullmatch(reason_code):
            raise ProtectedSubmitError(
                "protected broker denial reason is invalid"
            )
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.receipt = receipt


@dataclass(frozen=True)
class LoadedClientConfig:
    value: dict[str, Any]
    public_key: bytes


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProtectedSubmitError("value is not canonical JSON") from exc


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtectedSubmitError(
                "JSON object contains duplicate fields"
            )
        result[key] = value
    return result


def _reject_nonfinite(_: str) -> None:
    raise ProtectedSubmitError("JSON contains a non-finite number")


def parse_json_bytes(
    raw: bytes,
    *,
    field: str,
    maximum_bytes: int,
) -> Any:
    if len(raw) > maximum_bytes:
        raise ProtectedSubmitError(f"{field} exceeds its size limit")
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except ProtectedSubmitError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProtectedSubmitError(f"{field} is invalid JSON") from exc


def _mapping(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtectedSubmitError(f"{field} must be an object")
    return value


def _strict_keys(
    value: Mapping[str, Any],
    *,
    field: str,
    allowed: set[str],
) -> None:
    unknown = sorted(set(value) - allowed)
    missing = sorted(allowed - set(value))
    if unknown:
        raise ProtectedSubmitError(f"{field} contains unknown fields")
    if missing:
        raise ProtectedSubmitError(f"{field} is missing required fields")


def _positive_int(
    value: Any,
    *,
    field: str,
    maximum: int = 2**31 - 1,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtectedSubmitError(f"{field} must be an integer")
    if value <= 0 or value > maximum:
        raise ProtectedSubmitError(f"{field} is outside the allowed range")
    return value


def _uid(
    value: Any,
    *,
    field: str,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 2**31 - 1
    ):
        raise ProtectedSubmitError(f"{field} is invalid")
    return value


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
            normalized.add(_uid(value, field="trusted owner UID"))
    except TypeError as exc:
        raise ProtectedSubmitError(
            "trusted owner UID set is invalid"
        ) from exc
    if not normalized:
        raise ProtectedSubmitError("trusted owner UID set is empty")
    return frozenset(normalized)


def _absolute_path(value: Any, *, field: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ProtectedSubmitError(f"{field} must be an absolute path")
    path = Path(value)
    if (
        not path.is_absolute()
        or ".." in path.parts
        or str(path) != value
    ):
        raise ProtectedSubmitError(f"{field} must be normalized")
    return path


def _path_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def validate_trusted_parent_chain(
    path: Path,
    *,
    field: str,
    expected_owner_uids: int | Iterable[int] | None,
    trusted_path_root: Path | None = None,
) -> None:
    trusted = _uid_set(expected_owner_uids, default=(0,))
    path = _absolute_path(str(path), field=field)
    stop: Path | None = None
    if trusted_path_root is not None:
        stop = _absolute_path(
            str(trusted_path_root), field="trusted path root"
        )
        if not _path_within(path, stop):
            raise ProtectedSubmitError(
                f"{field} is outside the trusted path root"
            )
    current = path
    while True:
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise ProtectedSubmitError(
                f"{field} parent directory is unreadable"
            ) from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ProtectedSubmitError(
                f"{field} parent directory is unsafe"
            )
        if info.st_uid not in trusted:
            raise ProtectedSubmitError(
                f"{field} parent directory owner is untrusted"
            )
        if info.st_mode & 0o022:
            raise ProtectedSubmitError(
                f"{field} parent directory is group/other writable"
            )
        if stop is not None and current == stop:
            return
        if current.parent == current:
            return
        current = current.parent


def read_stable_file(
    path: Path,
    *,
    field: str,
    maximum_bytes: int,
    expected_owner_uids: int | Iterable[int] | None = None,
    reject_group_other_writable: bool = False,
) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ProtectedSubmitError(f"{field} is unreadable") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ProtectedSubmitError(
                f"{field} must be a regular non-symlink file"
            )
        if expected_owner_uids is not None:
            trusted = _uid_set(
                expected_owner_uids, default=(0,)
            )
            if info.st_uid not in trusted:
                raise ProtectedSubmitError(
                    f"{field} owner is untrusted"
                )
        if reject_group_other_writable and info.st_mode & 0o022:
            raise ProtectedSubmitError(
                f"{field} is group/other writable"
            )
        if info.st_size > maximum_bytes:
            raise ProtectedSubmitError(f"{field} exceeds its size limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                fd,
                min(64 * 1024, maximum_bytes + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise ProtectedSubmitError(
                    f"{field} exceeds its size limit"
                )
        return b"".join(chunks)
    except OSError as exc:
        raise ProtectedSubmitError(f"{field} is unreadable") from exc
    finally:
        os.close(fd)


def read_trusted_file(
    path: Path,
    *,
    field: str,
    maximum_bytes: int,
    expected_owner_uids: int | Iterable[int] | None,
    parent_owner_uids: int | Iterable[int] | None,
    trusted_path_root: Path | None = None,
) -> bytes:
    path = _absolute_path(str(path), field=field)
    validate_trusted_parent_chain(
        path.parent,
        field=field,
        expected_owner_uids=parent_owner_uids,
        trusted_path_root=trusted_path_root,
    )
    return read_stable_file(
        path,
        field=field,
        maximum_bytes=maximum_bytes,
        expected_owner_uids=expected_owner_uids,
        reject_group_other_writable=True,
    )


def _parse_utc(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise ProtectedSubmitError(f"{field} must be a UTC timestamp")
    try:
        parsed = datetime.strptime(
            value, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ProtectedSubmitError(
            f"{field} must be a UTC timestamp"
        ) from exc
    if parsed.year < 2020:
        raise ProtectedSubmitError(f"{field} is outside the allowed range")
    return parsed


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _github_url(
    value: Any,
    *,
    field: str,
    repo: str,
    pr_number: int,
    kind: str,
) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ProtectedSubmitError(f"{field} must be a GitHub URL")
    parsed = urlparse(value)
    expected_path = f"/{repo}/pull/{pr_number}"
    fragments = {
        "pr": None,
        "evidence_comment": re.compile(r"^issuecomment-[1-9][0-9]*$"),
        "review_thread": re.compile(r"^discussion_r[1-9][0-9]*$"),
    }
    expected_fragment = fragments.get(kind)
    if kind not in fragments:
        raise ProtectedSubmitError(f"{field} has an unsupported URL kind")
    if (
        parsed.scheme != "https"
        or parsed.netloc.lower() != "github.com"
        or parsed.path != expected_path
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.params
        or (kind == "pr" and bool(parsed.fragment))
        or (
            expected_fragment is not None
            and not expected_fragment.fullmatch(parsed.fragment)
        )
    ):
        raise ProtectedSubmitError(f"{field} must target the bound PR")
    if kind == "pr":
        return f"https://github.com{expected_path}"
    return f"https://github.com{expected_path}#{parsed.fragment}"


def _normalize_packet_request(raw: Any) -> dict[str, Any]:
    request = _mapping(raw, field="protected-action request")
    _strict_keys(
        request,
        field="protected-action request",
        allowed={
            "schema_version",
            "instance_slug",
            "action",
            "observed_at",
            "repo",
            "pr",
            "preconditions",
            "targets",
        },
    )
    if request.get("schema_version") != PACKET_INPUT_SCHEMA:
        raise ProtectedSubmitError(
            "protected-action input schema is unsupported"
        )
    instance_slug = str(request.get("instance_slug") or "")
    if not INSTANCE_SLUG_RE.fullmatch(instance_slug):
        raise ProtectedSubmitError(
            "protected-action instance slug is invalid"
        )
    action = str(request.get("action") or "")
    if action not in ALLOWED_ACTIONS:
        raise ProtectedSubmitError("protected action is unsupported")
    observed_at = _utc_text(
        _parse_utc(
            request.get("observed_at"),
            field="protected-action observed_at",
        )
    )
    repo = str(request.get("repo") or "")
    if not REPO_RE.fullmatch(repo):
        raise ProtectedSubmitError(
            "protected-action repository is invalid"
        )

    pr = _mapping(request.get("pr"), field="protected-action pr")
    _strict_keys(
        pr,
        field="protected-action pr",
        allowed={
            "number",
            "url",
            "base_branch",
            "head_sha",
            "author_login",
            "is_draft",
        },
    )
    pr_number = _positive_int(
        pr.get("number"), field="protected-action pr.number"
    )
    pr_url = _github_url(
        pr.get("url"),
        field="protected-action pr.url",
        repo=repo,
        pr_number=pr_number,
        kind="pr",
    )
    base_branch = str(pr.get("base_branch") or "")
    if not BRANCH_RE.fullmatch(base_branch):
        raise ProtectedSubmitError(
            "protected-action base branch is invalid"
        )
    head_sha = str(pr.get("head_sha") or "").lower()
    if not OID_RE.fullmatch(head_sha):
        raise ProtectedSubmitError(
            "protected-action head SHA is invalid"
        )
    author_login = str(pr.get("author_login") or "")
    if not LOGIN_RE.fullmatch(author_login):
        raise ProtectedSubmitError(
            "protected-action author login is invalid"
        )
    if type(pr.get("is_draft")) is not bool:
        raise ProtectedSubmitError(
            "protected-action draft state must be boolean"
        )
    is_draft = pr["is_draft"]

    preconditions = _mapping(
        request.get("preconditions"),
        field="protected-action preconditions",
    )
    _strict_keys(
        preconditions,
        field="protected-action preconditions",
        allowed={
            "checks_state",
            "unresolved_thread_count",
            "forbidden_paths_clear",
            "bot_authorship_verified",
            "verification",
            "evidence_comment_url",
        },
    )
    checks_state = str(preconditions.get("checks_state") or "")
    if checks_state not in {"success", "none"}:
        raise ProtectedSubmitError(
            "protected-action checks state is invalid"
        )
    thread_count = preconditions.get("unresolved_thread_count")
    if (
        isinstance(thread_count, bool)
        or not isinstance(thread_count, int)
        or thread_count < 0
        or thread_count > 10_000
    ):
        raise ProtectedSubmitError(
            "protected-action unresolved thread count is invalid"
        )
    if (
        preconditions.get("forbidden_paths_clear") is not True
        or preconditions.get("bot_authorship_verified") is not True
    ):
        raise ProtectedSubmitError(
            "protected-action proof flags are invalid"
        )
    verification = _mapping(
        preconditions.get("verification"),
        field="protected-action verification",
    )
    _strict_keys(
        verification,
        field="protected-action verification",
        allowed={"passed", "commands_sha256", "result_sha256"},
    )
    commands_sha256 = str(
        verification.get("commands_sha256") or ""
    )
    result_sha256 = str(verification.get("result_sha256") or "")
    if (
        verification.get("passed") is not True
        or not SHA256_RE.fullmatch(commands_sha256)
        or not SHA256_RE.fullmatch(result_sha256)
    ):
        raise ProtectedSubmitError(
            "protected-action verification proof is invalid"
        )
    evidence_url = _github_url(
        preconditions.get("evidence_comment_url"),
        field="protected-action evidence comment URL",
        repo=repo,
        pr_number=pr_number,
        kind="evidence_comment",
    )

    targets = _mapping(
        request.get("targets"), field="protected-action targets"
    )
    _strict_keys(
        targets,
        field="protected-action targets",
        allowed={"thread_node_ids", "thread_urls"},
    )
    node_ids = targets.get("thread_node_ids")
    thread_urls = targets.get("thread_urls")
    if (
        not isinstance(node_ids, list)
        or not isinstance(thread_urls, list)
        or len(node_ids) != len(thread_urls)
        or len(node_ids) > 50
    ):
        raise ProtectedSubmitError(
            "protected-action thread targets are inconsistent"
        )
    normalized_ids: list[str] = []
    normalized_urls: list[str] = []
    for index, node_id in enumerate(node_ids):
        if not isinstance(node_id, str) or not TOKEN_RE.fullmatch(node_id):
            raise ProtectedSubmitError(
                "protected-action thread node ID is invalid"
            )
        normalized_ids.append(node_id)
        normalized_urls.append(
            _github_url(
                thread_urls[index],
                field="protected-action review thread URL",
                repo=repo,
                pr_number=pr_number,
                kind="review_thread",
            )
        )
    if len(set(normalized_ids)) != len(normalized_ids):
        raise ProtectedSubmitError(
            "protected-action thread targets contain duplicates"
        )
    if action == "mark_pr_ready":
        if not is_draft or thread_count != 0 or normalized_ids:
            raise ProtectedSubmitError(
                "mark_pr_ready packet preconditions are inconsistent"
            )
    elif not normalized_ids or thread_count < len(normalized_ids):
        raise ProtectedSubmitError(
            "resolve_review_thread packet targets are inconsistent"
        )
    return {
        "schema_version": PACKET_INPUT_SCHEMA,
        "instance_slug": instance_slug,
        "action": action,
        "observed_at": observed_at,
        "repo": repo,
        "pr": {
            "number": pr_number,
            "url": pr_url,
            "base_branch": base_branch,
            "head_sha": head_sha,
            "author_login": author_login,
            "is_draft": is_draft,
        },
        "preconditions": {
            "checks_state": checks_state,
            "unresolved_thread_count": thread_count,
            "forbidden_paths_clear": True,
            "bot_authorship_verified": True,
            "verification": {
                "passed": True,
                "commands_sha256": commands_sha256,
                "result_sha256": result_sha256,
            },
            "evidence_comment_url": evidence_url,
        },
        "targets": {
            "thread_node_ids": normalized_ids,
            "thread_urls": normalized_urls,
        },
    }


def verify_packet(
    raw: Any,
    *,
    now: datetime | None = None,
    allow_expired: bool = False,
) -> dict[str, Any]:
    packet = _mapping(raw, field="protected-action packet")
    _strict_keys(
        packet,
        field="protected-action packet",
        allowed={
            "schema_version",
            "authority",
            "requested_by",
            "created_at",
            "expires_at",
            "request",
            "packet_id",
            "request_digest",
        },
    )
    if packet.get("schema_version") != PACKET_SCHEMA:
        raise ProtectedSubmitError(
            "protected-action packet schema is unsupported"
        )
    if packet.get("authority") != PACKET_AUTHORITY:
        raise ProtectedSubmitError(
            "protected-action packet authority is invalid"
        )
    if packet.get("requested_by") != "john-lomein-maintainer":
        raise ProtectedSubmitError(
            "protected-action packet requester is invalid"
        )
    created = _parse_utc(
        packet.get("created_at"),
        field="protected-action packet created_at",
    )
    expires = _parse_utc(
        packet.get("expires_at"),
        field="protected-action packet expires_at",
    )
    ttl = int((expires - created).total_seconds())
    if ttl < MIN_PACKET_TTL_SECONDS or ttl > MAX_PACKET_TTL_SECONDS:
        raise ProtectedSubmitError(
            "protected-action packet lifetime is invalid"
        )
    request = _normalize_packet_request(packet.get("request"))
    observed = _parse_utc(
        request["observed_at"],
        field="protected-action observed_at",
    )
    if (
        observed > created + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS)
        or observed
        < created - timedelta(
            seconds=MAX_PACKET_EVIDENCE_AGE_SECONDS
        )
    ):
        raise ProtectedSubmitError(
            "protected-action evidence is outside the freshness window"
        )
    body = {
        "schema_version": PACKET_SCHEMA,
        "authority": PACKET_AUTHORITY,
        "requested_by": "john-lomein-maintainer",
        "created_at": _utc_text(created),
        "expires_at": _utc_text(expires),
        "request": request,
    }
    digest = sha256_json(body)
    packet_id = f"jlpa-{digest[:24]}"
    if packet.get("request_digest") != digest:
        raise ProtectedSubmitError(
            "protected-action packet digest does not match"
        )
    if packet.get("packet_id") != packet_id:
        raise ProtectedSubmitError(
            "protected-action packet ID does not match"
        )
    current = (now or datetime.now(timezone.utc)).astimezone(
        timezone.utc
    )
    if created > current + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        raise ProtectedSubmitError(
            "protected-action packet creation time is in the future"
        )
    if current >= expires and not allow_expired:
        raise ProtectedSubmitError("protected-action packet has expired")
    return {
        **body,
        "packet_id": packet_id,
        "request_digest": digest,
    }


def load_packet(
    path: Path,
    *,
    now: datetime | None = None,
    allow_expired: bool = False,
) -> dict[str, Any]:
    raw = read_stable_file(
        path,
        field="protected-action packet",
        maximum_bytes=MAX_PACKET_BYTES,
    )
    return verify_packet(
        parse_json_bytes(
            raw,
            field="protected-action packet",
            maximum_bytes=MAX_PACKET_BYTES,
        ),
        now=now,
        allow_expired=allow_expired,
    )


def default_client_config_path(packet: Mapping[str, Any]) -> Path:
    request = _mapping(
        packet.get("request"), field="protected-action request"
    )
    slug = str(request.get("instance_slug") or "")
    if not INSTANCE_SLUG_RE.fullmatch(slug):
        raise ProtectedSubmitError(
            "protected-action instance slug is invalid"
        )
    return DEFAULT_CONFIG_ROOT / f"{slug}.json"


def normalize_client_config(raw: Any) -> dict[str, Any]:
    config = _mapping(raw, field="protected broker client config")
    _strict_keys(
        config,
        field="protected broker client config",
        allowed={
            "schema_version",
            "broker_id",
            "broker_uid",
            "broker_config_sha256",
            "socket_path",
            "public_key_path",
            "public_key_sha256",
            "key_id",
            "connect_timeout_seconds",
            "request_timeout_seconds",
            "max_response_bytes",
            "instance_slug",
            "repository_full_name",
            "repository_id",
            "default_branch",
            "github_app_id",
            "github_app_slug",
            "github_installation_id",
        },
    )
    if config.get("schema_version") != CLIENT_CONFIG_SCHEMA:
        raise ProtectedSubmitError(
            "protected broker client config schema is unsupported"
        )
    broker_id = str(config.get("broker_id") or "")
    if not TOKEN_RE.fullmatch(broker_id):
        raise ProtectedSubmitError(
            "protected broker ID is invalid"
        )
    broker_uid = _uid(
        config.get("broker_uid"), field="protected broker UID"
    )
    broker_config_sha256 = str(
        config.get("broker_config_sha256") or ""
    )
    if not SHA256_RE.fullmatch(broker_config_sha256):
        raise ProtectedSubmitError(
            "protected broker config digest is invalid"
        )
    socket_path = _absolute_path(
        config.get("socket_path"), field="protected broker socket path"
    )
    try:
        socket_bytes = os.fsencode(socket_path)
    except UnicodeError as exc:
        raise ProtectedSubmitError(
            "protected broker socket path is invalid"
        ) from exc
    if (
        not socket_bytes
        or len(socket_bytes) > MAX_SOCKET_PATH_BYTES
        or b"\x00" in socket_bytes
    ):
        raise ProtectedSubmitError(
            "protected broker socket path is outside policy"
        )
    public_key_path = _absolute_path(
        config.get("public_key_path"),
        field="protected broker public key path",
    )
    if socket_path == public_key_path:
        raise ProtectedSubmitError(
            "protected broker socket and public key paths must differ"
        )
    fingerprint = str(config.get("public_key_sha256") or "")
    if not SHA256_RE.fullmatch(fingerprint):
        raise ProtectedSubmitError(
            "protected broker public-key fingerprint is invalid"
        )
    key_id = str(config.get("key_id") or "")
    if not TOKEN_RE.fullmatch(key_id):
        raise ProtectedSubmitError(
            "protected broker key ID is invalid"
        )
    connect_timeout = _positive_int(
        config.get("connect_timeout_seconds"),
        field="protected broker connect timeout",
        maximum=30,
    )
    request_timeout = _positive_int(
        config.get("request_timeout_seconds"),
        field="protected broker request timeout",
        maximum=120,
    )
    max_response = _positive_int(
        config.get("max_response_bytes"),
        field="protected broker maximum response size",
        maximum=MAX_RESPONSE_BYTES,
    )
    if max_response < 1024:
        raise ProtectedSubmitError(
            "protected broker maximum response size is too small"
        )
    instance_slug = str(config.get("instance_slug") or "")
    repository_full_name = str(
        config.get("repository_full_name") or ""
    )
    default_branch = str(config.get("default_branch") or "")
    if not INSTANCE_SLUG_RE.fullmatch(instance_slug):
        raise ProtectedSubmitError(
            "protected broker instance slug is invalid"
        )
    if not REPO_RE.fullmatch(repository_full_name):
        raise ProtectedSubmitError(
            "protected broker repository is invalid"
        )
    repository_id = _positive_int(
        config.get("repository_id"),
        field="protected broker repository ID",
        maximum=2**63 - 1,
    )
    if not BRANCH_RE.fullmatch(default_branch):
        raise ProtectedSubmitError(
            "protected broker default branch is invalid"
        )
    github_app_id = _positive_int(
        config.get("github_app_id"),
        field="protected broker GitHub App ID",
        maximum=2**63 - 1,
    )
    github_app_slug = str(config.get("github_app_slug") or "")
    if not APP_SLUG_RE.fullmatch(github_app_slug):
        raise ProtectedSubmitError(
            "protected broker GitHub App slug is invalid"
        )
    github_installation_id = _positive_int(
        config.get("github_installation_id"),
        field="protected broker GitHub installation ID",
        maximum=2**63 - 1,
    )
    return {
        "schema_version": CLIENT_CONFIG_SCHEMA,
        "broker_id": broker_id,
        "broker_uid": broker_uid,
        "broker_config_sha256": broker_config_sha256,
        "socket_path": str(socket_path),
        "public_key_path": str(public_key_path),
        "public_key_sha256": fingerprint,
        "key_id": key_id,
        "connect_timeout_seconds": connect_timeout,
        "request_timeout_seconds": request_timeout,
        "max_response_bytes": max_response,
        "instance_slug": instance_slug,
        "repository_full_name": repository_full_name,
        "repository_id": repository_id,
        "default_branch": default_branch,
        "github_app_id": github_app_id,
        "github_app_slug": github_app_slug,
        "github_installation_id": github_installation_id,
    }


def load_client_config(
    path: Path,
    *,
    config_owner_uids: int | Iterable[int] | None = None,
    key_owner_uids: int | Iterable[int] | None = None,
    parent_owner_uids: int | Iterable[int] | None = None,
    trusted_path_root: Path | None = None,
    requester_uid: int | None = None,
    allow_same_identity: bool = False,
) -> LoadedClientConfig:
    config_owners = _uid_set(config_owner_uids, default=(0,))
    key_owners = _uid_set(key_owner_uids, default=(0,))
    parent_owners = _uid_set(parent_owner_uids, default=(0,))
    config_path = _absolute_path(
        str(path), field="protected broker client config"
    )
    raw = read_trusted_file(
        config_path,
        field="protected broker client config",
        maximum_bytes=MAX_CONFIG_BYTES,
        expected_owner_uids=config_owners,
        parent_owner_uids=parent_owners,
        trusted_path_root=trusted_path_root,
    )
    config = normalize_client_config(
        parse_json_bytes(
            raw,
            field="protected broker client config",
            maximum_bytes=MAX_CONFIG_BYTES,
        )
    )
    actual_requester_uid = (
        os.getuid()
        if requester_uid is None
        else _uid(requester_uid, field="protected broker requester UID")
    )
    if (
        not allow_same_identity
        and config["broker_uid"] == actual_requester_uid
    ):
        raise ProtectedSubmitError(
            "protected broker must use a separate OS identity"
        )
    public_key = read_trusted_file(
        Path(config["public_key_path"]),
        field="protected broker public key",
        maximum_bytes=MAX_KEY_BYTES,
        expected_owner_uids=key_owners,
        parent_owner_uids=parent_owners,
        trusted_path_root=trusted_path_root,
    )
    if b"PUBLIC KEY" not in public_key or b"PRIVATE KEY" in public_key:
        raise ProtectedSubmitError(
            "protected broker verification key is not a public key"
        )
    if (
        hashlib.sha256(public_key).hexdigest()
        != config["public_key_sha256"]
    ):
        raise ProtectedSubmitError(
            "protected broker public-key fingerprint does not match"
        )
    return LoadedClientConfig(value=config, public_key=public_key)


def _timestamp_or_none(
    value: Any,
    *,
    field: str,
) -> tuple[str | None, datetime | None]:
    if value is None:
        return None, None
    parsed = _parse_utc(value, field=field)
    return _utc_text(parsed), parsed


def _oid_or_none(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ProtectedSubmitError(f"{field} is invalid")
    normalized = value.lower()
    if not OID_RE.fullmatch(normalized):
        raise ProtectedSubmitError(f"{field} is invalid")
    return normalized


def _bool_or_none(value: Any, *, field: str) -> bool | None:
    if value is None:
        return None
    if type(value) is not bool:
        raise ProtectedSubmitError(f"{field} must be boolean or null")
    return value


def _thread_ids(value: Any, *, field: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 1:
        raise ProtectedSubmitError(
            f"{field} must contain at most one thread ID"
        )
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not TOKEN_RE.fullmatch(item):
            raise ProtectedSubmitError(f"{field} contains an invalid ID")
        result.append(item)
    if len(set(result)) != len(result):
        raise ProtectedSubmitError(f"{field} contains duplicate IDs")
    return result


def _reason_has_prefix(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and len(value) > len(prefix)


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
        raise ProtectedSubmitError(
            "broker receipt payload schema is unsupported"
        )
    broker_id = str(payload.get("broker_id") or "")
    if not TOKEN_RE.fullmatch(broker_id):
        raise ProtectedSubmitError("broker receipt broker ID is invalid")
    broker_uid = _uid(
        payload.get("broker_uid"), field="broker receipt broker UID"
    )
    broker_config_sha256 = str(
        payload.get("broker_config_sha256") or ""
    )
    signing_key_id = str(payload.get("signing_key_id") or "")
    if not SHA256_RE.fullmatch(broker_config_sha256):
        raise ProtectedSubmitError(
            "broker receipt config digest is invalid"
        )
    if not TOKEN_RE.fullmatch(signing_key_id):
        raise ProtectedSubmitError(
            "broker receipt signing key ID is invalid"
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
        raise ProtectedSubmitError("broker receipt packet ID is invalid")
    if not SHA256_RE.fullmatch(request_digest):
        raise ProtectedSubmitError(
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
    action = str(request.get("action") or "")
    repository = str(request.get("repository_full_name") or "")
    default_branch = str(request.get("default_branch") or "")
    if not INSTANCE_SLUG_RE.fullmatch(instance_slug):
        raise ProtectedSubmitError(
            "broker receipt instance slug is invalid"
        )
    if action not in ALLOWED_ACTIONS:
        raise ProtectedSubmitError(
            "broker receipt action is unsupported"
        )
    if not REPO_RE.fullmatch(repository):
        raise ProtectedSubmitError(
            "broker receipt repository is invalid"
        )
    repository_id = _positive_int(
        request.get("repository_id"),
        field="broker receipt repository ID",
        maximum=2**63 - 1,
    )
    if not BRANCH_RE.fullmatch(default_branch):
        raise ProtectedSubmitError(
            "broker receipt default branch is invalid"
        )
    pr_number = _positive_int(
        request.get("pr_number"),
        field="broker receipt PR number",
    )
    head_sha = _oid_or_none(
        request.get("head_sha"), field="broker receipt head SHA"
    )
    if head_sha is None:
        raise ProtectedSubmitError(
            "broker receipt head SHA is required"
        )
    target_thread_ids = _thread_ids(
        request.get("thread_node_ids"),
        field="broker receipt target thread IDs",
    )
    if action == "mark_pr_ready" and target_thread_ids:
        raise ProtectedSubmitError(
            "mark-ready receipt cannot target review threads"
        )
    if action == "resolve_review_thread" and len(target_thread_ids) != 1:
        raise ProtectedSubmitError(
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
        maximum=2**63 - 1,
    )
    app_slug = str(github_app.get("app_slug") or "")
    if not APP_SLUG_RE.fullmatch(app_slug):
        raise ProtectedSubmitError(
            "broker receipt GitHub App slug is invalid"
        )
    installation_id = _positive_int(
        github_app.get("installation_id"),
        field="broker receipt GitHub installation ID",
        maximum=2**63 - 1,
    )

    precondition_digest = str(
        payload.get("precondition_digest") or ""
    )
    if not SHA256_RE.fullmatch(precondition_digest):
        raise ProtectedSubmitError(
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
        raise ProtectedSubmitError(
            "broker receipt mutation status is unsupported"
        )
    attempted_at, attempted = _timestamp_or_none(
        mutation.get("attempted_at"),
        field="broker receipt mutation attempted_at",
    )
    operation_id_value = mutation.get("operation_id")
    if operation_id_value == "":
        operation_id = ""
    elif (
        not isinstance(operation_id_value, str)
        or not TOKEN_RE.fullmatch(operation_id_value)
    ):
        raise ProtectedSubmitError(
            "broker receipt mutation operation ID is invalid"
        )
    else:
        operation_id = operation_id_value
    if mutation_status in {"not_attempted", "already_satisfied"}:
        if attempted_at is not None or operation_id:
            raise ProtectedSubmitError(
                "unattempted mutation cannot carry attempt evidence"
            )
    elif attempted_at is None:
        raise ProtectedSubmitError(
            "attempted mutation requires an attempt timestamp"
        )
    if mutation_status in {"applied", "reconciled"} and not operation_id:
        raise ProtectedSubmitError(
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
        raise ProtectedSubmitError(
            "broker receipt readback status is unsupported"
        )
    readback_observed_at, observed = _timestamp_or_none(
        readback.get("observed_at"),
        field="broker receipt readback observed_at",
    )
    readback_head_sha = _oid_or_none(
        readback.get("head_sha"),
        field="broker receipt readback head SHA",
    )
    pr_is_draft = _bool_or_none(
        readback.get("pr_is_draft"),
        field="broker receipt readback draft state",
    )
    resolved_thread_ids = _thread_ids(
        readback.get("resolved_thread_node_ids"),
        field="broker receipt resolved thread IDs",
    )
    if readback_status == "not_attempted":
        if (
            readback_observed_at is not None
            or readback_head_sha is not None
            or pr_is_draft is not None
            or resolved_thread_ids
        ):
            raise ProtectedSubmitError(
                "not-attempted readback cannot carry observations"
            )
    elif readback_observed_at is None:
        raise ProtectedSubmitError(
            "broker receipt readback requires an observation timestamp"
        )
    if readback_status == "confirmed":
        if readback_head_sha != head_sha or pr_is_draft is None:
            raise ProtectedSubmitError(
                "confirmed readback must bind the exact head and draft state"
            )
        if action == "mark_pr_ready":
            if pr_is_draft is not False or resolved_thread_ids:
                raise ProtectedSubmitError(
                    "mark-ready readback does not prove promotion"
                )
        elif resolved_thread_ids != target_thread_ids:
            raise ProtectedSubmitError(
                "thread readback does not prove exact target resolution"
            )

    outcome = str(payload.get("outcome") or "")
    reason_code = str(payload.get("reason_code") or "")
    if outcome not in OUTCOMES:
        raise ProtectedSubmitError(
            "broker receipt outcome is unsupported"
        )
    if not REASON_CODE_RE.fullmatch(reason_code):
        raise ProtectedSubmitError(
            "broker receipt reason code is invalid"
        )
    started = _parse_utc(
        payload.get("started_at"), field="broker receipt started_at"
    )
    completed = _parse_utc(
        payload.get("completed_at"), field="broker receipt completed_at"
    )
    if completed < started:
        raise ProtectedSubmitError(
            "broker receipt completion precedes its start"
        )
    if attempted is not None and not (
        started <= attempted <= completed
    ):
        raise ProtectedSubmitError(
            "broker receipt mutation time is inconsistent"
        )
    if observed is not None and not (
        started <= observed <= completed
    ):
        raise ProtectedSubmitError(
            "broker receipt readback time is inconsistent"
        )
    if (
        attempted is not None
        and observed is not None
        and observed < attempted
    ):
        raise ProtectedSubmitError(
            "broker receipt readback precedes mutation"
        )
    if outcome == "succeeded":
        expected_reasons = {
            "applied": "readback_verified",
            "reconciled": "reconciled_readback_verified",
            "already_satisfied": "already_satisfied",
        }
        if (
            mutation_status not in expected_reasons
            or readback_status != "confirmed"
            or reason_code != expected_reasons.get(mutation_status)
        ):
            raise ProtectedSubmitError(
                "successful receipt lacks confirmed completion evidence"
            )
    elif outcome == "rejected":
        if (
            mutation_status != "not_attempted"
            or readback_status != "not_attempted"
            or not any(
                _reason_has_prefix(reason_code, prefix)
                for prefix in (
                    "precondition_",
                    "request_",
                    "policy_",
                    "budget_",
                    "circuit_",
                )
            )
        ):
            raise ProtectedSubmitError(
                "rejected receipt has inconsistent status"
            )
    elif outcome == "failed":
        if (
            mutation_status != "failed"
            or readback_status != "not_attempted"
            or not _reason_has_prefix(reason_code, "mutation_")
        ):
            raise ProtectedSubmitError(
                "failed receipt has inconsistent status"
            )
    elif (
        mutation_status
        not in {"applied", "reconciled", "indeterminate"}
        or readback_status not in {"not_confirmed", "indeterminate"}
        or not _reason_has_prefix(reason_code, "indeterminate_")
    ):
        raise ProtectedSubmitError(
            "indeterminate receipt has inconsistent status"
        )
    previous_receipt_sha256 = str(
        payload.get("previous_receipt_sha256") or ""
    )
    if not SHA256_RE.fullmatch(previous_receipt_sha256):
        raise ProtectedSubmitError(
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
            "repository_full_name": repository,
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
            "observed_at": readback_observed_at,
            "head_sha": readback_head_sha,
            "pr_is_draft": pr_is_draft,
            "resolved_thread_node_ids": resolved_thread_ids,
        },
        "outcome": outcome,
        "reason_code": reason_code,
        "started_at": _utc_text(started),
        "completed_at": _utc_text(completed),
        "previous_receipt_sha256": previous_receipt_sha256,
    }
    id_material = {
        key: value
        for key, value in normalized.items()
        if key != "receipt_id"
    }
    expected_id = f"jlbr-{sha256_json(id_material)[:24]}"
    if (
        not RECEIPT_ID_RE.fullmatch(normalized["receipt_id"])
        or normalized["receipt_id"] != expected_id
    ):
        raise ProtectedSubmitError(
            "broker receipt ID does not match its payload"
        )
    return normalized


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
        raise ProtectedSubmitError(
            "signed broker receipt schema is unsupported"
        )
    if envelope.get("algorithm") != SIGNATURE_ALGORITHM:
        raise ProtectedSubmitError(
            "signed broker receipt algorithm is unsupported"
        )
    key_id = str(envelope.get("key_id") or "")
    public_key_sha256 = str(
        envelope.get("public_key_sha256") or ""
    )
    payload_sha256 = str(envelope.get("payload_sha256") or "")
    if not TOKEN_RE.fullmatch(key_id):
        raise ProtectedSubmitError(
            "signed broker receipt key ID is invalid"
        )
    if (
        not SHA256_RE.fullmatch(public_key_sha256)
        or not SHA256_RE.fullmatch(payload_sha256)
    ):
        raise ProtectedSubmitError(
            "signed broker receipt digest is invalid"
        )
    payload = normalize_receipt_payload(envelope.get("payload"))
    if payload["signing_key_id"] != key_id:
        raise ProtectedSubmitError(
            "signed broker receipt key ID does not match its payload"
        )
    actual_payload_sha256 = hashlib.sha256(
        canonical_json(payload)
    ).hexdigest()
    if payload_sha256 != actual_payload_sha256:
        raise ProtectedSubmitError(
            "signed broker receipt payload digest does not match"
        )
    signature_text = envelope.get("signature")
    if not isinstance(signature_text, str):
        raise ProtectedSubmitError(
            "signed broker receipt signature is invalid"
        )
    try:
        signature = base64.b64decode(
            signature_text.encode("ascii"), validate=True
        )
    except (UnicodeError, ValueError, binascii.Error) as exc:
        raise ProtectedSubmitError(
            "signed broker receipt signature is invalid"
        ) from exc
    if len(signature) != 64:
        raise ProtectedSubmitError(
            "signed broker receipt signature size is invalid"
        )
    canonical_signature = base64.b64encode(signature).decode("ascii")
    if signature_text != canonical_signature:
        raise ProtectedSubmitError(
            "signed broker receipt signature is not canonical"
        )
    return {
        "schema_version": RECEIPT_ENVELOPE_SCHEMA,
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "public_key_sha256": public_key_sha256,
        "payload_sha256": actual_payload_sha256,
        "payload": payload,
        "signature": canonical_signature,
    }


def _openssl() -> str:
    for candidate in (
        "/opt/homebrew/bin/openssl",
        "/usr/local/bin/openssl",
        "/usr/bin/openssl",
    ):
        if Path(candidate).is_file():
            return candidate
    raise ProtectedSubmitError("openssl is unavailable")


def _write_private_snapshot(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o400)
    except OSError as exc:
        raise ProtectedSubmitError(
            "verification snapshot could not be created"
        ) from exc
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            if written <= 0:
                raise ProtectedSubmitError(
                    "verification snapshot write made no progress"
                )
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)


def _verify_signature(
    *,
    public_key: bytes,
    payload: bytes,
    signature: bytes,
) -> None:
    if len(signature) != 64:
        raise ProtectedSubmitError(
            "signed broker receipt signature size is invalid"
        )
    with tempfile.TemporaryDirectory(
        prefix="john-lomein-submit-verify-"
    ) as directory:
        root = Path(directory)
        key_path = root / "public.pem"
        payload_path = root / "payload.json"
        signature_path = root / "payload.sig"
        _write_private_snapshot(key_path, public_key)
        _write_private_snapshot(payload_path, payload)
        _write_private_snapshot(signature_path, signature)
        try:
            proc = subprocess.run(
                [
                    _openssl(),
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-pubin",
                    "-inkey",
                    str(key_path),
                    "-sigfile",
                    str(signature_path),
                    "-in",
                    str(payload_path),
                ],
                env={
                    "HOME": str(root),
                    "PATH": (
                        "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
                    ),
                    "OPENSSL_CONF": "/dev/null",
                },
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ProtectedSubmitError(
                "signed broker receipt verification failed"
            ) from exc
    if proc.returncode != 0:
        raise ProtectedSubmitError(
            "signed broker receipt verification failed"
        )


def verify_signed_receipt(
    raw: Any,
    *,
    packet: Mapping[str, Any],
    config: LoadedClientConfig,
    now: datetime | None = None,
) -> dict[str, Any]:
    envelope = normalize_receipt_envelope(raw)
    client = config.value
    if (
        envelope["key_id"] != client["key_id"]
        or envelope["public_key_sha256"]
        != client["public_key_sha256"]
    ):
        raise ProtectedSubmitError(
            "signed broker receipt key identity is not pinned"
        )
    try:
        signature = base64.b64decode(
            envelope["signature"].encode("ascii"), validate=True
        )
    except (UnicodeError, ValueError, binascii.Error) as exc:
        raise ProtectedSubmitError(
            "signed broker receipt signature is invalid"
        ) from exc
    _verify_signature(
        public_key=config.public_key,
        payload=canonical_json(envelope["payload"]),
        signature=signature,
    )
    payload = envelope["payload"]
    request = packet["request"]
    expected_packet = {
        "packet_id": packet["packet_id"],
        "request_digest": packet["request_digest"],
    }
    expected_request = {
        "instance_slug": client["instance_slug"],
        "action": request["action"],
        "repository_full_name": client["repository_full_name"],
        "repository_id": client["repository_id"],
        "default_branch": client["default_branch"],
        "pr_number": request["pr"]["number"],
        "head_sha": request["pr"]["head_sha"],
        "thread_node_ids": request["targets"]["thread_node_ids"],
    }
    if payload["packet"] != expected_packet:
        raise ProtectedSubmitError(
            "signed broker receipt packet binding does not match"
        )
    for field, expected in expected_request.items():
        if payload["request"][field] != expected:
            raise ProtectedSubmitError(
                "signed broker receipt request binding does not match"
            )
    expected_authority = {
        "broker_id": client["broker_id"],
        "broker_uid": client["broker_uid"],
        "broker_config_sha256": client["broker_config_sha256"],
        "signing_key_id": client["key_id"],
    }
    for field, expected in expected_authority.items():
        if payload[field] != expected:
            raise ProtectedSubmitError(
                "signed broker receipt authority binding does not match"
            )
    expected_app = {
        "app_id": client["github_app_id"],
        "app_slug": client["github_app_slug"],
        "installation_id": client["github_installation_id"],
    }
    if payload["github_app"] != expected_app:
        raise ProtectedSubmitError(
            "signed broker receipt GitHub App binding does not match"
        )
    started = _parse_utc(
        payload["started_at"], field="broker receipt started_at"
    )
    created = _parse_utc(
        packet["created_at"], field="protected-action packet created_at"
    )
    expires = _parse_utc(
        packet["expires_at"], field="protected-action packet expires_at"
    )
    if (
        started < created - timedelta(seconds=MAX_CLOCK_SKEW_SECONDS)
        or started >= expires
    ):
        raise ProtectedSubmitError(
            "signed broker receipt started outside packet authority"
        )
    current = (now or datetime.now(timezone.utc)).astimezone(
        timezone.utc
    )
    completed = _parse_utc(
        payload["completed_at"], field="broker receipt completed_at"
    )
    if completed > current + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        raise ProtectedSubmitError(
            "signed broker receipt completion is in the future"
        )
    return envelope


def receipt_is_completion(receipt: Mapping[str, Any]) -> bool:
    try:
        envelope = normalize_receipt_envelope(receipt)
    except ProtectedSubmitError:
        return False
    payload = envelope["payload"]
    return (
        payload["outcome"] == "succeeded"
        and payload["mutation"]["status"]
        in {"applied", "reconciled", "already_satisfied"}
        and payload["readback"]["status"] == "confirmed"
    )


def verify_completion_receipt(
    raw: Any,
    *,
    packet: Mapping[str, Any],
    config: LoadedClientConfig,
    now: datetime | None = None,
) -> dict[str, Any]:
    receipt = verify_signed_receipt(
        raw,
        packet=packet,
        config=config,
        now=now,
    )
    if not receipt_is_completion(receipt):
        raise BrokerDeniedError(
            receipt["payload"]["reason_code"],
            receipt=receipt,
        )
    return receipt


def normalize_response(raw: Any) -> dict[str, Any]:
    response = _mapping(raw, field="protected broker response")
    if response.get("ok") is True:
        _strict_keys(
            response,
            field="protected broker response",
            allowed={"schema_version", "ok", "receipt"},
        )
        if response.get("schema_version") != RESPONSE_SCHEMA:
            raise ProtectedSubmitError(
                "protected broker response schema is unsupported"
            )
        return {
            "schema_version": RESPONSE_SCHEMA,
            "ok": True,
            "receipt": normalize_receipt_envelope(
                response.get("receipt")
            ),
        }
    _strict_keys(
        response,
        field="protected broker response",
        allowed={"schema_version", "ok", "error"},
    )
    if response.get("schema_version") != RESPONSE_SCHEMA:
        raise ProtectedSubmitError(
            "protected broker response schema is unsupported"
        )
    if response.get("ok") is not False:
        raise ProtectedSubmitError(
            "protected broker response status is invalid"
        )
    error = _mapping(
        response.get("error"), field="protected broker error"
    )
    _strict_keys(
        error,
        field="protected broker error",
        allowed={"code"},
    )
    code = str(error.get("code") or "")
    if code not in DAEMON_ERROR_CODES:
        raise ProtectedSubmitError(
            "protected broker error code is unsupported"
        )
    return {
        "schema_version": RESPONSE_SCHEMA,
        "ok": False,
        "error": {"code": code},
    }


def _read_exact(sock: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        try:
            chunk = sock.recv(remaining)
        except socket.timeout as exc:
            raise ProtectedSubmitError(
                "protected broker response timed out"
            ) from exc
        except OSError as exc:
            raise ProtectedSubmitError(
                "protected broker response read failed"
            ) from exc
        if not chunk:
            raise ProtectedSubmitError(
                "protected broker response ended prematurely"
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _validate_socket(config: Mapping[str, Any]) -> None:
    path = Path(config["socket_path"])
    validate_trusted_parent_chain(
        path.parent,
        field="protected broker socket",
        expected_owner_uids={0, int(config["broker_uid"])},
    )
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise ProtectedSubmitError(
            "protected broker socket is unavailable"
        ) from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != config["broker_uid"]
        or stat.S_IMODE(info.st_mode) != 0o660
    ):
        raise ProtectedSubmitError(
            "protected broker socket is unsafe"
        )


def exchange(
    submission: Mapping[str, Any],
    config: Mapping[str, Any],
    *,
    validate_socket: bool = True,
) -> dict[str, Any]:
    payload = canonical_json(submission)
    if not payload or len(payload) > MAX_PACKET_BYTES + 4096:
        raise ProtectedSubmitError(
            "protected broker submission exceeds its size limit"
        )
    if validate_socket:
        _validate_socket(config)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.settimeout(float(config["connect_timeout_seconds"]))
        try:
            client.connect(config["socket_path"])
        except (socket.timeout, OSError) as exc:
            raise ProtectedSubmitError(
                "protected broker connection failed"
            ) from exc
        client.settimeout(float(config["request_timeout_seconds"]))
        frame = struct.pack("!I", len(payload)) + payload
        try:
            client.sendall(frame)
        except (socket.timeout, OSError) as exc:
            raise ProtectedSubmitError(
                "protected broker request write failed"
            ) from exc
        header = _read_exact(client, FRAME_HEADER_BYTES)
        (length,) = struct.unpack("!I", header)
        if (
            length <= 0
            or length > int(config["max_response_bytes"])
        ):
            raise ProtectedSubmitError(
                "protected broker response length is outside policy"
            )
        raw = _read_exact(client, length)
    finally:
        client.close()
    return normalize_response(
        parse_json_bytes(
            raw,
            field="protected broker response",
            maximum_bytes=int(config["max_response_bytes"]),
        )
    )


def persist_receipt(
    path: Path,
    receipt: Mapping[str, Any],
    *,
    owner_uids: int | Iterable[int] | None = None,
    trusted_path_root: Path | None = None,
) -> Path:
    output = _absolute_path(str(path), field="receipt output")
    owners = _uid_set(owner_uids, default=(0, os.getuid()))
    validate_trusted_parent_chain(
        output.parent,
        field="receipt output",
        expected_owner_uids=owners,
        trusted_path_root=trusted_path_root,
    )
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        directory_fd = os.open(output.parent, flags)
    except OSError as exc:
        raise ProtectedSubmitError(
            "receipt output directory is unsafe"
        ) from exc
    expected = canonical_json(dict(receipt)) + b"\n"
    temporary_name = (
        f".{output.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    )
    temporary_created = False
    try:
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            create_flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            create_flags |= os.O_NOFOLLOW
        try:
            fd = os.open(
                temporary_name,
                create_flags,
                0o600,
                dir_fd=directory_fd,
            )
        except OSError as exc:
            raise ProtectedSubmitError(
                "receipt output staging file could not be created"
            ) from exc
        temporary_created = True
        try:
            offset = 0
            while offset < len(expected):
                written = os.write(fd, expected[offset:])
                if written <= 0:
                    raise ProtectedSubmitError(
                        "receipt output write made no progress"
                    )
                offset += written
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(
                temporary_name,
                output.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            existing_flags = os.O_RDONLY
            if hasattr(os, "O_CLOEXEC"):
                existing_flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                existing_flags |= os.O_NOFOLLOW
            if hasattr(os, "O_NONBLOCK"):
                existing_flags |= os.O_NONBLOCK
            try:
                existing_fd = os.open(
                    output.name,
                    existing_flags,
                    dir_fd=directory_fd,
                )
            except OSError as exc:
                raise ProtectedSubmitError(
                    "existing receipt output is unsafe"
                ) from exc
            try:
                info = os.fstat(existing_fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid not in owners
                    or info.st_mode & 0o077
                    or info.st_size != len(expected)
                ):
                    raise ProtectedSubmitError(
                        "existing receipt output is unsafe"
                    )
                chunks: list[bytes] = []
                remaining = len(expected) + 1
                while remaining:
                    chunk = os.read(existing_fd, min(64 * 1024, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                if b"".join(chunks) != expected:
                    raise ProtectedSubmitError(
                        "existing receipt output conflicts"
                    )
            finally:
                os.close(existing_fd)
        except OSError as exc:
            raise ProtectedSubmitError(
                "receipt output could not be installed"
            ) from exc
        os.fsync(directory_fd)
    finally:
        if temporary_created:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        os.close(directory_fd)
    return output


def submit_packet(
    packet_path: Path,
    *,
    runtime_home: Path,
    client_config_path: Path | None = None,
    receipt_output: Path | None = None,
    now: datetime | None = None,
    config_owner_uids: int | Iterable[int] | None = None,
    key_owner_uids: int | Iterable[int] | None = None,
    parent_owner_uids: int | Iterable[int] | None = None,
    trusted_path_root: Path | None = None,
    requester_uid: int | None = None,
    allow_same_identity: bool = False,
    validate_socket: bool = True,
) -> dict[str, Any]:
    packet = load_packet(packet_path, now=now)
    config_path = (
        client_config_path
        if client_config_path is not None
        else default_client_config_path(packet)
    )
    loaded = load_client_config(
        config_path,
        config_owner_uids=config_owner_uids,
        key_owner_uids=key_owner_uids,
        parent_owner_uids=parent_owner_uids,
        trusted_path_root=trusted_path_root,
        requester_uid=requester_uid,
        allow_same_identity=allow_same_identity,
    )
    config = loaded.value
    request = packet["request"]
    if (
        request["instance_slug"] != config["instance_slug"]
        or request["repo"] != config["repository_full_name"]
        or request["pr"]["base_branch"] != config["default_branch"]
    ):
        raise ProtectedSubmitError(
            "protected-action packet does not match the client trust config"
        )
    try:
        runtime = anchored_runtime_home(
            SCRIPT_DIR,
            runtime_home,
        )
        control = deployed_runtime_control(runtime)
        require_effective_mutation(control)
    except AutonomyError as exc:
        raise ProtectedSubmitError(str(exc)) from exc
    if (
        control["BOT_SLUG"] != config["instance_slug"]
        or control["BOT_REPO"] != config["repository_full_name"]
        or control["BOT_DEFAULT_BRANCH"] != config["default_branch"]
    ):
        raise ProtectedSubmitError(
            "runtime authority does not match protected-action client"
        )
    response = exchange(
        {
            "schema_version": SUBMISSION_SCHEMA,
            "packet": packet,
        },
        config,
        validate_socket=validate_socket,
    )
    if response["ok"] is not True:
        raise BrokerDeniedError(
            response["error"]["code"]
        )
    receipt = verify_signed_receipt(
        response["receipt"],
        packet=packet,
        config=loaded,
        now=now,
    )
    if receipt_output is not None:
        persist_receipt(
            receipt_output,
            receipt,
            trusted_path_root=trusted_path_root,
        )
    if not receipt_is_completion(receipt):
        raise BrokerDeniedError(
            receipt["payload"]["reason_code"],
            receipt=receipt,
        )
    return receipt


def verify_receipt_file(
    packet_path: Path,
    receipt_path: Path,
    *,
    client_config_path: Path | None = None,
    now: datetime | None = None,
    config_owner_uids: int | Iterable[int] | None = None,
    key_owner_uids: int | Iterable[int] | None = None,
    parent_owner_uids: int | Iterable[int] | None = None,
    trusted_path_root: Path | None = None,
    requester_uid: int | None = None,
    allow_same_identity: bool = False,
) -> dict[str, Any]:
    packet = load_packet(
        packet_path,
        now=now,
        allow_expired=True,
    )
    config_path = (
        client_config_path
        if client_config_path is not None
        else default_client_config_path(packet)
    )
    loaded = load_client_config(
        config_path,
        config_owner_uids=config_owner_uids,
        key_owner_uids=key_owner_uids,
        parent_owner_uids=parent_owner_uids,
        trusted_path_root=trusted_path_root,
        requester_uid=requester_uid,
        allow_same_identity=allow_same_identity,
    )
    request = packet["request"]
    config = loaded.value
    if (
        request["instance_slug"] != config["instance_slug"]
        or request["repo"] != config["repository_full_name"]
        or request["pr"]["base_branch"] != config["default_branch"]
    ):
        raise ProtectedSubmitError(
            "protected-action packet does not match the client trust config"
        )
    raw = read_trusted_file(
        receipt_path,
        field="protected broker receipt",
        maximum_bytes=MAX_RESPONSE_BYTES,
        expected_owner_uids={0, os.getuid()},
        parent_owner_uids={0, os.getuid()},
        trusted_path_root=trusted_path_root,
    )
    receipt = verify_signed_receipt(
        parse_json_bytes(
            raw,
            field="protected broker receipt",
            maximum_bytes=MAX_RESPONSE_BYTES,
        ),
        packet=packet,
        config=loaded,
        now=now,
    )
    if not receipt_is_completion(receipt):
        raise BrokerDeniedError(
            receipt["payload"]["reason_code"],
            receipt=receipt,
        )
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet", required=True)
    parser.add_argument("--runtime-home")
    parser.add_argument("--client-config")
    parser.add_argument("--receipt-output")
    parser.add_argument("--verify-receipt")
    args = parser.parse_args(argv)
    try:
        config_path = (
            Path(args.client_config)
            if args.client_config
            else None
        )
        if args.verify_receipt:
            if args.receipt_output:
                raise ProtectedSubmitError(
                    "--receipt-output cannot be used with --verify-receipt"
                )
            receipt = verify_receipt_file(
                Path(args.packet),
                Path(args.verify_receipt),
                client_config_path=config_path,
            )
        else:
            if not args.runtime_home:
                raise ProtectedSubmitError(
                    "--runtime-home is required for submission"
                )
            receipt = submit_packet(
                Path(args.packet),
                runtime_home=Path(args.runtime_home),
                client_config_path=config_path,
                receipt_output=(
                    Path(args.receipt_output)
                    if args.receipt_output
                    else None
                ),
            )
        sys.stdout.buffer.write(canonical_json(receipt) + b"\n")
        return 0
    except BrokerDeniedError as exc:
        print(
            "john-lomein protected submit denied: "
            f"{exc.reason_code}",
            file=sys.stderr,
        )
        return 3
    except ProtectedSubmitError as exc:
        print(
            f"john-lomein protected submit blocked: {exc}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
