#!/usr/bin/env python3
"""Strict protocol and configuration boundary for the protected broker.

The broker must not import validation code from the model-controlled runtime.
The protected-action packet validator below is therefore a deliberately local
copy of the v1 wire contract.  A deployed broker can copy this package into a
root-owned location and validate untrusted runtime packets without adding the
runtime tree to ``sys.path``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


CONFIG_SCHEMA = "john-lomein.protected-broker-config.v1"
SUBMISSION_SCHEMA = "john-lomein.protected-broker-submit.v1"
PACKET_INPUT_SCHEMA = "john-lomein.protected-action-input.v1"
PACKET_SCHEMA = "john-lomein.protected-action-packet.v1"
PACKET_AUTHORITY = "request_only_no_execution_authority"

ALLOWED_ACTIONS = frozenset(
    {"mark_pr_ready", "resolve_review_thread"}
)
EVIDENCE_MARKER_PREFIX = "<!-- john-lomein-protected-evidence:v1 "
GITHUB_API_BASE_URL = "https://api.github.com"
TRANSPORT_KIND = "unix_socket"
PEER_CREDENTIAL_PROTOCOL = "os_peer_credentials_v1"

MAX_CONFIG_BYTES = 128 * 1024
MAX_SUBMISSION_BYTES = 512 * 1024
MAX_KEY_BYTES = 64 * 1024
MIN_PACKET_TTL_SECONDS = 60
MAX_PACKET_TTL_SECONDS = 3600
MAX_PACKET_EVIDENCE_AGE_SECONDS = 3600
MAX_CLOCK_SKEW_SECONDS = 300
MAX_SOCKET_PATH_BYTES = 100

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
PACKET_ID_RE = re.compile(r"^jlpa-[0-9a-f]{24}$")
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
ACCEPTED_GREEN_CHECK_CONCLUSIONS = frozenset(
    {"NEUTRAL", "SKIPPED", "SUCCESS"}
)


class BrokerProtocolError(ValueError):
    """A fail-closed broker protocol or local trust failure."""


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
        raise BrokerProtocolError("value is not canonical JSON") from exc


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise BrokerProtocolError(
                "JSON object contains duplicate fields"
            )
        value[key] = item
    return value


def _reject_nonfinite(_: str) -> None:
    raise BrokerProtocolError("JSON contains a non-finite number")


def parse_json_bytes(
    raw: bytes,
    *,
    field: str,
    maximum_bytes: int,
) -> Any:
    if len(raw) > maximum_bytes:
        raise BrokerProtocolError(f"{field} exceeds its size limit")
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except BrokerProtocolError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BrokerProtocolError(f"{field} is invalid JSON") from exc


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
            ):
                raise BrokerProtocolError(
                    "trusted owner UID set is invalid"
                )
            normalized.add(value)
    except TypeError as exc:
        raise BrokerProtocolError(
            "trusted owner UID set is invalid"
        ) from exc
    if not normalized:
        raise BrokerProtocolError("trusted owner UID set is empty")
    return frozenset(normalized)


def _lexical_absolute_path(value: Any, *, field: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise BrokerProtocolError(f"{field} must be an absolute path")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise BrokerProtocolError(f"{field} must be an absolute path")
    if str(path) != value:
        raise BrokerProtocolError(f"{field} must be normalized")
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
    """Reject symlinked or untrusted writable directories in a path.

    Owner-writable directories are safe only when their owner UID is explicitly
    trusted. Group/other write access is always rejected. ``trusted_path_root``
    is primarily useful for hermetic tests and for installations with a
    dedicated root-owned broker directory.
    """

    trusted = _uid_set(expected_owner_uids, default=(0,))
    path = _lexical_absolute_path(str(path), field=field)
    stop: Path | None = None
    if trusted_path_root is not None:
        stop = _lexical_absolute_path(
            str(trusted_path_root), field="trusted path root"
        )
        if not _path_within(path, stop):
            raise BrokerProtocolError(
                f"{field} is outside the trusted path root"
            )

    current = path
    while True:
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise BrokerProtocolError(
                f"{field} parent directory is unreadable"
            ) from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise BrokerProtocolError(
                f"{field} parent directory is unsafe"
            )
        if info.st_uid not in trusted:
            raise BrokerProtocolError(
                f"{field} parent directory owner is untrusted"
            )
        if info.st_mode & 0o022:
            raise BrokerProtocolError(
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
    """Read a bounded regular-file snapshot without following the final link."""

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise BrokerProtocolError(f"{field} is unreadable") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise BrokerProtocolError(
                f"{field} must be a regular non-symlink file"
            )
        if expected_owner_uids is not None:
            trusted = _uid_set(
                expected_owner_uids, default=(0,)
            )
            if info.st_uid not in trusted:
                raise BrokerProtocolError(f"{field} owner is untrusted")
        if reject_group_other_writable and info.st_mode & 0o022:
            raise BrokerProtocolError(
                f"{field} is group/other writable"
            )
        if info.st_size > maximum_bytes:
            raise BrokerProtocolError(f"{field} exceeds its size limit")
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
                raise BrokerProtocolError(
                    f"{field} exceeds its size limit"
                )
        return b"".join(chunks)
    except OSError as exc:
        raise BrokerProtocolError(f"{field} is unreadable") from exc
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
    path = _lexical_absolute_path(str(path), field=field)
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


def _mapping(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BrokerProtocolError(f"{field} must be an object")
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
        raise BrokerProtocolError(f"{field} contains unknown fields")
    if missing:
        raise BrokerProtocolError(f"{field} is missing required fields")


def _positive_int(
    value: Any,
    *,
    field: str,
    maximum: int = 2**63 - 1,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BrokerProtocolError(f"{field} must be an integer")
    if value <= 0 or value > maximum:
        raise BrokerProtocolError(f"{field} is outside the allowed range")
    return value


def _nonnegative_int(
    value: Any,
    *,
    field: str,
    maximum: int = 2**63 - 1,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BrokerProtocolError(f"{field} must be an integer")
    if value < 0 or value > maximum:
        raise BrokerProtocolError(f"{field} is outside the allowed range")
    return value


def _uid(value: Any, *, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 2**31 - 1
    ):
        raise BrokerProtocolError(f"{field} must be a UID")
    return value


def _gid(value: Any, *, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 2**31 - 1
    ):
        raise BrokerProtocolError(f"{field} must be a GID")
    return value


def _boolean(value: Any, *, field: str) -> bool:
    if type(value) is not bool:
        raise BrokerProtocolError(f"{field} must be boolean")
    return value


def _safe_text(
    value: Any,
    *,
    field: str,
    maximum: int,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        raise BrokerProtocolError(f"{field} is invalid")
    return value


def _sorted_unique_strings(
    value: Any,
    *,
    field: str,
    maximum_items: int,
    maximum_length: int,
    allow_empty: bool,
) -> list[str]:
    if not isinstance(value, list):
        raise BrokerProtocolError(f"{field} must be an array")
    if (not allow_empty and not value) or len(value) > maximum_items:
        raise BrokerProtocolError(f"{field} has an invalid item count")
    normalized = [
        _safe_text(
            item,
            field=f"{field} item",
            maximum=maximum_length,
        )
        for item in value
    ]
    if normalized != sorted(normalized) or len(set(normalized)) != len(
        normalized
    ):
        raise BrokerProtocolError(f"{field} must be sorted and unique")
    return normalized


def _absolute_path_text(value: Any, *, field: str) -> str:
    return str(_lexical_absolute_path(value, field=field))


def _forbidden_prefix(value: str, *, field: str) -> str:
    if (
        value.startswith("/")
        or value.startswith("./")
        or value.endswith("/")
        or "\\" in value
        or "*" in value
        or "?" in value
    ):
        raise BrokerProtocolError(f"{field} is invalid")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise BrokerProtocolError(f"{field} is invalid")
    return value


def normalize_config(raw: Any) -> dict[str, Any]:
    config = _mapping(raw, field="broker config")
    _strict_keys(
        config,
        field="broker config",
        allowed={
            "schema_version",
            "enabled",
            "broker_id",
            "broker_uid",
            "transport",
            "github_app",
            "receipt_signing",
            "state",
            "instance",
        },
    )
    if config.get("schema_version") != CONFIG_SCHEMA:
        raise BrokerProtocolError("broker config schema is unsupported")
    enabled = _boolean(
        config.get("enabled"), field="broker config enabled"
    )
    broker_id = str(config.get("broker_id") or "")
    if not TOKEN_RE.fullmatch(broker_id):
        raise BrokerProtocolError("broker config broker_id is invalid")
    broker_uid = _uid(
        config.get("broker_uid"), field="broker config broker_uid"
    )

    transport = _mapping(
        config.get("transport"), field="broker config transport"
    )
    _strict_keys(
        transport,
        field="broker config transport",
        allowed={
            "kind",
            "peer_credentials",
            "socket_path",
            "requester_uid",
            "submit_gid",
            "max_request_bytes",
            "request_timeout_seconds",
        },
    )
    if transport.get("kind") != TRANSPORT_KIND:
        raise BrokerProtocolError("broker transport kind is unsupported")
    if transport.get("peer_credentials") != PEER_CREDENTIAL_PROTOCOL:
        raise BrokerProtocolError(
            "broker peer-credential protocol is unsupported"
        )
    socket_path = _absolute_path_text(
        transport.get("socket_path"),
        field="broker transport socket_path",
    )
    if len(os.fsencode(socket_path)) > MAX_SOCKET_PATH_BYTES:
        raise BrokerProtocolError("broker socket path is too long")
    requester_uid = _uid(
        transport.get("requester_uid"),
        field="broker transport requester_uid",
    )
    if requester_uid == broker_uid:
        raise BrokerProtocolError(
            "broker and requester UIDs must be different"
        )
    submit_gid = _gid(
        transport.get("submit_gid"),
        field="broker transport submit_gid",
    )
    max_request_bytes = _positive_int(
        transport.get("max_request_bytes"),
        field="broker transport max_request_bytes",
        maximum=MAX_SUBMISSION_BYTES,
    )
    if max_request_bytes < 1024:
        raise BrokerProtocolError(
            "broker transport max_request_bytes is too small"
        )
    request_timeout_seconds = _positive_int(
        transport.get("request_timeout_seconds"),
        field="broker transport request_timeout_seconds",
        maximum=60,
    )

    github_app = _mapping(
        config.get("github_app"), field="broker config github_app"
    )
    _strict_keys(
        github_app,
        field="broker config github_app",
        allowed={
            "app_id",
            "app_slug",
            "installation_id",
            "private_key_path",
            "api_base_url",
        },
    )
    app_id = _positive_int(
        github_app.get("app_id"),
        field="broker GitHub App app_id",
    )
    app_slug = str(github_app.get("app_slug") or "")
    if not APP_SLUG_RE.fullmatch(app_slug):
        raise BrokerProtocolError(
            "broker GitHub App app_slug is invalid"
        )
    installation_id = _positive_int(
        github_app.get("installation_id"),
        field="broker GitHub App installation_id",
    )
    github_private_key_path = _absolute_path_text(
        github_app.get("private_key_path"),
        field="broker GitHub App private_key_path",
    )
    if github_app.get("api_base_url") != GITHUB_API_BASE_URL:
        raise BrokerProtocolError(
            "broker GitHub API base URL is unsupported"
        )

    receipt_signing = _mapping(
        config.get("receipt_signing"),
        field="broker config receipt_signing",
    )
    _strict_keys(
        receipt_signing,
        field="broker config receipt_signing",
        allowed={
            "key_id",
            "private_key_path",
            "public_key_path",
            "public_key_sha256",
        },
    )
    key_id = str(receipt_signing.get("key_id") or "")
    if not TOKEN_RE.fullmatch(key_id):
        raise BrokerProtocolError(
            "broker receipt signing key_id is invalid"
        )
    receipt_private_key_path = _absolute_path_text(
        receipt_signing.get("private_key_path"),
        field="broker receipt private_key_path",
    )
    receipt_public_key_path = _absolute_path_text(
        receipt_signing.get("public_key_path"),
        field="broker receipt public_key_path",
    )
    public_key_sha256 = str(
        receipt_signing.get("public_key_sha256") or ""
    )
    if not SHA256_RE.fullmatch(public_key_sha256):
        raise BrokerProtocolError(
            "broker receipt public-key fingerprint is invalid"
        )
    if len(
        {
            github_private_key_path,
            receipt_private_key_path,
            receipt_public_key_path,
        }
    ) != 3:
        raise BrokerProtocolError("broker key paths must be distinct")

    state = _mapping(
        config.get("state"), field="broker config state"
    )
    _strict_keys(
        state,
        field="broker config state",
        allowed={"database_path"},
    )
    database_path = _absolute_path_text(
        state.get("database_path"),
        field="broker state database_path",
    )
    if database_path in {
        github_private_key_path,
        receipt_private_key_path,
        receipt_public_key_path,
        socket_path,
    }:
        raise BrokerProtocolError(
            "broker state path must be distinct from keys and transport"
        )

    instance = _mapping(
        config.get("instance"), field="broker config instance"
    )
    _strict_keys(
        instance,
        field="broker config instance",
        allowed={"slug", "repository", "policy", "budgets"},
    )
    slug = str(instance.get("slug") or "")
    if not INSTANCE_SLUG_RE.fullmatch(slug):
        raise BrokerProtocolError("broker instance slug is invalid")

    repository = _mapping(
        instance.get("repository"),
        field="broker config instance repository",
    )
    _strict_keys(
        repository,
        field="broker config instance repository",
        allowed={"full_name", "id", "default_branch"},
    )
    full_name = str(repository.get("full_name") or "")
    if not REPO_RE.fullmatch(full_name):
        raise BrokerProtocolError("broker repository name is invalid")
    repository_id = _positive_int(
        repository.get("id"),
        field="broker repository id",
    )
    default_branch = str(repository.get("default_branch") or "")
    if not BRANCH_RE.fullmatch(default_branch):
        raise BrokerProtocolError(
            "broker repository default branch is invalid"
        )

    policy = _mapping(
        instance.get("policy"), field="broker config instance policy"
    )
    _strict_keys(
        policy,
        field="broker config instance policy",
        allowed={
            "allowed_actions",
            "expected_pr_author_login",
            "required_checks",
            "allow_no_required_checks",
            "forbidden_path_prefixes",
            "require_same_repository_head",
            "resolve_outdated_threads_only",
            "require_evidence_marker",
            "maximum_packet_ttl_seconds",
            "maximum_clock_skew_seconds",
            "accepted_check_conclusions",
            "maximum_changed_files",
            "minimum_rate_limit_remaining",
        },
    )
    actions = _sorted_unique_strings(
        policy.get("allowed_actions"),
        field="broker policy allowed_actions",
        maximum_items=len(ALLOWED_ACTIONS),
        maximum_length=64,
        allow_empty=False,
    )
    if not set(actions).issubset(ALLOWED_ACTIONS):
        raise BrokerProtocolError(
            "broker policy contains an unsupported action"
        )
    expected_author = str(
        policy.get("expected_pr_author_login") or ""
    )
    if not LOGIN_RE.fullmatch(expected_author):
        raise BrokerProtocolError(
            "broker policy expected PR author is invalid"
        )
    required_checks = _sorted_unique_strings(
        policy.get("required_checks"),
        field="broker policy required_checks",
        maximum_items=128,
        maximum_length=256,
        allow_empty=True,
    )
    allow_no_checks = _boolean(
        policy.get("allow_no_required_checks"),
        field="broker policy allow_no_required_checks",
    )
    if not required_checks and not allow_no_checks:
        raise BrokerProtocolError(
            "broker policy must name required checks or explicitly allow none"
        )
    forbidden_prefixes = _sorted_unique_strings(
        policy.get("forbidden_path_prefixes"),
        field="broker policy forbidden_path_prefixes",
        maximum_items=128,
        maximum_length=512,
        allow_empty=False,
    )
    forbidden_prefixes = [
        _forbidden_prefix(
            value,
            field="broker policy forbidden path prefix",
        )
        for value in forbidden_prefixes
    ]
    for field in (
        "require_same_repository_head",
        "resolve_outdated_threads_only",
        "require_evidence_marker",
    ):
        if _boolean(
            policy.get(field), field=f"broker policy {field}"
        ) is not True:
            raise BrokerProtocolError(
                f"broker policy {field} must remain enabled in v1"
            )
    maximum_clock_skew = _nonnegative_int(
        policy.get("maximum_clock_skew_seconds"),
        field="broker policy maximum_clock_skew_seconds",
        maximum=MAX_CLOCK_SKEW_SECONDS,
    )
    accepted_conclusions = _sorted_unique_strings(
        policy.get("accepted_check_conclusions"),
        field="broker policy accepted_check_conclusions",
        maximum_items=len(ACCEPTED_GREEN_CHECK_CONCLUSIONS),
        maximum_length=32,
        allow_empty=False,
    )
    if (
        "SUCCESS" not in accepted_conclusions
        or not set(accepted_conclusions).issubset(
            ACCEPTED_GREEN_CHECK_CONCLUSIONS
        )
    ):
        raise BrokerProtocolError(
            "broker policy accepted check conclusions are unsafe"
        )
    maximum_changed_files = _positive_int(
        policy.get("maximum_changed_files"),
        field="broker policy maximum_changed_files",
        maximum=10_000,
    )
    minimum_rate_limit_remaining = _positive_int(
        policy.get("minimum_rate_limit_remaining"),
        field="broker policy minimum_rate_limit_remaining",
        maximum=100_000,
    )
    maximum_packet_ttl = _positive_int(
        policy.get("maximum_packet_ttl_seconds"),
        field="broker policy maximum_packet_ttl_seconds",
        maximum=MAX_PACKET_TTL_SECONDS,
    )
    if maximum_packet_ttl < MIN_PACKET_TTL_SECONDS:
        raise BrokerProtocolError(
            "broker policy packet TTL is outside the allowed range"
        )

    budgets = _mapping(
        instance.get("budgets"),
        field="broker config instance budgets",
    )
    _strict_keys(
        budgets,
        field="broker config instance budgets",
        allowed={
            "requests_per_hour",
            "mutation_attempts_per_day",
            "daily_mark_pr_ready",
            "daily_resolve_review_thread",
            "max_threads_per_submission",
            "consecutive_indeterminate_limit",
        },
    )
    requests_per_hour = _positive_int(
        budgets.get("requests_per_hour"),
        field="broker budget requests_per_hour",
        maximum=10_000,
    )
    mutation_attempts_per_day = _positive_int(
        budgets.get("mutation_attempts_per_day"),
        field="broker budget mutation_attempts_per_day",
        maximum=10_000,
    )
    daily_mark_ready = _positive_int(
        budgets.get("daily_mark_pr_ready"),
        field="broker budget daily_mark_pr_ready",
        maximum=10_000,
    )
    daily_resolve = _positive_int(
        budgets.get("daily_resolve_review_thread"),
        field="broker budget daily_resolve_review_thread",
        maximum=10_000,
    )
    if (
        daily_mark_ready > mutation_attempts_per_day
        or daily_resolve > mutation_attempts_per_day
    ):
        raise BrokerProtocolError(
            "broker per-action budget exceeds mutation budget"
        )
    max_threads = _positive_int(
        budgets.get("max_threads_per_submission"),
        field="broker budget max_threads_per_submission",
        maximum=1,
    )
    if max_threads != 1:
        raise BrokerProtocolError(
            "broker v1 requires one thread per submission"
        )
    consecutive_indeterminate_limit = _positive_int(
        budgets.get("consecutive_indeterminate_limit"),
        field="broker budget consecutive_indeterminate_limit",
        maximum=20,
    )

    return {
        "schema_version": CONFIG_SCHEMA,
        "enabled": enabled,
        "broker_id": broker_id,
        "broker_uid": broker_uid,
        "transport": {
            "kind": TRANSPORT_KIND,
            "peer_credentials": PEER_CREDENTIAL_PROTOCOL,
            "socket_path": socket_path,
            "requester_uid": requester_uid,
            "submit_gid": submit_gid,
            "max_request_bytes": max_request_bytes,
            "request_timeout_seconds": request_timeout_seconds,
        },
        "github_app": {
            "app_id": app_id,
            "app_slug": app_slug,
            "installation_id": installation_id,
            "private_key_path": github_private_key_path,
            "api_base_url": GITHUB_API_BASE_URL,
        },
        "receipt_signing": {
            "key_id": key_id,
            "private_key_path": receipt_private_key_path,
            "public_key_path": receipt_public_key_path,
            "public_key_sha256": public_key_sha256,
        },
        "state": {
            "database_path": database_path,
        },
        "instance": {
            "slug": slug,
            "repository": {
                "full_name": full_name,
                "id": repository_id,
                "default_branch": default_branch,
            },
            "policy": {
                "allowed_actions": actions,
                "expected_pr_author_login": expected_author,
                "required_checks": required_checks,
                "allow_no_required_checks": allow_no_checks,
                "forbidden_path_prefixes": forbidden_prefixes,
                "require_same_repository_head": True,
                "resolve_outdated_threads_only": True,
                "require_evidence_marker": True,
                "maximum_packet_ttl_seconds": maximum_packet_ttl,
                "maximum_clock_skew_seconds": maximum_clock_skew,
                "accepted_check_conclusions": accepted_conclusions,
                "maximum_changed_files": maximum_changed_files,
                "minimum_rate_limit_remaining": (
                    minimum_rate_limit_remaining
                ),
            },
            "budgets": {
                "requests_per_hour": requests_per_hour,
                "mutation_attempts_per_day": mutation_attempts_per_day,
                "daily_mark_pr_ready": daily_mark_ready,
                "daily_resolve_review_thread": daily_resolve,
                "max_threads_per_submission": 1,
                "consecutive_indeterminate_limit": (
                    consecutive_indeterminate_limit
                ),
            },
        },
    }


def config_digest(config: Any) -> str:
    return sha256_json(normalize_config(config))


def load_config(
    path: Path,
    *,
    config_owner_uids: int | Iterable[int] | None = None,
    key_owner_uids: int | Iterable[int] | None = None,
    parent_owner_uids: int | Iterable[int] | None = None,
    trusted_path_root: Path | None = None,
    expected_broker_uid: int | None = None,
) -> dict[str, Any]:
    """Load a trusted config and validate every configured key path.

    Production defaults require a root-owned config. Tests can explicitly pass
    their current UID, which exercises the same ownership checks without
    pretending to be root.
    """

    config_owners = _uid_set(config_owner_uids, default=(0,))
    path = _lexical_absolute_path(str(path), field="broker config")
    validate_trusted_parent_chain(
        path.parent,
        field="broker config",
        expected_owner_uids=config_owners,
        trusted_path_root=trusted_path_root,
    )
    raw = read_stable_file(
        path,
        field="broker config",
        maximum_bytes=MAX_CONFIG_BYTES,
        expected_owner_uids=config_owners,
        reject_group_other_writable=True,
    )
    config = normalize_config(
        parse_json_bytes(
            raw,
            field="broker config",
            maximum_bytes=MAX_CONFIG_BYTES,
        )
    )
    if (
        expected_broker_uid is not None
        and config["broker_uid"] != expected_broker_uid
    ):
        raise BrokerProtocolError(
            "broker config broker UID does not match the service identity"
        )
    key_owners = _uid_set(
        key_owner_uids,
        default=(0, config["broker_uid"]),
    )
    parent_owners = _uid_set(
        parent_owner_uids,
        default=(0, config["broker_uid"]),
    )
    validate_trusted_parent_chain(
        Path(config["transport"]["socket_path"]).parent,
        field="broker socket",
        expected_owner_uids=parent_owners,
        trusted_path_root=trusted_path_root,
    )
    database_path = Path(config["state"]["database_path"])
    validate_trusted_parent_chain(
        database_path.parent,
        field="broker state database",
        expected_owner_uids=parent_owners,
        trusted_path_root=trusted_path_root,
    )
    try:
        database_info = os.lstat(database_path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise BrokerProtocolError(
            "broker state database is unreadable"
        ) from exc
    else:
        if (
            stat.S_ISLNK(database_info.st_mode)
            or not stat.S_ISREG(database_info.st_mode)
        ):
            raise BrokerProtocolError(
                "broker state database is unsafe"
            )
        if database_info.st_uid not in key_owners:
            raise BrokerProtocolError(
                "broker state database owner is untrusted"
            )
        if database_info.st_mode & 0o022:
            raise BrokerProtocolError(
                "broker state database is group/other writable"
            )
    key_specs = (
        (
            Path(config["github_app"]["private_key_path"]),
            "broker GitHub App private key",
            b"PRIVATE KEY",
        ),
        (
            Path(config["receipt_signing"]["private_key_path"]),
            "broker receipt private key",
            b"PRIVATE KEY",
        ),
        (
            Path(config["receipt_signing"]["public_key_path"]),
            "broker receipt public key",
            b"PUBLIC KEY",
        ),
    )
    snapshots: dict[str, bytes] = {}
    for key_path, field, marker in key_specs:
        snapshot = read_trusted_file(
            key_path,
            field=field,
            maximum_bytes=MAX_KEY_BYTES,
            expected_owner_uids=key_owners,
            parent_owner_uids=parent_owners,
            trusted_path_root=trusted_path_root,
        )
        if marker not in snapshot:
            raise BrokerProtocolError(f"{field} is not a PEM key")
        snapshots[field] = snapshot
    actual_fingerprint = hashlib.sha256(
        snapshots["broker receipt public key"]
    ).hexdigest()
    if (
        actual_fingerprint
        != config["receipt_signing"]["public_key_sha256"]
    ):
        raise BrokerProtocolError(
            "broker receipt public-key fingerprint does not match"
        )
    return config


def validate_requester_uid(config: Any, peer_uid: Any) -> int:
    normalized = normalize_config(config)
    actual = _uid(peer_uid, field="broker peer UID")
    if actual != normalized["transport"]["requester_uid"]:
        raise BrokerProtocolError("broker requester UID is not authorized")
    if actual == normalized["broker_uid"]:
        raise BrokerProtocolError(
            "broker requester cannot share the broker identity"
        )
    return actual


def _parse_utc(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise BrokerProtocolError(f"{field} must be a UTC timestamp")
    try:
        return datetime.strptime(
            value, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise BrokerProtocolError(
            f"{field} must be a UTC timestamp"
        ) from exc


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _current_utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise BrokerProtocolError(
            "broker clock value must be timezone-aware"
        )
    return value.astimezone(timezone.utc)


def _github_url(
    value: Any,
    *,
    field: str,
    repo: str,
    pr_number: int,
    kind: str,
) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise BrokerProtocolError(f"{field} must be a GitHub URL")
    parsed = urlparse(value)
    expected_path = f"/{repo}/pull/{pr_number}"
    fragment_re = {
        "pr": None,
        "evidence": re.compile(r"^issuecomment-[1-9][0-9]*$"),
        "thread": re.compile(r"^discussion_r[1-9][0-9]*$"),
    }.get(kind)
    if kind not in {"pr", "evidence", "thread"}:
        raise BrokerProtocolError(f"{field} URL kind is unsupported")
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
            fragment_re is not None
            and not fragment_re.fullmatch(parsed.fragment)
        )
    ):
        raise BrokerProtocolError(f"{field} must target the bound PR")
    suffix = f"#{parsed.fragment}" if parsed.fragment else ""
    return f"https://github.com{expected_path}{suffix}"


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
        raise BrokerProtocolError(
            "protected-action request schema is unsupported"
        )
    instance_slug = str(request.get("instance_slug") or "")
    if not INSTANCE_SLUG_RE.fullmatch(instance_slug):
        raise BrokerProtocolError(
            "protected-action instance slug is invalid"
        )
    action = str(request.get("action") or "")
    if action not in ALLOWED_ACTIONS:
        raise BrokerProtocolError("protected action is unsupported")
    observed_at = _utc_text(
        _parse_utc(
            request.get("observed_at"),
            field="protected-action observed_at",
        )
    )
    repo = str(request.get("repo") or "")
    if not REPO_RE.fullmatch(repo):
        raise BrokerProtocolError(
            "protected-action repository is invalid"
        )

    pr = _mapping(request.get("pr"), field="protected-action PR")
    _strict_keys(
        pr,
        field="protected-action PR",
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
        pr.get("number"), field="protected-action PR number"
    )
    pr_url = _github_url(
        pr.get("url"),
        field="protected-action PR URL",
        repo=repo,
        pr_number=pr_number,
        kind="pr",
    )
    base_branch = str(pr.get("base_branch") or "")
    if not BRANCH_RE.fullmatch(base_branch):
        raise BrokerProtocolError(
            "protected-action base branch is invalid"
        )
    head_sha = str(pr.get("head_sha") or "").lower()
    if not OID_RE.fullmatch(head_sha):
        raise BrokerProtocolError("protected-action head SHA is invalid")
    author_login = str(pr.get("author_login") or "")
    if not LOGIN_RE.fullmatch(author_login):
        raise BrokerProtocolError(
            "protected-action PR author is invalid"
        )
    is_draft = _boolean(
        pr.get("is_draft"), field="protected-action PR is_draft"
    )

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
        raise BrokerProtocolError(
            "protected-action checks state is invalid"
        )
    thread_count = preconditions.get("unresolved_thread_count")
    if (
        isinstance(thread_count, bool)
        or not isinstance(thread_count, int)
        or thread_count < 0
        or thread_count > 10_000
    ):
        raise BrokerProtocolError(
            "protected-action unresolved thread count is invalid"
        )
    if preconditions.get("forbidden_paths_clear") is not True:
        raise BrokerProtocolError(
            "protected-action forbidden-path proof is required"
        )
    if preconditions.get("bot_authorship_verified") is not True:
        raise BrokerProtocolError(
            "protected-action bot-authorship proof is required"
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
    if verification.get("passed") is not True:
        raise BrokerProtocolError(
            "protected-action verification must have passed"
        )
    commands_sha256 = str(
        verification.get("commands_sha256") or ""
    )
    result_sha256 = str(verification.get("result_sha256") or "")
    if not SHA256_RE.fullmatch(commands_sha256) or not SHA256_RE.fullmatch(
        result_sha256
    ):
        raise BrokerProtocolError(
            "protected-action verification digest is invalid"
        )
    evidence_url = _github_url(
        preconditions.get("evidence_comment_url"),
        field="protected-action evidence comment URL",
        repo=repo,
        pr_number=pr_number,
        kind="evidence",
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
    if not isinstance(node_ids, list) or not isinstance(thread_urls, list):
        raise BrokerProtocolError(
            "protected-action thread targets must be arrays"
        )
    if len(node_ids) != len(thread_urls) or len(node_ids) > 50:
        raise BrokerProtocolError(
            "protected-action thread targets are inconsistent"
        )
    normalized_ids: list[str] = []
    normalized_urls: list[str] = []
    for index, node_id in enumerate(node_ids):
        if not isinstance(node_id, str) or not TOKEN_RE.fullmatch(node_id):
            raise BrokerProtocolError(
                f"protected-action thread node id {index} is invalid"
            )
        normalized_ids.append(node_id)
        normalized_urls.append(
            _github_url(
                thread_urls[index],
                field=f"protected-action thread URL {index}",
                repo=repo,
                pr_number=pr_number,
                kind="thread",
            )
        )
    if len(set(normalized_ids)) != len(normalized_ids):
        raise BrokerProtocolError(
            "protected-action thread node IDs must be unique"
        )
    if action == "mark_pr_ready":
        if not is_draft or thread_count != 0 or normalized_ids:
            raise BrokerProtocolError(
                "mark_pr_ready packet preconditions are inconsistent"
            )
    else:
        if (
            not normalized_ids
            or thread_count < len(normalized_ids)
        ):
            raise BrokerProtocolError(
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


def verify_protected_packet(
    raw: Any,
    *,
    now: datetime | None = None,
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
        raise BrokerProtocolError(
            "protected-action packet schema is unsupported"
        )
    if packet.get("authority") != PACKET_AUTHORITY:
        raise BrokerProtocolError(
            "protected-action packet authority is invalid"
        )
    if packet.get("requested_by") != "john-lomein-maintainer":
        raise BrokerProtocolError(
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
    ttl_seconds = int((expires - created).total_seconds())
    if (
        ttl_seconds < MIN_PACKET_TTL_SECONDS
        or ttl_seconds > MAX_PACKET_TTL_SECONDS
    ):
        raise BrokerProtocolError(
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
        < created
        - timedelta(seconds=MAX_PACKET_EVIDENCE_AGE_SECONDS)
    ):
        raise BrokerProtocolError(
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
        raise BrokerProtocolError(
            "protected-action packet digest does not match"
        )
    if packet.get("packet_id") != packet_id:
        raise BrokerProtocolError(
            "protected-action packet ID does not match"
        )
    current = _current_utc(now)
    if created > current + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        raise BrokerProtocolError(
            "protected-action packet creation time is in the future"
        )
    if current >= expires:
        raise BrokerProtocolError("protected-action packet has expired")
    return {
        **body,
        "packet_id": packet_id,
        "request_digest": digest,
    }


def normalize_submission(
    raw: Any,
    config: Any,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    normalized_config = normalize_config(config)
    submission = _mapping(raw, field="broker submission")
    _strict_keys(
        submission,
        field="broker submission",
        allowed={
            "schema_version",
            "packet",
        },
    )
    if submission.get("schema_version") != SUBMISSION_SCHEMA:
        raise BrokerProtocolError(
            "broker submission schema is unsupported"
        )
    if not normalized_config["enabled"]:
        raise BrokerProtocolError(
            "protected broker is disabled"
        )
    packet = verify_protected_packet(
        submission.get("packet"), now=now
    )
    request = packet["request"]
    instance = normalized_config["instance"]
    repository = instance["repository"]
    policy = instance["policy"]
    if request["instance_slug"] != instance["slug"]:
        raise BrokerProtocolError(
            "broker submission instance does not match"
        )
    if request["repo"] != repository["full_name"]:
        raise BrokerProtocolError(
            "broker submission repository does not match"
        )
    if request["pr"]["base_branch"] != repository["default_branch"]:
        raise BrokerProtocolError(
            "broker submission default branch does not match"
        )
    if request["pr"]["author_login"] != policy[
        "expected_pr_author_login"
    ]:
        raise BrokerProtocolError(
            "broker submission PR author does not match policy"
        )
    if request["action"] not in policy["allowed_actions"]:
        raise BrokerProtocolError(
            "broker submission action is not allowed"
        )
    if (
        request["preconditions"]["checks_state"] == "none"
        and not policy["allow_no_required_checks"]
    ):
        raise BrokerProtocolError(
            "broker submission cannot claim absent checks"
        )
    created = _parse_utc(
        packet["created_at"],
        field="protected-action packet created_at",
    )
    expires = _parse_utc(
        packet["expires_at"],
        field="protected-action packet expires_at",
    )
    if int((expires - created).total_seconds()) > policy[
        "maximum_packet_ttl_seconds"
    ]:
        raise BrokerProtocolError(
            "broker submission packet exceeds the policy TTL"
        )
    current = _current_utc(now)
    if created > current + timedelta(
        seconds=policy["maximum_clock_skew_seconds"]
    ):
        raise BrokerProtocolError(
            "broker submission exceeds the policy clock skew"
        )
    thread_ids = request["targets"]["thread_node_ids"]
    if request["action"] == "resolve_review_thread":
        if len(thread_ids) != 1:
            raise BrokerProtocolError(
                "broker v1 requires exactly one review thread"
            )
    elif thread_ids:
        raise BrokerProtocolError(
            "mark_pr_ready cannot contain review-thread targets"
        )
    return {
        "schema_version": SUBMISSION_SCHEMA,
        "packet": packet,
    }


def evidence_marker_for_packet(packet: Any) -> str:
    """Return the one exact live comment marker accepted by broker v1."""

    verified = verify_protected_packet(
        packet,
        now=_parse_utc(
            _mapping(packet, field="protected-action packet").get(
                "created_at"
            ),
            field="protected-action packet created_at",
        ),
    )
    request = verified["request"]
    verification = request["preconditions"]["verification"]
    return (
        f"{EVIDENCE_MARKER_PREFIX}"
        f"instance={request['instance_slug']} "
        f"action={request['action']} "
        f"head={request['pr']['head_sha']} "
        f"commands={verification['commands_sha256']} "
        f"result={verification['result_sha256']} -->"
    )


def load_submission(
    source: bytes | bytearray | memoryview | Path | os.PathLike[str],
    config: Any,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    if isinstance(source, (bytes, bytearray, memoryview)):
        raw = bytes(source)
    elif isinstance(source, (Path, os.PathLike)):
        raw = read_stable_file(
            Path(source),
            field="broker submission",
            maximum_bytes=MAX_SUBMISSION_BYTES,
        )
    else:
        raise BrokerProtocolError(
            "broker submission source must be bytes or a path"
        )
    value = parse_json_bytes(
        raw,
        field="broker submission",
        maximum_bytes=MAX_SUBMISSION_BYTES,
    )
    return normalize_submission(value, config, now=now)
