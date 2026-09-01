#!/usr/bin/env python3
"""Strict, self-contained wire boundary for protected release requests.

The release broker intentionally does not import validation helpers from the
Hermes/model-controlled runtime.  This module is installed with the protected
broker and independently validates the release bundle, owner authorization,
and request packet before any credential-bearing component sees the request.

The canonical JSON implementation is a deliberately small RFC 8785-compatible
subset: strings must already be NFC, numbers must be JSON-safe integers, and
floats are forbidden.  Those restrictions remove the ambiguous cases that are
unnecessary in the release protocol while preserving deterministic signing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import unicodedata
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


BUNDLE_SCHEMA = "john-lomein.release-bundle.v6"
PACKET_SCHEMA = "john-lomein.protected-release-merge-packet.v1"
SUBMISSION_SCHEMA = "john-lomein.protected-release-broker-submit.v1"
CONFIG_SCHEMA = "john-lomein.protected-release-broker-config.v1"
OWNER_ASSERTION_SCHEMA = "john-lomein.owner-assertion.v2"
SIGNED_ENVELOPE_SCHEMA = "john-lomein.signed-envelope.v1"
PACKET_AUTHORITY = "request_only_no_execution_authority"
REQUEST_COMPONENT = "john-lomein-release-executor"
RELEASE_ACTION = "merge_release_bundle"
SIGNATURE_ALGORITHM = "ed25519"
MERGE_METHOD = "squash"
GITHUB_API_BASE_URL = "https://api.github.com"
TRANSPORT_KIND = "unix_socket"
PEER_CREDENTIAL_PROTOCOL = "os_peer_credentials_v1"

MIN_BUNDLE_TTL_SECONDS = 60
MAX_BUNDLE_TTL_SECONDS = 24 * 60 * 60
MIN_PACKET_TTL_SECONDS = 60
MAX_PACKET_TTL_SECONDS = 60 * 60
MAX_CLOCK_SKEW_SECONDS = 300
MAX_ASSERTION_TTL_SECONDS = 15 * 60
MAX_PACKET_BYTES = 2 * 1024 * 1024
MAX_CONFIG_BYTES = 256 * 1024
MAX_KEY_BYTES = 64 * 1024
MAX_APPROVAL_TEXT_BYTES = 4096
MAX_CHANGED_PATHS_PER_PR = 2000
MAX_CHANGED_PATH_BYTES = 1024
MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991
MAX_SOCKET_PATH_BYTES = 100

OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
BUNDLE_ID_RE = re.compile(r"^jlb-[0-9a-f]{24}$")
PACKET_ID_RE = re.compile(r"^jlrp-[0-9a-f]{24}$")
NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
INSTANCE_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
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


class ReleaseBrokerProtocolError(ValueError):
    """A fail-closed release wire, signature, or binding failure."""


def _trusted_uid_set(
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
                raise ReleaseBrokerProtocolError(
                    "trusted UID set is invalid"
                )
            normalized.add(value)
    except TypeError as exc:
        raise ReleaseBrokerProtocolError(
            "trusted UID set is invalid"
        ) from exc
    if not normalized:
        raise ReleaseBrokerProtocolError("trusted UID set is empty")
    return frozenset(normalized)


def validate_trusted_parent_chain(
    path: Path,
    *,
    field: str,
    expected_owner_uids: int | Iterable[int] | None,
    trusted_path_root: Path | None = None,
) -> None:
    """Reject symlinked, writable, or unexpectedly owned path parents."""

    if not path.is_absolute() or ".." in path.parts:
        raise ReleaseBrokerProtocolError(f"{field} path is unsafe")
    trusted = _trusted_uid_set(expected_owner_uids, default=(0,))
    stop = trusted_path_root
    if stop is not None:
        if not stop.is_absolute() or ".." in stop.parts:
            raise ReleaseBrokerProtocolError(
                "trusted path root is unsafe"
            )
        try:
            path.relative_to(stop)
        except ValueError as exc:
            raise ReleaseBrokerProtocolError(
                f"{field} is outside the trusted path root"
            ) from exc
    current = path
    while True:
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise ReleaseBrokerProtocolError(
                f"{field} parent directory is unreadable"
            ) from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ReleaseBrokerProtocolError(
                f"{field} parent directory is unsafe"
            )
        if info.st_uid not in trusted:
            raise ReleaseBrokerProtocolError(
                f"{field} parent directory owner is untrusted"
            )
        if info.st_mode & 0o022:
            raise ReleaseBrokerProtocolError(
                f"{field} parent directory is group/other writable"
            )
        if (stop is not None and current == stop) or current.parent == current:
            return
        current = current.parent


def read_trusted_file(
    path: Path,
    *,
    field: str,
    maximum_bytes: int,
    expected_owner_uids: int | Iterable[int] | None,
    parent_owner_uids: int | Iterable[int] | None,
    trusted_path_root: Path | None = None,
) -> bytes:
    """Read one immutable-looking trusted file without following links."""

    if not path.is_absolute() or ".." in path.parts:
        raise ReleaseBrokerProtocolError(f"{field} path is unsafe")
    validate_trusted_parent_chain(
        path.parent,
        field=field,
        expected_owner_uids=parent_owner_uids,
        trusted_path_root=trusted_path_root,
    )
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ReleaseBrokerProtocolError(f"{field} is unreadable") from exc
    try:
        info = os.fstat(fd)
        trusted = _trusted_uid_set(expected_owner_uids, default=(0,))
        if not stat.S_ISREG(info.st_mode):
            raise ReleaseBrokerProtocolError(
                f"{field} must be a regular non-symlink file"
            )
        if info.st_uid not in trusted:
            raise ReleaseBrokerProtocolError(
                f"{field} owner is untrusted"
            )
        if info.st_mode & 0o022:
            raise ReleaseBrokerProtocolError(
                f"{field} is group/other writable"
            )
        if info.st_nlink != 1:
            raise ReleaseBrokerProtocolError(
                f"{field} must not have hard links"
            )
        if info.st_size < 1 or info.st_size > maximum_bytes:
            raise ReleaseBrokerProtocolError(
                f"{field} size is invalid"
            )
        raw = bytearray()
        while len(raw) <= maximum_bytes:
            chunk = os.read(
                fd, min(16 * 1024, maximum_bytes + 1 - len(raw))
            )
            if not chunk:
                break
            raw.extend(chunk)
        if not raw or len(raw) > maximum_bytes:
            raise ReleaseBrokerProtocolError(
                f"{field} size is invalid"
            )
        return bytes(raw)
    except ReleaseBrokerProtocolError:
        raise
    except OSError as exc:
        raise ReleaseBrokerProtocolError(f"{field} is unreadable") from exc
    finally:
        os.close(fd)


def _validate_canonical_value(value: Any, *, field: str = "value") -> None:
    if value is None or type(value) is bool:
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > MAX_SAFE_JSON_INTEGER:
            raise ReleaseBrokerProtocolError(
                f"{field} integer is outside the canonical JSON range"
            )
        return
    if isinstance(value, float):
        raise ReleaseBrokerProtocolError(
            f"{field} floats are forbidden in canonical JSON"
        )
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise ReleaseBrokerProtocolError(
                f"{field} string is not NFC-normalized"
            )
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ReleaseBrokerProtocolError(
                f"{field} string is not valid Unicode"
            ) from exc
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_canonical_value(item, field=f"{field}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ReleaseBrokerProtocolError(
                    f"{field} object key must be a string"
                )
            _validate_canonical_value(key, field=f"{field} object key")
            _validate_canonical_value(item, field=f"{field}.{key}")
        return
    raise ReleaseBrokerProtocolError(
        f"{field} has an unsupported canonical JSON type"
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
    if isinstance(value, list):
        return "[" + ",".join(_canonical_text(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=_utf16_sort_key)
        return (
            "{"
            + ",".join(
                f"{_canonical_text(key)}:{_canonical_text(value[key])}"
                for key in keys
            )
            + "}"
        )
    raise ReleaseBrokerProtocolError(
        "value has an unsupported canonical JSON type"
    )


def canonical_json(value: Any) -> bytes:
    _validate_canonical_value(value)
    return _canonical_text(value).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def sha256_text(value: str) -> str:
    _validate_canonical_value(value, field="text")
    return sha256_bytes(value.encode("utf-8"))


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseBrokerProtocolError(
                "JSON object contains duplicate fields"
            )
        result[key] = value
    return result


def _reject_float(_: str) -> None:
    raise ReleaseBrokerProtocolError("JSON floats are forbidden")


def _reject_nonfinite(_: str) -> None:
    raise ReleaseBrokerProtocolError("JSON non-finite numbers are forbidden")


def parse_json_bytes(
    raw: bytes,
    *,
    field: str,
    maximum_bytes: int = MAX_PACKET_BYTES,
) -> Any:
    if not isinstance(raw, bytes):
        raise ReleaseBrokerProtocolError(f"{field} must be bytes")
    if len(raw) > maximum_bytes:
        raise ReleaseBrokerProtocolError(f"{field} exceeds its size limit")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_nonfinite,
        )
    except ReleaseBrokerProtocolError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseBrokerProtocolError(f"{field} is invalid JSON") from exc
    _validate_canonical_value(value, field=field)
    return value


def _mapping(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseBrokerProtocolError(f"{field} must be an object")
    return value


def _strict_keys(
    value: dict[str, Any],
    *,
    field: str,
    required: set[str],
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    unknown = sorted(set(value) - required - optional)
    missing = sorted(required - set(value))
    if unknown:
        raise ReleaseBrokerProtocolError(f"{field} contains unknown fields")
    if missing:
        raise ReleaseBrokerProtocolError(
            f"{field} is missing required fields"
        )


def _positive_int(
    value: Any,
    *,
    field: str,
    maximum: int = MAX_SAFE_JSON_INTEGER,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReleaseBrokerProtocolError(f"{field} must be an integer")
    if value <= 0 or value > maximum:
        raise ReleaseBrokerProtocolError(
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
        raise ReleaseBrokerProtocolError(f"{field} must be an integer")
    if value < 0 or value > maximum:
        raise ReleaseBrokerProtocolError(
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
        raise ReleaseBrokerProtocolError(f"{field} must be a UID")
    return value


def _gid(value: Any, *, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 2**31 - 1
    ):
        raise ReleaseBrokerProtocolError(f"{field} must be a GID")
    return value


def _safe_text(
    value: Any,
    *,
    field: str,
    maximum_bytes: int,
    allow_space: bool = True,
) -> str:
    if not isinstance(value, str) or not value:
        raise ReleaseBrokerProtocolError(f"{field} is invalid")
    _validate_canonical_value(value, field=field)
    if len(value.encode("utf-8")) > maximum_bytes:
        raise ReleaseBrokerProtocolError(f"{field} exceeds its size limit")
    if "\x00" in value or any(
        ord(character) < 0x20 for character in value
    ):
        raise ReleaseBrokerProtocolError(
            f"{field} contains control characters"
        )
    if not allow_space and any(character.isspace() for character in value):
        raise ReleaseBrokerProtocolError(f"{field} contains whitespace")
    return value


def _parse_utc(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise ReleaseBrokerProtocolError(f"{field} must be a UTC timestamp")
    try:
        return datetime.strptime(
            value, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ReleaseBrokerProtocolError(
            f"{field} must be a canonical UTC timestamp"
        ) from exc


def utc_text(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ReleaseBrokerProtocolError(
            "clock value must be timezone-aware"
        )
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _current_utc(value: datetime | None) -> datetime:
    return (
        datetime.now(timezone.utc)
        if value is None
        else _parse_datetime(value)
    )


def _parse_datetime(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ReleaseBrokerProtocolError(
            "clock value must be timezone-aware"
        )
    return value.astimezone(timezone.utc)


def _digest(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ReleaseBrokerProtocolError(f"{field} must be a SHA-256 digest")
    return value


def _absolute_path(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or not value.startswith("/")
    ):
        raise ReleaseBrokerProtocolError(f"{field} must be an absolute path")
    parts = value.split("/")
    if ".." in parts or "." in parts or "//" in value or value != str(
        Path(value)
    ):
        raise ReleaseBrokerProtocolError(f"{field} must be normalized")
    return value


def _sorted_unique_texts(
    value: Any,
    *,
    field: str,
    maximum_items: int,
    validator: Any,
) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > maximum_items
    ):
        raise ReleaseBrokerProtocolError(f"{field} has an invalid item count")
    normalized = [validator(item) for item in value]
    if normalized != sorted(normalized) or len(normalized) != len(
        set(normalized)
    ):
        raise ReleaseBrokerProtocolError(
            f"{field} must be sorted and unique"
        )
    return normalized


def _oid(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not OID_RE.fullmatch(value):
        raise ReleaseBrokerProtocolError(f"{field} must be a full Git OID")
    return value


def _github_pr_url(
    value: Any,
    *,
    repository: str,
    number: int,
    field: str,
) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ReleaseBrokerProtocolError(f"{field} must be a GitHub PR URL")
    parsed = urlparse(value)
    expected_path = f"/{repository}/pull/{number}"
    if (
        parsed.scheme != "https"
        or parsed.netloc.lower() != "github.com"
        or parsed.path != expected_path
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.params
        or parsed.fragment
    ):
        raise ReleaseBrokerProtocolError(
            f"{field} must target the bound GitHub PR"
        )
    return f"https://github.com{expected_path}"


def _changed_path(value: Any, *, field: str) -> str:
    path = _safe_text(
        value,
        field=field,
        maximum_bytes=MAX_CHANGED_PATH_BYTES,
        allow_space=True,
    )
    if (
        path.startswith("/")
        or path.startswith("./")
        or path.endswith("/")
        or "\\" in path
    ):
        raise ReleaseBrokerProtocolError(f"{field} is unsafe")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ReleaseBrokerProtocolError(f"{field} is unsafe")
    return path


def normalize_config(raw: Any) -> dict[str, Any]:
    """Normalize the root-owned release broker configuration.

    Dangerous defaults are not implicit: the merge method, one-PR limit,
    publish/delete prohibitions, App origin, permission-independent producer
    identities, budgets, and transport identities are all explicit.
    """

    config = _mapping(raw, field="release broker config")
    _strict_keys(
        config,
        field="release broker config",
        required={
            "schema_version",
            "enabled",
            "broker_id",
            "broker_uid",
            "broker_private_gid",
            "transport",
            "github_app",
            "owner_assertion",
            "receipt_signing",
            "state",
            "instance",
        },
    )
    if config.get("schema_version") != CONFIG_SCHEMA:
        raise ReleaseBrokerProtocolError(
            "release broker config schema is unsupported"
        )
    if type(config.get("enabled")) is not bool:
        raise ReleaseBrokerProtocolError(
            "release broker enabled must be boolean"
        )
    broker_id = str(config.get("broker_id") or "")
    if not TOKEN_RE.fullmatch(broker_id):
        raise ReleaseBrokerProtocolError(
            "release broker ID is invalid"
        )
    broker_uid = _uid(
        config.get("broker_uid"), field="release broker UID"
    )
    broker_private_gid = _gid(
        config.get("broker_private_gid"),
        field="release broker private GID",
    )
    if broker_private_gid == 0:
        raise ReleaseBrokerProtocolError(
            "release broker private GID must be nonzero"
        )

    transport = _mapping(
        config.get("transport"), field="release broker transport"
    )
    _strict_keys(
        transport,
        field="release broker transport",
        required={
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
        raise ReleaseBrokerProtocolError(
            "release broker transport kind is unsupported"
        )
    if transport.get("peer_credentials") != PEER_CREDENTIAL_PROTOCOL:
        raise ReleaseBrokerProtocolError(
            "release broker peer credentials are unsupported"
        )
    socket_path = _absolute_path(
        transport.get("socket_path"),
        field="release broker socket path",
    )
    if len(os.fsencode(socket_path)) > MAX_SOCKET_PATH_BYTES:
        raise ReleaseBrokerProtocolError(
            "release broker socket path is too long"
        )
    requester_uid = _uid(
        transport.get("requester_uid"),
        field="release broker requester UID",
    )
    if requester_uid == broker_uid:
        raise ReleaseBrokerProtocolError(
            "release broker and requester UIDs must differ"
        )
    submit_gid = _gid(
        transport.get("submit_gid"),
        field="release broker submit GID",
    )
    if broker_private_gid == submit_gid:
        raise ReleaseBrokerProtocolError(
            "release broker private and submit GIDs must differ"
        )
    max_request_bytes = _positive_int(
        transport.get("max_request_bytes"),
        field="release broker max request bytes",
        maximum=MAX_PACKET_BYTES,
    )
    if max_request_bytes < 4096:
        raise ReleaseBrokerProtocolError(
            "release broker max request bytes is too small"
        )
    request_timeout_seconds = _positive_int(
        transport.get("request_timeout_seconds"),
        field="release broker request timeout",
        maximum=60,
    )

    github_app = _mapping(
        config.get("github_app"), field="release broker GitHub App"
    )
    _strict_keys(
        github_app,
        field="release broker GitHub App",
        required={
            "app_id",
            "app_slug",
            "installation_id",
            "private_key_path",
            "api_base_url",
        },
    )
    app_id = _positive_int(
        github_app.get("app_id"),
        field="release GitHub App ID",
    )
    app_slug = str(github_app.get("app_slug") or "")
    if not re.fullmatch(
        r"^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$", app_slug
    ):
        raise ReleaseBrokerProtocolError(
            "release GitHub App slug is invalid"
        )
    installation_id = _positive_int(
        github_app.get("installation_id"),
        field="release GitHub App installation ID",
    )
    github_key_path = _absolute_path(
        github_app.get("private_key_path"),
        field="release GitHub App private key path",
    )
    if github_app.get("api_base_url") != GITHUB_API_BASE_URL:
        raise ReleaseBrokerProtocolError(
            "release GitHub API origin is unsupported"
        )

    owner = _mapping(
        config.get("owner_assertion"),
        field="release broker owner assertion",
    )
    _strict_keys(
        owner,
        field="release broker owner assertion",
        required={
            "issuer",
            "key_id",
            "public_key_path",
            "public_key_sha256",
            "allowed_actor_ids",
            "maximum_ttl_seconds",
            "maximum_clock_skew_seconds",
        },
    )
    owner_issuer = str(owner.get("issuer") or "")
    owner_key_id = str(owner.get("key_id") or "")
    if not TOKEN_RE.fullmatch(owner_issuer):
        raise ReleaseBrokerProtocolError(
            "release owner assertion issuer is invalid"
        )
    if not KEY_ID_RE.fullmatch(owner_key_id):
        raise ReleaseBrokerProtocolError(
            "release owner assertion key ID is invalid"
        )
    owner_public_key_path = _absolute_path(
        owner.get("public_key_path"),
        field="release owner public key path",
    )
    owner_public_key_sha256 = _digest(
        owner.get("public_key_sha256"),
        field="release owner public key fingerprint",
    )
    allowed_actor_ids = _sorted_unique_texts(
        owner.get("allowed_actor_ids"),
        field="release owner actor IDs",
        maximum_items=50,
        validator=lambda value: (
            str(value)
            if TOKEN_RE.fullmatch(str(value))
            else (_ for _ in ()).throw(
                ReleaseBrokerProtocolError(
                    "release owner actor ID is invalid"
                )
            )
        ),
    )
    assertion_ttl = _positive_int(
        owner.get("maximum_ttl_seconds"),
        field="release owner assertion TTL",
        maximum=MAX_ASSERTION_TTL_SECONDS,
    )
    assertion_clock_skew = _nonnegative_int(
        owner.get("maximum_clock_skew_seconds"),
        field="release owner assertion clock skew",
        maximum=MAX_CLOCK_SKEW_SECONDS,
    )

    receipt = _mapping(
        config.get("receipt_signing"),
        field="release broker receipt signing",
    )
    _strict_keys(
        receipt,
        field="release broker receipt signing",
        required={
            "key_id",
            "private_key_path",
            "public_key_path",
            "public_key_sha256",
        },
    )
    receipt_key_id = str(receipt.get("key_id") or "")
    if not KEY_ID_RE.fullmatch(receipt_key_id):
        raise ReleaseBrokerProtocolError(
            "release receipt key ID is invalid"
        )
    receipt_private_path = _absolute_path(
        receipt.get("private_key_path"),
        field="release receipt private key path",
    )
    receipt_public_path = _absolute_path(
        receipt.get("public_key_path"),
        field="release receipt public key path",
    )
    receipt_fingerprint = _digest(
        receipt.get("public_key_sha256"),
        field="release receipt public key fingerprint",
    )
    key_paths = {
        github_key_path,
        owner_public_key_path,
        receipt_private_path,
        receipt_public_path,
    }
    if len(key_paths) != 4:
        raise ReleaseBrokerProtocolError(
            "release broker key paths must be distinct"
        )

    state = _mapping(
        config.get("state"), field="release broker state"
    )
    _strict_keys(
        state,
        field="release broker state",
        required={"database_path"},
    )
    database_path = _absolute_path(
        state.get("database_path"),
        field="release broker database path",
    )
    if database_path in key_paths or database_path == socket_path:
        raise ReleaseBrokerProtocolError(
            "release broker state and credential paths must be distinct"
        )

    instance = _mapping(
        config.get("instance"), field="release broker instance"
    )
    _strict_keys(
        instance,
        field="release broker instance",
        required={"slug", "repository", "policy", "budgets"},
    )
    instance_slug = str(instance.get("slug") or "")
    if not INSTANCE_SLUG_RE.fullmatch(instance_slug):
        raise ReleaseBrokerProtocolError(
            "release broker instance slug is invalid"
        )
    repository = _mapping(
        instance.get("repository"),
        field="release broker repository",
    )
    _strict_keys(
        repository,
        field="release broker repository",
        required={"id", "full_name", "default_branch"},
    )
    repository_id = _positive_int(
        repository.get("id"),
        field="release broker repository ID",
    )
    repository_name = str(repository.get("full_name") or "")
    default_branch = str(repository.get("default_branch") or "")
    if not REPOSITORY_RE.fullmatch(repository_name):
        raise ReleaseBrokerProtocolError(
            "release broker repository name is invalid"
        )
    if not BRANCH_RE.fullmatch(default_branch):
        raise ReleaseBrokerProtocolError(
            "release broker default branch is invalid"
        )

    policy = _mapping(
        instance.get("policy"), field="release broker policy"
    )
    _strict_keys(
        policy,
        field="release broker policy",
        required={
            "expected_pr_author_logins",
            "expected_merge_actor_login",
            "codex_evidence_author_logins",
            "required_checks",
            "forbidden_path_prefixes",
            "require_same_repository_head",
            "require_codex_evidence",
            "reject_unconfigured_failures",
            "maximum_changed_files_per_pr",
            "maximum_total_changed_files",
            "minimum_rate_limit_remaining",
            "maximum_bundle_ttl_seconds",
            "maximum_packet_ttl_seconds",
            "maximum_execution_seconds",
            "max_prs_per_bundle",
            "merge_method",
            "publish",
            "delete_branch",
        },
    )
    expected_authors = _sorted_unique_texts(
        policy.get("expected_pr_author_logins"),
        field="release expected PR authors",
        maximum_items=50,
        validator=lambda value: (
            str(value)
            if LOGIN_RE.fullmatch(str(value))
            else (_ for _ in ()).throw(
                ReleaseBrokerProtocolError(
                    "release expected PR author is invalid"
                )
            )
        ),
    )
    merge_actor = str(policy.get("expected_merge_actor_login") or "")
    if not LOGIN_RE.fullmatch(merge_actor):
        raise ReleaseBrokerProtocolError(
            "release expected merge actor is invalid"
        )
    codex_authors = _sorted_unique_texts(
        policy.get("codex_evidence_author_logins"),
        field="release Codex evidence authors",
        maximum_items=20,
        validator=lambda value: (
            str(value)
            if LOGIN_RE.fullmatch(str(value))
            else (_ for _ in ()).throw(
                ReleaseBrokerProtocolError(
                    "release Codex evidence author is invalid"
                )
            )
        ),
    )
    raw_checks = policy.get("required_checks")
    if (
        not isinstance(raw_checks, list)
        or not raw_checks
        or len(raw_checks) > 100
    ):
        raise ReleaseBrokerProtocolError(
            "release required checks are invalid"
        )
    required_checks: list[dict[str, Any]] = []
    for index, raw_check in enumerate(raw_checks):
        check = _mapping(
            raw_check, field=f"release required check {index}"
        )
        _strict_keys(
            check,
            field=f"release required check {index}",
            required={
                "kind",
                "name",
                "producer_app_id",
                "producer_slug",
                "producer_login",
            },
        )
        kind = str(check.get("kind") or "")
        if kind not in {"check_run", "commit_status"}:
            raise ReleaseBrokerProtocolError(
                f"release required check {index} kind is invalid"
            )
        name = _safe_text(
            check.get("name"),
            field=f"release required check {index} name",
            maximum_bytes=255,
        )
        producer_app_id: int | None
        producer_slug: str | None
        producer_login: str | None
        if kind == "check_run":
            producer_app_id = _positive_int(
                check.get("producer_app_id"),
                field=f"release required check {index} producer App ID",
            )
            producer_slug = str(check.get("producer_slug") or "")
            if not re.fullmatch(
                r"^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$",
                producer_slug,
            ):
                raise ReleaseBrokerProtocolError(
                    f"release required check {index} producer slug is invalid"
                )
            if check.get("producer_login") is not None:
                raise ReleaseBrokerProtocolError(
                    f"release required check {index} login must be null"
                )
            producer_login = None
        else:
            if (
                check.get("producer_app_id") is not None
                or check.get("producer_slug") is not None
            ):
                raise ReleaseBrokerProtocolError(
                    f"release required status {index} App fields must be null"
                )
            producer_app_id = None
            producer_slug = None
            producer_login = str(check.get("producer_login") or "")
            if not LOGIN_RE.fullmatch(producer_login):
                raise ReleaseBrokerProtocolError(
                    f"release required status {index} producer is invalid"
                )
        required_checks.append(
            {
                "kind": kind,
                "name": name,
                "producer_app_id": producer_app_id,
                "producer_slug": producer_slug,
                "producer_login": producer_login,
            }
        )
    check_keys = [
        (
            item["kind"],
            item["name"],
            item["producer_app_id"] or 0,
            item["producer_slug"] or "",
            item["producer_login"] or "",
        )
        for item in required_checks
    ]
    if check_keys != sorted(check_keys) or len(check_keys) != len(
        set(check_keys)
    ):
        raise ReleaseBrokerProtocolError(
            "release required checks must be sorted and unique"
        )
    forbidden_prefixes = _sorted_unique_texts(
        policy.get("forbidden_path_prefixes"),
        field="release forbidden path prefixes",
        maximum_items=100,
        validator=lambda value: _changed_path(
            value, field="release forbidden path prefix"
        ),
    )
    for boolean_field in (
        "require_same_repository_head",
        "require_codex_evidence",
        "reject_unconfigured_failures",
    ):
        if policy.get(boolean_field) is not True:
            raise ReleaseBrokerProtocolError(
                f"release policy {boolean_field} must be true"
            )
    maximum_changed_files = _positive_int(
        policy.get("maximum_changed_files_per_pr"),
        field="release maximum changed files per PR",
        maximum=MAX_CHANGED_PATHS_PER_PR,
    )
    maximum_total_changed_files = _positive_int(
        policy.get("maximum_total_changed_files"),
        field="release maximum total changed files",
        maximum=MAX_CHANGED_PATHS_PER_PR,
    )
    if maximum_total_changed_files < maximum_changed_files:
        raise ReleaseBrokerProtocolError(
            "release total changed-file limit is too small"
        )
    minimum_rate = _positive_int(
        policy.get("minimum_rate_limit_remaining"),
        field="release minimum rate limit",
        maximum=100_000,
    )
    maximum_bundle_ttl = _positive_int(
        policy.get("maximum_bundle_ttl_seconds"),
        field="release maximum bundle TTL",
        maximum=MAX_BUNDLE_TTL_SECONDS,
    )
    maximum_packet_ttl = _positive_int(
        policy.get("maximum_packet_ttl_seconds"),
        field="release maximum packet TTL",
        maximum=MAX_PACKET_TTL_SECONDS,
    )
    maximum_execution = _positive_int(
        policy.get("maximum_execution_seconds"),
        field="release maximum execution time",
        maximum=3600,
    )
    if policy.get("max_prs_per_bundle") != 1:
        raise ReleaseBrokerProtocolError(
            "release live v1 max_prs_per_bundle must be one"
        )
    if policy.get("merge_method") != MERGE_METHOD:
        raise ReleaseBrokerProtocolError(
            "release policy merge method must be squash"
        )
    if policy.get("publish") is not False:
        raise ReleaseBrokerProtocolError(
            "release policy may not enable publishing"
        )
    if policy.get("delete_branch") is not False:
        raise ReleaseBrokerProtocolError(
            "release policy may not delete branches"
        )

    budgets = _mapping(
        instance.get("budgets"), field="release broker budgets"
    )
    budget_fields = {
        "unique_requests_per_hour": 10_000,
        "owner_assertions_per_hour": 10_000,
        "bundles_per_day": 10_000,
        "mutation_attempts_per_day": 10_000,
        "confirmed_merges_per_day": 10_000,
        "consecutive_indeterminate_limit": 100,
    }
    _strict_keys(
        budgets,
        field="release broker budgets",
        required=set(budget_fields),
    )
    normalized_budgets = {
        field: _positive_int(
            budgets.get(field),
            field=f"release budget {field}",
            maximum=maximum,
        )
        for field, maximum in budget_fields.items()
    }
    if (
        normalized_budgets["confirmed_merges_per_day"]
        > normalized_budgets["mutation_attempts_per_day"]
    ):
        raise ReleaseBrokerProtocolError(
            "release confirmed-merge budget exceeds attempt budget"
        )

    return {
        "schema_version": CONFIG_SCHEMA,
        "enabled": config["enabled"],
        "broker_id": broker_id,
        "broker_uid": broker_uid,
        "broker_private_gid": broker_private_gid,
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
            "private_key_path": github_key_path,
            "api_base_url": GITHUB_API_BASE_URL,
        },
        "owner_assertion": {
            "issuer": owner_issuer,
            "key_id": owner_key_id,
            "public_key_path": owner_public_key_path,
            "public_key_sha256": owner_public_key_sha256,
            "allowed_actor_ids": allowed_actor_ids,
            "maximum_ttl_seconds": assertion_ttl,
            "maximum_clock_skew_seconds": assertion_clock_skew,
        },
        "receipt_signing": {
            "key_id": receipt_key_id,
            "private_key_path": receipt_private_path,
            "public_key_path": receipt_public_path,
            "public_key_sha256": receipt_fingerprint,
        },
        "state": {"database_path": database_path},
        "instance": {
            "slug": instance_slug,
            "repository": {
                "id": repository_id,
                "full_name": repository_name,
                "default_branch": default_branch,
            },
            "policy": {
                "expected_pr_author_logins": expected_authors,
                "expected_merge_actor_login": merge_actor,
                "codex_evidence_author_logins": codex_authors,
                "required_checks": required_checks,
                "forbidden_path_prefixes": forbidden_prefixes,
                "require_same_repository_head": True,
                "require_codex_evidence": True,
                "reject_unconfigured_failures": True,
                "maximum_changed_files_per_pr": maximum_changed_files,
                "maximum_total_changed_files": maximum_total_changed_files,
                "minimum_rate_limit_remaining": minimum_rate,
                "maximum_bundle_ttl_seconds": maximum_bundle_ttl,
                "maximum_packet_ttl_seconds": maximum_packet_ttl,
                "maximum_execution_seconds": maximum_execution,
                "max_prs_per_bundle": 1,
                "merge_method": MERGE_METHOD,
                "publish": False,
                "delete_branch": False,
            },
            "budgets": normalized_budgets,
        },
    }


def config_digest(config: Any) -> str:
    return sha256_json(normalize_config(config))


def load_config(
    path: Path,
    *,
    expected_owner_uids: int | Iterable[int] | None = None,
    parent_owner_uids: int | Iterable[int] | None = None,
    trusted_path_root: Path | None = None,
) -> dict[str, Any]:
    raw = read_trusted_file(
        path,
        field="release broker config",
        maximum_bytes=MAX_CONFIG_BYTES,
        expected_owner_uids=expected_owner_uids,
        parent_owner_uids=parent_owner_uids,
        trusted_path_root=trusted_path_root,
    )
    return normalize_config(
        parse_json_bytes(
            raw,
            field="release broker config",
            maximum_bytes=MAX_CONFIG_BYTES,
        )
    )


def validate_requester_uid(config: Any, peer_uid: Any) -> int:
    normalized = normalize_config(config)
    actual = _uid(peer_uid, field="release requester peer UID")
    if actual != normalized["transport"]["requester_uid"]:
        raise ReleaseBrokerProtocolError(
            "release requester peer UID is unauthorized"
        )
    if actual == normalized["broker_uid"]:
        raise ReleaseBrokerProtocolError(
            "release requester cannot share broker identity"
        )
    return actual


def release_bundle_digest_payload(bundle: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in bundle.items()
        if key not in {"bundle_id", "bundle_digest"}
    }


def release_bundle_digest(bundle: dict[str, Any]) -> str:
    return sha256_json(release_bundle_digest_payload(bundle))


def release_bundle_id(bundle: dict[str, Any]) -> str:
    return f"jlb-{release_bundle_digest(bundle).removeprefix('sha256:')[:24]}"


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


def normalize_release_bundle(raw: Any) -> dict[str, Any]:
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
        raise ReleaseBrokerProtocolError(
            "release bundle schema is unsupported"
        )
    instance_slug = str(bundle.get("instance_slug") or "")
    if not INSTANCE_SLUG_RE.fullmatch(instance_slug):
        raise ReleaseBrokerProtocolError(
            "release bundle instance slug is invalid"
        )

    repository = _mapping(
        bundle.get("repository"), field="release bundle repository"
    )
    _strict_keys(
        repository,
        field="release bundle repository",
        required={"id", "full_name", "default_branch"},
    )
    repository_id = _positive_int(
        repository.get("id"), field="release repository ID"
    )
    full_name = str(repository.get("full_name") or "")
    if not REPOSITORY_RE.fullmatch(full_name):
        raise ReleaseBrokerProtocolError(
            "release repository full name is invalid"
        )
    default_branch = str(repository.get("default_branch") or "")
    if not BRANCH_RE.fullmatch(default_branch):
        raise ReleaseBrokerProtocolError(
            "release repository default branch is invalid"
        )

    created = _parse_utc(
        bundle.get("created_at"), field="release bundle created_at"
    )
    expires = _parse_utc(
        bundle.get("expires_at"), field="release bundle expires_at"
    )
    ttl = int((expires - created).total_seconds())
    if ttl < MIN_BUNDLE_TTL_SECONDS or ttl > MAX_BUNDLE_TTL_SECONDS:
        raise ReleaseBrokerProtocolError(
            "release bundle lifetime is invalid"
        )
    initial_base_sha = _oid(
        bundle.get("initial_base_sha"),
        field="release bundle initial base",
    )
    if bundle.get("merge_method") != MERGE_METHOD:
        raise ReleaseBrokerProtocolError(
            "release bundle merge method must be squash"
        )
    if bundle.get("publish") is not False:
        raise ReleaseBrokerProtocolError(
            "release bundle may not authorize publishing"
        )

    raw_prs = bundle.get("ordered_prs")
    if (
        not isinstance(raw_prs, list)
        or not raw_prs
        or len(raw_prs) > 50
    ):
        raise ReleaseBrokerProtocolError(
            "release bundle ordered PR list is invalid"
        )
    ordered_prs: list[dict[str, Any]] = []
    seen_numbers: set[int] = set()
    for index, raw_pr in enumerate(raw_prs):
        pr = _mapping(
            raw_pr, field=f"release bundle PR at position {index}"
        )
        _strict_keys(
            pr,
            field=f"release bundle PR at position {index}",
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
            field=f"release bundle PR {index} position",
            maximum=49,
        )
        if position != index:
            raise ReleaseBrokerProtocolError(
                "release bundle PR positions must be contiguous and ordered"
            )
        number = _positive_int(
            pr.get("number"),
            field=f"release bundle PR {index} number",
            maximum=2**31 - 1,
        )
        if number in seen_numbers:
            raise ReleaseBrokerProtocolError(
                "release bundle PR numbers must be unique"
            )
        seen_numbers.add(number)
        url = _github_pr_url(
            pr.get("url"),
            repository=full_name,
            number=number,
            field=f"release bundle PR {index} URL",
        )
        head_sha = _oid(
            pr.get("head_sha"),
            field=f"release bundle PR {index} head SHA",
        )
        expected_merge_tree_sha = _oid(
            pr.get("expected_merge_tree_sha"),
            field=(
                f"release bundle PR {index} expected merge tree SHA"
            ),
        )
        base_branch = str(pr.get("base_branch") or "")
        if base_branch != default_branch:
            raise ReleaseBrokerProtocolError(
                "release bundle PR base must be the default branch"
            )
        author_login = str(pr.get("author_login") or "")
        if not LOGIN_RE.fullmatch(author_login):
            raise ReleaseBrokerProtocolError(
                f"release bundle PR {index} author is invalid"
            )
        raw_paths = pr.get("changed_paths")
        if (
            not isinstance(raw_paths, list)
            or len(raw_paths) > MAX_CHANGED_PATHS_PER_PR
        ):
            raise ReleaseBrokerProtocolError(
                f"release bundle PR {index} changed paths are invalid"
            )
        paths = [
            _changed_path(
                path,
                field=f"release bundle PR {index} changed path",
            )
            for path in raw_paths
        ]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ReleaseBrokerProtocolError(
                "release bundle changed paths must be sorted and unique"
            )
        path_count = _nonnegative_int(
            pr.get("changed_path_count"),
            field=f"release bundle PR {index} changed path count",
            maximum=MAX_CHANGED_PATHS_PER_PR,
        )
        if path_count != len(paths):
            raise ReleaseBrokerProtocolError(
                "release bundle changed path count does not match"
            )
        expected_paths_digest = sha256_json(paths)
        if pr.get("changed_paths_digest") != expected_paths_digest:
            raise ReleaseBrokerProtocolError(
                "release bundle changed paths digest does not match"
            )
        risk_class = str(pr.get("risk_class") or "")
        if risk_class not in RISK_RANK:
            raise ReleaseBrokerProtocolError(
                f"release bundle PR {index} risk class is invalid"
            )
        review_quorum_sha256 = _digest(pr.get("review_quorum_sha256"), field=f"release bundle PR {index} review quorum digest")
        review_quorum_policy_sha256 = _digest(pr.get("review_quorum_policy_sha256"), field=f"release bundle PR {index} review policy digest")
        ordered_prs.append(
            {
                "position": position,
                "number": number,
                "url": url,
                "head_sha": head_sha,
                "expected_merge_tree_sha": expected_merge_tree_sha,
                "base_branch": base_branch,
                "author_login": author_login,
                "changed_paths": paths,
                "changed_paths_digest": expected_paths_digest,
                "changed_path_count": path_count,
                "risk_class": risk_class,
                "review_quorum_sha256": review_quorum_sha256,
                "review_quorum_policy_sha256": review_quorum_policy_sha256,
            }
        )

    train_digest = bundle.get("train_attestation_digest")
    if train_digest is not None:
        train_digest = _digest(
            train_digest,
            field="release train attestation digest",
        )
    actions = _mapping(
        bundle.get("actions"), field="release bundle actions"
    )
    _strict_keys(
        actions,
        field="release bundle actions",
        required={"merge", "publish"},
    )
    if actions.get("merge") is not True or actions.get("publish") is not False:
        raise ReleaseBrokerProtocolError(
            "release bundle actions must authorize merge only"
        )
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
    expected_digest = release_bundle_digest(normalized)
    expected_id = release_bundle_id(normalized)
    if normalized["bundle_digest"] != expected_digest:
        raise ReleaseBrokerProtocolError(
            "release bundle digest does not match"
        )
    if normalized["bundle_id"] != expected_id:
        raise ReleaseBrokerProtocolError(
            "release bundle ID does not match its digest"
        )
    return normalized


def normalize_owner_assertion_envelope(
    raw: Any,
    *,
    now: datetime | None = None,
    allow_expired: bool = False,
    maximum_ttl_seconds: int = MAX_ASSERTION_TTL_SECONDS,
    maximum_clock_skew_seconds: int = MAX_CLOCK_SKEW_SECONDS,
) -> dict[str, Any]:
    envelope = _mapping(raw, field="owner assertion envelope")
    _strict_keys(
        envelope,
        field="owner assertion envelope",
        required={
            "schema_version",
            "algorithm",
            "key_id",
            "payload",
            "signature",
        },
    )
    if envelope.get("schema_version") != SIGNED_ENVELOPE_SCHEMA:
        raise ReleaseBrokerProtocolError(
            "owner assertion envelope schema is unsupported"
        )
    if envelope.get("algorithm") != SIGNATURE_ALGORITHM:
        raise ReleaseBrokerProtocolError(
            "owner assertion algorithm is unsupported"
        )
    key_id = str(envelope.get("key_id") or "")
    if not KEY_ID_RE.fullmatch(key_id):
        raise ReleaseBrokerProtocolError(
            "owner assertion key ID is invalid"
        )
    signature = str(envelope.get("signature") or "")
    if not SIGNATURE_RE.fullmatch(signature):
        raise ReleaseBrokerProtocolError(
            "owner assertion signature encoding is invalid"
        )
    try:
        signature_bytes = base64.urlsafe_b64decode(signature + "==")
    except (ValueError, TypeError) as exc:
        raise ReleaseBrokerProtocolError(
            "owner assertion signature encoding is invalid"
        ) from exc
    if len(signature_bytes) != 64:
        raise ReleaseBrokerProtocolError(
            "owner assertion signature size is invalid"
        )

    payload = _mapping(
        envelope.get("payload"), field="owner assertion payload"
    )
    _strict_keys(
        payload,
        field="owner assertion payload",
        required={
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
        },
    )
    if payload.get("schema_version") != OWNER_ASSERTION_SCHEMA:
        raise ReleaseBrokerProtocolError(
            "owner assertion payload schema is unsupported"
        )
    if payload.get("purpose") != "release_merge":
        raise ReleaseBrokerProtocolError(
            "owner assertion purpose is invalid"
        )
    issuer = str(payload.get("issuer") or "")
    actor_id = str(payload.get("actor_id") or "")
    if not TOKEN_RE.fullmatch(issuer) or not TOKEN_RE.fullmatch(actor_id):
        raise ReleaseBrokerProtocolError(
            "owner assertion issuer or actor ID is invalid"
        )
    actor_login = str(payload.get("actor_login") or "")
    if not LOGIN_RE.fullmatch(actor_login):
        raise ReleaseBrokerProtocolError(
            "owner assertion actor login is invalid"
        )
    if payload.get("tier") != "owner":
        raise ReleaseBrokerProtocolError(
            "owner assertion tier must be owner"
        )
    issued = _parse_utc(
        payload.get("issued_at"), field="owner assertion issued_at"
    )
    expires = _parse_utc(
        payload.get("expires_at"), field="owner assertion expires_at"
    )
    ttl = int((expires - issued).total_seconds())
    if ttl < 1 or ttl > maximum_ttl_seconds:
        raise ReleaseBrokerProtocolError(
            "owner assertion lifetime is invalid"
        )
    current = _current_utc(now)
    if issued > current + timedelta(seconds=maximum_clock_skew_seconds):
        raise ReleaseBrokerProtocolError(
            "owner assertion was issued in the future"
        )
    if not allow_expired and current >= expires:
        raise ReleaseBrokerProtocolError("owner assertion has expired")
    nonce = str(payload.get("nonce") or "")
    if not NONCE_RE.fullmatch(nonce):
        raise ReleaseBrokerProtocolError(
            "owner assertion nonce must contain 256 random bits"
        )
    instance_slug = str(payload.get("instance_slug") or "")
    if not INSTANCE_SLUG_RE.fullmatch(instance_slug):
        raise ReleaseBrokerProtocolError(
            "owner assertion instance slug is invalid"
        )
    repository_id = _positive_int(
        payload.get("repository_id"),
        field="owner assertion repository ID",
    )
    repository_full_name = str(
        payload.get("repository_full_name") or ""
    )
    if not REPOSITORY_RE.fullmatch(repository_full_name):
        raise ReleaseBrokerProtocolError(
            "owner assertion repository name is invalid"
        )
    bundle_id = str(payload.get("bundle_id") or "")
    if not BUNDLE_ID_RE.fullmatch(bundle_id):
        raise ReleaseBrokerProtocolError(
            "owner assertion bundle ID is invalid"
        )
    bundle_digest = _digest(
        payload.get("bundle_digest"),
        field="owner assertion bundle digest",
    )
    approval_digest = _digest(
        payload.get("approval_text_sha256"),
        field="owner assertion approval text digest",
    )
    if payload.get("action") != RELEASE_ACTION:
        raise ReleaseBrokerProtocolError(
            "owner assertion action is unsupported"
        )
    if payload.get("merge_method") != MERGE_METHOD:
        raise ReleaseBrokerProtocolError(
            "owner assertion merge method must be squash"
        )
    if payload.get("publish") is not False:
        raise ReleaseBrokerProtocolError(
            "owner assertion may not authorize publishing"
        )
    ordered_digest = _digest(
        payload.get("ordered_prs_digest"),
        field="owner assertion ordered PR digest",
    )
    paths_digest = _digest(
        payload.get("changed_paths_digest"),
        field="owner assertion changed paths digest",
    )
    risk_class = str(payload.get("risk_class") or "")
    if risk_class not in RISK_RANK:
        raise ReleaseBrokerProtocolError(
            "owner assertion risk class is invalid"
        )
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
        "repository_id": repository_id,
        "repository_full_name": repository_full_name,
        "bundle_id": bundle_id,
        "bundle_digest": bundle_digest,
        "approval_text_sha256": approval_digest,
        "action": RELEASE_ACTION,
        "merge_method": MERGE_METHOD,
        "publish": False,
        "ordered_prs_digest": ordered_digest,
        "changed_paths_digest": paths_digest,
        "risk_class": risk_class,
    }
    return {
        "schema_version": SIGNED_ENVELOPE_SCHEMA,
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "payload": normalized_payload,
        "signature": signature,
    }


def verify_owner_assertion_signature(
    raw: Any,
    *,
    public_key: bytes,
    expected_public_key_sha256: str | None = None,
    expected_key_id: str | None = None,
    expected_issuer: str | None = None,
    allowed_actor_ids: set[str] | frozenset[str] | None = None,
    now: datetime | None = None,
    allow_expired: bool = False,
    maximum_ttl_seconds: int = MAX_ASSERTION_TTL_SECONDS,
    maximum_clock_skew_seconds: int = MAX_CLOCK_SKEW_SECONDS,
) -> dict[str, Any]:
    envelope = normalize_owner_assertion_envelope(
        raw,
        now=now,
        allow_expired=allow_expired,
        maximum_ttl_seconds=maximum_ttl_seconds,
        maximum_clock_skew_seconds=maximum_clock_skew_seconds,
    )
    if not isinstance(public_key, bytes) or not public_key:
        raise ReleaseBrokerProtocolError(
            "owner assertion public key is missing"
        )
    fingerprint = sha256_bytes(public_key)
    if (
        expected_public_key_sha256 is not None
        and fingerprint != expected_public_key_sha256
    ):
        raise ReleaseBrokerProtocolError(
            "owner assertion public key fingerprint does not match"
        )
    if expected_key_id is not None and envelope["key_id"] != expected_key_id:
        raise ReleaseBrokerProtocolError(
            "owner assertion key ID does not match"
        )
    payload = envelope["payload"]
    if expected_issuer is not None and payload["issuer"] != expected_issuer:
        raise ReleaseBrokerProtocolError(
            "owner assertion issuer does not match"
        )
    if (
        allowed_actor_ids is not None
        and payload["actor_id"] not in allowed_actor_ids
    ):
        raise ReleaseBrokerProtocolError(
            "owner assertion actor is not authorized"
        )
    try:
        loaded_key = serialization.load_pem_public_key(public_key)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ReleaseBrokerProtocolError(
            "owner assertion public key is invalid"
        ) from exc
    if not isinstance(loaded_key, Ed25519PublicKey):
        raise ReleaseBrokerProtocolError(
            "owner assertion public key is not Ed25519"
        )
    signature = base64.urlsafe_b64decode(envelope["signature"] + "==")
    try:
        loaded_key.verify(signature, canonical_json(payload))
    except InvalidSignature as exc:
        raise ReleaseBrokerProtocolError(
            "owner assertion signature is invalid"
        ) from exc
    return envelope


def verify_configured_owner_assertion(
    raw: Any,
    config: Any,
    *,
    now: datetime | None = None,
    allow_expired: bool = False,
    key_owner_uids: int | Iterable[int] | None = None,
    parent_owner_uids: int | Iterable[int] | None = None,
    trusted_path_root: Path | None = None,
) -> dict[str, Any]:
    normalized_config = normalize_config(config)
    owner = normalized_config["owner_assertion"]
    public_key = read_trusted_file(
        Path(owner["public_key_path"]),
        field="release owner assertion public key",
        maximum_bytes=MAX_KEY_BYTES,
        expected_owner_uids=key_owner_uids,
        parent_owner_uids=parent_owner_uids,
        trusted_path_root=trusted_path_root,
    )
    return verify_owner_assertion_signature(
        raw,
        public_key=public_key,
        expected_public_key_sha256=owner["public_key_sha256"],
        expected_key_id=owner["key_id"],
        expected_issuer=owner["issuer"],
        allowed_actor_ids=set(owner["allowed_actor_ids"]),
        now=now,
        allow_expired=allow_expired,
        maximum_ttl_seconds=owner["maximum_ttl_seconds"],
        maximum_clock_skew_seconds=owner[
            "maximum_clock_skew_seconds"
        ],
    )


def owner_assertion_digest(envelope: dict[str, Any]) -> str:
    return sha256_json(envelope)


def _normalize_approval(raw: Any) -> dict[str, str]:
    approval = _mapping(raw, field="release approval")
    _strict_keys(
        approval,
        field="release approval",
        required={"text", "text_sha256"},
    )
    text = _safe_text(
        approval.get("text"),
        field="release approval text",
        maximum_bytes=MAX_APPROVAL_TEXT_BYTES,
        allow_space=True,
    )
    expected = sha256_text(text)
    if approval.get("text_sha256") != expected:
        raise ReleaseBrokerProtocolError(
            "release approval text digest does not match"
        )
    return {"text": text, "text_sha256": expected}


def normalize_release_packet(
    raw: Any,
    *,
    now: datetime | None = None,
    allow_expired: bool = False,
    allow_expired_assertion: bool = False,
) -> dict[str, Any]:
    packet = _mapping(raw, field="release merge packet")
    _strict_keys(
        packet,
        field="release merge packet",
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
        raise ReleaseBrokerProtocolError(
            "release packet schema is unsupported"
        )
    if packet.get("authority") != PACKET_AUTHORITY:
        raise ReleaseBrokerProtocolError(
            "release packet authority is invalid"
        )
    requested_by = _mapping(
        packet.get("requested_by"), field="release packet requester"
    )
    _strict_keys(
        requested_by,
        field="release packet requester",
        required={"component", "instance_slug"},
    )
    if requested_by.get("component") != REQUEST_COMPONENT:
        raise ReleaseBrokerProtocolError(
            "release packet requester component is invalid"
        )
    requester_instance = str(requested_by.get("instance_slug") or "")
    if not INSTANCE_SLUG_RE.fullmatch(requester_instance):
        raise ReleaseBrokerProtocolError(
            "release packet requester instance is invalid"
        )
    created = _parse_utc(
        packet.get("created_at"), field="release packet created_at"
    )
    expires = _parse_utc(
        packet.get("expires_at"), field="release packet expires_at"
    )
    ttl = int((expires - created).total_seconds())
    if ttl < MIN_PACKET_TTL_SECONDS or ttl > MAX_PACKET_TTL_SECONDS:
        raise ReleaseBrokerProtocolError(
            "release packet lifetime is invalid"
        )
    current = _current_utc(now)
    if created > current + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        raise ReleaseBrokerProtocolError(
            "release packet creation time is in the future"
        )
    if not allow_expired and current >= expires:
        raise ReleaseBrokerProtocolError("release packet has expired")

    request = _mapping(
        packet.get("request"), field="release packet request"
    )
    _strict_keys(
        request,
        field="release packet request",
        required={
            "action",
            "bundle",
            "approval",
            "owner_assertion",
            "train_attestation",
        },
    )
    if request.get("action") != RELEASE_ACTION:
        raise ReleaseBrokerProtocolError(
            "release packet action is unsupported"
        )
    bundle = normalize_release_bundle(request.get("bundle"))
    approval = _normalize_approval(request.get("approval"))
    assertion = normalize_owner_assertion_envelope(
        request.get("owner_assertion"),
        now=now,
        allow_expired=allow_expired_assertion,
    )
    train_attestation = request.get("train_attestation")
    if train_attestation is not None:
        raise ReleaseBrokerProtocolError(
            "release train attestations are not implemented"
        )
    if len(bundle["ordered_prs"]) != 1:
        raise ReleaseBrokerProtocolError(
            "live release v1 accepts exactly one PR per bundle"
        )
    if bundle["train_attestation_digest"] is not None:
        raise ReleaseBrokerProtocolError(
            "single-PR release bundle may not carry a train attestation"
        )
    if requester_instance != bundle["instance_slug"]:
        raise ReleaseBrokerProtocolError(
            "release packet requester instance does not match the bundle"
        )
    payload = assertion["payload"]
    bindings = {
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
    for field, expected in bindings.items():
        if payload.get(field) != expected:
            raise ReleaseBrokerProtocolError(
                f"owner assertion {field} does not match the request"
            )
    if created < _parse_utc(
        bundle["created_at"], field="release bundle created_at"
    ):
        raise ReleaseBrokerProtocolError(
            "release packet predates its bundle"
        )
    if expires > _parse_utc(
        bundle["expires_at"], field="release bundle expires_at"
    ):
        raise ReleaseBrokerProtocolError(
            "release packet outlives its bundle"
        )
    normalized_request = {
        "action": RELEASE_ACTION,
        "bundle": bundle,
        "approval": approval,
        "owner_assertion": assertion,
        "train_attestation": None,
    }
    normalized_body = {
        "schema_version": PACKET_SCHEMA,
        "created_at": utc_text(created),
        "expires_at": utc_text(expires),
        "authority": PACKET_AUTHORITY,
        "requested_by": {
            "component": REQUEST_COMPONENT,
            "instance_slug": requester_instance,
        },
        "request": normalized_request,
    }
    expected_request_digest = sha256_json(normalized_request)
    expected_packet_id = (
        "jlrp-"
        + sha256_json(normalized_body).removeprefix("sha256:")[:24]
    )
    if packet.get("request_digest") != expected_request_digest:
        raise ReleaseBrokerProtocolError(
            "release packet request digest does not match"
        )
    if packet.get("packet_id") != expected_packet_id:
        raise ReleaseBrokerProtocolError(
            "release packet ID does not match"
        )
    return {
        **normalized_body,
        "packet_id": expected_packet_id,
        "request_digest": expected_request_digest,
    }


def normalize_submission(
    raw: Any,
    *,
    now: datetime | None = None,
    allow_expired: bool = False,
    allow_expired_assertion: bool = False,
) -> dict[str, Any]:
    submission = _mapping(raw, field="release broker submission")
    _strict_keys(
        submission,
        field="release broker submission",
        required={"schema_version", "packet"},
    )
    if submission.get("schema_version") != SUBMISSION_SCHEMA:
        raise ReleaseBrokerProtocolError(
            "release broker submission schema is unsupported"
        )
    return {
        "schema_version": SUBMISSION_SCHEMA,
        "packet": normalize_release_packet(
            submission.get("packet"),
            now=now,
            allow_expired=allow_expired,
            allow_expired_assertion=allow_expired_assertion,
        ),
    }


def normalize_configured_submission(
    raw: Any,
    config: Any,
    *,
    now: datetime | None = None,
    allow_expired: bool = False,
    allow_expired_assertion: bool = False,
    key_owner_uids: int | Iterable[int] | None = None,
    parent_owner_uids: int | Iterable[int] | None = None,
    trusted_path_root: Path | None = None,
) -> dict[str, Any]:
    """Validate a submission against all immutable local policy bindings."""

    normalized_config = normalize_config(config)
    if not normalized_config["enabled"]:
        raise ReleaseBrokerProtocolError(
            "protected release broker is disabled"
        )
    submission = normalize_submission(
        raw,
        now=now,
        allow_expired=allow_expired,
        allow_expired_assertion=allow_expired_assertion,
    )
    packet = submission["packet"]
    instance = normalized_config["instance"]
    repository = instance["repository"]
    validate_packet_binding(
        packet,
        instance_slug=instance["slug"],
        repository_id=repository["id"],
        repository_full_name=repository["full_name"],
        default_branch=repository["default_branch"],
    )
    policy = instance["policy"]
    bundle = packet["request"]["bundle"]
    bundle_ttl = int(
        (
            _parse_utc(
                bundle["expires_at"], field="release bundle expires_at"
            )
            - _parse_utc(
                bundle["created_at"], field="release bundle created_at"
            )
        ).total_seconds()
    )
    if bundle_ttl > policy["maximum_bundle_ttl_seconds"]:
        raise ReleaseBrokerProtocolError(
            "release bundle exceeds configured TTL"
        )
    packet_ttl = int(
        (
            _parse_utc(
                packet["expires_at"], field="release packet expires_at"
            )
            - _parse_utc(
                packet["created_at"], field="release packet created_at"
            )
        ).total_seconds()
    )
    if packet_ttl > policy["maximum_packet_ttl_seconds"]:
        raise ReleaseBrokerProtocolError(
            "release packet exceeds configured TTL"
        )
    total_changed = 0
    forbidden = policy["forbidden_path_prefixes"]
    for pr in bundle["ordered_prs"]:
        if pr["author_login"] not in policy["expected_pr_author_logins"]:
            raise ReleaseBrokerProtocolError(
                "release PR author is not configured"
            )
        if (
            pr["changed_path_count"]
            > policy["maximum_changed_files_per_pr"]
        ):
            raise ReleaseBrokerProtocolError(
                "release PR exceeds configured changed-file limit"
            )
        total_changed += pr["changed_path_count"]
        for path in pr["changed_paths"]:
            if any(
                path == prefix or path.startswith(prefix + "/")
                for prefix in forbidden
            ):
                raise ReleaseBrokerProtocolError(
                    "release PR touches a forbidden path"
                )
    if total_changed > policy["maximum_total_changed_files"]:
        raise ReleaseBrokerProtocolError(
            "release bundle exceeds configured changed-file limit"
        )
    verified_assertion = verify_configured_owner_assertion(
        packet["request"]["owner_assertion"],
        normalized_config,
        now=now,
        allow_expired=allow_expired_assertion,
        key_owner_uids=key_owner_uids,
        parent_owner_uids=parent_owner_uids,
        trusted_path_root=trusted_path_root,
    )
    return {
        "schema_version": SUBMISSION_SCHEMA,
        "packet": packet,
        "owner_assertion": verified_assertion,
        "config_digest": config_digest(normalized_config),
    }


def validate_packet_binding(
    packet: dict[str, Any],
    *,
    instance_slug: str,
    repository_id: int,
    repository_full_name: str,
    default_branch: str,
) -> dict[str, Any]:
    """Bind a normalized packet to immutable root-owned configuration."""

    bundle = packet["request"]["bundle"]
    repository = bundle["repository"]
    if bundle["instance_slug"] != instance_slug:
        raise ReleaseBrokerProtocolError(
            "release packet instance does not match broker configuration"
        )
    if repository["id"] != repository_id:
        raise ReleaseBrokerProtocolError(
            "release packet repository ID does not match configuration"
        )
    if repository["full_name"] != repository_full_name:
        raise ReleaseBrokerProtocolError(
            "release packet repository name does not match configuration"
        )
    if repository["default_branch"] != default_branch:
        raise ReleaseBrokerProtocolError(
            "release packet default branch does not match configuration"
        )
    return packet
