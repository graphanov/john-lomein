#!/usr/bin/env python3
"""Submit exactly one protected release packet and verify its signed receipt.

This client has no GitHub credential and no release-broker private material.
It reads a root-pinned public client configuration, independently validates
the complete release packet before transmission, authenticates the Unix
socket peer with kernel credentials, and accepts only a release receipt whose
Ed25519 signature and complete packet/config bindings verify.

There is deliberately no retry loop.  Once any request byte may have reached
the broker, a transport or verification failure is reported as ambiguous.
Operators may then use offline receipt verification or submit the *exact*
packet again; the broker's durable idempotency boundary owns terminal replay.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import socket
import stat
import struct
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from john_lomein_autonomy import (
    AutonomyError,
    anchored_runtime_home,
    deployed_runtime_control,
    require_effective_protected_release,
)
from release_broker import john_lomein_release_broker_protocol as protocol
from release_broker import john_lomein_release_broker_receipts as receipts


CLIENT_CONFIG_SCHEMA = (
    "john-lomein.protected-release-broker-client-config.v1"
)
RESPONSE_SCHEMA = "john-lomein.protected-release-broker-response.v1"
DEFAULT_CONFIG_ROOT = Path(
    "/private/etc/john-lomein-release-broker-public"
)
RECEIPT_LOCATOR_ROOT = Path("state/protected-releases/receipts")

MAX_CONFIG_BYTES = 64 * 1024
MAX_KEY_BYTES = 64 * 1024
MAX_PACKET_BYTES = protocol.MAX_PACKET_BYTES
MAX_RESPONSE_BYTES = receipts.MAX_RECEIPT_BYTES + 64 * 1024
MAX_SOCKET_PATH_BYTES = protocol.MAX_SOCKET_PATH_BYTES
FRAME_HEADER_BYTES = 4

EXIT_BLOCKED = 2
EXIT_REJECTED = 3
EXIT_PARTIAL = 4
EXIT_INDETERMINATE = 5
EXIT_AMBIGUOUS = 6

TOKEN_RE = protocol.TOKEN_RE
KEY_ID_RE = protocol.KEY_ID_RE
SHA256_RE = protocol.SHA256_RE
INSTANCE_SLUG_RE = protocol.INSTANCE_SLUG_RE
REPOSITORY_RE = protocol.REPOSITORY_RE
BRANCH_RE = protocol.BRANCH_RE
APP_SLUG_RE = receipts.APP_SLUG_RE

DAEMON_ERROR_CODES = frozenset(
    {"request_rejected", "transport_rejected", "broker_failure"}
)


class ReleaseSubmitError(ValueError):
    """A public-safe, fail-closed release client error."""


class ReleaseSubmitAmbiguousError(ReleaseSubmitError):
    """The broker may have received the request; automatic retry is unsafe."""


@dataclass(frozen=True)
class LoadedClientConfig:
    value: dict[str, Any]
    receipt_public_key: bytes


@dataclass(frozen=True)
class VerifiedReceipt:
    envelope: dict[str, Any]
    locator: str


def canonical_json(value: Any) -> bytes:
    try:
        return protocol.canonical_json(value)
    except protocol.ReleaseBrokerProtocolError as exc:
        raise ReleaseSubmitError(str(exc)) from exc


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseSubmitError(
                "JSON object contains duplicate fields"
            )
        result[key] = value
    return result


def _reject_float(_: str) -> None:
    raise ReleaseSubmitError("JSON floats are forbidden")


def _reject_nonfinite(_: str) -> None:
    raise ReleaseSubmitError("JSON non-finite numbers are forbidden")


def parse_json_bytes(
    raw: bytes,
    *,
    field: str,
    maximum_bytes: int,
) -> Any:
    if not isinstance(raw, bytes) or len(raw) > maximum_bytes:
        raise ReleaseSubmitError(f"{field} exceeds its size limit")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_nonfinite,
        )
        # This also rejects non-NFC strings and unsafe integer ranges.
        protocol.canonical_json(value)
        return value
    except ReleaseSubmitError:
        raise
    except protocol.ReleaseBrokerProtocolError as exc:
        raise ReleaseSubmitError(str(exc)) from exc
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseSubmitError(f"{field} is invalid JSON") from exc


def _mapping(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseSubmitError(f"{field} must be an object")
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
        raise ReleaseSubmitError(f"{field} contains unknown fields")
    if missing:
        raise ReleaseSubmitError(f"{field} is missing required fields")


def _positive_int(
    value: Any,
    *,
    field: str,
    maximum: int = protocol.MAX_SAFE_JSON_INTEGER,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReleaseSubmitError(f"{field} must be an integer")
    if value <= 0 or value > maximum:
        raise ReleaseSubmitError(f"{field} is outside the allowed range")
    return value


def _uid(value: Any, *, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 2**31 - 1
    ):
        raise ReleaseSubmitError(f"{field} is invalid")
    return value


def _gid(value: Any, *, field: str) -> int:
    return _uid(value, field=field)


def _uid_set(
    values: int | Iterable[int] | None,
    *,
    default: Iterable[int],
) -> frozenset[int]:
    if values is None:
        values = default
    elif isinstance(values, int) and not isinstance(values, bool):
        values = (values,)
    result: set[int] = set()
    try:
        for value in values:
            result.add(_uid(value, field="trusted owner UID"))
    except TypeError as exc:
        raise ReleaseSubmitError(
            "trusted owner UID set is invalid"
        ) from exc
    if not result:
        raise ReleaseSubmitError("trusted owner UID set is empty")
    return frozenset(result)


def _absolute_path(value: Any, *, field: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ReleaseSubmitError(f"{field} must be an absolute path")
    path = Path(value)
    if (
        not path.is_absolute()
        or str(path) != value
        or "." in path.parts
        or ".." in path.parts
    ):
        raise ReleaseSubmitError(f"{field} must be normalized")
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
    owners = _uid_set(expected_owner_uids, default=(0,))
    checked = _absolute_path(str(path), field=field)
    stop: Path | None = None
    if trusted_path_root is not None:
        stop = _absolute_path(
            str(trusted_path_root), field="trusted path root"
        )
        if not _path_within(checked, stop):
            raise ReleaseSubmitError(
                f"{field} is outside the trusted path root"
            )
    current = checked
    while True:
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise ReleaseSubmitError(
                f"{field} parent directory is unreadable"
            ) from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ReleaseSubmitError(
                f"{field} parent directory is unsafe"
            )
        if info.st_uid not in owners or info.st_mode & 0o022:
            raise ReleaseSubmitError(
                f"{field} parent directory is untrusted"
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
    expected_owner_uids: int | Iterable[int] | None,
    private_mode: bool,
    parent_owner_uids: int | Iterable[int] | None = None,
    trusted_path_root: Path | None = None,
) -> bytes:
    normalized = _absolute_path(str(path), field=field)
    validate_trusted_parent_chain(
        normalized.parent,
        field=field,
        expected_owner_uids=parent_owner_uids,
        trusted_path_root=trusted_path_root,
    )
    owners = _uid_set(expected_owner_uids, default=(0,))
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(normalized, flags)
    except OSError as exc:
        raise ReleaseSubmitError(f"{field} is unreadable") from exc
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in owners
            or before.st_size > maximum_bytes
            or mode & 0o022
            or (private_mode and mode & 0o077)
        ):
            raise ReleaseSubmitError(f"{field} is unsafe")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, maximum_bytes + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise ReleaseSubmitError(
                    f"{field} exceeds its size limit"
                )
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(
            getattr(before, name) != getattr(after, name)
            for name in stable_fields
        ) or total != before.st_size:
            raise ReleaseSubmitError(f"{field} changed while being read")
        return b"".join(chunks)
    except OSError as exc:
        raise ReleaseSubmitError(f"{field} is unreadable") from exc
    finally:
        os.close(descriptor)


def load_packet(
    path: Path,
    *,
    now: datetime | None = None,
    allow_expired: bool = False,
    packet_owner_uids: int | Iterable[int] | None = None,
    parent_owner_uids: int | Iterable[int] | None = None,
    trusted_path_root: Path | None = None,
) -> dict[str, Any]:
    owners = (
        packet_owner_uids
        if packet_owner_uids is not None
        else {0, os.getuid()}
    )
    parent_owners = (
        parent_owner_uids
        if parent_owner_uids is not None
        else {0, os.getuid()}
    )
    raw = read_stable_file(
        path,
        field="release packet",
        maximum_bytes=MAX_PACKET_BYTES,
        expected_owner_uids=owners,
        private_mode=True,
        parent_owner_uids=parent_owners,
        trusted_path_root=trusted_path_root,
    )
    value = parse_json_bytes(
        raw,
        field="release packet",
        maximum_bytes=MAX_PACKET_BYTES,
    )
    try:
        return protocol.normalize_release_packet(
            value,
            now=now,
            allow_expired=allow_expired,
            allow_expired_assertion=allow_expired,
        )
    except protocol.ReleaseBrokerProtocolError as exc:
        raise ReleaseSubmitError(str(exc)) from exc


def default_client_config_path(packet: Mapping[str, Any]) -> Path:
    requested_by = _mapping(
        packet.get("requested_by"), field="release packet requester"
    )
    slug = str(requested_by.get("instance_slug") or "")
    if not INSTANCE_SLUG_RE.fullmatch(slug):
        raise ReleaseSubmitError("release packet instance is invalid")
    return DEFAULT_CONFIG_ROOT / f"{slug}.json"


def normalize_client_config(raw: Any) -> dict[str, Any]:
    config = _mapping(raw, field="release broker client config")
    _strict_keys(
        config,
        field="release broker client config",
        required={
            "schema_version",
            "broker_id",
            "broker_uid",
            "requester_uid",
            "submit_gid",
            "broker_config_sha256",
            "socket_path",
            "receipt_public_key_path",
            "receipt_public_key_sha256",
            "receipt_key_id",
            "connect_timeout_seconds",
            "request_timeout_seconds",
            "max_response_bytes",
            "instance_slug",
            "repository",
            "github_app",
        },
    )
    if config.get("schema_version") != CLIENT_CONFIG_SCHEMA:
        raise ReleaseSubmitError(
            "release broker client config schema is unsupported"
        )
    broker_id = str(config.get("broker_id") or "")
    if not TOKEN_RE.fullmatch(broker_id):
        raise ReleaseSubmitError("release broker ID is invalid")
    broker_uid = _uid(
        config.get("broker_uid"), field="release broker UID"
    )
    requester_uid = _uid(
        config.get("requester_uid"), field="release requester UID"
    )
    if broker_uid == requester_uid:
        raise ReleaseSubmitError(
            "release broker must use a separate OS identity"
        )
    submit_gid = _gid(
        config.get("submit_gid"), field="release submit GID"
    )
    config_digest = str(config.get("broker_config_sha256") or "")
    if not SHA256_RE.fullmatch(config_digest):
        raise ReleaseSubmitError(
            "release broker config digest is invalid"
        )
    socket_path = _absolute_path(
        config.get("socket_path"), field="release broker socket path"
    )
    try:
        socket_bytes = os.fsencode(socket_path)
    except UnicodeError as exc:
        raise ReleaseSubmitError(
            "release broker socket path is invalid"
        ) from exc
    if (
        not socket_bytes
        or len(socket_bytes) > MAX_SOCKET_PATH_BYTES
        or b"\x00" in socket_bytes
    ):
        raise ReleaseSubmitError(
            "release broker socket path is outside policy"
        )
    public_key_path = _absolute_path(
        config.get("receipt_public_key_path"),
        field="release receipt public key path",
    )
    if public_key_path == socket_path:
        raise ReleaseSubmitError(
            "release socket and receipt key paths must differ"
        )
    public_key_digest = str(
        config.get("receipt_public_key_sha256") or ""
    )
    if not SHA256_RE.fullmatch(public_key_digest):
        raise ReleaseSubmitError(
            "release receipt key fingerprint is invalid"
        )
    receipt_key_id = str(config.get("receipt_key_id") or "")
    if not KEY_ID_RE.fullmatch(receipt_key_id):
        raise ReleaseSubmitError("release receipt key ID is invalid")
    connect_timeout = _positive_int(
        config.get("connect_timeout_seconds"),
        field="release broker connect timeout",
        maximum=30,
    )
    request_timeout = _positive_int(
        config.get("request_timeout_seconds"),
        field="release broker request timeout",
        maximum=3600,
    )
    max_response = _positive_int(
        config.get("max_response_bytes"),
        field="release broker maximum response size",
        maximum=MAX_RESPONSE_BYTES,
    )
    if max_response < 4096:
        raise ReleaseSubmitError(
            "release broker maximum response size is too small"
        )
    instance_slug = str(config.get("instance_slug") or "")
    if not INSTANCE_SLUG_RE.fullmatch(instance_slug):
        raise ReleaseSubmitError("release broker instance is invalid")

    repository = _mapping(
        config.get("repository"), field="release broker repository"
    )
    _strict_keys(
        repository,
        field="release broker repository",
        required={"id", "full_name", "default_branch"},
    )
    repository_id = _positive_int(
        repository.get("id"), field="release repository ID"
    )
    repository_name = str(repository.get("full_name") or "")
    default_branch = str(repository.get("default_branch") or "")
    if not REPOSITORY_RE.fullmatch(repository_name):
        raise ReleaseSubmitError("release repository name is invalid")
    if not BRANCH_RE.fullmatch(default_branch):
        raise ReleaseSubmitError(
            "release repository default branch is invalid"
        )

    app = _mapping(
        config.get("github_app"), field="release broker GitHub App"
    )
    _strict_keys(
        app,
        field="release broker GitHub App",
        required={"app_id", "app_slug", "installation_id"},
    )
    app_id = _positive_int(
        app.get("app_id"), field="release GitHub App ID"
    )
    app_slug = str(app.get("app_slug") or "")
    if not APP_SLUG_RE.fullmatch(app_slug):
        raise ReleaseSubmitError("release GitHub App slug is invalid")
    installation_id = _positive_int(
        app.get("installation_id"),
        field="release GitHub installation ID",
    )
    return {
        "schema_version": CLIENT_CONFIG_SCHEMA,
        "broker_id": broker_id,
        "broker_uid": broker_uid,
        "requester_uid": requester_uid,
        "submit_gid": submit_gid,
        "broker_config_sha256": config_digest,
        "socket_path": str(socket_path),
        "receipt_public_key_path": str(public_key_path),
        "receipt_public_key_sha256": public_key_digest,
        "receipt_key_id": receipt_key_id,
        "connect_timeout_seconds": connect_timeout,
        "request_timeout_seconds": request_timeout,
        "max_response_bytes": max_response,
        "instance_slug": instance_slug,
        "repository": {
            "id": repository_id,
            "full_name": repository_name,
            "default_branch": default_branch,
        },
        "github_app": {
            "app_id": app_id,
            "app_slug": app_slug,
            "installation_id": installation_id,
        },
    }


def load_client_config(
    path: Path,
    *,
    config_owner_uids: int | Iterable[int] | None = None,
    key_owner_uids: int | Iterable[int] | None = None,
    parent_owner_uids: int | Iterable[int] | None = None,
    trusted_path_root: Path | None = None,
    requester_uid: int | None = None,
    requester_groups: Iterable[int] | None = None,
) -> LoadedClientConfig:
    config_owners = _uid_set(config_owner_uids, default=(0,))
    key_owners = _uid_set(key_owner_uids, default=(0,))
    parent_owners = _uid_set(parent_owner_uids, default=(0,))
    raw = read_stable_file(
        path,
        field="release broker client config",
        maximum_bytes=MAX_CONFIG_BYTES,
        expected_owner_uids=config_owners,
        private_mode=False,
        parent_owner_uids=parent_owners,
        trusted_path_root=trusted_path_root,
    )
    config = normalize_client_config(
        parse_json_bytes(
            raw,
            field="release broker client config",
            maximum_bytes=MAX_CONFIG_BYTES,
        )
    )
    actual_uid = (
        os.getuid()
        if requester_uid is None
        else _uid(requester_uid, field="release requester UID")
    )
    if actual_uid != config["requester_uid"]:
        raise ReleaseSubmitError(
            "release client is running under the wrong OS identity"
        )
    groups = (
        {os.getgid(), *os.getgroups()}
        if requester_groups is None
        else {
            _gid(value, field="release requester group")
            for value in requester_groups
        }
    )
    if config["submit_gid"] not in groups:
        raise ReleaseSubmitError(
            "release client is not in the configured submit group"
        )
    key_path = Path(config["receipt_public_key_path"])
    if trusted_path_root is not None and not _path_within(
        key_path, trusted_path_root
    ):
        raise ReleaseSubmitError(
            "release receipt public key is outside the trusted path root"
        )
    public_key = read_stable_file(
        key_path,
        field="release receipt public key",
        maximum_bytes=MAX_KEY_BYTES,
        expected_owner_uids=key_owners,
        private_mode=False,
        parent_owner_uids=parent_owners,
        trusted_path_root=trusted_path_root,
    )
    if b"PUBLIC KEY" not in public_key or b"PRIVATE KEY" in public_key:
        raise ReleaseSubmitError(
            "release receipt verification key is not public"
        )
    actual_fingerprint = protocol.sha256_bytes(public_key)
    if actual_fingerprint != config["receipt_public_key_sha256"]:
        raise ReleaseSubmitError(
            "release receipt public-key fingerprint does not match"
        )
    return LoadedClientConfig(
        value=config, receipt_public_key=public_key
    )


def validate_packet_config_binding(
    packet: Mapping[str, Any],
    config: Mapping[str, Any],
) -> None:
    bundle = _mapping(
        _mapping(packet.get("request"), field="release packet request").get(
            "bundle"
        ),
        field="release bundle",
    )
    repository = _mapping(
        bundle.get("repository"), field="release bundle repository"
    )
    if bundle.get("instance_slug") != config["instance_slug"]:
        raise ReleaseSubmitError(
            "release packet instance does not match client config"
        )
    if repository != config["repository"]:
        raise ReleaseSubmitError(
            "release packet repository does not match client config"
        )


def _validate_socket_file(config: Mapping[str, Any]) -> None:
    path = Path(config["socket_path"])
    validate_trusted_parent_chain(
        path.parent,
        field="release broker socket",
        expected_owner_uids={0, int(config["broker_uid"])},
    )
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise ReleaseSubmitError(
            "release broker socket is unavailable"
        ) from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != config["broker_uid"]
        or info.st_gid != config["submit_gid"]
        or stat.S_IMODE(info.st_mode) != 0o660
    ):
        raise ReleaseSubmitError("release broker socket is unsafe")


def _peer_uid(client: socket.socket) -> int:
    getpeereid = getattr(client, "getpeereid", None)
    if callable(getpeereid):
        try:
            uid, _ = getpeereid()
        except OSError as exc:
            raise ReleaseSubmitError(
                "release broker peer identity is unavailable"
            ) from exc
        return _uid(uid, field="release broker peer UID")

    peercred = getattr(socket, "SO_PEERCRED", None)
    if peercred is not None:
        try:
            raw = client.getsockopt(socket.SOL_SOCKET, peercred, 12)
            _, uid, _ = struct.unpack("=3i", raw)
        except (OSError, struct.error) as exc:
            raise ReleaseSubmitError(
                "release broker peer identity is unavailable"
            ) from exc
        return _uid(uid, field="release broker peer UID")

    local_peercred = getattr(socket, "LOCAL_PEERCRED", None)
    sol_local = getattr(socket, "SOL_LOCAL", 0)
    if local_peercred is not None:
        try:
            raw = client.getsockopt(sol_local, local_peercred, 256)
            if len(raw) < 10:
                raise struct.error("short xucred")
            _, uid, _ = struct.unpack_from("@IIh", raw)
        except (OSError, struct.error) as exc:
            raise ReleaseSubmitError(
                "release broker peer identity is unavailable"
            ) from exc
        return _uid(uid, field="release broker peer UID")
    raise ReleaseSubmitError(
        "release broker peer credentials are unsupported"
    )


def _read_exact(
    client: socket.socket,
    count: int,
    *,
    ambiguous: bool,
) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        try:
            chunk = client.recv(remaining)
        except socket.timeout as exc:
            error = (
                ReleaseSubmitAmbiguousError
                if ambiguous
                else ReleaseSubmitError
            )
            raise error("release broker response timed out") from exc
        except OSError as exc:
            error = (
                ReleaseSubmitAmbiguousError
                if ambiguous
                else ReleaseSubmitError
            )
            raise error("release broker response read failed") from exc
        if not chunk:
            error = (
                ReleaseSubmitAmbiguousError
                if ambiguous
                else ReleaseSubmitError
            )
            raise error(
                "release broker response ended prematurely"
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def normalize_response(raw: Any) -> dict[str, Any]:
    response = _mapping(raw, field="release broker response")
    if response.get("ok") is True:
        _strict_keys(
            response,
            field="release broker response",
            required={"schema_version", "ok", "receipt"},
        )
        if response.get("schema_version") != RESPONSE_SCHEMA:
            raise ReleaseSubmitError(
                "release broker response schema is unsupported"
            )
        try:
            normalized_receipt = receipts.normalize_receipt_envelope(
                response.get("receipt")
            )
        except protocol.ReleaseBrokerProtocolError as exc:
            raise ReleaseSubmitError(str(exc)) from exc
        return {
            "schema_version": RESPONSE_SCHEMA,
            "ok": True,
            "receipt": normalized_receipt,
        }
    _strict_keys(
        response,
        field="release broker response",
        required={"schema_version", "ok", "error"},
    )
    if (
        response.get("schema_version") != RESPONSE_SCHEMA
        or response.get("ok") is not False
    ):
        raise ReleaseSubmitError(
            "release broker response status is invalid"
        )
    error = _mapping(
        response.get("error"), field="release broker response error"
    )
    _strict_keys(
        error,
        field="release broker response error",
        required={"code"},
    )
    code = str(error.get("code") or "")
    if code not in DAEMON_ERROR_CODES:
        raise ReleaseSubmitError(
            "release broker response error is unsupported"
        )
    return {
        "schema_version": RESPONSE_SCHEMA,
        "ok": False,
        "error": {"code": code},
    }


def exchange(
    submission: Mapping[str, Any],
    config: Mapping[str, Any],
    *,
    validate_socket: bool = True,
    socket_factory: Any = socket.socket,
) -> dict[str, Any]:
    payload = canonical_json(dict(submission))
    if not payload or len(payload) > MAX_PACKET_BYTES + 4096:
        raise ReleaseSubmitError(
            "release broker submission exceeds its size limit"
        )
    if validate_socket:
        _validate_socket_file(config)
    client = socket_factory(socket.AF_UNIX, socket.SOCK_STREAM)
    request_may_have_arrived = False
    try:
        client.settimeout(float(config["connect_timeout_seconds"]))
        try:
            client.connect(config["socket_path"])
        except (socket.timeout, OSError) as exc:
            raise ReleaseSubmitError(
                "release broker connection failed"
            ) from exc
        if _peer_uid(client) != config["broker_uid"]:
            raise ReleaseSubmitError(
                "release broker peer UID does not match"
            )
        client.settimeout(float(config["request_timeout_seconds"]))
        frame = struct.pack("!I", len(payload)) + payload
        request_may_have_arrived = True
        try:
            client.sendall(frame)
            client.shutdown(socket.SHUT_WR)
        except (socket.timeout, OSError) as exc:
            raise ReleaseSubmitAmbiguousError(
                "release submission status is ambiguous"
            ) from exc
        header = _read_exact(
            client, FRAME_HEADER_BYTES, ambiguous=True
        )
        (length,) = struct.unpack("!I", header)
        if length <= 0 or length > int(config["max_response_bytes"]):
            raise ReleaseSubmitAmbiguousError(
                "release broker response length is outside policy"
            )
        raw = _read_exact(client, length, ambiguous=True)
        try:
            trailing = client.recv(1)
        except socket.timeout as exc:
            raise ReleaseSubmitAmbiguousError(
                "release broker response did not terminate"
            ) from exc
        except OSError as exc:
            raise ReleaseSubmitAmbiguousError(
                "release broker response termination failed"
            ) from exc
        if trailing:
            raise ReleaseSubmitAmbiguousError(
                "release broker response contains trailing data"
            )
    except ReleaseSubmitAmbiguousError:
        raise
    except ReleaseSubmitError:
        if request_may_have_arrived:
            raise ReleaseSubmitAmbiguousError(
                "release submission status is ambiguous"
            )
        raise
    finally:
        client.close()
    try:
        parsed = parse_json_bytes(
            raw,
            field="release broker response",
            maximum_bytes=int(config["max_response_bytes"]),
        )
        response = normalize_response(parsed)
    except ReleaseSubmitError as exc:
        raise ReleaseSubmitAmbiguousError(
            "release broker response could not be authenticated"
        ) from exc
    if response["ok"] is not True:
        raise ReleaseSubmitAmbiguousError(
            "release broker returned no signed terminal receipt"
        )
    return response


def verify_signed_receipt(
    source: Any,
    *,
    packet: Mapping[str, Any],
    config: LoadedClientConfig,
    now: datetime | None = None,
) -> dict[str, Any]:
    client = config.value
    try:
        envelope = receipts.verify_receipt_with_public_key(
            source,
            public_key=config.receipt_public_key,
            expected_public_key_sha256=client[
                "receipt_public_key_sha256"
            ],
            expected_key_id=client["receipt_key_id"],
            expected_broker_id=client["broker_id"],
            expected_broker_uid=client["broker_uid"],
            expected_config_sha256=client[
                "broker_config_sha256"
            ],
            expected_instance_slug=client["instance_slug"],
            expected_repository_id=client["repository"]["id"],
            expected_repository_full_name=client["repository"][
                "full_name"
            ],
            expected_github_app=client["github_app"],
            packet=dict(packet),
            now=now or datetime.now(timezone.utc),
        )
    except protocol.ReleaseBrokerProtocolError as exc:
        raise ReleaseSubmitError(str(exc)) from exc
    if (
        envelope["payload"]["repository"]["default_branch"]
        != client["repository"]["default_branch"]
    ):
        raise ReleaseSubmitError(
            "release receipt default-branch binding does not match"
        )
    outcome = envelope["payload"]["outcome"]
    if outcome not in receipts.TERMINAL_OUTCOMES:
        raise ReleaseSubmitError(
            "release receipt is not terminal"
        )
    return envelope


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _open_runtime_directory(path: Path, *, field: str) -> int:
    normalized = _absolute_path(str(path), field=field)
    try:
        descriptor = os.open(normalized, _directory_flags())
    except OSError as exc:
        raise ReleaseSubmitError(f"{field} is unsafe") from exc
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o022
    ):
        os.close(descriptor)
        raise ReleaseSubmitError(f"{field} is unsafe")
    return descriptor


def _ensure_private_directory_at(
    parent_fd: int,
    name: str,
    *,
    field: str,
) -> int:
    if not re.fullmatch(r"^[a-z][a-z0-9-]{0,63}$", name):
        raise ReleaseSubmitError(f"{field} directory name is unsafe")
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileExistsError:
        pass
    except OSError as exc:
        raise ReleaseSubmitError(f"{field} is unsafe") from exc
    try:
        descriptor = os.open(
            name, _directory_flags(), dir_fd=parent_fd
        )
    except OSError as exc:
        raise ReleaseSubmitError(f"{field} is unsafe") from exc
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink < 2
    ):
        os.close(descriptor)
        raise ReleaseSubmitError(f"{field} is unsafe")
    try:
        os.fchmod(descriptor, 0o700)
    except OSError:
        os.close(descriptor)
        raise
    return descriptor


def _write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(descriptor, raw[offset:])
        if written <= 0:
            raise ReleaseSubmitError(
                "release receipt write made no progress"
            )
        offset += written


def _read_existing_at(
    directory_fd: int,
    name: str,
    *,
    expected: bytes,
) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise ReleaseSubmitError(
            "existing release receipt is unsafe"
        ) from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size != len(expected)
        ):
            raise ReleaseSubmitError(
                "existing release receipt is unsafe"
            )
        chunks: list[bytes] = []
        remaining = len(expected) + 1
        while remaining:
            chunk = os.read(
                descriptor, min(64 * 1024, remaining)
            )
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if b"".join(chunks) != expected:
            raise ReleaseSubmitError(
                "existing release receipt conflicts"
            )
    finally:
        os.close(descriptor)


def persist_receipt(
    runtime_home: Path,
    envelope: Mapping[str, Any],
) -> str:
    try:
        normalized = receipts.normalize_receipt_envelope(dict(envelope))
    except protocol.ReleaseBrokerProtocolError as exc:
        raise ReleaseSubmitError(str(exc)) from exc
    receipt_id = normalized["payload"]["receipt_id"]
    if not receipts.RECEIPT_ID_RE.fullmatch(receipt_id):
        raise ReleaseSubmitError("release receipt ID is unsafe")
    expected = canonical_json(normalized) + b"\n"
    runtime_fd = _open_runtime_directory(
        runtime_home, field="release runtime home"
    )
    state_fd = protected_fd = receipts_fd = -1
    temporary_name = (
        f".{receipt_id}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    temporary_created = False
    final_name = f"{receipt_id}.json"
    try:
        state_fd = _ensure_private_directory_at(
            runtime_fd, "state", field="release state"
        )
        protected_fd = _ensure_private_directory_at(
            state_fd,
            "protected-releases",
            field="protected releases",
        )
        receipts_fd = _ensure_private_directory_at(
            protected_fd,
            "receipts",
            field="protected release receipts",
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=receipts_fd,
            )
        except OSError as exc:
            raise ReleaseSubmitError(
                "release receipt staging file could not be created"
            ) from exc
        temporary_created = True
        try:
            _write_all(descriptor, expected)
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.link(
                temporary_name,
                final_name,
                src_dir_fd=receipts_fd,
                dst_dir_fd=receipts_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            _read_existing_at(
                receipts_fd, final_name, expected=expected
            )
        except OSError as exc:
            raise ReleaseSubmitError(
                "release receipt could not be installed"
            ) from exc
        os.fsync(receipts_fd)
    finally:
        if temporary_created and receipts_fd >= 0:
            try:
                os.unlink(temporary_name, dir_fd=receipts_fd)
                os.fsync(receipts_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        for descriptor in (
            receipts_fd,
            protected_fd,
            state_fd,
            runtime_fd,
        ):
            if descriptor >= 0:
                os.close(descriptor)
    locator = RECEIPT_LOCATOR_ROOT / final_name
    if locator.is_absolute() or ".." in locator.parts:
        raise ReleaseSubmitError("release receipt locator is unsafe")
    return locator.as_posix()


def _load_bound_config(
    packet: Mapping[str, Any],
    client_config_path: Path | None,
    *,
    config_owner_uids: int | Iterable[int] | None,
    key_owner_uids: int | Iterable[int] | None,
    parent_owner_uids: int | Iterable[int] | None,
    trusted_config_root: Path | None,
    requester_uid: int | None,
    requester_groups: Iterable[int] | None,
) -> LoadedClientConfig:
    config_path = (
        client_config_path
        if client_config_path is not None
        else default_client_config_path(packet)
    )
    trust_root = (
        trusted_config_root
        if trusted_config_root is not None
        else (
            DEFAULT_CONFIG_ROOT
            if client_config_path is None
            else None
        )
    )
    loaded = load_client_config(
        config_path,
        config_owner_uids=config_owner_uids,
        key_owner_uids=key_owner_uids,
        parent_owner_uids=parent_owner_uids,
        trusted_path_root=trust_root,
        requester_uid=requester_uid,
        requester_groups=requester_groups,
    )
    validate_packet_config_binding(packet, loaded.value)
    return loaded


def submit_packet(
    packet_path: Path,
    *,
    runtime_home: Path,
    client_config_path: Path | None = None,
    now: datetime | None = None,
    packet_owner_uids: int | Iterable[int] | None = None,
    config_owner_uids: int | Iterable[int] | None = None,
    key_owner_uids: int | Iterable[int] | None = None,
    parent_owner_uids: int | Iterable[int] | None = None,
    trusted_packet_root: Path | None = None,
    trusted_config_root: Path | None = None,
    requester_uid: int | None = None,
    requester_groups: Iterable[int] | None = None,
    validate_socket: bool = True,
    socket_factory: Any = socket.socket,
) -> VerifiedReceipt:
    packet = load_packet(
        packet_path,
        now=now,
        packet_owner_uids=packet_owner_uids,
        parent_owner_uids=parent_owner_uids,
        trusted_path_root=trusted_packet_root,
    )
    loaded = _load_bound_config(
        packet,
        client_config_path,
        config_owner_uids=config_owner_uids,
        key_owner_uids=key_owner_uids,
        parent_owner_uids=parent_owner_uids,
        trusted_config_root=trusted_config_root,
        requester_uid=requester_uid,
        requester_groups=requester_groups,
    )
    try:
        runtime = anchored_runtime_home(
            SCRIPT_DIR,
            runtime_home,
        )
        control = deployed_runtime_control(runtime)
        require_effective_protected_release(control)
    except AutonomyError as exc:
        raise ReleaseSubmitError(str(exc)) from exc
    repository = loaded.value["repository"]
    if (
        control["BOT_SLUG"] != loaded.value["instance_slug"]
        or control["BOT_REPO"] != repository["full_name"]
        or control["BOT_DEFAULT_BRANCH"] != repository["default_branch"]
    ):
        raise ReleaseSubmitError(
            "runtime authority does not match release client"
        )
    submission = {
        "schema_version": protocol.SUBMISSION_SCHEMA,
        "packet": packet,
    }
    response = exchange(
        submission,
        loaded.value,
        validate_socket=validate_socket,
        socket_factory=socket_factory,
    )
    try:
        envelope = verify_signed_receipt(
            response["receipt"],
            packet=packet,
            config=loaded,
            now=now,
        )
    except ReleaseSubmitError as exc:
        raise ReleaseSubmitAmbiguousError(
            "release broker receipt authentication failed"
        ) from exc
    locator = persist_receipt(runtime_home, envelope)
    return VerifiedReceipt(envelope=envelope, locator=locator)


def verify_receipt_file(
    packet_path: Path,
    receipt_path: Path,
    *,
    runtime_home: Path,
    client_config_path: Path | None = None,
    now: datetime | None = None,
    packet_owner_uids: int | Iterable[int] | None = None,
    receipt_owner_uids: int | Iterable[int] | None = None,
    config_owner_uids: int | Iterable[int] | None = None,
    key_owner_uids: int | Iterable[int] | None = None,
    parent_owner_uids: int | Iterable[int] | None = None,
    trusted_packet_root: Path | None = None,
    trusted_receipt_root: Path | None = None,
    trusted_config_root: Path | None = None,
    requester_uid: int | None = None,
    requester_groups: Iterable[int] | None = None,
) -> VerifiedReceipt:
    packet = load_packet(
        packet_path,
        now=now,
        allow_expired=True,
        packet_owner_uids=packet_owner_uids,
        parent_owner_uids=parent_owner_uids,
        trusted_path_root=trusted_packet_root,
    )
    loaded = _load_bound_config(
        packet,
        client_config_path,
        config_owner_uids=config_owner_uids,
        key_owner_uids=key_owner_uids,
        parent_owner_uids=parent_owner_uids,
        trusted_config_root=trusted_config_root,
        requester_uid=requester_uid,
        requester_groups=requester_groups,
    )
    raw = read_stable_file(
        receipt_path,
        field="release receipt",
        maximum_bytes=receipts.MAX_RECEIPT_BYTES,
        expected_owner_uids=(
            receipt_owner_uids
            if receipt_owner_uids is not None
            else {0, os.getuid()}
        ),
        private_mode=True,
        parent_owner_uids=(
            parent_owner_uids
            if parent_owner_uids is not None
            else {0, os.getuid()}
        ),
        trusted_path_root=trusted_receipt_root,
    )
    try:
        envelope = verify_signed_receipt(
            raw,
            packet=packet,
            config=loaded,
            now=now,
        )
    except ReleaseSubmitError:
        raise
    locator = persist_receipt(runtime_home, envelope)
    return VerifiedReceipt(envelope=envelope, locator=locator)


def public_result(result: VerifiedReceipt) -> dict[str, Any]:
    payload = result.envelope["payload"]
    return {
        "schema_version": "john-lomein.release-submit-result.v1",
        "packet_id": payload["packet"]["packet_id"],
        "bundle_id": payload["bundle"]["bundle_id"],
        "outcome": payload["outcome"],
        "reason_code": payload["reason_code"],
        "receipt_locator": result.locator,
    }


def exit_for_outcome(outcome: str) -> int:
    return {
        "succeeded": 0,
        "rejected": EXIT_REJECTED,
        "partial": EXIT_PARTIAL,
        "indeterminate": EXIT_INDETERMINATE,
    }.get(outcome, EXIT_BLOCKED)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    submit = subparsers.add_parser("submit")
    submit.add_argument("--packet", required=True)
    submit.add_argument("--runtime-home", required=True)
    submit.add_argument("--client-config")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--packet", required=True)
    verify.add_argument("--receipt", required=True)
    verify.add_argument("--runtime-home", required=True)
    verify.add_argument("--client-config")
    args = parser.parse_args(argv)
    try:
        config_path = (
            Path(args.client_config)
            if args.client_config
            else None
        )
        if args.command == "submit":
            result = submit_packet(
                Path(args.packet),
                runtime_home=Path(args.runtime_home),
                client_config_path=config_path,
            )
        else:
            result = verify_receipt_file(
                Path(args.packet),
                Path(args.receipt),
                runtime_home=Path(args.runtime_home),
                client_config_path=config_path,
            )
        sys.stdout.buffer.write(canonical_json(public_result(result)) + b"\n")
        return exit_for_outcome(result.envelope["payload"]["outcome"])
    except ReleaseSubmitAmbiguousError:
        print(
            "john-lomein release submit ambiguous: inspect the signed "
            "receipt store before any retry",
            file=sys.stderr,
        )
        return EXIT_AMBIGUOUS
    except ReleaseSubmitError as exc:
        print(
            f"john-lomein release submit blocked: {exc}",
            file=sys.stderr,
        )
        return EXIT_BLOCKED
    except Exception:
        print(
            "john-lomein release submit blocked: internal client failure",
            file=sys.stderr,
        )
        return EXIT_BLOCKED


if __name__ == "__main__":
    raise SystemExit(main())
