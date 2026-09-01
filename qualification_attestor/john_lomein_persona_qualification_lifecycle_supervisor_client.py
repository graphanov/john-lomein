#!/usr/bin/env python3
"""Fail-closed client boundary for the root lifecycle supervisor.

The public client configuration is root-owned and measurement-pinned.  Every
connection authenticates the socket leaf, its parent chain, and the kernel
peer credential before sending a byte.  The wire transcript is then bound to
fresh client randomness and validated exclusively through the lifecycle
supervisor protocol guards.

Scope operations do not accept a generic payload.  They derive the outer
journal coordinates from an active, descriptor-bound
``TransactionJournalSession`` after rescanning its durable records.  Process
IDs, signals, paths, commands, argument vectors, and environments are not
part of the operation API.

Production construction remains disabled until the root daemon, privileged
canary, installer role, and process-boundary review are complete.  Private
test seams exercise the mechanical transport and proof contracts without
creating a public activation route.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import socket
import stat
import struct
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from qualification_attestor import (
    john_lomein_persona_qualification_lifecycle_receipts
    as lifecycle_receipts,
)
from qualification_attestor import (
    john_lomein_persona_qualification_lifecycle_supervisor_protocol
    as protocol,
)
from qualification_attestor import (
    john_lomein_persona_qualification_transaction_journal
    as transaction_journal,
)


PRODUCTION_ACTIVATION = False
# The exact outer head is now reserved before every scoped handshake and a
# correlated outcome can only release that reservation or consume it through
# one exact-head successor permit.  Production remains disabled for the
# separate daemon, installer, provider, and canary blockers.
TRANSACTION_JOURNAL_OPERATION_LEASE_MISSING = False

CLIENT_CONFIG_SCHEMA = (
    "john-lomein.persona-qualification-"
    "lifecycle-supervisor-client-config.v1"
)
MAX_CONFIG_BYTES = 64 * 1024
MAX_SOCKET_PATH_BYTES = 103
MAX_CONNECT_TIMEOUT_SECONDS = 30
MAX_RANDOM_ATTEMPTS = 8
CONFIG_FILE_MODE = 0o600
SOCKET_FILE_MODE = 0o600

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
INSTANCE_SLUG_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$"
)
ZERO_SHA256 = "0" * 64
MAX_IDENTITY = (1 << 31) - 1

CLIENT_CONFIG_FIELDS = frozenset(
    {
        "schema_version",
        "instance_slug",
        "supervisor_uid",
        "requester_uid",
        "requester_gid",
        "socket_path",
        "connect_timeout_seconds",
        "request_timeout_seconds",
        "expected_supervisor_policy_sha256",
        "expected_supervisor_bundle_sha256",
        "expected_helper_activation_policy_sha256",
        "expected_lifecycle_canary_sha256",
    }
)

_LOADED_CONFIG_TOKEN = object()
_CLEARANCE_RESULT_TOKEN = object()
_RECOVERY_RESULT_TOKEN = object()
_PENDING_EVENT_RESULT_TOKEN = object()
_AUTHENTICATED_EXCHANGE_TOKEN = object()


class LifecycleSupervisorClientError(ValueError):
    """Stable, public-safe client rejection."""

    def __init__(
        self,
        code: str,
        *,
        retryable: bool = False,
        outcome_ambiguous: bool = False,
    ) -> None:
        self.code = code
        self.retryable = retryable
        self.outcome_ambiguous = outcome_ambiguous
        super().__init__(code)


class LifecycleSupervisorTransportError(
    LifecycleSupervisorClientError
):
    """No lifecycle operation byte reached an authenticated supervisor."""

    def __init__(self, code: str) -> None:
        super().__init__(
            code,
            retryable=True,
            outcome_ambiguous=False,
        )


class LifecycleSupervisorRemoteError(
    LifecycleSupervisorClientError
):
    """A correlated response proves the request had no lifecycle effect."""

    def __init__(
        self,
        remote_code: str,
        *,
        error_outcome: str,
        observed_ledger_head_sha256: str | None,
    ) -> None:
        try:
            no_effect = protocol.error_outcome_is_no_effect(
                error_outcome
            )
            retryable = protocol.error_outcome_retryable(error_outcome)
        except protocol.LifecycleSupervisorProtocolError as exc:
            raise LifecycleSupervisorClientError(
                "lifecycle_client_remote_error_outcome_invalid"
            ) from exc
        if not no_effect:
            raise LifecycleSupervisorClientError(
                "lifecycle_client_remote_error_effect_uncertain"
            )
        self.remote_code = remote_code
        self.error_outcome = error_outcome
        self.observed_ledger_head_sha256 = _nullable_digest(
            observed_ledger_head_sha256,
            code="lifecycle_client_observed_ledger_head_invalid",
        )
        super().__init__(
            f"lifecycle_supervisor_remote_{remote_code}",
            retryable=retryable,
            outcome_ambiguous=False,
        )


class LifecycleSupervisorAmbiguousError(
    LifecycleSupervisorClientError
):
    """The exact operation may have committed; automatic retry is unsafe."""

    def __init__(
        self,
        code: str,
        *,
        operation: str,
        request_id: str,
        capture_session_id: str | None,
        scope_incarnation_id: str | None,
    ) -> None:
        self.operation = operation
        self.request_id = request_id
        self.capture_session_id = capture_session_id
        self.scope_incarnation_id = scope_incarnation_id
        super().__init__(
            code,
            retryable=False,
            outcome_ambiguous=True,
        )


class LifecycleSupervisorRecoveryRequiredError(
    LifecycleSupervisorClientError
):
    """The scope requires recovery before another workflow action."""

    def __init__(
        self,
        remote_code: str,
        *,
        operation: str,
        request_id: str,
        capture_session_id: str | None,
        scope_incarnation_id: str | None,
        observed_ledger_head_sha256: str | None,
        request_dispatched: bool,
    ) -> None:
        if type(request_dispatched) is not bool:
            raise TypeError("request_dispatched must be an exact bool")
        self.remote_code = remote_code
        self.error_outcome = (
            protocol.ERROR_OUTCOME_RECOVER_SCOPE_REQUIRED
        )
        self.observed_ledger_head_sha256 = _nullable_digest(
            observed_ledger_head_sha256,
            code="lifecycle_client_observed_ledger_head_invalid",
        )
        self.operation = operation
        self.request_id = request_id
        self.capture_session_id = capture_session_id
        self.scope_incarnation_id = scope_incarnation_id
        self.request_dispatched = request_dispatched
        super().__init__(
            f"lifecycle_supervisor_remote_{remote_code}",
            retryable=False,
            outcome_ambiguous=request_dispatched,
        )


class LifecycleSupervisorOperatorAttentionError(
    LifecycleSupervisorClientError
):
    """Automated progress must stop until an operator resolves the scope."""

    def __init__(
        self,
        remote_code: str,
        *,
        operation: str,
        request_id: str,
        capture_session_id: str | None,
        scope_incarnation_id: str | None,
        observed_ledger_head_sha256: str | None,
    ) -> None:
        self.remote_code = remote_code
        self.error_outcome = (
            protocol.ERROR_OUTCOME_OPERATOR_ATTENTION_REQUIRED
        )
        self.observed_ledger_head_sha256 = _nullable_digest(
            observed_ledger_head_sha256,
            code="lifecycle_client_observed_ledger_head_invalid",
        )
        self.operation = operation
        self.request_id = request_id
        self.capture_session_id = capture_session_id
        self.scope_incarnation_id = scope_incarnation_id
        super().__init__(
            f"lifecycle_supervisor_remote_{remote_code}",
            retryable=False,
            outcome_ambiguous=False,
        )


def _error(code: str) -> LifecycleSupervisorClientError:
    return LifecycleSupervisorClientError(code)


def _strict_mapping(
    value: Any,
    fields: frozenset[str],
    *,
    code: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise _error(code)
    return {field: value[field] for field in fields}


def _exact(value: Any, expected: Any, *, code: str) -> Any:
    if value != expected or type(value) is not type(expected):
        raise _error(code)
    return expected


def _integer(
    value: Any,
    *,
    minimum: int,
    maximum: int,
    code: str,
) -> int:
    if (
        type(value) is not int
        or value < minimum
        or value > maximum
    ):
        raise _error(code)
    return value


def _digest(value: Any, *, code: str) -> str:
    if (
        not isinstance(value, str)
        or not SHA256_RE.fullmatch(value)
        or value == ZERO_SHA256
    ):
        raise _error(code)
    return value


def _nullable_digest(value: Any, *, code: str) -> str | None:
    if value is None:
        return None
    return _digest(value, code=code)


def _identity(value: Any, *, code: str, allow_root: bool) -> int:
    minimum = 0 if allow_root else 1
    return _integer(
        value,
        minimum=minimum,
        maximum=MAX_IDENTITY,
        code=code,
    )


def _instance_slug(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not INSTANCE_SLUG_RE.fullmatch(value)
    ):
        raise _error("lifecycle_client_instance_slug_invalid")
    return value


def _absolute_normal_path(
    value: Any,
    *,
    maximum_bytes: int,
    code: str,
) -> Path:
    if isinstance(value, Path):
        raw = str(value)
    elif isinstance(value, str):
        raw = value
    else:
        raise _error(code)
    if (
        not raw
        or "\x00" in raw
        or not raw.startswith("/")
        or raw == "/"
        or raw.endswith("/")
        or os.path.normpath(raw) != raw
    ):
        raise _error(code)
    try:
        encoded = os.fsencode(raw)
    except (TypeError, UnicodeError) as exc:
        raise _error(code) from exc
    if len(encoded) > maximum_bytes:
        raise _error(code)
    selected = Path(raw)
    if selected.name in {"", ".", ".."}:
        raise _error(code)
    return selected


def normalize_client_config(value: Any) -> dict[str, Any]:
    """Normalize the exact public, root-pinned client policy."""

    selected = _strict_mapping(
        value,
        CLIENT_CONFIG_FIELDS,
        code="lifecycle_client_config_fields_invalid",
    )
    supervisor_uid = _identity(
        selected["supervisor_uid"],
        code="lifecycle_client_supervisor_uid_invalid",
        allow_root=True,
    )
    if supervisor_uid != 0:
        raise _error("lifecycle_client_supervisor_must_be_root")
    socket_path = _absolute_normal_path(
        selected["socket_path"],
        maximum_bytes=MAX_SOCKET_PATH_BYTES,
        code="lifecycle_client_socket_path_invalid",
    )
    return {
        "schema_version": _exact(
            selected["schema_version"],
            CLIENT_CONFIG_SCHEMA,
            code="lifecycle_client_config_schema_invalid",
        ),
        "instance_slug": _instance_slug(selected["instance_slug"]),
        "supervisor_uid": 0,
        "requester_uid": _exact(
            _identity(
                selected["requester_uid"],
                code="lifecycle_client_requester_uid_invalid",
                allow_root=True,
            ),
            0,
            code="lifecycle_client_requester_uid_invalid",
        ),
        "requester_gid": _exact(
            _identity(
                selected["requester_gid"],
                code="lifecycle_client_requester_gid_invalid",
                allow_root=True,
            ),
            0,
            code="lifecycle_client_requester_gid_invalid",
        ),
        "socket_path": str(socket_path),
        "connect_timeout_seconds": _integer(
            selected["connect_timeout_seconds"],
            minimum=1,
            maximum=MAX_CONNECT_TIMEOUT_SECONDS,
            code="lifecycle_client_connect_timeout_invalid",
        ),
        "request_timeout_seconds": _integer(
            selected["request_timeout_seconds"],
            minimum=1,
            maximum=protocol.MAX_TIMEOUT_SECONDS,
            code="lifecycle_client_request_timeout_invalid",
        ),
        "expected_supervisor_policy_sha256": _digest(
            selected["expected_supervisor_policy_sha256"],
            code="lifecycle_client_supervisor_policy_invalid",
        ),
        "expected_supervisor_bundle_sha256": _digest(
            selected["expected_supervisor_bundle_sha256"],
            code="lifecycle_client_supervisor_bundle_invalid",
        ),
        "expected_helper_activation_policy_sha256": _digest(
            selected["expected_helper_activation_policy_sha256"],
            code="lifecycle_client_helper_policy_invalid",
        ),
        "expected_lifecycle_canary_sha256": _digest(
            selected["expected_lifecycle_canary_sha256"],
            code="lifecycle_client_lifecycle_canary_invalid",
        ),
    }


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _error("lifecycle_client_config_duplicate_key")
        result[key] = value
    return result


def _parse_config(raw: bytes) -> dict[str, Any]:
    if (
        not isinstance(raw, bytes)
        or not raw
        or len(raw) > MAX_CONFIG_BYTES
        or b"\x00" in raw
    ):
        raise _error("lifecycle_client_config_size_invalid")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=lambda _value: (_ for _ in ()).throw(
                ValueError("float")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite")
            ),
        )
    except LifecycleSupervisorClientError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        raise _error("lifecycle_client_config_json_invalid") from exc
    try:
        protocol.canonical_json(value)
    except protocol.LifecycleSupervisorProtocolError as exc:
        raise _error("lifecycle_client_config_json_invalid") from exc
    return normalize_client_config(value)


def _directory_flags() -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def _file_flags() -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def _validate_parent_descriptor(
    descriptor: int,
    *,
    expected_owner_uid: int,
) -> os.stat_result:
    try:
        info = os.fstat(descriptor)
        inheritable = os.get_inheritable(descriptor)
    except OSError as exc:
        raise _error("lifecycle_client_parent_unreadable") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != expected_owner_uid
        or stat.S_IMODE(info.st_mode) & 0o022
        or inheritable
    ):
        raise _error("lifecycle_client_parent_unsafe")
    return info


def _open_parent_chain(
    target: Path,
    *,
    expected_owner_uid: int,
    trusted_root: Path | None,
) -> int:
    parent = target.parent
    if trusted_root is None:
        root = Path("/")
        parts = parent.parts[1:]
    else:
        root = _absolute_normal_path(
            trusted_root,
            maximum_bytes=4096,
            code="lifecycle_client_trusted_root_invalid",
        )
        try:
            relative = parent.relative_to(root)
        except ValueError as exc:
            raise _error(
                "lifecycle_client_target_outside_trusted_root"
            ) from exc
        parts = relative.parts
    try:
        descriptor = os.open(root, _directory_flags())
    except OSError as exc:
        raise _error("lifecycle_client_parent_unreadable") from exc
    os.set_inheritable(descriptor, False)
    try:
        _validate_parent_descriptor(
            descriptor,
            expected_owner_uid=expected_owner_uid,
        )
        for component in parts:
            if component in {"", ".", ".."}:
                raise _error("lifecycle_client_parent_unsafe")
            try:
                child = os.open(
                    component,
                    _directory_flags(),
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise _error(
                    "lifecycle_client_parent_unreadable"
                ) from exc
            os.set_inheritable(child, False)
            try:
                _validate_parent_descriptor(
                    child,
                    expected_owner_uid=expected_owner_uid,
                )
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_all(descriptor: int, maximum_bytes: int) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum_bytes + 1
    while remaining:
        try:
            chunk = os.read(descriptor, min(remaining, 16 * 1024))
        except OSError as exc:
            raise _error("lifecycle_client_config_read_failed") from exc
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) > maximum_bytes:
        raise _error("lifecycle_client_config_size_invalid")
    return raw


def _read_pinned_config(
    path: Path,
    *,
    expected_owner_uid: int,
    expected_owner_gid: int,
    trusted_root: Path | None,
) -> bytes:
    selected = _absolute_normal_path(
        path,
        maximum_bytes=4096,
        code="lifecycle_client_config_path_invalid",
    )
    parent_fd = _open_parent_chain(
        selected,
        expected_owner_uid=expected_owner_uid,
        trusted_root=trusted_root,
    )
    descriptor = -1
    try:
        try:
            descriptor = os.open(
                selected.name,
                _file_flags(),
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise _error("lifecycle_client_config_unreadable") from exc
        os.set_inheritable(descriptor, False)
        try:
            before = os.fstat(descriptor)
            named = os.stat(
                selected.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise _error("lifecycle_client_config_unreadable") from exc
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_owner_uid
            or before.st_gid != expected_owner_gid
            or stat.S_IMODE(before.st_mode) != CONFIG_FILE_MODE
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > MAX_CONFIG_BYTES
            or (before.st_dev, before.st_ino)
            != (named.st_dev, named.st_ino)
            or os.get_inheritable(descriptor)
        ):
            raise _error("lifecycle_client_config_unsafe")
        raw = _read_all(descriptor, MAX_CONFIG_BYTES)
        try:
            after = os.fstat(descriptor)
        except OSError as exc:
            raise _error("lifecycle_client_config_unreadable") from exc
        stable = (
            "st_dev",
            "st_ino",
            "st_uid",
            "st_gid",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(
            getattr(before, field) != getattr(after, field)
            for field in stable
        ) or len(raw) != before.st_size:
            raise _error("lifecycle_client_config_changed")
        return raw
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


class LoadedLifecycleSupervisorClientConfig:
    """Immutable result of one stable, root-pinned configuration read."""

    __slots__ = ("__canonical",)

    def __init__(
        self,
        *,
        _token: object,
        value: Mapping[str, Any],
    ) -> None:
        if _token is not _LOADED_CONFIG_TOKEN:
            raise TypeError(
                "LoadedLifecycleSupervisorClientConfig "
                "cannot be constructed directly"
            )
        normalized = normalize_client_config(value)
        self.__canonical = protocol.canonical_json(normalized)

    @property
    def value(self) -> dict[str, Any]:
        value = json.loads(self.__canonical.decode("ascii"))
        if not isinstance(value, dict):
            raise AssertionError("client config is not an object")
        return value

    def __reduce__(self) -> Any:
        raise TypeError(
            "LoadedLifecycleSupervisorClientConfig is not serializable"
        )

    def __reduce_ex__(self, protocol_version: int) -> Any:
        del protocol_version
        raise TypeError(
            "LoadedLifecycleSupervisorClientConfig is not serializable"
        )


def _validate_runtime_identity(
    config: Mapping[str, Any],
    *,
    requester_uid: int,
    requester_groups: Iterable[int],
) -> None:
    uid = _identity(
        requester_uid,
        code="lifecycle_client_runtime_uid_invalid",
        allow_root=True,
    )
    try:
        groups = {
            _identity(
                group,
                code="lifecycle_client_runtime_gid_invalid",
                allow_root=True,
            )
            for group in requester_groups
        }
    except TypeError as exc:
        raise _error("lifecycle_client_runtime_groups_invalid") from exc
    if uid != config["requester_uid"]:
        raise _error("lifecycle_client_runtime_uid_mismatch")
    if config["requester_gid"] not in groups:
        raise _error("lifecycle_client_runtime_gid_mismatch")


def _load_client_config(
    path: Path,
    *,
    expected_owner_uid: int,
    expected_owner_gid: int,
    trusted_root: Path | None,
    requester_uid: int,
    requester_groups: Iterable[int],
) -> LoadedLifecycleSupervisorClientConfig:
    raw = _read_pinned_config(
        path,
        expected_owner_uid=expected_owner_uid,
        expected_owner_gid=expected_owner_gid,
        trusted_root=trusted_root,
    )
    config = _parse_config(raw)
    _validate_runtime_identity(
        config,
        requester_uid=requester_uid,
        requester_groups=requester_groups,
    )
    return LoadedLifecycleSupervisorClientConfig(
        _token=_LOADED_CONFIG_TOKEN,
        value=config,
    )


def load_client_config(
    path: Path,
) -> LoadedLifecycleSupervisorClientConfig:
    """Read an exact root-owned config for the root coordinator role."""

    return _load_client_config(
        path,
        expected_owner_uid=0,
        expected_owner_gid=0,
        trusted_root=None,
        requester_uid=os.getuid(),
        requester_groups={os.getgid(), *os.getgroups()},
    )


def _load_client_config_for_test(
    path: Path,
    *,
    expected_owner_uid: int,
    expected_owner_gid: int,
    trusted_root: Path,
    requester_uid: int,
    requester_groups: Iterable[int],
) -> LoadedLifecycleSupervisorClientConfig:
    """Private ownership seam; never used by the production constructor."""

    return _load_client_config(
        path,
        expected_owner_uid=expected_owner_uid,
        expected_owner_gid=expected_owner_gid,
        trusted_root=trusted_root,
        requester_uid=requester_uid,
        requester_groups=requester_groups,
    )


class _SocketIdentity:
    __slots__ = ("device", "inode", "owner_uid", "owner_gid", "mode")

    def __init__(self, info: os.stat_result) -> None:
        self.device = int(info.st_dev)
        self.inode = int(info.st_ino)
        self.owner_uid = int(info.st_uid)
        self.owner_gid = int(info.st_gid)
        self.mode = stat.S_IMODE(info.st_mode)

    def same_as(self, other: _SocketIdentity) -> bool:
        return (
            type(other) is _SocketIdentity
            and self.device == other.device
            and self.inode == other.inode
            and self.owner_uid == other.owner_uid
            and self.owner_gid == other.owner_gid
            and self.mode == other.mode
        )


def _validate_socket_leaf(
    config: Mapping[str, Any],
    *,
    expected_owner_uid: int,
    trusted_root: Path | None,
) -> _SocketIdentity:
    selected = normalize_client_config(config)
    path = Path(selected["socket_path"])
    parent_fd = _open_parent_chain(
        path,
        expected_owner_uid=expected_owner_uid,
        trusted_root=trusted_root,
    )
    try:
        try:
            info = os.stat(
                path.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise _error("lifecycle_client_socket_unavailable") from exc
        if (
            not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != expected_owner_uid
            or info.st_gid != selected["requester_gid"]
            or stat.S_IMODE(info.st_mode) != SOCKET_FILE_MODE
            or info.st_nlink != 1
        ):
            raise _error("lifecycle_client_socket_unsafe")
        return _SocketIdentity(info)
    finally:
        os.close(parent_fd)


def _validate_socket_leaf_for_test(
    config: Mapping[str, Any],
    *,
    expected_owner_uid: int,
    trusted_root: Path,
) -> _SocketIdentity:
    return _validate_socket_leaf(
        config,
        expected_owner_uid=expected_owner_uid,
        trusted_root=trusted_root,
    )


def _peer_uid(client: socket.socket) -> int:
    getpeereid = getattr(client, "getpeereid", None)
    if callable(getpeereid):
        try:
            uid, _gid = getpeereid()
        except OSError as exc:
            raise _error("lifecycle_client_peer_identity_unavailable") from exc
        return _identity(
            uid,
            code="lifecycle_client_peer_uid_invalid",
            allow_root=True,
        )

    peercred = getattr(socket, "SO_PEERCRED", None)
    if peercred is not None:
        try:
            raw = client.getsockopt(socket.SOL_SOCKET, peercred, 12)
            _pid, uid, _gid = struct.unpack("=3i", raw)
        except (OSError, struct.error) as exc:
            raise _error(
                "lifecycle_client_peer_identity_unavailable"
            ) from exc
        return _identity(
            uid,
            code="lifecycle_client_peer_uid_invalid",
            allow_root=True,
        )

    local_peercred = getattr(socket, "LOCAL_PEERCRED", None)
    sol_local = getattr(socket, "SOL_LOCAL", 0)
    if local_peercred is not None:
        try:
            raw = client.getsockopt(sol_local, local_peercred, 256)
            if len(raw) < 10:
                raise struct.error("short peer credential")
            _version, uid, _groups = struct.unpack_from("@IIh", raw)
        except (OSError, struct.error) as exc:
            raise _error(
                "lifecycle_client_peer_identity_unavailable"
            ) from exc
        return _identity(
            uid,
            code="lifecycle_client_peer_uid_invalid",
            allow_root=True,
        )
    raise _error("lifecycle_client_peer_credentials_unsupported")


def _read_exact(
    client: socket.socket,
    count: int,
    *,
    ambiguous: bool,
    deadline: float,
) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        timeout = deadline - time.monotonic()
        if timeout <= 0:
            if ambiguous:
                raise _error("lifecycle_client_ambiguous_timeout")
            raise LifecycleSupervisorTransportError(
                "lifecycle_client_response_timeout"
            )
        try:
            client.settimeout(timeout)
            chunk = client.recv(remaining)
        except (socket.timeout, OSError) as exc:
            if ambiguous:
                raise _error(
                    "lifecycle_client_ambiguous_transport"
                ) from exc
            raise LifecycleSupervisorTransportError(
                "lifecycle_client_response_transport_failed"
            ) from exc
        if not chunk:
            if ambiguous:
                raise _error("lifecycle_client_ambiguous_transport")
            raise LifecycleSupervisorTransportError(
                "lifecycle_client_response_truncated"
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_frame(
    client: socket.socket,
    *,
    ambiguous: bool,
    deadline: float,
) -> dict[str, Any]:
    header = _read_exact(
        client,
        4,
        ambiguous=ambiguous,
        deadline=deadline,
    )
    (length,) = struct.unpack("!I", header)
    if length < 2 or length > protocol.MAX_FRAME_BYTES:
        if ambiguous:
            raise _error("lifecycle_client_ambiguous_frame_invalid")
        raise LifecycleSupervisorTransportError(
            "lifecycle_client_response_frame_invalid"
        )
    payload = _read_exact(
        client,
        length,
        ambiguous=ambiguous,
        deadline=deadline,
    )
    try:
        return protocol.decode_frame(header + payload)
    except protocol.LifecycleSupervisorProtocolError as exc:
        if ambiguous:
            raise _error("lifecycle_client_ambiguous_frame_invalid") from exc
        raise LifecycleSupervisorTransportError(
            "lifecycle_client_response_frame_invalid"
        ) from exc


def _send_frame(
    client: socket.socket,
    value: Mapping[str, Any],
    *,
    ambiguous: bool,
    deadline: float,
) -> None:
    try:
        frame = protocol.encode_frame(value)
    except protocol.LifecycleSupervisorProtocolError as exc:
        raise _error("lifecycle_client_request_frame_invalid") from exc
    timeout = deadline - time.monotonic()
    if timeout <= 0:
        if ambiguous:
            raise _error("lifecycle_client_ambiguous_timeout")
        raise LifecycleSupervisorTransportError(
            "lifecycle_client_handshake_timeout"
        )
    try:
        client.settimeout(timeout)
        client.sendall(frame)
    except (socket.timeout, OSError) as exc:
        if ambiguous:
            raise _error("lifecycle_client_ambiguous_transport") from exc
        raise LifecycleSupervisorTransportError(
            "lifecycle_client_handshake_send_failed"
        ) from exc


class _JournalSnapshot:
    __slots__ = (
        "session",
        "live_snapshot",
        "instance_slug",
        "session_id",
        "state",
        "revision",
        "record_sha256",
        "records",
    )

    def __init__(
        self,
        *,
        session: transaction_journal.TransactionJournalSession,
        live_snapshot: (
            transaction_journal.TransactionJournalLiveSnapshot
        ),
    ) -> None:
        self.session = session
        self.live_snapshot = live_snapshot
        self.instance_slug = live_snapshot.instance_slug
        self.session_id = live_snapshot.session_id
        self.state = live_snapshot.state
        self.revision = live_snapshot.revision
        self.record_sha256 = live_snapshot.head_record_sha256
        self.records = live_snapshot.records


def _scan_live_journal(
    session: Any,
    *,
    instance_slug: str,
    permitted_states: frozenset[str],
) -> _JournalSnapshot:
    if type(session) is not transaction_journal.TransactionJournalSession:
        raise _error("lifecycle_client_live_journal_session_required")
    if not session.active:
        raise _error("lifecycle_client_journal_session_closed")
    try:
        live_snapshot = session.live_snapshot()
        if (
            type(live_snapshot)
            is not transaction_journal.TransactionJournalLiveSnapshot
        ):
            raise TypeError("unexpected live snapshot type")
        snapshot = _JournalSnapshot(
            session=session,
            live_snapshot=live_snapshot,
        )
    except (
        AttributeError,
        OSError,
        TypeError,
        transaction_journal.TransactionJournalError,
    ) as exc:
        raise _error("lifecycle_client_journal_rescan_failed") from exc
    if (
        snapshot.instance_slug != instance_slug
        or snapshot.session_id != session.session_id
        or snapshot.revision != len(snapshot.records)
        or snapshot.state not in permitted_states
    ):
        raise _error("lifecycle_client_journal_head_binding_invalid")
    return snapshot


def _assert_live_snapshot(snapshot: _JournalSnapshot) -> None:
    if not snapshot.session.active:
        raise _error("lifecycle_client_journal_session_closed")
    try:
        snapshot.session.assert_live_snapshot_current(
            snapshot.live_snapshot
        )
    except (
        OSError,
        transaction_journal.TransactionJournalError,
    ) as exc:
        if (
            isinstance(
                exc, transaction_journal.TransactionJournalError
            )
            and exc.code
            == "transaction_journal_live_snapshot_stale"
        ):
            raise _error(
                "lifecycle_client_journal_head_changed"
            ) from exc
        raise _error("lifecycle_client_journal_rescan_failed") from exc


def _begin_scoped_operation(
    snapshot: _JournalSnapshot,
    operation: str,
) -> transaction_journal.TransactionJournalOperationLease:
    """Reserve the exact descriptor-bound head before opening a socket."""

    try:
        lease = snapshot.session._begin_lifecycle_operation_for_client(
            operation=operation,
            snapshot=snapshot.live_snapshot,
        )
    except transaction_journal.TransactionJournalError as exc:
        raise _error(
            f"lifecycle_client_journal_{exc.code}"
        ) from exc
    if type(lease) is not (
        transaction_journal.TransactionJournalOperationLease
    ):
        raise _error("lifecycle_client_operation_lease_invalid")
    return lease


def _binding_from_records(
    snapshot: _JournalSnapshot,
) -> tuple[str | None, int]:
    """Derive the supervisor cursor solely from durable outer bindings."""

    ledger_head: str | None = None
    event_sequence = 0
    for record in snapshot.records:
        raw = record.details.get("lifecycle_operation_binding")
        if raw is None:
            continue
        try:
            binding = (
                transaction_journal.normalize_lifecycle_operation_binding(
                    raw
                )
            )
        except transaction_journal.TransactionJournalError as exc:
            raise _error(
                "lifecycle_client_journal_operation_binding_invalid"
            ) from exc
        selected_head = binding[
            "supervisor_ledger_head_sha256"
        ]
        if selected_head is not None:
            ledger_head = selected_head
        selected_sequence = binding["supervisor_event_sequence"]
        if selected_sequence is not None:
            if selected_sequence <= event_sequence:
                raise _error(
                    "lifecycle_client_journal_event_sequence_invalid"
                )
            event_sequence = selected_sequence
    return ledger_head, event_sequence


def _required_ledger_head(snapshot: _JournalSnapshot) -> str:
    ledger_head, _event_sequence = _binding_from_records(snapshot)
    if ledger_head is None:
        raise _error(
            "lifecycle_client_journal_ledger_head_binding_missing"
        )
    return ledger_head


def _journal_timestamp(
    snapshot: _JournalSnapshot,
    recorded_at_unix: int,
) -> int:
    minimum = snapshot.records[-1].recorded_at_unix
    selected = _integer(
        recorded_at_unix,
        minimum=1,
        maximum=(1 << 63) - 1,
        code="lifecycle_client_recorded_at_unix_invalid",
    )
    if selected < minimum:
        raise _error("lifecycle_client_recorded_at_clock_rollback")
    return selected


def _operation_binding(
    *,
    lease: transaction_journal.TransactionJournalOperationLease,
    request_sha256: str,
    response_sha256: str | None,
    outcome: str,
    error_code: str | None,
    result: Mapping[str, Any] | None,
    supervisor_ledger_head_sha256: str | None,
    supervisor_event_sequence: int | None = None,
    supervisor_event: str | None = None,
    supervisor_event_record_sha256: str | None = None,
    supervisor_event_evidence_sha256: str | None = None,
) -> dict[str, Any]:
    binding = {
        "schema_version": (
            transaction_journal.LIFECYCLE_OPERATION_BINDING_SCHEMA
        ),
        "operation": lease.operation,
        "base_record_revision": lease.base_record_revision,
        "base_record_sha256": lease.base_record_sha256,
        "request_sha256": request_sha256,
        "response_sha256": response_sha256,
        "outcome": outcome,
        "error_code": error_code,
        "result_sha256": (
            None
            if result is None
            else protocol.sha256_json(dict(result))
        ),
        "supervisor_ledger_head_sha256": (
            supervisor_ledger_head_sha256
        ),
        "supervisor_event_sequence": supervisor_event_sequence,
        "supervisor_event": supervisor_event,
        "supervisor_event_record_sha256": (
            supervisor_event_record_sha256
        ),
        "supervisor_event_evidence_sha256": (
            supervisor_event_evidence_sha256
        ),
    }
    try:
        return transaction_journal.normalize_lifecycle_operation_binding(
            binding
        )
    except transaction_journal.TransactionJournalError as exc:
        raise _error(
            "lifecycle_client_operation_binding_invalid"
        ) from exc


def _success_binding(
    *,
    lease: transaction_journal.TransactionJournalOperationLease,
    request_sha256: str,
    response_sha256: str,
    result: Mapping[str, Any],
) -> dict[str, Any]:
    event_sequence: int | None = None
    event: str | None = None
    event_record_sha256: str | None = None
    event_evidence_sha256: str | None = None
    if lease.operation == "await_capture_event" or (
        lease.operation == "recover_scope"
        and result.get("recovery_state") == "capture_event"
    ):
        event_sequence = result["event_sequence"]
        event = result["event"]
        event_record_sha256 = result["event_record_sha256"]
        event_evidence_sha256 = result["event_evidence_sha256"]
    return _operation_binding(
        lease=lease,
        request_sha256=request_sha256,
        response_sha256=response_sha256,
        outcome="success",
        error_code=None,
        result=result,
        supervisor_ledger_head_sha256=result["ledger_head_sha256"],
        supervisor_event_sequence=event_sequence,
        supervisor_event=event,
        supervisor_event_record_sha256=event_record_sha256,
        supervisor_event_evidence_sha256=event_evidence_sha256,
    )


def _record(
    snapshot: _JournalSnapshot,
    state: str,
) -> transaction_journal.TransactionJournalRecord:
    matches = tuple(
        record for record in snapshot.records if record.state == state
    )
    if len(matches) != 1:
        raise _error("lifecycle_client_journal_history_binding_missing")
    return matches[0]


def _scope_values(
    snapshot: _JournalSnapshot,
) -> tuple[str, str, str | None]:
    launch = _record(snapshot, "child_launch_intent")
    expected_incarnation = protocol.derive_scope_incarnation_id(
        instance_slug=snapshot.instance_slug,
        capture_session_id=snapshot.session_id,
        child_launch_intent_record_sha256=launch.record_sha256,
        lifecycle_activation_receipt_sha256=launch.details[
            "lifecycle_activation_receipt_sha256"
        ],
    )
    running = tuple(
        record
        for record in snapshot.records
        if record.state == "child_running"
    )
    if running:
        if len(running) != 1:
            raise _error("lifecycle_client_journal_history_binding_invalid")
        receipt = running[0].details[
            "lifecycle_scope_started_receipt"
        ]
        scope_id = receipt["lifecycle_scope_id"]
        incarnation = receipt["scope_incarnation_id"]
        if not hmac.compare_digest(
            expected_incarnation, incarnation
        ):
            raise _error("lifecycle_client_scope_incarnation_mismatch")
        return scope_id, incarnation, running[0].details[
            "lifecycle_scope_started_receipt_sha256"
        ]
    return (
        f"jlq-root_supervisor-{snapshot.session_id}",
        expected_incarnation,
        None,
    )


def _scope_start_authorization_sha256(
    snapshot: _JournalSnapshot,
) -> str:
    staging_intent = _record(snapshot, "staging_create_intent")
    exposure = _record(snapshot, "staging_exposed")
    launch = _record(snapshot, "child_launch_intent")
    activation = launch.details["lifecycle_activation_receipt"]
    scope_id, incarnation, _started_digest = _scope_values(snapshot)
    if scope_id != f"jlq-root_supervisor-{snapshot.session_id}":
        raise _error("lifecycle_client_scope_id_binding_changed")
    return protocol.derive_scope_start_authorization_sha256(
        instance_slug=snapshot.instance_slug,
        capture_session_id=snapshot.session_id,
        scope_incarnation_id=incarnation,
        child_launch_intent_record_revision=launch.revision,
        child_launch_intent_record_sha256=launch.record_sha256,
        staging_transaction_intent_sha256=(
            staging_intent.record_sha256
        ),
        staging_exposure_receipt_sha256=exposure.details[
            "staging_exposure_receipt_sha256"
        ],
        handoff_policy_sha256=launch.to_dict()[
            "handoff_policy_sha256"
        ],
        helper_activation_policy_sha256=activation[
            "helper_activation_policy_sha256"
        ],
        lifecycle_provider=activation["lifecycle_provider"],
        capture_uid=staging_intent.details["capture_uid"],
        export_gid=staging_intent.details["export_gid"],
        lifecycle_activation_receipt_sha256=launch.details[
            "lifecycle_activation_receipt_sha256"
        ],
        activation_host_boot_id_sha256=activation[
            "host_boot_id_sha256"
        ],
    )


def _effect_origin_record(
    snapshot: _JournalSnapshot,
) -> transaction_journal.TransactionJournalRecord:
    candidates = tuple(
        record
        for record in snapshot.records
        if record.state in protocol.EFFECT_ORIGIN_STATES
    )
    if not candidates:
        raise _error(
            "lifecycle_client_recovery_effect_origin_missing"
        )
    selected = candidates[-1]
    clearance_records = tuple(
        record
        for record in snapshot.records
        if record.state == "lifecycle_clearance_intent"
    )
    if clearance_records:
        if len(clearance_records) != 1:
            raise _error(
                "lifecycle_client_journal_history_binding_invalid"
            )
        details = clearance_records[0].details
        if (
            details["effect_origin_state"] != selected.state
            or not hmac.compare_digest(
                details["effect_origin_record_sha256"],
                selected.record_sha256,
            )
        ):
            raise _error(
                "lifecycle_client_recovery_effect_origin_changed"
            )
    return selected


def _validate_scope_started_against_snapshot(
    snapshot: _JournalSnapshot,
    receipt: Mapping[str, Any] | None,
    receipt_sha256: str | None,
) -> dict[str, Any] | None:
    running_records = tuple(
        record
        for record in snapshot.records
        if record.state == "child_running"
    )
    if receipt is None:
        if receipt_sha256 is not None or running_records:
            raise _error(
                "lifecycle_client_recovery_started_receipt_missing"
            )
        return None
    if receipt_sha256 is None:
        raise _error(
            "lifecycle_client_recovery_started_receipt_digest_missing"
        )
    try:
        normalized = lifecycle_receipts.normalize_scope_started_receipt(
            receipt
        )
        expected_digest = (
            lifecycle_receipts.scope_started_receipt_sha256(
                normalized
            )
        )
    except lifecycle_receipts.LifecycleReceiptError as exc:
        raise _error(
            "lifecycle_client_recovery_started_receipt_invalid"
        ) from exc
    observed_digest = _digest(
        receipt_sha256,
        code="lifecycle_client_recovery_started_digest_invalid",
    )
    if not hmac.compare_digest(expected_digest, observed_digest):
        raise _error(
            "lifecycle_client_recovery_started_digest_mismatch"
        )
    staging_intent = _record(snapshot, "staging_create_intent")
    exposure = _record(snapshot, "staging_exposed")
    launch = _record(snapshot, "child_launch_intent")
    activation = launch.details["lifecycle_activation_receipt"]
    activation_digest = launch.details[
        "lifecycle_activation_receipt_sha256"
    ]
    scope_id, incarnation, _known_started_digest = _scope_values(
        snapshot
    )
    expected_stable = {
        "capture_session_id": snapshot.session_id,
        "lifecycle_backend": lifecycle_receipts.LIFECYCLE_BACKEND,
        "lifecycle_provider": activation["lifecycle_provider"],
        "lifecycle_scope_id": scope_id,
        "scope_incarnation_id": incarnation,
        "host_boot_id_sha256": activation[
            "host_boot_id_sha256"
        ],
        "staging_transaction_intent_sha256": (
            staging_intent.record_sha256
        ),
        "staging_exposure_receipt_sha256": exposure.details[
            "staging_exposure_receipt_sha256"
        ],
        "child_launch_intent_record_sha256": launch.record_sha256,
        "handoff_policy_sha256": launch.to_dict()[
            "handoff_policy_sha256"
        ],
        "helper_activation_policy_sha256": activation[
            "helper_activation_policy_sha256"
        ],
        "capture_uid": staging_intent.details["capture_uid"],
        "export_gid": staging_intent.details["export_gid"],
        "lifecycle_activation_receipt_sha256": activation_digest,
    }
    if any(
        normalized[field] != value
        for field, value in expected_stable.items()
    ):
        raise _error(
            "lifecycle_client_recovery_started_binding_mismatch"
        )
    if running_records:
        if len(running_records) != 1:
            raise _error(
                "lifecycle_client_journal_history_binding_invalid"
            )
        known = running_records[0].details
        if (
            normalized != known["lifecycle_scope_started_receipt"]
            or not hmac.compare_digest(
                observed_digest,
                known["lifecycle_scope_started_receipt_sha256"],
            )
        ):
            raise _error(
                "lifecycle_client_recovery_started_binding_changed"
            )
    return normalized


def _validate_clearance_bundle_against_snapshot(
    snapshot: _JournalSnapshot,
    bundle: Mapping[str, Any],
    bundle_sha256: str,
) -> dict[str, Any]:
    try:
        normalized = lifecycle_receipts.normalize_clearance_bundle(
            bundle
        )
        expected_digest = (
            lifecycle_receipts.clearance_bundle_sha256(normalized)
        )
    except lifecycle_receipts.LifecycleReceiptError as exc:
        raise _error(
            "lifecycle_client_clearance_bundle_invalid"
        ) from exc
    observed_digest = _digest(
        bundle_sha256,
        code="lifecycle_client_clearance_bundle_digest_invalid",
    )
    if not hmac.compare_digest(expected_digest, observed_digest):
        raise _error(
            "lifecycle_client_clearance_bundle_digest_mismatch"
        )
    launch = _record(snapshot, "child_launch_intent")
    activation = launch.details["lifecycle_activation_receipt"]
    activation_digest = launch.details[
        "lifecycle_activation_receipt_sha256"
    ]
    if (
        normalized["activation_receipt"] != activation
        or not hmac.compare_digest(
            normalized["activation_receipt_sha256"],
            activation_digest,
        )
    ):
        raise _error(
            "lifecycle_client_clearance_activation_binding_changed"
        )
    _validate_scope_started_against_snapshot(
        snapshot,
        normalized["scope_started_receipt"],
        normalized["scope_started_receipt_sha256"],
    )
    clearance = _record(snapshot, "lifecycle_clearance_intent")
    details = clearance.details
    origin = _record(snapshot, details["effect_origin_state"])
    scope_id, incarnation, _known_started_digest = _scope_values(
        snapshot
    )
    intent = normalized["clearance_intent_receipt"]
    expected_intent = {
        "capture_session_id": snapshot.session_id,
        "lifecycle_backend": lifecycle_receipts.LIFECYCLE_BACKEND,
        "lifecycle_provider": activation["lifecycle_provider"],
        "lifecycle_scope_id": scope_id,
        "scope_incarnation_id": incarnation,
        "lifecycle_activation_receipt_sha256": activation_digest,
        "child_launch_intent_record_sha256": launch.record_sha256,
        "effect_origin_state": origin.state,
        "effect_origin_record_sha256": origin.record_sha256,
        "scope_started_receipt_sha256": details[
            "scope_started_receipt_sha256"
        ],
        "clearance_mode": details["clearance_mode"],
        "outer_clearance_intent_record_sha256": (
            clearance.record_sha256
        ),
    }
    if any(
        intent[field] != value
        for field, value in expected_intent.items()
    ):
        raise _error(
            "lifecycle_client_clearance_intent_binding_changed"
        )
    accepted_empty_records = tuple(
        record
        for record in snapshot.records
        if record.state == "lifecycle_scope_empty"
    )
    if accepted_empty_records:
        if len(accepted_empty_records) != 1:
            raise _error(
                "lifecycle_client_journal_history_binding_invalid"
            )
        accepted = accepted_empty_records[0].details
        if (
            normalized != accepted[
                "lifecycle_clearance_bundle"
            ]
            or not hmac.compare_digest(
                observed_digest,
                accepted["lifecycle_clearance_bundle_sha256"],
            )
        ):
            raise _error(
                "lifecycle_client_clearance_bundle_changed"
            )
    return normalized


def _validate_recovery_result_against_snapshot(
    snapshot: _JournalSnapshot,
    result: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        normalized = protocol.normalize_operation_result(
            "recover_scope", result
        )
    except protocol.LifecycleSupervisorProtocolError as exc:
        raise _error("lifecycle_client_recovery_result_invalid") from exc
    scope_id, incarnation, _started_digest = _scope_values(snapshot)
    expected_scope = {
        "capture_session_id": snapshot.session_id,
        "lifecycle_scope_id": scope_id,
        "scope_incarnation_id": incarnation,
    }
    if any(
        normalized[field] != value
        for field, value in expected_scope.items()
    ):
        raise _error("lifecycle_client_recovery_scope_binding_changed")
    origin = _record(
        snapshot, normalized["effect_origin_state"]
    )
    if (
        normalized["effect_origin_record_revision"]
        != origin.revision
        or not hmac.compare_digest(
            normalized["effect_origin_record_sha256"],
            origin.record_sha256,
        )
    ):
        raise _error(
            "lifecycle_client_recovery_effect_origin_changed"
        )
    _validate_scope_started_against_snapshot(
        snapshot,
        normalized["scope_started_receipt"],
        normalized["scope_started_receipt_sha256"],
    )
    bundle = normalized["clearance_bundle"]
    scope_empty_already_accepted = any(
        record.state == "lifecycle_scope_empty"
        for record in snapshot.records
    )
    if (
        scope_empty_already_accepted
        and normalized["recovery_state"] != "settled_bundle"
    ):
        raise _error(
            "lifecycle_client_recovery_settlement_regressed"
        )
    if bundle is not None:
        _validate_clearance_bundle_against_snapshot(
            snapshot,
            bundle,
            normalized["clearance_bundle_sha256"],
        )
    return normalized


class _AuthenticatedClearanceExchange:
    __slots__ = ("__bundle", "__bundle_sha256", "__used")

    def __init__(
        self,
        *,
        _token: object,
        bundle: Mapping[str, Any],
        bundle_sha256: str,
    ) -> None:
        if _token is not _AUTHENTICATED_EXCHANGE_TOKEN:
            raise TypeError(
                "_AuthenticatedClearanceExchange "
                "cannot be constructed directly"
            )
        normalized = lifecycle_receipts.normalize_clearance_bundle(
            bundle
        )
        expected = lifecycle_receipts.clearance_bundle_sha256(
            normalized
        )
        observed = _digest(
            bundle_sha256,
            code="lifecycle_client_clearance_bundle_digest_invalid",
        )
        if not hmac.compare_digest(observed, expected):
            raise _error(
                "lifecycle_client_clearance_bundle_digest_mismatch"
            )
        self.__bundle = protocol.canonical_json(normalized)
        self.__bundle_sha256 = observed
        self.__used = False

    def take(self) -> tuple[dict[str, Any], str]:
        if self.__used:
            raise _error(
                "lifecycle_client_authenticated_exchange_consumed"
            )
        self.__used = True
        value = json.loads(self.__bundle.decode("ascii"))
        if not isinstance(value, dict):
            raise AssertionError("clearance bundle is not an object")
        return value, self.__bundle_sha256


def _mint_authenticated_clearance_proof(
    exchange: _AuthenticatedClearanceExchange,
) -> tuple[dict[str, Any], str, lifecycle_receipts.ScopeClearanceProof]:
    if type(exchange) is not _AuthenticatedClearanceExchange:
        raise _error("lifecycle_client_authenticated_exchange_required")
    bundle, bundle_sha256 = exchange.take()
    # This capability is only an in-process linearity aid: underscore names and
    # Python object tokens are reachable inside one process and are not security
    # authority.  Authority comes from the authenticated root exchange, its
    # fully correlated isolated bundle, and the process boundary.  Both public
    # production entrypoints remain disabled while that boundary is unproven.
    proof = lifecycle_receipts._mint_scope_clearance_proof(bundle)
    return bundle, bundle_sha256, proof


class _ScopedExchangeTranscript:
    __slots__ = (
        "result",
        "request_id",
        "request_sha256",
        "response_sha256",
    )

    def __init__(
        self,
        *,
        result: Mapping[str, Any],
        request_id: str,
        request_sha256: str,
        response_sha256: str,
    ) -> None:
        self.result = dict(result)
        self.request_id = request_id
        self.request_sha256 = request_sha256
        self.response_sha256 = response_sha256


class LifecycleSupervisorPendingCaptureEvent:
    """Authenticated capture-ready event awaiting exact local evidence."""

    __slots__ = ("__result", "__binding", "__lease")

    def __init__(
        self,
        *,
        _token: object,
        result: Mapping[str, Any],
        binding: Mapping[str, Any],
        lease: transaction_journal.TransactionJournalOperationLease,
    ) -> None:
        if _token is not _PENDING_EVENT_RESULT_TOKEN:
            raise TypeError(
                "LifecycleSupervisorPendingCaptureEvent "
                "cannot be constructed directly"
            )
        try:
            normalized = protocol.normalize_operation_result(
                (
                    "recover_scope"
                    if lease.operation == "recover_scope"
                    else "await_capture_event"
                ),
                result,
            )
            normalized_binding = (
                transaction_journal.normalize_lifecycle_operation_binding(
                    binding
                )
            )
        except (
            protocol.LifecycleSupervisorProtocolError,
            transaction_journal.TransactionJournalError,
        ) as exc:
            raise _error(
                "lifecycle_client_pending_event_invalid"
            ) from exc
        event = normalized["event"]
        if (
            event != "capture_ready"
            or normalized["event_evidence_sha256"] is None
            or normalized_binding["supervisor_event"] != event
            or normalized_binding[
                "supervisor_event_evidence_sha256"
            ]
            != normalized["event_evidence_sha256"]
            or lease.state != "dispatched"
        ):
            raise _error("lifecycle_client_pending_event_invalid")
        self.__result = protocol.canonical_json(normalized)
        self.__binding = protocol.canonical_json(
            normalized_binding
        )
        self.__lease = lease

    @property
    def result(self) -> dict[str, Any]:
        value = json.loads(self.__result.decode("ascii"))
        if not isinstance(value, dict):
            raise AssertionError("pending event is not an object")
        return value

    @property
    def event_sequence(self) -> int:
        return self.result["event_sequence"]

    @property
    def event_record_sha256(self) -> str:
        return self.result["event_record_sha256"]

    @property
    def event_evidence_sha256(self) -> str:
        value = self.result["event_evidence_sha256"]
        if value is None:
            raise AssertionError("capture-ready evidence is missing")
        return value

    @property
    def ledger_head_sha256(self) -> str:
        return self.result["ledger_head_sha256"]

    def commit_capture_ready(
        self,
        details: Mapping[str, Any],
        *,
        recorded_at_unix: int,
    ) -> transaction_journal.TransactionJournalRecord:
        if self.__lease.state != "dispatched":
            raise _error("lifecycle_client_pending_event_consumed")
        try:
            observed = protocol.capture_event_evidence_sha256(details)
            if not hmac.compare_digest(
                observed, self.event_evidence_sha256
            ):
                raise _error(
                    "lifecycle_client_capture_event_evidence_mismatch"
                )
            binding = json.loads(self.__binding.decode("ascii"))
            if not isinstance(binding, dict):
                raise TypeError("binding is not an object")
            permit = self.__lease.mint_successor_permit(
                next_state="capture_ready",
                details=details,
                lifecycle_operation_binding=binding,
                recorded_at_unix=recorded_at_unix,
            )
            return permit.commit()
        except transaction_journal.TransactionJournalError as exc:
            if self.__lease.state == "dispatched":
                self.__lease.require_recovery()
            raise _error(
                "lifecycle_client_capture_event_commit_failed"
            ) from exc
        except LifecycleSupervisorClientError:
            if self.__lease.state == "dispatched":
                self.__lease.require_recovery()
            raise
        except (TypeError, ValueError) as exc:
            if self.__lease.state == "dispatched":
                self.__lease.require_recovery()
            raise _error(
                "lifecycle_client_capture_event_commit_failed"
            ) from exc

    def require_recovery(self) -> None:
        if self.__lease.state != "dispatched":
            raise _error("lifecycle_client_pending_event_consumed")
        try:
            self.__lease.require_recovery()
        except transaction_journal.TransactionJournalError as exc:
            raise _error(
                "lifecycle_client_pending_event_recovery_failed"
            ) from exc

    def __copy__(self) -> Any:
        raise TypeError(
            "LifecycleSupervisorPendingCaptureEvent is not copyable"
        )

    def __deepcopy__(self, memo: Any) -> Any:
        del memo
        raise TypeError(
            "LifecycleSupervisorPendingCaptureEvent is not copyable"
        )

    def __reduce__(self) -> Any:
        raise TypeError(
            "LifecycleSupervisorPendingCaptureEvent is not serializable"
        )

    def __reduce_ex__(self, protocol_version: int) -> Any:
        del protocol_version
        raise TypeError(
            "LifecycleSupervisorPendingCaptureEvent is not serializable"
        )


class LifecycleSupervisorClearanceResult:
    """Validated clearance evidence plus its one-shot local capability."""

    __slots__ = (
        "__bundle",
        "__bundle_sha256",
        "__ledger_head_sha256",
        "__outer_record_sha256",
        "__proof",
    )

    def __init__(
        self,
        *,
        _token: object,
        bundle: Mapping[str, Any],
        bundle_sha256: str,
        ledger_head_sha256: str,
        outer_record_sha256: str,
        proof: lifecycle_receipts.ScopeClearanceProof,
    ) -> None:
        if _token is not _CLEARANCE_RESULT_TOKEN:
            raise TypeError(
                "LifecycleSupervisorClearanceResult "
                "cannot be constructed directly"
            )
        if type(proof) is not lifecycle_receipts.ScopeClearanceProof:
            raise TypeError("an exact ScopeClearanceProof is required")
        normalized = lifecycle_receipts.normalize_clearance_bundle(
            bundle
        )
        expected_bundle_sha256 = (
            lifecycle_receipts.clearance_bundle_sha256(normalized)
        )
        observed_bundle_sha256 = _digest(
            bundle_sha256,
            code="lifecycle_client_clearance_bundle_digest_invalid",
        )
        if not hmac.compare_digest(
            expected_bundle_sha256, observed_bundle_sha256
        ):
            raise _error(
                "lifecycle_client_clearance_bundle_digest_mismatch"
            )
        self.__bundle = protocol.canonical_json(normalized)
        self.__bundle_sha256 = observed_bundle_sha256
        self.__ledger_head_sha256 = _digest(
            ledger_head_sha256,
            code="lifecycle_client_ledger_head_invalid",
        )
        self.__outer_record_sha256 = _digest(
            outer_record_sha256,
            code="lifecycle_client_outer_record_invalid",
        )
        self.__proof = proof

    @property
    def clearance_bundle(self) -> dict[str, Any]:
        value = json.loads(self.__bundle.decode("ascii"))
        if not isinstance(value, dict):
            raise AssertionError("clearance bundle is not an object")
        return value

    @property
    def clearance_bundle_sha256(self) -> str:
        return self.__bundle_sha256

    @property
    def ledger_head_sha256(self) -> str:
        return self.__ledger_head_sha256

    @property
    def outer_record_sha256(self) -> str:
        return self.__outer_record_sha256

    @property
    def scope_clearance_proof(
        self,
    ) -> lifecycle_receipts.ScopeClearanceProof:
        return self.__proof

    def __reduce__(self) -> Any:
        raise TypeError(
            "LifecycleSupervisorClearanceResult is not serializable"
        )

    def __reduce_ex__(self, protocol_version: int) -> Any:
        del protocol_version
        raise TypeError(
            "LifecycleSupervisorClearanceResult is not serializable"
        )


class LifecycleSupervisorRecoveryResult:
    """Exactly reconciled recovery state with optional clearance authority."""

    __slots__ = (
        "__result",
        "__clearance_result",
        "__pending_capture_event",
        "__outer_record_sha256",
    )

    def __init__(
        self,
        *,
        _token: object,
        result: Mapping[str, Any],
        clearance_result: (
            LifecycleSupervisorClearanceResult | None
        ),
        pending_capture_event: (
            LifecycleSupervisorPendingCaptureEvent | None
        ),
        outer_record_sha256: str | None,
    ) -> None:
        if _token is not _RECOVERY_RESULT_TOKEN:
            raise TypeError(
                "LifecycleSupervisorRecoveryResult "
                "cannot be constructed directly"
            )
        try:
            normalized = protocol.normalize_operation_result(
                "recover_scope", result
            )
        except protocol.LifecycleSupervisorProtocolError as exc:
            raise _error(
                "lifecycle_client_recovery_result_invalid"
            ) from exc
        settled = normalized["recovery_state"] == "settled_bundle"
        if settled is not (
            type(clearance_result)
            is LifecycleSupervisorClearanceResult
        ):
            raise _error(
                "lifecycle_client_recovery_clearance_result_mismatch"
            )
        pending = (
            normalized["recovery_state"] == "capture_event"
            and normalized["event"] == "capture_ready"
        )
        if pending is not (
            type(pending_capture_event)
            is LifecycleSupervisorPendingCaptureEvent
        ):
            raise _error(
                "lifecycle_client_recovery_pending_event_mismatch"
            )
        self.__result = protocol.canonical_json(normalized)
        self.__clearance_result = clearance_result
        self.__pending_capture_event = pending_capture_event
        self.__outer_record_sha256 = _nullable_digest(
            outer_record_sha256,
            code="lifecycle_client_outer_record_invalid",
        )

    @property
    def result(self) -> dict[str, Any]:
        value = json.loads(self.__result.decode("ascii"))
        if not isinstance(value, dict):
            raise AssertionError("recovery result is not an object")
        return value

    @property
    def recovery_state(self) -> str:
        return self.result["recovery_state"]

    @property
    def clearance_result(
        self,
    ) -> LifecycleSupervisorClearanceResult | None:
        return self.__clearance_result

    @property
    def pending_capture_event(
        self,
    ) -> LifecycleSupervisorPendingCaptureEvent | None:
        return self.__pending_capture_event

    @property
    def outer_record_sha256(self) -> str | None:
        return self.__outer_record_sha256

    def __reduce__(self) -> Any:
        raise TypeError(
            "LifecycleSupervisorRecoveryResult is not serializable"
        )

    def __reduce_ex__(self, protocol_version: int) -> Any:
        del protocol_version
        raise TypeError(
            "LifecycleSupervisorRecoveryResult is not serializable"
        )


class LifecycleSupervisorClient:
    """Measured one-request lifecycle supervisor client."""

    __slots__ = (
        "_config",
        "_socket_factory",
        "_random_bytes",
        "_validate_socket",
        "_socket_owner_uid",
        "_trusted_socket_root",
        "_client_incarnation_id",
        "_used_random",
        "_random_lock",
        "_lock",
    )

    def __init__(
        self,
        config: LoadedLifecycleSupervisorClientConfig,
    ) -> None:
        if not PRODUCTION_ACTIVATION:
            raise _error("lifecycle_client_production_disabled")
        if type(config) is not LoadedLifecycleSupervisorClientConfig:
            raise _error("lifecycle_client_loaded_config_required")
        self._initialize(
            config.value,
            socket_factory=socket.socket,
            random_bytes=secrets.token_bytes,
            validate_socket=True,
            socket_owner_uid=0,
            trusted_socket_root=None,
        )

    def _initialize(
        self,
        config: Mapping[str, Any],
        *,
        socket_factory: Callable[..., socket.socket],
        random_bytes: Callable[[int], bytes],
        validate_socket: bool,
        socket_owner_uid: int,
        trusted_socket_root: Path | None,
    ) -> None:
        if not callable(socket_factory) or not callable(random_bytes):
            raise _error("lifecycle_client_test_seam_invalid")
        self._config = normalize_client_config(config)
        self._socket_factory = socket_factory
        self._random_bytes = random_bytes
        self._validate_socket = bool(validate_socket)
        self._socket_owner_uid = _identity(
            socket_owner_uid,
            code="lifecycle_client_socket_owner_uid_invalid",
            allow_root=True,
        )
        self._trusted_socket_root = trusted_socket_root
        self._used_random: set[str] = set()
        self._random_lock = threading.Lock()
        self._lock = threading.Lock()
        self._client_incarnation_id = self._fresh_hex(32)

    @property
    def client_incarnation_id(self) -> str:
        return self._client_incarnation_id

    def _fresh_hex(self, count: int) -> str:
        with self._random_lock:
            for _attempt in range(MAX_RANDOM_ATTEMPTS):
                try:
                    raw = self._random_bytes(count)
                except BaseException as exc:
                    raise _error(
                        "lifecycle_client_randomness_unavailable"
                    ) from exc
                if type(raw) is not bytes or len(raw) != count:
                    raise _error("lifecycle_client_randomness_invalid")
                value = raw.hex()
                if (
                    value != "0" * (count * 2)
                    and value not in self._used_random
                ):
                    self._used_random.add(value)
                    return value
        raise _error("lifecycle_client_randomness_collision")

    def _fresh_request_id(self) -> str:
        return f"jlqreq-{self._fresh_hex(16)}"

    def _open_authenticated_socket(
        self,
    ) -> socket.socket:
        before: _SocketIdentity | None = None
        if self._validate_socket:
            before = _validate_socket_leaf(
                self._config,
                expected_owner_uid=self._socket_owner_uid,
                trusted_root=self._trusted_socket_root,
            )
        try:
            client = self._socket_factory(
                socket.AF_UNIX, socket.SOCK_STREAM
            )
        except (OSError, TypeError) as exc:
            raise LifecycleSupervisorTransportError(
                "lifecycle_client_socket_create_failed"
            ) from exc
        try:
            client.settimeout(
                float(self._config["connect_timeout_seconds"])
            )
            try:
                client.connect(self._config["socket_path"])
            except (socket.timeout, OSError) as exc:
                raise LifecycleSupervisorTransportError(
                    "lifecycle_client_connect_failed"
                ) from exc
            try:
                observed_peer = _peer_uid(client)
            except LifecycleSupervisorClientError as exc:
                raise LifecycleSupervisorTransportError(exc.code) from exc
            if observed_peer != self._config["supervisor_uid"]:
                raise LifecycleSupervisorTransportError(
                    "lifecycle_client_peer_uid_mismatch"
                )
            if self._validate_socket:
                after = _validate_socket_leaf(
                    self._config,
                    expected_owner_uid=self._socket_owner_uid,
                    trusted_root=self._trusted_socket_root,
                )
                if before is None or not before.same_as(after):
                    raise LifecycleSupervisorTransportError(
                        "lifecycle_client_socket_changed"
                    )
            client.settimeout(
                float(self._config["request_timeout_seconds"])
            )
            return client
        except BaseException:
            client.close()
            raise

    def _exchange(
        self,
        *,
        operation: str,
        payload_builder: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        expected_activation_receipt_sha256: str | None,
        journal_snapshot: _JournalSnapshot | None,
        scope_incarnation_id: str | None,
        operation_lease: (
            transaction_journal.TransactionJournalOperationLease | None
        ) = None,
        failure_recorded_at_unix: int | None = None,
    ) -> _ScopedExchangeTranscript:
        if operation not in protocol.OPERATIONS:
            raise _error("lifecycle_client_operation_invalid")
        scoped = operation != "get_activation"
        if scoped is not (
            type(operation_lease)
            is transaction_journal.TransactionJournalOperationLease
        ) or scoped is not (journal_snapshot is not None):
            raise _error("lifecycle_client_operation_lease_binding_invalid")
        if operation_lease is not None and (
            operation_lease.operation != operation
            or journal_snapshot is None
            or operation_lease.base_record_revision
            != journal_snapshot.revision
            or operation_lease.base_record_sha256
            != journal_snapshot.record_sha256
        ):
            raise _error("lifecycle_client_operation_lease_binding_invalid")
        if scoped and type(failure_recorded_at_unix) is not int:
            raise _error("lifecycle_client_recorded_at_unix_invalid")
        expected_activation = _nullable_digest(
            expected_activation_receipt_sha256,
            code="lifecycle_client_activation_receipt_invalid",
        )
        with self._lock:
            hello_request_id = self._fresh_request_id()
            operation_request_id = self._fresh_request_id()
            client_nonce = self._fresh_hex(32)
            client_hello = protocol.build_client_hello(
                instance_slug=self._config["instance_slug"],
                request_id=hello_request_id,
                client_incarnation_id=self._client_incarnation_id,
                client_nonce=client_nonce,
                expected_supervisor_policy_sha256=self._config[
                    "expected_supervisor_policy_sha256"
                ],
                expected_supervisor_bundle_sha256=self._config[
                    "expected_supervisor_bundle_sha256"
                ],
                expected_helper_activation_policy_sha256=self._config[
                    "expected_helper_activation_policy_sha256"
                ],
                expected_lifecycle_canary_sha256=self._config[
                    "expected_lifecycle_canary_sha256"
                ],
            )
            client: socket.socket | None = None
            request_sent = False
            request_digest: str | None = None
            try:
                client = self._open_authenticated_socket()
                handshake_deadline = (
                    time.monotonic()
                    + self._config["connect_timeout_seconds"]
                )
                _send_frame(
                    client,
                    client_hello,
                    ambiguous=False,
                    deadline=handshake_deadline,
                )
                raw_server_hello = _read_frame(
                    client,
                    ambiguous=False,
                    deadline=handshake_deadline,
                )
                try:
                    server_hello = protocol.validate_server_hello(
                        client_hello, raw_server_hello
                    )
                except protocol.LifecycleSupervisorProtocolError as exc:
                    raise LifecycleSupervisorTransportError(
                        "lifecycle_client_handshake_invalid"
                    ) from exc
                observed_activation = server_hello[
                    "activation_receipt_sha256"
                ]
                if operation in {"start_scope", "await_capture_event"}:
                    if (
                        expected_activation is None
                        or observed_activation is None
                        or not hmac.compare_digest(
                            expected_activation, observed_activation
                        )
                    ):
                        raise LifecycleSupervisorRecoveryRequiredError(
                            "activation_mismatch",
                            operation=operation,
                            request_id=operation_request_id,
                            capture_session_id=(
                                None
                                if journal_snapshot is None
                                else journal_snapshot.session_id
                            ),
                            scope_incarnation_id=scope_incarnation_id,
                            observed_ledger_head_sha256=None,
                            request_dispatched=False,
                        )
                elif operation in {
                    "request_clearance",
                    "recover_scope",
                }:
                    # The authenticated supervisor may be in a newer boot
                    # epoch than the durable launch.  These operations bind
                    # scope identity and evidence to the old launch activation
                    # in their payload while authenticating the non-null
                    # current activation independently in this handshake.
                    if (
                        expected_activation is None
                        or observed_activation is None
                    ):
                        raise LifecycleSupervisorTransportError(
                            "lifecycle_client_activation_binding_missing"
                        )
                elif (
                    expected_activation is not None
                    and observed_activation is not None
                    and not hmac.compare_digest(
                        expected_activation, observed_activation
                    )
                ):
                    raise LifecycleSupervisorTransportError(
                        "lifecycle_client_activation_binding_mismatch"
                    )
                if journal_snapshot is not None:
                    _assert_live_snapshot(journal_snapshot)
                try:
                    payload = payload_builder(server_hello)
                    guard = protocol.ClientExchangeGuard(
                        client_hello, server_hello
                    )
                    request = guard.build_request(
                        request_id=operation_request_id,
                        operation=operation,
                        payload=payload,
                    )
                except protocol.LifecycleSupervisorProtocolError as exc:
                    raise _error(
                        "lifecycle_client_request_binding_invalid"
                    ) from exc
                operation_deadline = (
                    time.monotonic()
                    + self._config["request_timeout_seconds"]
                )
                request_digest = protocol.request_sha256(request)
                if operation_lease is not None:
                    try:
                        operation_lease.mark_dispatched(request_digest)
                    except transaction_journal.TransactionJournalError as exc:
                        raise _error(
                            "lifecycle_client_operation_dispatch_barrier_failed"
                        ) from exc
                request_sent = True
                _send_frame(
                    client,
                    request,
                    ambiguous=True,
                    deadline=operation_deadline,
                )
                raw_response = _read_frame(
                    client,
                    ambiguous=True,
                    deadline=operation_deadline,
                )
                try:
                    response = guard.accept_response(raw_response)
                except protocol.LifecycleSupervisorProtocolError as exc:
                    raise _error(
                        "lifecycle_client_ambiguous_response_invalid"
                    ) from exc
                if journal_snapshot is not None:
                    try:
                        _assert_live_snapshot(journal_snapshot)
                    except LifecycleSupervisorClientError as exc:
                        raise _error(
                            "lifecycle_client_ambiguous_journal_changed"
                        ) from exc
                response_digest = protocol.sha256_json(response)
                if response["status"] == "error":
                    error_outcome = response["error_outcome"]
                    observed_head = response[
                        "observed_ledger_head_sha256"
                    ]
                    capture_session_id = (
                        None
                        if journal_snapshot is None
                        else journal_snapshot.session_id
                    )
                    if protocol.error_outcome_is_no_effect(
                        error_outcome
                    ):
                        if (
                            operation_lease is not None
                            and request_digest is not None
                        ):
                            binding = _operation_binding(
                                lease=operation_lease,
                                request_sha256=request_digest,
                                response_sha256=response_digest,
                                outcome="no_effect",
                                error_code=response["error_code"],
                                result=None,
                                supervisor_ledger_head_sha256=(
                                    observed_head
                                ),
                            )
                            try:
                                operation_lease.complete_no_effect(
                                    binding
                                )
                            except (
                                transaction_journal.TransactionJournalError
                            ) as exc:
                                raise _error(
                                    "lifecycle_client_no_effect_release_failed"
                                ) from exc
                        raise LifecycleSupervisorRemoteError(
                            response["error_code"],
                            error_outcome=error_outcome,
                            observed_ledger_head_sha256=(
                                observed_head
                            ),
                        )
                    recovery_required = (
                        protocol.error_outcome_requires_recovery(
                            error_outcome
                        )
                    )
                    attention_required = (
                        protocol.error_outcome_requires_operator_attention(
                            error_outcome
                        )
                    )
                    if recovery_required or attention_required:
                        if (
                            operation_lease is None
                            or request_digest is None
                            or journal_snapshot is None
                        ):
                            raise _error(
                                "lifecycle_client_failure_barrier_missing"
                            )
                        outcome = (
                            "recovery"
                            if recovery_required
                            else "attention"
                        )
                        binding = _operation_binding(
                            lease=operation_lease,
                            request_sha256=request_digest,
                            response_sha256=response_digest,
                            outcome=outcome,
                            error_code=response["error_code"],
                            result=None,
                            supervisor_ledger_head_sha256=observed_head,
                        )
                        try:
                            permit = operation_lease.mint_successor_permit(
                                next_state="operator_attention",
                                details={
                                    "reason_code": response[
                                        "error_code"
                                    ]
                                },
                                lifecycle_operation_binding=binding,
                                recorded_at_unix=(
                                    _journal_timestamp(
                                        journal_snapshot,
                                        failure_recorded_at_unix,
                                    )
                                ),
                            )
                            permit.commit()
                        except (
                            transaction_journal.TransactionJournalError
                        ) as exc:
                            raise _error(
                                "lifecycle_client_failure_barrier_failed"
                            ) from exc
                    if recovery_required:
                        raise LifecycleSupervisorRecoveryRequiredError(
                            response["error_code"],
                            operation=operation,
                            request_id=operation_request_id,
                            capture_session_id=capture_session_id,
                            scope_incarnation_id=scope_incarnation_id,
                            observed_ledger_head_sha256=(
                                observed_head
                            ),
                            request_dispatched=True,
                        )
                    if attention_required:
                        raise LifecycleSupervisorOperatorAttentionError(
                            response["error_code"],
                            operation=operation,
                            request_id=operation_request_id,
                            capture_session_id=capture_session_id,
                            scope_incarnation_id=scope_incarnation_id,
                            observed_ledger_head_sha256=(
                                observed_head
                            ),
                        )
                    raise _error(
                        "lifecycle_client_ambiguous_response_invalid"
                    )
                if request_digest is None:
                    request_digest = protocol.request_sha256(request)
                return _ScopedExchangeTranscript(
                    result=response["result"],
                    request_id=operation_request_id,
                    request_sha256=request_digest,
                    response_sha256=response_digest,
                )
            except (
                LifecycleSupervisorRemoteError,
                LifecycleSupervisorRecoveryRequiredError,
                LifecycleSupervisorOperatorAttentionError,
            ) as exc:
                if (
                    operation_lease is not None
                    and operation_lease.state == "open"
                ):
                    try:
                        if isinstance(
                            exc,
                            LifecycleSupervisorRecoveryRequiredError,
                        ):
                            operation_lease.require_recovery()
                        else:
                            operation_lease.cancel_before_dispatch()
                    except transaction_journal.TransactionJournalError as cause:
                        raise _error(
                            "lifecycle_client_operation_barrier_failed"
                        ) from cause
                raise
            except LifecycleSupervisorAmbiguousError:
                raise
            except LifecycleSupervisorClientError as exc:
                if operation_lease is not None:
                    try:
                        if operation_lease.state == "open":
                            operation_lease.cancel_before_dispatch()
                        elif operation_lease.state == "dispatched":
                            operation_lease.require_recovery()
                    except transaction_journal.TransactionJournalError as cause:
                        raise _error(
                            "lifecycle_client_operation_barrier_failed"
                        ) from cause
                if request_sent:
                    raise LifecycleSupervisorAmbiguousError(
                        exc.code,
                        operation=operation,
                        request_id=operation_request_id,
                        capture_session_id=(
                            None
                            if journal_snapshot is None
                            else journal_snapshot.session_id
                        ),
                        scope_incarnation_id=scope_incarnation_id,
                    ) from exc
                raise
            except (socket.timeout, OSError) as exc:
                if operation_lease is not None:
                    try:
                        if operation_lease.state == "open":
                            operation_lease.cancel_before_dispatch()
                        elif operation_lease.state == "dispatched":
                            operation_lease.require_recovery()
                    except transaction_journal.TransactionJournalError as cause:
                        raise _error(
                            "lifecycle_client_operation_barrier_failed"
                        ) from cause
                if request_sent:
                    raise LifecycleSupervisorAmbiguousError(
                        "lifecycle_client_ambiguous_transport",
                        operation=operation,
                        request_id=operation_request_id,
                        capture_session_id=(
                            None
                            if journal_snapshot is None
                            else journal_snapshot.session_id
                        ),
                        scope_incarnation_id=scope_incarnation_id,
                    ) from exc
                raise LifecycleSupervisorTransportError(
                    "lifecycle_client_transport_failed"
                ) from exc
            finally:
                if client is not None:
                    client.close()

    def get_activation(
        self,
        *,
        expected_activation_receipt_sha256: str | None = None,
    ) -> dict[str, Any]:
        expected = _nullable_digest(
            expected_activation_receipt_sha256,
            code="lifecycle_client_activation_receipt_invalid",
        )

        def payload(server: Mapping[str, Any]) -> Mapping[str, Any]:
            selected_expected = (
                server["activation_receipt_sha256"]
                if expected is None
                else expected
            )
            return {
                "expected_activation_receipt_sha256": (
                    selected_expected
                ),
                "expected_supervisor_policy_sha256": self._config[
                    "expected_supervisor_policy_sha256"
                ],
                "expected_supervisor_bundle_sha256": self._config[
                    "expected_supervisor_bundle_sha256"
                ],
                "expected_helper_activation_policy_sha256": self._config[
                    "expected_helper_activation_policy_sha256"
                ],
                "expected_lifecycle_canary_sha256": self._config[
                    "expected_lifecycle_canary_sha256"
                ],
            }

        transcript = self._exchange(
            operation="get_activation",
            payload_builder=payload,
            expected_activation_receipt_sha256=expected,
            journal_snapshot=None,
            scope_incarnation_id=None,
        )
        return transcript.result

    def start_scope(
        self,
        journal_session: transaction_journal.TransactionJournalSession,
        *,
        recorded_at_unix: int,
    ) -> dict[str, Any]:
        snapshot = _scan_live_journal(
            journal_session,
            instance_slug=self._config["instance_slug"],
            permitted_states=frozenset({"child_launch_intent"}),
        )
        staging_intent = _record(snapshot, "staging_create_intent")
        exposure = _record(snapshot, "staging_exposed")
        launch = _record(snapshot, "child_launch_intent")
        activation = launch.details["lifecycle_activation_receipt"]
        activation_digest = launch.details[
            "lifecycle_activation_receipt_sha256"
        ]
        scope_incarnation_id = protocol.derive_scope_incarnation_id(
            instance_slug=snapshot.instance_slug,
            capture_session_id=snapshot.session_id,
            child_launch_intent_record_sha256=launch.record_sha256,
            lifecycle_activation_receipt_sha256=activation_digest,
        )
        payload = {
            "capture_session_id": snapshot.session_id,
            "lifecycle_scope_id": (
                f"jlq-root_supervisor-{snapshot.session_id}"
            ),
            "scope_incarnation_id": scope_incarnation_id,
            "child_launch_intent_record_revision": launch.revision,
            "child_launch_intent_record_sha256": launch.record_sha256,
            "staging_transaction_intent_sha256": (
                staging_intent.record_sha256
            ),
            "staging_exposure_receipt_sha256": exposure.details[
                "staging_exposure_receipt_sha256"
            ],
            "handoff_policy_sha256": launch.to_dict()[
                "handoff_policy_sha256"
            ],
            "helper_activation_policy_sha256": activation[
                "helper_activation_policy_sha256"
            ],
            "lifecycle_provider": activation[
                "lifecycle_provider"
            ],
            "capture_uid": staging_intent.details["capture_uid"],
            "export_gid": staging_intent.details["export_gid"],
            "lifecycle_activation_receipt_sha256": activation_digest,
        }
        lease = _begin_scoped_operation(snapshot, "start_scope")
        transcript = self._exchange(
            operation="start_scope",
            payload_builder=lambda _server: payload,
            expected_activation_receipt_sha256=activation_digest,
            journal_snapshot=snapshot,
            scope_incarnation_id=scope_incarnation_id,
            operation_lease=lease,
            failure_recorded_at_unix=recorded_at_unix,
        )
        try:
            _validate_scope_started_against_snapshot(
                snapshot,
                transcript.result["scope_started_receipt"],
                transcript.result["scope_started_receipt_sha256"],
            )
            binding = _success_binding(
                lease=lease,
                request_sha256=transcript.request_sha256,
                response_sha256=transcript.response_sha256,
                result=transcript.result,
            )
            permit = lease.mint_successor_permit(
                next_state="child_running",
                details={
                    "lifecycle_scope_started_receipt": (
                        transcript.result["scope_started_receipt"]
                    ),
                    "lifecycle_scope_started_receipt_sha256": (
                        transcript.result[
                            "scope_started_receipt_sha256"
                        ]
                    ),
                },
                lifecycle_operation_binding=binding,
                recorded_at_unix=_journal_timestamp(
                    snapshot, recorded_at_unix
                ),
            )
            permit.commit()
        except (
            LifecycleSupervisorClientError,
            transaction_journal.TransactionJournalError,
        ) as exc:
            if lease.state == "dispatched":
                lease.require_recovery()
            raise LifecycleSupervisorAmbiguousError(
                (
                    exc.code
                    if hasattr(exc, "code")
                    else "lifecycle_client_start_outer_commit_failed"
                ),
                operation="start_scope",
                request_id=transcript.request_id,
                capture_session_id=snapshot.session_id,
                scope_incarnation_id=scope_incarnation_id,
            ) from exc
        return transcript.result

    def await_capture_event(
        self,
        journal_session: transaction_journal.TransactionJournalSession,
        *,
        timeout_seconds: int,
        recorded_at_unix: int,
    ) -> (
        LifecycleSupervisorPendingCaptureEvent
        | transaction_journal.TransactionJournalRecord
    ):
        snapshot = _scan_live_journal(
            journal_session,
            instance_slug=self._config["instance_slug"],
            permitted_states=frozenset(
                {"child_running", "capture_ready"}
            ),
        )
        if (
            type(timeout_seconds) is not int
            or timeout_seconds
            > self._config["request_timeout_seconds"]
        ):
            raise _error("lifecycle_client_timeout_exceeds_config")
        launch = _record(snapshot, "child_launch_intent")
        running = _record(snapshot, "child_running")
        started = running.details["lifecycle_scope_started_receipt"]
        activation_digest = launch.details[
            "lifecycle_activation_receipt_sha256"
        ]
        expected_ledger_head_sha256, after_event_sequence = (
            _binding_from_records(snapshot)
        )
        if expected_ledger_head_sha256 is None:
            raise _error(
                "lifecycle_client_journal_ledger_head_binding_missing"
            )
        payload = {
            "capture_session_id": snapshot.session_id,
            "lifecycle_scope_id": started["lifecycle_scope_id"],
            "scope_incarnation_id": started["scope_incarnation_id"],
            "scope_started_receipt_sha256": running.details[
                "lifecycle_scope_started_receipt_sha256"
            ],
            "child_launch_intent_record_sha256": launch.record_sha256,
            "outer_journal_record_state": snapshot.state,
            "outer_journal_record_revision": snapshot.revision,
            "outer_journal_record_sha256": snapshot.record_sha256,
            "expected_ledger_head_sha256": (
                expected_ledger_head_sha256
            ),
            "after_event_sequence": after_event_sequence,
            "timeout_seconds": timeout_seconds,
        }
        lease = _begin_scoped_operation(
            snapshot, "await_capture_event"
        )
        transcript = self._exchange(
            operation="await_capture_event",
            payload_builder=lambda _server: payload,
            expected_activation_receipt_sha256=activation_digest,
            journal_snapshot=snapshot,
            scope_incarnation_id=started["scope_incarnation_id"],
            operation_lease=lease,
            failure_recorded_at_unix=recorded_at_unix,
        )
        try:
            binding = _success_binding(
                lease=lease,
                request_sha256=transcript.request_sha256,
                response_sha256=transcript.response_sha256,
                result=transcript.result,
            )
            if transcript.result["event"] == "capture_ready":
                return LifecycleSupervisorPendingCaptureEvent(
                    _token=_PENDING_EVENT_RESULT_TOKEN,
                    result=transcript.result,
                    binding=binding,
                    lease=lease,
                )
            origin = _effect_origin_record(snapshot)
            _scope_id, _incarnation, started_digest = _scope_values(
                snapshot
            )
            clearance_mode = (
                "terminate_and_clear"
                if origin.state != "capture_ready"
                else "wait_clean_then_terminate_on_deadline"
            )
            permit = lease.mint_successor_permit(
                next_state="lifecycle_clearance_intent",
                details={
                    "effect_origin_state": origin.state,
                    "effect_origin_record_revision": origin.revision,
                    "effect_origin_record_sha256": (
                        origin.record_sha256
                    ),
                    "scope_started_receipt_sha256": started_digest,
                    "clearance_mode": clearance_mode,
                },
                lifecycle_operation_binding=binding,
                recorded_at_unix=_journal_timestamp(
                    snapshot, recorded_at_unix
                ),
            )
            return permit.commit()
        except (
            LifecycleSupervisorClientError,
            transaction_journal.TransactionJournalError,
        ) as exc:
            if lease.state == "dispatched":
                lease.require_recovery()
            raise LifecycleSupervisorAmbiguousError(
                (
                    exc.code
                    if hasattr(exc, "code")
                    else "lifecycle_client_event_outer_commit_failed"
                ),
                operation="await_capture_event",
                request_id=transcript.request_id,
                capture_session_id=snapshot.session_id,
                scope_incarnation_id=started["scope_incarnation_id"],
            ) from exc

    def request_clearance(
        self,
        journal_session: transaction_journal.TransactionJournalSession,
        *,
        timeout_seconds: int,
        recorded_at_unix: int,
    ) -> LifecycleSupervisorClearanceResult:
        snapshot = _scan_live_journal(
            journal_session,
            instance_slug=self._config["instance_slug"],
            permitted_states=frozenset(
                {"lifecycle_clearance_intent"}
            ),
        )
        if (
            type(timeout_seconds) is not int
            or timeout_seconds
            > self._config["request_timeout_seconds"]
        ):
            raise _error("lifecycle_client_timeout_exceeds_config")
        launch = _record(snapshot, "child_launch_intent")
        clearance = _record(snapshot, "lifecycle_clearance_intent")
        scope_id, incarnation, started_digest = _scope_values(
            snapshot,
        )
        details = clearance.details
        if details["scope_started_receipt_sha256"] != started_digest:
            raise _error("lifecycle_client_scope_started_binding_changed")
        origin = _record(snapshot, details["effect_origin_state"])
        if not hmac.compare_digest(
            origin.record_sha256,
            details["effect_origin_record_sha256"],
        ):
            raise _error("lifecycle_client_effect_origin_binding_changed")
        activation_digest = launch.details[
            "lifecycle_activation_receipt_sha256"
        ]
        expected_ledger_head_sha256 = _required_ledger_head(snapshot)
        payload = {
            "capture_session_id": snapshot.session_id,
            "lifecycle_scope_id": scope_id,
            "scope_incarnation_id": incarnation,
            "lifecycle_activation_receipt_sha256": activation_digest,
            "child_launch_intent_record_sha256": launch.record_sha256,
            "effect_origin_state": origin.state,
            "effect_origin_record_revision": origin.revision,
            "effect_origin_record_sha256": origin.record_sha256,
            "scope_started_receipt_sha256": started_digest,
            "clearance_mode": details["clearance_mode"],
            "lifecycle_clearance_intent_record_revision": (
                clearance.revision
            ),
            "lifecycle_clearance_intent_record_sha256": (
                clearance.record_sha256
            ),
            "expected_ledger_head_sha256": (
                expected_ledger_head_sha256
            ),
            "timeout_seconds": timeout_seconds,
        }
        lease = _begin_scoped_operation(
            snapshot, "request_clearance"
        )
        transcript = self._exchange(
            operation="request_clearance",
            payload_builder=lambda _server: payload,
            expected_activation_receipt_sha256=activation_digest,
            journal_snapshot=snapshot,
            scope_incarnation_id=incarnation,
            operation_lease=lease,
            failure_recorded_at_unix=recorded_at_unix,
        )
        try:
            reconciled_bundle = (
                _validate_clearance_bundle_against_snapshot(
                    snapshot,
                    transcript.result["clearance_bundle"],
                    transcript.result["clearance_bundle_sha256"],
                )
            )
            binding = _success_binding(
                lease=lease,
                request_sha256=transcript.request_sha256,
                response_sha256=transcript.response_sha256,
                result=transcript.result,
            )
            permit = lease.mint_successor_permit(
                next_state="lifecycle_scope_empty",
                details={
                    "lifecycle_clearance_bundle": reconciled_bundle,
                    "lifecycle_clearance_bundle_sha256": (
                        transcript.result[
                            "clearance_bundle_sha256"
                        ]
                    ),
                },
                lifecycle_operation_binding=binding,
                recorded_at_unix=_journal_timestamp(
                    snapshot, recorded_at_unix
                ),
            )
            outer_record = permit.commit()
            authenticated = _AuthenticatedClearanceExchange(
                _token=_AUTHENTICATED_EXCHANGE_TOKEN,
                bundle=reconciled_bundle,
                bundle_sha256=transcript.result[
                    "clearance_bundle_sha256"
                ],
            )
            bundle, bundle_sha256, proof = (
                _mint_authenticated_clearance_proof(authenticated)
            )
            return LifecycleSupervisorClearanceResult(
                _token=_CLEARANCE_RESULT_TOKEN,
                bundle=bundle,
                bundle_sha256=bundle_sha256,
                ledger_head_sha256=transcript.result[
                    "ledger_head_sha256"
                ],
                outer_record_sha256=outer_record.record_sha256,
                proof=proof,
            )
        except (
            LifecycleSupervisorClientError,
            lifecycle_receipts.LifecycleReceiptError,
            transaction_journal.TransactionJournalError,
        ) as exc:
            if lease.state == "dispatched":
                lease.require_recovery()
            raise LifecycleSupervisorAmbiguousError(
                (
                    exc.code
                    if hasattr(exc, "code")
                    else "lifecycle_client_clearance_proof_failed"
                ),
                operation="request_clearance",
                request_id=transcript.request_id,
                capture_session_id=snapshot.session_id,
                scope_incarnation_id=incarnation,
            ) from exc

    def recover_scope(
        self,
        journal_session: transaction_journal.TransactionJournalSession,
        *,
        recovery_reason: str,
        recorded_at_unix: int,
    ) -> LifecycleSupervisorRecoveryResult:
        snapshot = _scan_live_journal(
            journal_session,
            instance_slug=self._config["instance_slug"],
            permitted_states=protocol.OUTER_RECORD_STATES,
        )
        launch = _record(snapshot, "child_launch_intent")
        scope_id, incarnation, started_digest = _scope_values(
            snapshot,
        )
        effect_origin = _effect_origin_record(snapshot)
        clearance_records = tuple(
            record
            for record in snapshot.records
            if record.state == "lifecycle_clearance_intent"
        )
        if len(clearance_records) > 1:
            raise _error(
                "lifecycle_client_journal_history_binding_invalid"
            )
        clearance_record = (
            clearance_records[0] if clearance_records else None
        )
        activation_digest = launch.details[
            "lifecycle_activation_receipt_sha256"
        ]
        expected_ledger_head_sha256, _event_sequence = (
            _binding_from_records(snapshot)
        )
        payload = {
            "capture_session_id": snapshot.session_id,
            "lifecycle_scope_id": scope_id,
            "scope_incarnation_id": incarnation,
            "lifecycle_activation_receipt_sha256": activation_digest,
            "child_launch_intent_record_revision": launch.revision,
            "child_launch_intent_record_sha256": launch.record_sha256,
            "outer_journal_record_state": snapshot.state,
            "outer_journal_record_revision": snapshot.revision,
            "outer_journal_record_sha256": snapshot.record_sha256,
            "expected_scope_started_receipt_sha256": started_digest,
            "expected_scope_start_authorization_sha256": (
                _scope_start_authorization_sha256(snapshot)
            ),
            "expected_effect_origin_state": effect_origin.state,
            "expected_effect_origin_record_revision": (
                effect_origin.revision
            ),
            "expected_effect_origin_record_sha256": (
                effect_origin.record_sha256
            ),
            "expected_clearance_intent_record_revision": (
                None
                if clearance_record is None
                else clearance_record.revision
            ),
            "expected_clearance_intent_record_sha256": (
                None
                if clearance_record is None
                else clearance_record.record_sha256
            ),
            "expected_clearance_mode": (
                None
                if clearance_record is None
                else clearance_record.details["clearance_mode"]
            ),
            "expected_ledger_head_sha256": expected_ledger_head_sha256,
            "recovery_reason": recovery_reason,
        }
        lease = _begin_scoped_operation(snapshot, "recover_scope")
        transcript = self._exchange(
            operation="recover_scope",
            payload_builder=lambda _server: payload,
            expected_activation_receipt_sha256=activation_digest,
            journal_snapshot=snapshot,
            scope_incarnation_id=incarnation,
            operation_lease=lease,
            failure_recorded_at_unix=recorded_at_unix,
        )
        try:
            reconciled = _validate_recovery_result_against_snapshot(
                snapshot, transcript.result
            )
            binding = _success_binding(
                lease=lease,
                request_sha256=transcript.request_sha256,
                response_sha256=transcript.response_sha256,
                result=reconciled,
            )
            clearance_result: (
                LifecycleSupervisorClearanceResult | None
            ) = None
            pending_capture_event: (
                LifecycleSupervisorPendingCaptureEvent | None
            ) = None
            outer_record: (
                transaction_journal.TransactionJournalRecord | None
            ) = None
            recovery_state = reconciled["recovery_state"]
            current_state = snapshot.state
            attention_origin = (
                snapshot.records[-1].details["from_state"]
                if current_state == "operator_attention"
                else None
            )
            if attention_origin in protocol.EFFECT_ORIGIN_STATES:
                origin = _record(snapshot, attention_origin)
                permit = lease.mint_successor_permit(
                    next_state="lifecycle_clearance_intent",
                    details={
                        "effect_origin_state": origin.state,
                        "effect_origin_record_revision": (
                            origin.revision
                        ),
                        "effect_origin_record_sha256": (
                            origin.record_sha256
                        ),
                        "scope_started_receipt_sha256": (
                            None
                            if origin.state == "child_launch_intent"
                            else started_digest
                        ),
                        "clearance_mode": (
                            "wait_clean_then_terminate_on_deadline"
                            if origin.state == "capture_ready"
                            else "terminate_and_clear"
                        ),
                    },
                    lifecycle_operation_binding=binding,
                    recorded_at_unix=_journal_timestamp(
                        snapshot, recorded_at_unix
                    ),
                )
                outer_record = permit.commit()
            elif (
                attention_origin == "lifecycle_clearance_intent"
                and recovery_state == "settled_bundle"
            ):
                permit = lease.mint_successor_permit(
                    next_state="lifecycle_scope_empty",
                    details={
                        "lifecycle_clearance_bundle": reconciled[
                            "clearance_bundle"
                        ],
                        "lifecycle_clearance_bundle_sha256": (
                            reconciled["clearance_bundle_sha256"]
                        ),
                    },
                    lifecycle_operation_binding=binding,
                    recorded_at_unix=_journal_timestamp(
                        snapshot, recorded_at_unix
                    ),
                )
                outer_record = permit.commit()
            elif current_state == "operator_attention":
                lease.require_recovery()
            elif recovery_state == "scope_started" and (
                current_state == "child_launch_intent"
            ):
                permit = lease.mint_successor_permit(
                    next_state="child_running",
                    details={
                        "lifecycle_scope_started_receipt": (
                            reconciled["scope_started_receipt"]
                        ),
                        "lifecycle_scope_started_receipt_sha256": (
                            reconciled[
                                "scope_started_receipt_sha256"
                            ]
                        ),
                    },
                    lifecycle_operation_binding=binding,
                    recorded_at_unix=_journal_timestamp(
                        snapshot, recorded_at_unix
                    ),
                )
                outer_record = permit.commit()
            elif recovery_state == "capture_event" and (
                reconciled["event"] == "capture_ready"
            ):
                if current_state == "child_running":
                    pending_capture_event = (
                        LifecycleSupervisorPendingCaptureEvent(
                            _token=_PENDING_EVENT_RESULT_TOKEN,
                            result=reconciled,
                            binding=binding,
                            lease=lease,
                        )
                    )
                elif current_state == "capture_ready":
                    existing = snapshot.records[-1].details[
                        "lifecycle_operation_binding"
                    ]
                    expected_replay = {
                        "supervisor_ledger_head_sha256": (
                            reconciled["ledger_head_sha256"]
                        ),
                        "supervisor_event_sequence": (
                            reconciled["event_sequence"]
                        ),
                        "supervisor_event": reconciled["event"],
                        "supervisor_event_record_sha256": (
                            reconciled["event_record_sha256"]
                        ),
                        "supervisor_event_evidence_sha256": (
                            reconciled["event_evidence_sha256"]
                        ),
                    }
                    if any(
                        existing[field] != value
                        for field, value in expected_replay.items()
                    ):
                        raise _error(
                            "lifecycle_client_recovery_event_replay_changed"
                        )
                    lease.complete_success_no_change(binding)
                    outer_record = snapshot.records[-1]
                else:
                    raise _error(
                        "lifecycle_client_recovery_event_state_invalid"
                    )
            elif recovery_state == "capture_event":
                if current_state not in {
                    "child_running",
                    "capture_ready",
                }:
                    raise _error(
                        "lifecycle_client_recovery_event_state_invalid"
                    )
                origin = _effect_origin_record(snapshot)
                permit = lease.mint_successor_permit(
                    next_state="lifecycle_clearance_intent",
                    details={
                        "effect_origin_state": origin.state,
                        "effect_origin_record_revision": (
                            origin.revision
                        ),
                        "effect_origin_record_sha256": (
                            origin.record_sha256
                        ),
                        "scope_started_receipt_sha256": started_digest,
                        "clearance_mode": (
                            "terminate_and_clear"
                            if origin.state != "capture_ready"
                            else (
                                "wait_clean_then_terminate_on_deadline"
                            )
                        ),
                    },
                    lifecycle_operation_binding=binding,
                    recorded_at_unix=_journal_timestamp(
                        snapshot, recorded_at_unix
                    ),
                )
                outer_record = permit.commit()
            elif recovery_state == "settled_bundle":
                if current_state == "lifecycle_scope_empty":
                    lease.complete_success_no_change(binding)
                    outer_record = snapshot.records[-1]
                elif current_state == "lifecycle_clearance_intent":
                    permit = lease.mint_successor_permit(
                        next_state="lifecycle_scope_empty",
                        details={
                            "lifecycle_clearance_bundle": reconciled[
                                "clearance_bundle"
                            ],
                            "lifecycle_clearance_bundle_sha256": (
                                reconciled[
                                    "clearance_bundle_sha256"
                                ]
                            ),
                        },
                        lifecycle_operation_binding=binding,
                        recorded_at_unix=_journal_timestamp(
                            snapshot, recorded_at_unix
                        ),
                    )
                    outer_record = permit.commit()
                else:
                    raise _error(
                        "lifecycle_client_recovery_settlement_state_invalid"
                    )
            elif (
                recovery_state == "start_intent"
                and current_state == "child_launch_intent"
            ):
                origin = _record(snapshot, "child_launch_intent")
                permit = lease.mint_successor_permit(
                    next_state="lifecycle_clearance_intent",
                    details={
                        "effect_origin_state": origin.state,
                        "effect_origin_record_revision": origin.revision,
                        "effect_origin_record_sha256": (
                            origin.record_sha256
                        ),
                        "scope_started_receipt_sha256": None,
                        "clearance_mode": "terminate_and_clear",
                    },
                    lifecycle_operation_binding=binding,
                    recorded_at_unix=_journal_timestamp(
                        snapshot, recorded_at_unix
                    ),
                )
                outer_record = permit.commit()
            elif (
                recovery_state == "scope_started"
                and current_state == "child_running"
            ) or (
                recovery_state in {
                    "clearance_intent",
                    "provider_observation",
                }
                and current_state == "lifecycle_clearance_intent"
            ):
                lease.complete_success_no_change(binding)
                outer_record = snapshot.records[-1]
            elif recovery_state in {
                "clearance_intent",
                "provider_observation",
            }:
                lease.require_recovery()
            else:
                raise _error(
                    "lifecycle_client_recovery_state_transition_invalid"
                )
            if reconciled["recovery_state"] == "settled_bundle":
                authenticated = _AuthenticatedClearanceExchange(
                    _token=_AUTHENTICATED_EXCHANGE_TOKEN,
                    bundle=reconciled["clearance_bundle"],
                    bundle_sha256=reconciled[
                        "clearance_bundle_sha256"
                    ],
                )
                bundle, bundle_sha256, proof = (
                    _mint_authenticated_clearance_proof(authenticated)
                )
                clearance_result = LifecycleSupervisorClearanceResult(
                    _token=_CLEARANCE_RESULT_TOKEN,
                    bundle=bundle,
                    bundle_sha256=bundle_sha256,
                    ledger_head_sha256=reconciled[
                        "ledger_head_sha256"
                    ],
                    outer_record_sha256=(
                        outer_record.record_sha256
                        if outer_record is not None
                        else snapshot.record_sha256
                    ),
                    proof=proof,
                )
            return LifecycleSupervisorRecoveryResult(
                _token=_RECOVERY_RESULT_TOKEN,
                result=reconciled,
                clearance_result=clearance_result,
                pending_capture_event=pending_capture_event,
                outer_record_sha256=(
                    None
                    if outer_record is None
                    else outer_record.record_sha256
                ),
            )
        except (
            LifecycleSupervisorClientError,
            lifecycle_receipts.LifecycleReceiptError,
            transaction_journal.TransactionJournalError,
        ) as exc:
            if lease.state == "dispatched":
                lease.require_recovery()
            raise LifecycleSupervisorAmbiguousError(
                (
                    exc.code
                    if hasattr(exc, "code")
                    else "lifecycle_client_recovery_proof_failed"
                ),
                operation="recover_scope",
                request_id=transcript.request_id,
                capture_session_id=snapshot.session_id,
                scope_incarnation_id=incarnation,
            ) from exc


def _new_lifecycle_supervisor_client_for_test(
    config: Mapping[str, Any],
    *,
    socket_factory: Callable[..., socket.socket],
    random_bytes: Callable[[int], bytes],
    validate_socket: bool = False,
    socket_owner_uid: int = 0,
    trusted_socket_root: Path | None = None,
) -> LifecycleSupervisorClient:
    """Private construction seam; public production activation stays false."""

    client = LifecycleSupervisorClient.__new__(
        LifecycleSupervisorClient
    )
    client._initialize(
        config,
        socket_factory=socket_factory,
        random_bytes=random_bytes,
        validate_socket=validate_socket,
        socket_owner_uid=socket_owner_uid,
        trusted_socket_root=trusted_socket_root,
    )
    return client


__all__ = [
    "CLIENT_CONFIG_SCHEMA",
    "LifecycleSupervisorAmbiguousError",
    "LifecycleSupervisorClearanceResult",
    "LifecycleSupervisorClient",
    "LifecycleSupervisorClientError",
    "LifecycleSupervisorOperatorAttentionError",
    "LifecycleSupervisorPendingCaptureEvent",
    "LifecycleSupervisorRemoteError",
    "LifecycleSupervisorRecoveryRequiredError",
    "LifecycleSupervisorRecoveryResult",
    "LifecycleSupervisorTransportError",
    "LoadedLifecycleSupervisorClientConfig",
    "PRODUCTION_ACTIVATION",
    "TRANSACTION_JOURNAL_OPERATION_LEASE_MISSING",
    "load_client_config",
    "normalize_client_config",
]
