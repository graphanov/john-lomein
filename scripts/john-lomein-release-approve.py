#!/usr/bin/env python3
"""Process one exact protected-release approval from the current Discord message.

This helper is deliberately credential-free. It trusts neither Hermes session
identity nor approval text as authorization. The session channel/message IDs
only identify the Discord message that the isolated owner gateway must
independently re-fetch and authenticate. The helper then prepares one packet
and makes exactly one submission attempt to the protected release broker.
"""

from __future__ import annotations

import argparse
import grp
import importlib.util
import json
import os
import pwd
import re
import secrets
import shlex
import socket
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import john_lomein_release_packets as packets
from john_lomein_owner_actions import release_owner_approval_text


INVOCATION_SCHEMA = "john-lomein.release-owner-gateway-invocation.v2"
RESULT_SCHEMA = "john-lomein.current-release-approval-result.v1"
STATUS_SCHEMA = "john-lomein.protected-release-runtime-status.v1"
GATEWAY_SELF_CHECK_SCHEMA = (
    "john-lomein.release-owner-gateway-self-check.v1"
)
PUBLIC_GATEWAY_CONFIG_ROOT = Path(
    "/private/etc/john-lomein-release-owner-gateway-public"
)
PUBLIC_BROKER_CONFIG_ROOT = Path(
    "/private/etc/john-lomein-release-broker-public"
)
OWNER_GATEWAY_SPOOL_ROOT = Path(
    "/private/var/db/john-lomein-release-owner-gateway/requests"
)
OWNER_GATEWAY_WRAPPER_ROOT = Path(
    "/usr/local/libexec/john-lomein-release-owner-gateway-instances"
)
SUDO = Path("/usr/bin/sudo")
MAX_INVOCATION_CONFIG_BYTES = 64 * 1024
MAX_SIGNER_RESPONSE_BYTES = 2 * 1024 * 1024

SNOWFLAKE_RE = re.compile(r"^[0-9]{17,20}$")
ACCOUNT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
RECORD_ID_RE = re.compile(r"^jlros-[0-9a-f]{24}$")
EVENT_ID_RE = re.compile(r"^jlroe-[0-9a-f]{24}$")
APPROVAL_RE = re.compile(
    r"^APPROVE JOHN-LOMEIN BUNDLE "
    r"(?P<bundle_id>jlb-[0-9a-f]{24}) DIGEST "
    r"(?P<bundle_digest>sha256:[0-9a-f]{64}): "
    r"squash-merge the listed PR with the protected release broker; "
    r"DO NOT publish\. Post-merge repository verification and any "
    r"publication require separate gates\.$"
)


class CurrentReleaseApprovalError(ValueError):
    """A public-safe refusal from the credential-free runtime helper."""


def _release_submit_module() -> ModuleType:
    name = "john_lomein_release_submit_runtime"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    path = SCRIPT_DIR / "john-lomein-release-submit.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise CurrentReleaseApprovalError(
            "release submission client is unavailable"
        )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        # Never retain a partially initialized module.  A second lookup from
        # the public error path could otherwise return an object missing its
        # exception classes and obscure the original deployment defect with
        # a secondary AttributeError.
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise CurrentReleaseApprovalError(
            "release submission client is unavailable"
        ) from exc
    return module


def _strict_keys(
    value: Mapping[str, Any],
    *,
    field: str,
    required: set[str],
) -> None:
    if set(value) != required:
        raise CurrentReleaseApprovalError(
            f"{field} fields do not match the fixed contract"
        )


def _runtime_home() -> Path:
    env_path = SCRIPT_DIR / "john-lomein-instance.env"
    if not env_path.exists():
        raise CurrentReleaseApprovalError(
            "current release approval helper is not deployed"
        )
    return SCRIPT_DIR.parent.resolve()


def _load_runtime_env(runtime_home: Path) -> dict[str, str]:
    client = _release_submit_module()
    path = runtime_home / "scripts" / "john-lomein-instance.env"
    raw = client.read_stable_file(
        path,
        field="deployed instance environment",
        maximum_bytes=256 * 1024,
        expected_owner_uids={os.getuid()},
        private_mode=True,
        parent_owner_uids={os.getuid()},
        trusted_path_root=runtime_home,
    )
    values: dict[str, str] = {}
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise CurrentReleaseApprovalError(
            "deployed instance environment is invalid"
        ) from exc
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise CurrentReleaseApprovalError(
                "deployed instance environment contains an unsafe key"
            )
        try:
            parts = shlex.split(value)
        except ValueError as exc:
            raise CurrentReleaseApprovalError(
                "deployed instance environment is malformed"
            ) from exc
        if len(parts) > 1:
            raise CurrentReleaseApprovalError(
                "deployed instance environment contains an unsafe value"
            )
        values[key] = parts[0] if parts else ""
    return values


def _runtime_binding(env: Mapping[str, str]) -> tuple[str, str, str]:
    slug = str(env.get("BOT_SLUG") or "")
    repository = str(env.get("BOT_REPO") or "")
    default_branch = str(env.get("BOT_DEFAULT_BRANCH") or "")
    if not packets.INSTANCE_RE.fullmatch(slug):
        raise CurrentReleaseApprovalError("runtime instance slug is invalid")
    if not packets.REPOSITORY_RE.fullmatch(repository):
        raise CurrentReleaseApprovalError("runtime repository is invalid")
    if not packets.BRANCH_RE.fullmatch(default_branch):
        raise CurrentReleaseApprovalError(
            "runtime default branch is invalid"
        )
    return slug, repository, default_branch


def _require_enabled(env: Mapping[str, str]) -> None:
    if env.get("BOT_MISSION_COMPLETE") != "1":
        raise CurrentReleaseApprovalError(
            "runtime owner mission is incomplete"
        )
    if env.get("BOT_MUTATION_ENABLED") != "1":
        raise CurrentReleaseApprovalError(
            "runtime mutation is disabled"
        )
    if env.get("BOT_PROTECTED_RELEASE_BROKER_ENABLED") != "1":
        raise CurrentReleaseApprovalError(
            "protected release broker is disabled by the instance manifest"
        )


def _session_ids(
    session_env: Mapping[str, str],
) -> tuple[str, str]:
    if str(session_env.get("HERMES_SESSION_PLATFORM") or "").casefold() != (
        "discord"
    ):
        raise CurrentReleaseApprovalError(
            "current release approval is not a regular Discord message"
        )
    channel_id = str(session_env.get("HERMES_SESSION_CHAT_ID") or "")
    message_id = str(session_env.get("HERMES_SESSION_MESSAGE_ID") or "")
    for value, field in (
        (channel_id, "Discord channel ID"),
        (message_id, "Discord message ID"),
    ):
        if not SNOWFLAKE_RE.fullmatch(value):
            raise CurrentReleaseApprovalError(
                f"current {field} is missing or invalid"
            )
    # HERMES_SESSION_USER_ID is intentionally not read. The isolated signer
    # derives actor identity by re-fetching the exact channel/message.
    return channel_id, message_id


def _approval_binding(approval_text: str) -> tuple[str, str]:
    if (
        not isinstance(approval_text, str)
        or not approval_text
        or len(approval_text.encode("utf-8")) > packets.MAX_APPROVAL_BYTES
        or "\x00" in approval_text
        or "\r" in approval_text
        or "\n" in approval_text
    ):
        raise CurrentReleaseApprovalError(
            "current release approval text is invalid"
        )
    match = APPROVAL_RE.fullmatch(approval_text)
    if match is None:
        raise CurrentReleaseApprovalError(
            "current message is not the exact generated release approval"
        )
    return match.group("bundle_id"), match.group("bundle_digest")


def _load_bound_bundle(
    runtime_home: Path,
    *,
    approval_text: str,
) -> dict[str, Any]:
    bundle_id, digest = _approval_binding(approval_text)
    path = (
        runtime_home
        / "private"
        / "release-bundles"
        / f"{bundle_id}.json"
    )
    raw = packets.load_json(path, field="release bundle")
    bundle = packets.normalize_bundle(raw)
    if bundle["bundle_id"] != bundle_id:
        raise CurrentReleaseApprovalError(
            "release approval bundle ID does not match the stored bundle"
        )
    if bundle["bundle_digest"] != digest:
        raise CurrentReleaseApprovalError(
            "release approval digest does not match the stored bundle"
        )
    if release_owner_approval_text(bundle) != approval_text:
        raise CurrentReleaseApprovalError(
            "release approval text does not exactly match the stored bundle"
        )
    return bundle


def _load_invocation_config(
    *,
    slug: str,
    repository: str,
) -> dict[str, Any]:
    client = _release_submit_module()
    path = PUBLIC_GATEWAY_CONFIG_ROOT / f"{slug}.json"
    raw = client.read_stable_file(
        path,
        field="release owner gateway invocation config",
        maximum_bytes=MAX_INVOCATION_CONFIG_BYTES,
        expected_owner_uids={0},
        private_mode=False,
        parent_owner_uids={0},
        trusted_path_root=PUBLIC_GATEWAY_CONFIG_ROOT,
    )
    parsed = client.parse_json_bytes(
        raw,
        field="release owner gateway invocation config",
        maximum_bytes=MAX_INVOCATION_CONFIG_BYTES,
    )
    if not isinstance(parsed, dict):
        raise CurrentReleaseApprovalError(
            "release owner gateway invocation config must be an object"
        )
    _strict_keys(
        parsed,
        field="release owner gateway invocation config",
        required={
            "schema_version",
            "instance_slug",
            "repository_full_name",
            "approval_channel_ids",
            "requester_uid",
            "signer_user",
            "signer_primary_group",
            "request_spool_dir",
            "wrapper_path",
        },
    )
    if parsed.get("schema_version") != INVOCATION_SCHEMA:
        raise CurrentReleaseApprovalError(
            "release owner gateway invocation config is unsupported"
        )
    if parsed.get("instance_slug") != slug:
        raise CurrentReleaseApprovalError(
            "release owner gateway instance binding differs"
        )
    if parsed.get("repository_full_name") != repository:
        raise CurrentReleaseApprovalError(
            "release owner gateway repository binding differs"
        )
    approval_channels = parsed.get("approval_channel_ids")
    if (
        not isinstance(approval_channels, list)
        or not approval_channels
        or any(
            not isinstance(channel_id, str)
            or SNOWFLAKE_RE.fullmatch(channel_id) is None
            for channel_id in approval_channels
        )
        or approval_channels != sorted(approval_channels)
        or len(approval_channels) != len(set(approval_channels))
    ):
        raise CurrentReleaseApprovalError(
            "release owner gateway approval channels are invalid"
        )
    requester_uid = parsed.get("requester_uid")
    if (
        isinstance(requester_uid, bool)
        or not isinstance(requester_uid, int)
        or requester_uid != os.getuid()
    ):
        raise CurrentReleaseApprovalError(
            "release owner gateway requester identity differs"
        )
    signer_user = str(parsed.get("signer_user") or "")
    signer_group = str(parsed.get("signer_primary_group") or "")
    if not ACCOUNT_RE.fullmatch(signer_user) or not ACCOUNT_RE.fullmatch(
        signer_group
    ):
        raise CurrentReleaseApprovalError(
            "release owner gateway signer identity is invalid"
        )
    expected_spool = OWNER_GATEWAY_SPOOL_ROOT / slug
    expected_wrapper = OWNER_GATEWAY_WRAPPER_ROOT / slug / "mint"
    if parsed.get("request_spool_dir") != str(expected_spool):
        raise CurrentReleaseApprovalError(
            "release owner gateway spool binding differs"
        )
    if parsed.get("wrapper_path") != str(expected_wrapper):
        raise CurrentReleaseApprovalError(
            "release owner gateway wrapper binding differs"
        )
    return dict(parsed)


def _manifest_channel_set(
    env: Mapping[str, str],
    key: str,
) -> set[str]:
    raw = str(env.get(key) or "")
    values = [value.strip() for value in raw.split(",") if value.strip()]
    if any(SNOWFLAKE_RE.fullmatch(value) is None for value in values):
        raise CurrentReleaseApprovalError(
            "protected release Discord channel policy is invalid"
        )
    return set(values)


def _validate_approval_channels(
    invocation: Mapping[str, Any],
    env: Mapping[str, str],
    *,
    current_channel_id: str | None = None,
) -> None:
    approval_channels = set(invocation["approval_channel_ids"])
    allowed_channels = _manifest_channel_set(env, "BOT_ALLOWED_CHANNELS")
    free_response_channels = _manifest_channel_set(
        env, "BOT_FREE_RESPONSE_CHANNELS"
    )
    no_thread_channels = _manifest_channel_set(
        env, "BOT_NO_THREAD_CHANNELS"
    )
    if (
        not approval_channels <= allowed_channels
        or not approval_channels <= free_response_channels
        or not approval_channels <= no_thread_channels
    ):
        raise CurrentReleaseApprovalError(
            "protected release approval channels must be allowed, "
            "free-response, and no-thread in the instance manifest"
        )
    if (
        current_channel_id is not None
        and current_channel_id not in approval_channels
    ):
        raise CurrentReleaseApprovalError(
            "current Discord channel is not configured for protected "
            "release approvals"
        )


def _open_spool_directory(path: Path) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CurrentReleaseApprovalError(
            "release owner gateway request spool is unavailable"
        ) from exc
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o2770
    ):
        os.close(descriptor)
        raise CurrentReleaseApprovalError(
            "release owner gateway request spool is unsafe"
        )
    return descriptor, info


def _read_existing_at(
    directory_fd: int,
    name: str,
    *,
    expected: bytes,
    expected_gid: int,
) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise CurrentReleaseApprovalError(
            "existing release owner gateway request is unreadable"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_gid != expected_gid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o640
            or before.st_size != len(expected)
        ):
            raise CurrentReleaseApprovalError(
                "existing release owner gateway request is unsafe"
            )
        data = bytearray()
        while len(data) <= len(expected):
            chunk = os.read(
                descriptor, min(64 * 1024, len(expected) + 1 - len(data))
            )
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        if (
            bytes(data) != expected
            or any(
                getattr(before, field) != getattr(after, field)
                for field in (
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
            )
        ):
            raise CurrentReleaseApprovalError(
                "existing release owner gateway request conflicts"
            )
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(descriptor, raw[offset:])
        if written <= 0:
            raise CurrentReleaseApprovalError(
                "release owner gateway request write made no progress"
            )
        offset += written


def _stage_bundle(
    bundle: Mapping[str, Any],
    *,
    spool_dir: Path,
) -> Path:
    normalized = packets.normalize_bundle(dict(bundle))
    expected = packets.canonical_json(normalized) + b"\n"
    digest_component = normalized["bundle_digest"].removeprefix("sha256:")
    final_name = f"{normalized['bundle_id']}.{digest_component}.json"
    directory_fd, directory_info = _open_spool_directory(spool_dir)
    temporary_name = (
        f".{final_name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    temporary_created = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(
            temporary_name,
            flags,
            0o640,
            dir_fd=directory_fd,
        )
        temporary_created = True
        try:
            _write_all(descriptor, expected)
            os.fchmod(descriptor, 0o640)
            info = os.fstat(descriptor)
            if (
                info.st_uid != os.getuid()
                or info.st_gid != directory_info.st_gid
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o640
            ):
                raise CurrentReleaseApprovalError(
                    "staged release owner gateway request is unsafe"
                )
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.link(
                temporary_name,
                final_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            _read_existing_at(
                directory_fd,
                final_name,
                expected=expected,
                expected_gid=directory_info.st_gid,
            )
        except OSError as exc:
            raise CurrentReleaseApprovalError(
                "release owner gateway request could not be installed"
            ) from exc
        os.fsync(directory_fd)
    finally:
        if temporary_created:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
                os.fsync(directory_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        os.close(directory_fd)
    return spool_dir / final_name


def _validate_wrapper(path: Path) -> None:
    client = _release_submit_module()
    client.validate_trusted_parent_chain(
        path.parent,
        field="release owner gateway wrapper",
        expected_owner_uids={0},
        trusted_path_root=OWNER_GATEWAY_WRAPPER_ROOT,
    )
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise CurrentReleaseApprovalError(
            "release owner gateway wrapper is unavailable"
        ) from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_nlink != 1
        or info.st_mode & 0o022
        or not info.st_mode & stat.S_IXUSR
    ):
        raise CurrentReleaseApprovalError(
            "release owner gateway wrapper is unsafe"
        )


def _run_signer(
    invocation: Mapping[str, Any],
    *,
    bundle_path: Path,
    channel_id: str,
    message_id: str,
) -> dict[str, Any]:
    wrapper = Path(str(invocation["wrapper_path"]))
    _validate_wrapper(wrapper)
    command = [
        str(SUDO),
        "-n",
        "-u",
        str(invocation["signer_user"]),
        "-g",
        str(invocation["signer_primary_group"]),
        "--",
        str(wrapper),
        "--bundle",
        str(bundle_path),
        "--channel-id",
        channel_id,
        "--message-id",
        message_id,
    ]
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            timeout=90,
            check=False,
            env={
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "C.UTF-8",
            },
        )
    except Exception as exc:
        raise CurrentReleaseApprovalError(
            "release owner gateway invocation failed"
        ) from exc
    if proc.returncode != 0:
        raise CurrentReleaseApprovalError(
            "release owner gateway refused the current message"
        )
    if proc.stderr:
        raise CurrentReleaseApprovalError(
            "release owner gateway returned unexpected diagnostic output"
        )
    client = _release_submit_module()
    parsed = client.parse_json_bytes(
        bytes(proc.stdout),
        field="release owner gateway response",
        maximum_bytes=MAX_SIGNER_RESPONSE_BYTES,
    )
    if not isinstance(parsed, dict):
        raise CurrentReleaseApprovalError(
            "release owner gateway response must be an object"
        )
    _strict_keys(
        parsed,
        field="release owner gateway response",
        required={
            "ok",
            "record_id",
            "event_id",
            "bundle_id",
            "owner_assertion_sha256",
            "owner_assertion",
        },
    )
    if parsed.get("ok") is not True:
        raise CurrentReleaseApprovalError(
            "release owner gateway did not authorize the current message"
        )
    if not RECORD_ID_RE.fullmatch(str(parsed.get("record_id") or "")):
        raise CurrentReleaseApprovalError(
            "release owner gateway record ID is invalid"
        )
    if not EVENT_ID_RE.fullmatch(str(parsed.get("event_id") or "")):
        raise CurrentReleaseApprovalError(
            "release owner gateway event ID is invalid"
        )
    assertion = parsed.get("owner_assertion")
    if not isinstance(assertion, dict):
        raise CurrentReleaseApprovalError(
            "release owner gateway assertion is invalid"
        )
    if parsed.get("owner_assertion_sha256") != packets.sha256_json(
        assertion
    ):
        raise CurrentReleaseApprovalError(
            "release owner gateway assertion digest differs"
        )
    return dict(parsed)


def _probe_gateway_authorization(
    invocation: Mapping[str, Any],
    *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> None:
    wrapper = Path(str(invocation["wrapper_path"]))
    command = [
        str(SUDO),
        "-n",
        "-l",
        "-u",
        str(invocation["signer_user"]),
        "-g",
        str(invocation["signer_primary_group"]),
        "--",
        str(wrapper),
        "--status",
    ]
    try:
        proc = runner(
            command,
            capture_output=True,
            timeout=15,
            check=False,
            env={
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "C.UTF-8",
            },
        )
    except Exception as exc:
        raise CurrentReleaseApprovalError(
            "release owner gateway authorization could not be inspected"
        ) from exc
    if proc.returncode != 0:
        raise CurrentReleaseApprovalError(
            "release owner gateway runtime authorization is disabled"
        )


def _run_gateway_self_check(
    invocation: Mapping[str, Any],
    *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> dict[str, Any]:
    command = [
        str(SUDO),
        "-n",
        "-u",
        str(invocation["signer_user"]),
        "-g",
        str(invocation["signer_primary_group"]),
        "--",
        str(invocation["wrapper_path"]),
        "--status",
    ]
    try:
        proc = runner(
            command,
            capture_output=True,
            timeout=30,
            check=False,
            env={
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "C.UTF-8",
            },
        )
    except Exception as exc:
        raise CurrentReleaseApprovalError(
            "release owner gateway self-check could not be invoked"
        ) from exc
    if proc.returncode != 0 or proc.stderr:
        raise CurrentReleaseApprovalError(
            "release owner gateway private self-check failed"
        )
    client = _release_submit_module()
    parsed = client.parse_json_bytes(
        bytes(proc.stdout),
        field="release owner gateway self-check",
        maximum_bytes=MAX_INVOCATION_CONFIG_BYTES,
    )
    if not isinstance(parsed, dict):
        raise CurrentReleaseApprovalError(
            "release owner gateway self-check must be an object"
        )
    _strict_keys(
        parsed,
        field="release owner gateway self-check",
        required={"schema_version", "enabled", "healthy"},
    )
    if (
        parsed.get("schema_version") != GATEWAY_SELF_CHECK_SCHEMA
        or type(parsed.get("enabled")) is not bool
        or parsed.get("healthy") is not True
    ):
        raise CurrentReleaseApprovalError(
            "release owner gateway self-check is invalid"
        )
    return dict(parsed)


def _validate_spool_membership(
    invocation: Mapping[str, Any],
    directory_info: os.stat_result,
) -> None:
    try:
        requester = pwd.getpwuid(os.getuid())
        signer = pwd.getpwnam(str(invocation["signer_user"]))
        signer_primary_group = grp.getgrgid(signer.pw_gid).gr_name
        requester_groups = set(os.getgroups()) | {requester.pw_gid}
        signer_groups = set(os.getgrouplist(signer.pw_name, signer.pw_gid))
    except (KeyError, OSError) as exc:
        raise CurrentReleaseApprovalError(
            "release owner gateway account/group membership is unavailable"
        ) from exc
    if signer_primary_group != invocation["signer_primary_group"]:
        raise CurrentReleaseApprovalError(
            "release owner gateway signer primary group differs"
        )
    if (
        directory_info.st_gid not in requester_groups
        or directory_info.st_gid not in signer_groups
    ):
        raise CurrentReleaseApprovalError(
            "release owner gateway request spool membership is incomplete"
        )


def _probe_broker_socket(
    config: Mapping[str, Any],
    *,
    socket_factory: Callable[..., socket.socket] = socket.socket,
    peer_uid_getter: Callable[[socket.socket], int] | None = None,
) -> None:
    client_module = _release_submit_module()
    client_module._validate_socket_file(config)
    client_socket = socket_factory(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client_socket.settimeout(float(config["connect_timeout_seconds"]))
        try:
            client_socket.connect(str(config["socket_path"]))
        except (OSError, socket.timeout) as exc:
            raise CurrentReleaseApprovalError(
                "protected release broker socket has no reachable listener"
            ) from exc
        peer_uid = (
            peer_uid_getter(client_socket)
            if peer_uid_getter is not None
            else client_module._peer_uid(client_socket)
        )
        if peer_uid != config["broker_uid"]:
            raise CurrentReleaseApprovalError(
                "protected release broker peer identity differs"
            )
    finally:
        client_socket.close()


def _load_broker_binding(
    *,
    slug: str,
    repository: str,
    default_branch: str,
) -> dict[str, Any]:
    client = _release_submit_module()
    loaded = client.load_client_config(
        PUBLIC_BROKER_CONFIG_ROOT / f"{slug}.json",
        trusted_path_root=PUBLIC_BROKER_CONFIG_ROOT,
    )
    config = loaded.value
    if config["instance_slug"] != slug:
        raise CurrentReleaseApprovalError(
            "protected release broker instance binding differs"
        )
    if config["repository"]["full_name"] != repository:
        raise CurrentReleaseApprovalError(
            "protected release broker repository binding differs"
        )
    if config["repository"]["default_branch"] != default_branch:
        raise CurrentReleaseApprovalError(
            "protected release broker default branch binding differs"
        )
    return config


def runtime_status(
    runtime_home: Path,
    *,
    env: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any], int]:
    runtime_env = dict(env or _load_runtime_env(runtime_home))
    slug, repository, default_branch = _runtime_binding(runtime_env)
    route_enabled = (
        runtime_env.get("BOT_MISSION_COMPLETE") == "1"
        and runtime_env.get("BOT_PROTECTED_RELEASE_BROKER_ENABLED") == "1"
        and runtime_env.get("BOT_MUTATION_ENABLED") == "1"
    )
    gateway_configured = False
    gateway_authorization_present = False
    gateway_private_enabled = False
    gateway_private_healthy = False
    broker_configured = False
    broker_listening = False
    gateway_reason = ""
    broker_reason = ""
    try:
        invocation = _load_invocation_config(
            slug=slug, repository=repository
        )
        _validate_approval_channels(invocation, runtime_env)
        _open_fd, _ = _open_spool_directory(
            Path(invocation["request_spool_dir"])
        )
        directory_info = os.fstat(_open_fd)
        os.close(_open_fd)
        _validate_spool_membership(invocation, directory_info)
        _validate_wrapper(Path(invocation["wrapper_path"]))
        gateway_configured = True
        _probe_gateway_authorization(invocation)
        gateway_authorization_present = True
        self_check = _run_gateway_self_check(invocation)
        gateway_private_enabled = self_check["enabled"] is True
        gateway_private_healthy = self_check["healthy"] is True
        if not gateway_private_enabled:
            gateway_reason = "release owner gateway private signer is disabled"
    except Exception as exc:
        gateway_reason = str(exc)
    try:
        config = _load_broker_binding(
            slug=slug,
            repository=repository,
            default_branch=default_branch,
        )
        broker_configured = True
        _probe_broker_socket(config)
        broker_listening = True
    except Exception as exc:
        broker_reason = str(exc)
    gateway_self_check_supported = True
    gateway_ready = (
        gateway_authorization_present
        and gateway_private_enabled
        and gateway_private_healthy
    )
    broker_ready = broker_listening
    ready = route_enabled and gateway_ready and broker_ready
    unexpected_privileged_surface = (
        not route_enabled
        and (
            gateway_authorization_present
            or gateway_private_enabled
            or broker_listening
        )
    )
    result = {
        "schema_version": STATUS_SCHEMA,
        "instance_slug": slug,
        "repository": repository,
        "enabled": route_enabled,
        "runtime_route_enabled": route_enabled,
        "ready": ready,
        "unexpected_privileged_surface": unexpected_privileged_surface,
        "owner_gateway": {
            "configured": gateway_configured,
            "authorization_present": gateway_authorization_present,
            "self_check_supported": gateway_self_check_supported,
            "private_enabled": gateway_private_enabled,
            "private_healthy": gateway_private_healthy,
            "ready": gateway_ready,
            "reason": "" if gateway_ready else gateway_reason,
        },
        "release_broker": {
            "configured": broker_configured,
            "listening": broker_listening,
            "peer_authenticated": broker_listening,
            "ready": broker_ready,
            "reason": "" if broker_listening else broker_reason,
        },
    }
    return result, (
        2
        if unexpected_privileged_surface or (route_enabled and not ready)
        else 0
    )


def approve_current_message(
    runtime_home: Path,
    *,
    approval_text: str,
    session_env: Mapping[str, str],
    runtime_env: Mapping[str, str] | None = None,
    invocation: Mapping[str, Any] | None = None,
    signer: Callable[..., dict[str, Any]] = _run_signer,
    submitter: Callable[..., Any] | None = None,
) -> tuple[dict[str, Any], int]:
    env = dict(runtime_env or _load_runtime_env(runtime_home))
    _require_enabled(env)
    slug, repository, default_branch = _runtime_binding(env)
    channel_id, message_id = _session_ids(session_env)
    bundle = _load_bound_bundle(
        runtime_home, approval_text=approval_text
    )
    if bundle["instance_slug"] != slug:
        raise CurrentReleaseApprovalError(
            "release bundle instance differs from the deployed runtime"
        )
    if bundle["repository"]["full_name"] != repository:
        raise CurrentReleaseApprovalError(
            "release bundle repository differs from the deployed runtime"
        )
    if bundle["repository"]["default_branch"] != default_branch:
        raise CurrentReleaseApprovalError(
            "release bundle default branch differs from the deployed runtime"
        )
    gateway = dict(
        invocation
        or _load_invocation_config(slug=slug, repository=repository)
    )
    _validate_approval_channels(
        gateway, env, current_channel_id=channel_id
    )
    spool_path = _stage_bundle(
        bundle, spool_dir=Path(str(gateway["request_spool_dir"]))
    )
    signer_result = signer(
        gateway,
        bundle_path=spool_path,
        channel_id=channel_id,
        message_id=message_id,
    )
    if signer_result.get("bundle_id") != bundle["bundle_id"]:
        raise CurrentReleaseApprovalError(
            "release owner gateway authorized a different bundle"
        )
    assertion = signer_result.get("owner_assertion")
    packet = packets.prepare_packet(
        bundle=bundle,
        approval_text=approval_text,
        owner_assertion=assertion,
        ttl_seconds=300,
    )
    packet_path = packets.persist_packet(runtime_home, packet)
    client = _release_submit_module()
    submit_once = submitter or client.submit_packet
    receipt = submit_once(packet_path, runtime_home=runtime_home)
    public_receipt = client.public_result(receipt)
    result = {
        "schema_version": RESULT_SCHEMA,
        "instance_slug": slug,
        "bundle_id": bundle["bundle_id"],
        "bundle_digest": bundle["bundle_digest"],
        "record_id": signer_result["record_id"],
        "event_id": signer_result["event_id"],
        "packet_id": packet["packet_id"],
        "packet_locator": str(packet_path.relative_to(runtime_home)),
        "submission": public_receipt,
    }
    return result, client.exit_for_outcome(
        receipt.envelope["payload"]["outcome"]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    approve = subparsers.add_parser("approve")
    approve.add_argument("--approval", required=True)
    subparsers.add_parser("status")
    args = parser.parse_args(argv)
    try:
        runtime_home = _runtime_home()
        if args.command == "status":
            result, code = runtime_status(runtime_home)
        else:
            result, code = approve_current_message(
                runtime_home,
                approval_text=args.approval,
                session_env=os.environ,
            )
        sys.stdout.buffer.write(packets.canonical_json(result) + b"\n")
        return code
    except CurrentReleaseApprovalError as exc:
        print(
            f"john-lomein current release approval blocked: {exc}",
            file=sys.stderr,
        )
        return 2
    except packets.ReleasePacketError as exc:
        print(
            f"john-lomein current release approval blocked: {exc}",
            file=sys.stderr,
        )
        return 2
    except Exception as exc:
        try:
            client = _release_submit_module()
        except CurrentReleaseApprovalError:
            print(
                "john-lomein current release approval blocked: internal "
                "runtime helper failure",
                file=sys.stderr,
            )
            return 2
        if isinstance(exc, client.ReleaseSubmitAmbiguousError):
            print(
                "john-lomein current release approval ambiguous: inspect "
                "the signed receipt store before any retry",
                file=sys.stderr,
            )
            return client.EXIT_AMBIGUOUS
        if isinstance(exc, client.ReleaseSubmitError):
            print(
                f"john-lomein current release approval blocked: {exc}",
                file=sys.stderr,
            )
            return client.EXIT_BLOCKED
        print(
            "john-lomein current release approval blocked: internal "
            "runtime helper failure",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
