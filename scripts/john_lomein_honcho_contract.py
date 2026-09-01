#!/usr/bin/env python3
"""Local Honcho configuration contract for John Lomein profiles."""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from copy import deepcopy
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from http.client import HTTPConnection, HTTPException
from urllib.parse import urlparse

ROLES = frozenset({"guide", "forge", "maintainer", "overwatch", "learning_steward"})
DEFAULT_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_REDIS_URL = "redis://127.0.0.1:6379/0"
DEFAULT_TIMEOUT = 120
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def _section(container: Mapping[str, Any], key: str, field: str) -> Mapping[str, Any]:
    value=container.get(key)
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f'{field} must be a YAML mapping')
    return value


def _text(value: Any, default: str) -> str:
    if value is None:
        return default
    if not isinstance(value, str):
        raise ValueError("Honcho text fields must be YAML strings")
    text = value.strip()
    return text or default


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("owner ID lists must be YAML lists")
    return value


def _strict_bool(value: Any, *, field: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a YAML boolean")
    return value


def honcho_settings(manifest: Mapping[str, Any], *, instance_slug: str) -> dict[str, Any]:
    memory = _section(manifest, "memory", "memory")
    provider = _text(memory.get("provider"), "honcho").lower()
    if provider != "honcho":
        raise ValueError("memory.provider must be honcho")
    honcho = _section(memory, "honcho", "memory.honcho")
    base_url = _text(honcho.get("base_url"), DEFAULT_BASE_URL)
    parsed = urlparse(base_url)
    try:
        _parsed_port=parsed.port
    except ValueError as exc:
        raise ValueError('memory.honcho.base_url has an invalid port') from exc
    if _parsed_port is not None and _parsed_port < 1:
        raise ValueError('memory.honcho.base_url port must be positive')
    if parsed.scheme != "http" or parsed.hostname not in LOOPBACK_HOSTS:
        raise ValueError("memory.honcho.base_url must be a loopback http URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {'','/'}:
        raise ValueError('memory.honcho.base_url must not contain credentials, query, fragment, or path')
    redis_url = _text(honcho.get("redis_url"), DEFAULT_REDIS_URL)
    redis = urlparse(redis_url)
    try:
        redis_port = redis.port
    except ValueError as exc:
        raise ValueError("memory.honcho.redis_url has an invalid port") from exc
    if redis.scheme != "redis" or redis.hostname not in LOOPBACK_HOSTS or redis_port is None or redis_port < 1 or redis.username or redis.password or redis.query or redis.fragment or re.fullmatch(r"/[0-9]+", redis.path or "") is None:
        raise ValueError("memory.honcho.redis_url must be a loopback Redis URL with a numeric database")
    workspace = _text(honcho.get("workspace"), f"john-lomein-{instance_slug}")
    owner_peer = _text(honcho.get("owner_peer"), "owner")
    timeout_raw = honcho.get("timeout", DEFAULT_TIMEOUT)
    if isinstance(timeout_raw, bool) or not isinstance(timeout_raw, int):
        raise ValueError("memory.honcho.timeout must be an integer")
    timeout = timeout_raw
    if timeout < 1 or timeout > 600:
        raise ValueError("memory.honcho.timeout must be between 1 and 600")
    discord = _section(manifest, "discord", "discord")
    authority = _section(manifest, "authority", "authority")
    raw_owner_ids = discord.get("owner_user_ids") or authority.get("owner_approvers")
    owner_ids = [str(value) for value in _list(raw_owner_ids)]
    guide_save_messages = _strict_bool(
        honcho.get("guide_save_messages"),
        field="memory.honcho.guide_save_messages",
        default=True,
    )
    database = _text(honcho.get("database"), "honcho_local")
    if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,62}", database) is None:
        raise ValueError("memory.honcho.database is invalid")
    watchdog_enabled = _strict_bool(
        honcho.get("watchdog_enabled"),
        field="memory.honcho.watchdog_enabled",
        default=False,
    )
    expected_memory_model = _text(honcho.get("expected_memory_model"), "")
    server_root = _text(honcho.get("server_root"), "")
    if expected_memory_model and re.fullmatch(r"[A-Za-z0-9._:/-]{1,128}", expected_memory_model) is None:
        raise ValueError("memory.honcho.expected_memory_model is invalid")
    if server_root and not Path(server_root).expanduser().is_absolute():
        raise ValueError("memory.honcho.server_root must be absolute")
    if watchdog_enabled and (not expected_memory_model or not server_root):
        raise ValueError("Honcho watchdog requires server_root and expected_memory_model")
    return {
        "base_url": base_url,
        "redis_url": redis_url,
        "workspace": workspace,
        "owner_peer": owner_peer,
        "timeout": timeout,
        "guide_save_messages": guide_save_messages,
        "database": database,
        "watchdog_enabled": watchdog_enabled,
        "expected_memory_model": expected_memory_model,
        "server_root": server_root,
        "owner_ids": owner_ids,
    }

def probe_honcho_health(base_url: str, *, timeout: float = 5.0) -> None:
    parsed=urlparse(base_url)
    host=parsed.hostname
    if host not in LOOPBACK_HOSTS:
        raise RuntimeError('local Honcho health probe rejected non-loopback host')
    port=parsed.port if parsed.port is not None else 80
    if port < 1:
        raise RuntimeError('local Honcho health probe rejected non-positive port')
    connection=HTTPConnection(host,port,timeout=timeout)
    try:
        connection.request('GET','/health')
        status=int(connection.getresponse().status)
    except (OSError,HTTPException,TimeoutError) as exc:
        raise RuntimeError(f'local Honcho health probe failed: {exc}') from exc
    finally:
        connection.close()
    if status < 200 or status >= 300:
        raise RuntimeError(f'local Honcho health probe returned HTTP {status}')


def profile_honcho_config(
    manifest: Mapping[str, Any],
    *,
    instance_slug: str,
    role: str,
    profile: str,
) -> dict[str, Any]:
    if role not in ROLES:
        raise ValueError(f"unsupported operational role: {role}")
    settings = honcho_settings(manifest, instance_slug=instance_slug)
    host = f"hermes_{profile}"
    save_messages = role == "guide" and settings["guide_save_messages"]
    aliases = {runtime_id: settings["owner_peer"] for runtime_id in settings["owner_ids"]}
    host_config: dict[str, Any] = {
        "environment": "local",
        "peerName": settings["owner_peer"],
        "aiPeer": profile,
        "workspace": settings["workspace"],
        "pinUserPeer": role != "guide",
        "observationMode": "unified",
        "observation": {
            "user": {"observeMe": True, "observeOthers": False},
            "ai": {"observeMe": False, "observeOthers": True},
        },
        "writeFrequency": "async",
        "recallMode": "context",
        "dialecticCadence": 2,
        "dialecticReasoningLevel": "low",
        "sessionStrategy": "per-session",
        "enabled": True,
        "saveMessages": save_messages,
        "runtimePeerPrefix": "discord_",
    }
    if aliases:
        host_config["userPeerAliases"] = aliases
    return {
        "hosts": {host: host_config, "hermes": deepcopy(host_config)},
        "baseUrl": settings["base_url"],
        "timeout": settings["timeout"],
    }

def write_profile_honcho_config(
    manifest: Mapping[str, Any],
    *,
    instance_slug: str,
    role: str,
    profile: str,
    profile_home: str | Path,
) -> Path:
    path = Path(profile_home) / "honcho.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or info.st_mode & 0o022
        ):
            raise ValueError(f"unsafe existing Honcho config: {path}")
    payload = profile_honcho_config(
        manifest,
        instance_slug=instance_slug,
        role=role,
        profile=profile,
    )
    content = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    fd, temporary = tempfile.mkstemp(prefix=".honcho-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return path


def profile_honcho_errors(
    data: Mapping[str, Any] | Any,
    *,
    instance_slug: str,
    role: str,
    profile: str,
    manifest: Mapping[str, Any],
) -> list[str]:
    if not isinstance(data, Mapping):
        return ["honcho config is not a mapping"]
    expected = profile_honcho_config(
        manifest,
        instance_slug=instance_slug,
        role=role,
        profile=profile,
    )
    return [] if dict(data) == expected else ["honcho config does not exactly match the product contract"]
