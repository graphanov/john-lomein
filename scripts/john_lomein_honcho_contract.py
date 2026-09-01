#!/usr/bin/env python3
"""Local Honcho configuration contract for John Lomein profiles."""

from __future__ import annotations

import json
import hashlib
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
DEFAULT_TIMEOUT = 120
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
PUBLIC_HONCHO_CHECKOUT_URL = "https://github.com/plastic-labs/honcho.git"
PUBLIC_HONCHO_COMMIT = "9379c634ed240d0225b63443606e5304a4e261c5"
PUBLIC_RETENTION_INTERVAL_SECONDS = 300
PUBLIC_BACKUP_MAX_AGE_DAYS = 30


def _public_service_defaults(instance_slug: str) -> dict[str, Any]:
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", instance_slug) is None:
        raise ValueError("unsafe instance.slug for dedicated Honcho")
    digest = hashlib.sha256(instance_slug.encode("utf-8")).hexdigest()
    port_offset = int(digest[:8], 16) % 1000
    database_slug = re.sub(r"[^a-z0-9_]", "_", instance_slug.lower())[:24]
    return {
        "base_url": f"http://127.0.0.1:{18000 + port_offset}",
        "redis_url": f"redis://127.0.0.1:{19000 + port_offset}/0",
        "database": f"john_lomein_{database_slug}_public_{digest[:8]}",
        "supervisor_label": f"ai.john-lomein.{instance_slug}.public-honcho",
    }


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
    defaults = _public_service_defaults(instance_slug)
    memory = _section(manifest, "memory", "memory")
    provider = _text(memory.get("provider"), "honcho").lower()
    if provider != "honcho":
        raise ValueError("memory.provider must be honcho")
    honcho = _section(memory, "honcho", "memory.honcho")
    service_mode = _text(honcho.get("service_mode"), "dedicated_public")
    if service_mode != "dedicated_public":
        raise ValueError("memory.honcho.service_mode must be dedicated_public")
    base_url = _text(honcho.get("base_url"), defaults["base_url"])
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
    if parsed.hostname != "127.0.0.1" or _parsed_port in {None, 8000}:
        raise ValueError("memory.honcho.base_url must use a dedicated API port")
    redis_url = _text(honcho.get("redis_url"), defaults["redis_url"])
    redis = urlparse(redis_url)
    try:
        redis_port = redis.port
    except ValueError as exc:
        raise ValueError("memory.honcho.redis_url has an invalid port") from exc
    if redis.scheme != "redis" or redis.hostname not in LOOPBACK_HOSTS or redis_port is None or redis_port < 1 or redis.username or redis.password or redis.query or redis.fragment or re.fullmatch(r"/[0-9]+", redis.path or "") is None:
        raise ValueError("memory.honcho.redis_url must be a loopback Redis URL with a numeric database")
    if redis.hostname != "127.0.0.1" or redis_port == 6379 or redis.path != "/0":
        raise ValueError(
            "memory.honcho.redis_url must use a dedicated Redis instance and database 0"
        )
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
    database = _text(honcho.get("database"), defaults["database"])
    if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,62}", database) is None:
        raise ValueError("memory.honcho.database is invalid")
    if database in {"honcho_local", "postgres", "template0", "template1"}:
        raise ValueError("memory.honcho.database must be a dedicated PostgreSQL database")
    if database != defaults["database"]:
        raise ValueError(
            "memory.honcho.database must use the instance-derived dedicated PostgreSQL database"
        )
    watchdog_enabled = _strict_bool(
        honcho.get("watchdog_enabled"),
        field="memory.honcho.watchdog_enabled",
        default=False,
    )
    expected_memory_model = _text(honcho.get("expected_memory_model"), "")
    runtime = _section(manifest, "runtime", "runtime")
    runtime_home_text = _text(runtime.get("hermes_home"), "")
    derived_server_root = (
        str(
            (
                Path(runtime_home_text).expanduser()
                / "services"
                / "public-honcho"
                / "server"
            ).resolve()
        )
        if runtime_home_text and Path(runtime_home_text).expanduser().is_absolute()
        else ""
    )
    server_root = _text(honcho.get("server_root"), derived_server_root)
    if expected_memory_model and re.fullmatch(r"[A-Za-z0-9._:/-]{1,128}", expected_memory_model) is None:
        raise ValueError("memory.honcho.expected_memory_model is invalid")
    if server_root and not Path(server_root).expanduser().is_absolute():
        raise ValueError("memory.honcho.server_root must be absolute")
    personal_root = (Path.home() / ".hermes" / "honcho-local").resolve()
    if server_root:
        resolved_server_root = Path(server_root).expanduser().resolve()
        try:
            resolved_server_root.relative_to(personal_root)
        except ValueError:
            pass
        else:
            raise ValueError(
                "memory.honcho.server_root must not use the personal Honcho checkout"
            )
        if derived_server_root and resolved_server_root != Path(derived_server_root):
            raise ValueError(
                "memory.honcho.server_root must use the product-owned instance service root"
            )
    checkout_url = _text(
        honcho.get("checkout_url"), PUBLIC_HONCHO_CHECKOUT_URL
    )
    if checkout_url != PUBLIC_HONCHO_CHECKOUT_URL:
        raise ValueError("memory.honcho.checkout_url is not the approved Honcho remote")
    checkout_commit = _text(
        honcho.get("checkout_commit"), PUBLIC_HONCHO_COMMIT
    )
    if re.fullmatch(r"[0-9a-f]{40}", checkout_commit) is None:
        raise ValueError("memory.honcho.checkout_commit must be a 40-character commit")
    if checkout_commit != PUBLIC_HONCHO_COMMIT:
        raise ValueError("memory.honcho.checkout_commit is not the supported pinned commit")
    retention_interval_seconds = honcho.get(
        "retention_interval_seconds", PUBLIC_RETENTION_INTERVAL_SECONDS
    )
    if (
        type(retention_interval_seconds) is not int
        or retention_interval_seconds != PUBLIC_RETENTION_INTERVAL_SECONDS
    ):
        raise ValueError(
            "memory.honcho.retention_interval_seconds must remain exactly 300"
        )
    backup_max_age_days = honcho.get(
        "backup_max_age_days", PUBLIC_BACKUP_MAX_AGE_DAYS
    )
    if (
        type(backup_max_age_days) is not int
        or backup_max_age_days < 1
        or backup_max_age_days > PUBLIC_BACKUP_MAX_AGE_DAYS
    ):
        raise ValueError("memory.honcho.backup_max_age_days must be at most 30")
    if watchdog_enabled and (not expected_memory_model or not server_root):
        raise ValueError("Honcho watchdog requires server_root and expected_memory_model")
    return {
        "service_mode": service_mode,
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
        "checkout_url": checkout_url,
        "checkout_commit": checkout_commit,
        "retention_interval_seconds": retention_interval_seconds,
        "backup_max_age_days": backup_max_age_days,
        "supervisor_label": defaults["supervisor_label"],
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
