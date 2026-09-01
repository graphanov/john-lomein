#!/usr/bin/env python3
"""Provision and supervise John Lomein's dedicated public Honcho service.

The only launchd process created by this module is the product-owned supervisor.
Redis, Honcho API, and Honcho deriver are descendants of that supervisor and are
never loaded through the personal Hermes Honcho LaunchAgents.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlparse

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from john_lomein_honcho_contract import honcho_settings
from john_lomein_honcho_pilot import (
    api_health,
    assert_honcho_quiescent,
    expire_public_backups,
    flush_dedicated_honcho_cache,
    honcho_startup_blockers,
    psql_json,
    run_public_retention_cycle,
    sha256_json,
    write_pause_receipt,
    write_private_json,
)
from john_lomein_manifest_contract import validate_manifest_contract

RETENTION_RECEIPT_SCHEMA = "john-lomein.honcho-retention-receipt.v2"
SERVICE_STATUS_SCHEMA = "john-lomein.public-honcho-supervisor.v1"
SUPERVISOR_LABEL_PREFIX = "ai.john-lomein."
RETENTION_INTERVAL_SECONDS = 300
APPROVED_HONCHO_REMOTE = "https://github.com/plastic-labs/honcho.git"


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _safe_slug(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", value or "") is None:
        raise ValueError("instance slug is invalid for a public Honcho service")
    return value


def public_supervisor_label(instance_slug: str) -> str:
    return f"{SUPERVISOR_LABEL_PREFIX}{_safe_slug(instance_slug)}.public-honcho"


def public_child_names(instance_slug: str) -> tuple[str, str]:
    label = public_supervisor_label(instance_slug)
    return (f"{label}.child.api", f"{label}.child.deriver")


def build_supervisor_plist(
    *,
    manifest_path: Path,
    runtime_home: Path,
    instance_slug: str,
    python: str,
    uv: str,
    supervisor_script: Path,
) -> dict[str, Any]:
    label = public_supervisor_label(instance_slug)
    runtime = Path(runtime_home).expanduser().resolve()
    script = Path(supervisor_script).expanduser().resolve()
    manifest = Path(manifest_path).expanduser().resolve()
    logs = runtime / "logs" / "public-honcho"
    return {
        "Label": label,
        "ProgramArguments": [
            str(python),
            str(script),
            "supervise",
            "--manifest",
            str(manifest),
        ],
        "WorkingDirectory": str(runtime),
        "EnvironmentVariables": {
            "JOHN_LOMEIN_UV": str(uv),
            "PYTHONUNBUFFERED": "1",
            "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
        },
        "LimitLoadToSessionType": ["Aqua", "Background"],
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 30,
        "StandardOutPath": str(logs / "supervisor.log"),
        "StandardErrorPath": str(logs / "supervisor.error.log"),
    }


def validate_pinned_checkout(
    server_root: Path,
    *,
    expected_url: str,
    expected_commit: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    raw_root = Path(server_root).expanduser()
    if not raw_root.is_absolute() or raw_root.is_symlink():
        raise ValueError("public Honcho checkout is missing or unsafe")
    current = Path(raw_root.anchor)
    for part in raw_root.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise ValueError("public Honcho checkout traverses a symlink")
    root = raw_root.resolve()
    if not root.is_dir():
        raise ValueError("public Honcho checkout is missing or unsafe")
    if expected_url != APPROVED_HONCHO_REMOTE:
        raise ValueError("public Honcho checkout remote is not approved")
    if re.fullmatch(r"[0-9a-f]{40}", expected_commit or "") is None:
        raise ValueError("public Honcho checkout has no pinned commit")

    def git(*arguments: str) -> str:
        result = runner(
            ["git", "-C", str(root), *arguments],
            text=True,
            capture_output=True,
            check=True,
            timeout=30,
        )
        return str(result.stdout).strip()

    remote = git("remote", "get-url", "origin")
    if remote != expected_url:
        raise ValueError("public Honcho checkout remote changed")
    head = git("rev-parse", "HEAD")
    if head != expected_commit:
        raise ValueError("public Honcho checkout does not match the pinned commit")
    dirty = git("status", "--porcelain=v1", "--untracked-files=all")
    if dirty:
        raise ValueError("public Honcho checkout is dirty")
    lock = root / "uv.lock"
    lock_digest = (
        "sha256:" + hashlib.sha256(lock.read_bytes()).hexdigest()
        if lock.is_file() and not lock.is_symlink()
        else ""
    )
    return {
        "remote": remote,
        "head": head,
        "clean": True,
        "uv_lock_sha256": lock_digest,
        "checkout_identity_digest": sha256_json(
            {"remote": remote, "head": head, "uv_lock_sha256": lock_digest}
        ),
    }


DATABASE_ISOLATION_SQL = r"""
WITH workspace_names(name) AS (
  SELECT name FROM workspaces
  UNION SELECT workspace_name FROM peers
  UNION SELECT workspace_name FROM sessions
  UNION SELECT workspace_name FROM session_peers
  UNION SELECT workspace_name FROM messages
  UNION SELECT workspace_name FROM message_embeddings
  UNION SELECT workspace_name FROM documents
  UNION SELECT workspace_name FROM collections
  UNION SELECT workspace_name FROM queue WHERE workspace_name IS NOT NULL
)
SELECT json_build_object(
  'database', current_database(),
  'database_oid', (SELECT oid FROM pg_database WHERE datname=current_database()),
  'system_identifier', (SELECT system_identifier::text FROM pg_control_system()),
  'server_port', inet_server_port(),
  'workspace_names', COALESCE(
    (SELECT json_agg(name ORDER BY name) FROM workspace_names), '[]'::json
  )
)::text;
"""


def assert_dedicated_database(database: str, workspace: str) -> dict[str, Any]:
    if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,62}", database or "") is None:
        raise ValueError("dedicated PostgreSQL database name is invalid")
    if database == "honcho_local":
        raise ValueError("dedicated PostgreSQL database cannot be honcho_local")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", workspace or "") is None:
        raise ValueError("public Honcho workspace is invalid")
    payload = psql_json(database, DATABASE_ISOLATION_SQL)
    if not isinstance(payload, Mapping):
        raise ValueError("dedicated PostgreSQL identity query failed")
    names = payload.get("workspace_names")
    if not isinstance(names, list) or any(not isinstance(item, str) for item in names):
        raise ValueError("dedicated PostgreSQL workspace inventory is invalid")
    if any(name != workspace for name in names) or len(set(names)) > 1:
        raise ValueError("public Honcho database is shared or multi-workspace")
    if payload.get("database") != database:
        raise ValueError("dedicated PostgreSQL database identity changed")
    if re.fullmatch(r"[0-9]+", str(payload.get("system_identifier") or "")) is None:
        raise ValueError("dedicated PostgreSQL cluster identity is invalid")
    result = dict(payload)
    result["workspace_names"] = sorted(set(names))
    result["database_identity_digest"] = sha256_json(result)
    return result


def build_retention_receipt(
    *,
    database_identity_digest: str,
    workspace: str,
    cutoff: str,
    completed_at: str,
    deleted_counts: Mapping[str, int],
) -> dict[str, Any]:
    if re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", database_identity_digest or "") is None:
        raise ValueError("retention database identity digest is invalid")
    counts = {str(key): int(value) for key, value in sorted(deleted_counts.items())}
    if any(value < 0 for value in counts.values()):
        raise ValueError("retention deleted counts cannot be negative")
    if not _retention_cutoff_bounded(cutoff, completed_at, completed_at):
        raise ValueError("retention cutoff is not bound to completion time")
    payload = {
        "schema_version": RETENTION_RECEIPT_SCHEMA,
        "database_identity_digest": database_identity_digest.removeprefix("sha256:"),
        "workspace": workspace,
        "cutoff": cutoff,
        "completed_at": completed_at,
        "retention_days": 30,
        "maximum_active_store_lag_seconds": RETENTION_INTERVAL_SECONDS,
        "deleted_counts": counts,
    }
    payload["receipt_digest"] = sha256_json(payload)
    return payload


def validate_retention_receipt(
    receipt: Mapping[str, Any],
    *,
    expected_database_identity_digest: str,
    expected_workspace: str,
    now: datetime,
) -> bool:
    unsigned = dict(receipt)
    digest = unsigned.pop("receipt_digest", "")
    if digest != sha256_json(unsigned):
        return False
    if receipt.get("schema_version") != RETENTION_RECEIPT_SCHEMA:
        return False
    if receipt.get("retention_days") != 30:
        return False
    if receipt.get("maximum_active_store_lag_seconds") != RETENTION_INTERVAL_SECONDS:
        return False
    if receipt.get("workspace") != expected_workspace:
        return False
    if receipt.get("database_identity_digest") != expected_database_identity_digest.removeprefix("sha256:"):
        return False
    try:
        completed = datetime.fromisoformat(
            str(receipt["completed_at"]).replace("Z", "+00:00")
        )
        cutoff = datetime.fromisoformat(str(receipt["cutoff"]).replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError):
        return False
    if completed.tzinfo is None or cutoff.tzinfo is None:
        return False
    current = now.astimezone(timezone.utc)
    completed_utc = completed.astimezone(timezone.utc)
    cutoff_utc = cutoff.astimezone(timezone.utc)
    return (
        timedelta(0)
        <= current - completed_utc
        <= timedelta(seconds=RETENTION_INTERVAL_SECONDS)
        and _retention_cutoff_bounded(cutoff_utc, completed_utc, current)
    )


def _retention_cutoff_bounded(
    cutoff: str | datetime,
    completed_at: str | datetime,
    current: str | datetime,
) -> bool:
    try:
        parsed = []
        for value in (cutoff, completed_at, current):
            timestamp = (
                value
                if isinstance(value, datetime)
                else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            )
            if timestamp.tzinfo is None:
                return False
            parsed.append(timestamp.astimezone(timezone.utc))
    except (TypeError, ValueError):
        return False
    cutoff_utc, completed_utc, current_utc = parsed
    minimum_age = timedelta(days=30)
    maximum_age = minimum_age + timedelta(seconds=RETENTION_INTERVAL_SECONDS)
    return (
        minimum_age <= completed_utc - cutoff_utc <= maximum_age
        and minimum_age <= current_utc - cutoff_utc <= maximum_age
    )


def _load_manifest(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    raw = Path(path).expanduser()
    if not raw.is_absolute() or raw.is_symlink() or not raw.is_file():
        raise ValueError("instance manifest is missing or unsafe")
    info = raw.stat()
    if info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o022:
        raise ValueError("instance manifest metadata is unsafe")
    manifest_path = raw.resolve()
    payload = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise ValueError("instance manifest is invalid")
    validate_manifest_contract(payload)
    slug = str((payload.get("instance") or {}).get("slug") or "")
    return payload, honcho_settings(payload, instance_slug=slug)


def _atomic_bytes(path: Path, data: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _provision_checkout(settings: Mapping[str, Any]) -> dict[str, Any]:
    server_root = Path(str(settings["server_root"])).resolve()
    if not server_root.exists():
        server_root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = Path(
            tempfile.mkdtemp(prefix=".honcho-checkout-", dir=server_root.parent)
        )
        try:
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--no-checkout",
                    str(settings["checkout_url"]),
                    str(temporary),
                ],
                check=True,
                timeout=600,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(temporary),
                    "checkout",
                    "--detach",
                    str(settings["checkout_commit"]),
                ],
                check=True,
                timeout=120,
            )
            os.replace(temporary, server_root)
        finally:
            if temporary.exists():
                # A failed new clone contains no user data and remains isolated
                # under the product service root for operator inspection.
                pass
    checkout = validate_pinned_checkout(
        server_root,
        expected_url=str(settings["checkout_url"]),
        expected_commit=str(settings["checkout_commit"]),
    )
    subprocess.run(
        ["uv", "sync", "--frozen"],
        cwd=server_root,
        check=True,
        timeout=1200,
    )
    return checkout


def _database_exists(database: str) -> bool:
    payload = psql_json(
        "postgres",
        "SELECT json_build_object('exists', EXISTS(SELECT 1 FROM pg_database WHERE datname=:'database'))::text;",
        variables={"database": database},
    )
    return bool(isinstance(payload, Mapping) and payload.get("exists") is True)


def _assert_existing_database_safe(database: str, workspace: str) -> None:
    payload = psql_json(
        database,
        "SELECT json_build_object('has_workspaces',to_regclass('public.workspaces') IS NOT NULL,'user_table_count',(SELECT count(*) FROM pg_tables WHERE schemaname='public'))::text;",
    )
    if not isinstance(payload, Mapping):
        raise ValueError("existing public PostgreSQL database inventory failed")
    if payload.get("has_workspaces") is True:
        assert_dedicated_database(database, workspace)
    elif int(payload.get("user_table_count") or 0) != 0:
        raise ValueError("existing public PostgreSQL database is nonempty and unrecognized")


def _write_runtime_configuration(settings: Mapping[str, Any]) -> Path:
    server_root = Path(str(settings["server_root"])).resolve()
    parsed_redis = urlparse(str(settings["redis_url"]))
    database = str(settings["database"])
    memory_model = str(settings["expected_memory_model"] or "")
    if not memory_model:
        raise ValueError("dedicated public Honcho requires an expected memory model")
    model_lines = [
        "LLM_OPENAI_API_KEY=ollama-local",
        "EMBEDDING_VECTOR_DIMENSIONS=768",
        "EMBEDDING_MODEL_CONFIG__TRANSPORT=openai",
        "EMBEDDING_MODEL_CONFIG__MODEL=nomic-embed-text:latest",
        "EMBEDDING_MODEL_CONFIG__OVERRIDES__BASE_URL=http://127.0.0.1:11434/v1",
        "DERIVER_ENABLED=true",
        "DERIVER_MODEL_CONFIG__TRANSPORT=openai",
        f"DERIVER_MODEL_CONFIG__MODEL={memory_model}",
        "DERIVER_MODEL_CONFIG__OVERRIDES__BASE_URL=http://127.0.0.1:11434/v1",
        "DERIVER_REPRESENTATION_BATCH_WORK_UNIT_TARGET_TOKENS=0",
        "DERIVER_REPRESENTATION_BATCH_MAX_AGE_SECONDS=30",
        "PEER_CARD_ENABLED=false",
        "SUMMARY_ENABLED=false",
        "DREAM_ENABLED=false",
    ]
    for level in ("MINIMAL", "LOW", "MEDIUM", "HIGH", "MAX"):
        model_lines.extend(
            [
                f"DIALECTIC_LEVELS__{level}__MODEL_CONFIG__TRANSPORT=openai",
                f"DIALECTIC_LEVELS__{level}__MODEL_CONFIG__MODEL={memory_model}",
                f"DIALECTIC_LEVELS__{level}__MODEL_CONFIG__OVERRIDES__BASE_URL=http://127.0.0.1:11434/v1",
            ]
        )
    env = (
        f"DB_CONNECTION_URI=postgresql+psycopg:///{database}\n"
        f"CACHE_URL={settings['redis_url']}?suppress=true\n"
        "CACHE_ENABLED=true\n"
        "AUTH_USE_AUTH=false\n"
        "SENTRY_ENABLED=false\n"
        "TELEMETRY_ENABLED=false\n"
        "EMBEDDING_MAX_INPUT_TOKENS=1000\n"
        + "\n".join(model_lines)
        + "\n"
    ).encode("utf-8")
    _atomic_bytes(server_root / ".env", env, mode=0o600)
    redis_root = server_root.parent / "redis"
    redis_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    redis_config = (
        f"bind 127.0.0.1\nport {parsed_redis.port}\nprotected-mode yes\n"
        f"dir {redis_root}\ndbfilename public-honcho.rdb\n"
        "databases 1\nappendonly no\nsave \"\"\n"
    ).encode("utf-8")
    _atomic_bytes(redis_root / "redis.conf", redis_config, mode=0o600)
    return redis_root / "redis.conf"


def _configure_embedding_schema(
    server_root: Path,
    *,
    uv_binary: str,
    runner: Callable[..., Any] = subprocess.run,
) -> None:
    runner(
        [
            str(uv_binary),
            "run",
            "--frozen",
            "python",
            "scripts/configure_embeddings.py",
            "--yes",
        ],
        cwd=str(Path(server_root).expanduser().resolve()),
        check=True,
        timeout=600,
    )


def provision_public_service(manifest_path: Path) -> dict[str, Any]:
    manifest, settings = _load_manifest(manifest_path)
    runtime_value = str((manifest.get("runtime") or {}).get("hermes_home") or "")
    if not runtime_value or not Path(runtime_value).expanduser().is_absolute():
        raise ValueError("instance runtime home is invalid")
    runtime = Path(runtime_value).expanduser().resolve()
    checkout = _provision_checkout(settings)
    redis_config = _write_runtime_configuration(settings)
    database = str(settings["database"])
    database_exists = _database_exists(database)
    if database_exists:
        _assert_existing_database_safe(database, str(settings["workspace"]))
    else:
        subprocess.run(
            ["createdb", "--encoding=UTF8", "--template=template0", database],
            check=True,
            timeout=60,
        )
    uv_value = shutil.which("uv")
    if not uv_value:
        raise ValueError("public Honcho uv is unavailable")
    uv_binary = str(Path(uv_value).expanduser().resolve())
    subprocess.run(
        [uv_binary, "run", "--frozen", "alembic", "upgrade", "head"],
        cwd=str(settings["server_root"]),
        check=True,
        timeout=600,
    )
    _configure_embedding_schema(
        Path(str(settings["server_root"])),
        uv_binary=uv_binary,
    )
    database_identity = assert_dedicated_database(database, str(settings["workspace"]))
    for directory in (
        runtime / "state" / "honcho",
        runtime / "private" / "honcho-deletion-tombstones",
        runtime / "private" / "honcho-backups",
        runtime / "logs" / "public-honcho",
    ):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
    receipt = {
        "schema_version": "john-lomein.public-honcho-provision.v1",
        "provisioned_at": utc_now(),
        "checkout": checkout,
        "database_identity": database_identity,
        "redis_config": str(redis_config),
        "supervisor_label": settings["supervisor_label"],
    }
    receipt["receipt_digest"] = sha256_json(receipt)
    write_private_json(runtime / "state" / "honcho" / "provision.json", receipt)
    return receipt


def _supervisor_python_path(settings: Mapping[str, Any]) -> Path:
    server_value = str(settings.get("server_root") or "")
    server_root = Path(server_value).expanduser()
    if not server_value or not server_root.is_absolute():
        raise ValueError("public Honcho server root is invalid")
    interpreter = Path(
        os.path.abspath(os.fspath(server_root / ".venv" / "bin" / "python"))
    )
    if not interpreter.is_file() or not os.access(interpreter, os.X_OK):
        raise ValueError("public Honcho supervisor Python is invalid")
    return interpreter


def install_public_service(manifest_path: Path) -> dict[str, Any]:
    manifest_path = Path(manifest_path).expanduser().resolve()
    manifest, settings = _load_manifest(manifest_path)
    provision = provision_public_service(manifest_path)
    runtime_value = str((manifest.get("runtime") or {}).get("hermes_home") or "")
    if not runtime_value or not Path(runtime_value).expanduser().is_absolute():
        raise ValueError("instance runtime home is invalid")
    runtime = Path(runtime_value).expanduser().resolve()
    slug = str((manifest.get("instance") or {}).get("slug") or "")
    script = runtime / "scripts" / Path(__file__).name
    supervisor_python = _supervisor_python_path(settings)
    uv_value = shutil.which("uv")
    if not uv_value:
        raise ValueError("public Honcho supervisor uv is unavailable")
    uv_binary = Path(uv_value).expanduser().resolve()
    if not uv_binary.is_file() or not os.access(uv_binary, os.X_OK):
        raise ValueError("public Honcho supervisor uv is invalid")
    plist = build_supervisor_plist(
        manifest_path=manifest_path,
        runtime_home=runtime,
        instance_slug=slug,
        python=str(supervisor_python),
        uv=str(uv_binary),
        supervisor_script=script,
    )
    label = str(settings["supervisor_label"])
    if not label.startswith(SUPERVISOR_LABEL_PREFIX):
        raise ValueError("public Honcho supervisor label is not product-owned")
    agents = Path.home() / "Library" / "LaunchAgents"
    target = agents / f"{label}.plist"
    domain = f"gui/{os.getuid()}"
    subprocess.run(
        ["/bin/launchctl", "bootout", domain, str(target)],
        check=False,
        timeout=30,
        capture_output=True,
        text=True,
    )
    _atomic_bytes(target, plistlib.dumps(plist, sort_keys=True), mode=0o600)
    if plistlib.loads(target.read_bytes()) != plist:
        raise RuntimeError("public Honcho supervisor plist verification failed")
    _write_status(runtime, state="launching")
    subprocess.run(
        ["/bin/launchctl", "bootstrap", domain, str(target)],
        check=True,
        timeout=30,
    )
    status_path = runtime / "state" / "honcho" / "supervisor.json"
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            status = json.loads(status_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            status = {}
        if status.get("state") == "paused":
            raise RuntimeError("public Honcho supervisor paused during installation")
        if status.get("state") == "running" and api_health(str(settings["base_url"])):
            break
        time.sleep(0.25)
    else:
        raise RuntimeError("public Honcho supervisor did not become healthy")
    return {"installed": True, "label": label, "plist": str(target), "provision": provision}


def _stop_children(children: Sequence[subprocess.Popen[Any]]) -> None:
    for child in children:
        if child.poll() is None:
            child.terminate()
    deadline = time.monotonic() + 15
    for child in children:
        remaining = max(0.0, deadline - time.monotonic())
        try:
            child.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)


def _stop_guide(manifest: Path, runtime: Path, slug: str) -> None:
    registry = runtime / "scripts" / "john_lomein_service_registry.py"
    subprocess.run(
        [
            sys.executable,
            str(registry),
            "stop",
            "--manifest",
            str(manifest),
            "--runtime-home",
            str(runtime),
            "--service",
            f"guide=ai.hermes.gateway-john-lomein-{slug}-guide",
        ],
        check=True,
        timeout=60,
    )


def _write_status(runtime: Path, **fields: Any) -> dict[str, Any]:
    payload = {
        "schema_version": SERVICE_STATUS_SCHEMA,
        "observed_at": utc_now(),
        **fields,
    }
    payload["status_digest"] = sha256_json(payload)
    write_private_json(runtime / "state" / "honcho" / "supervisor.json", payload)
    return payload


def _redis_listener_present(redis_url: str) -> bool:
    parsed = urlparse(redis_url)
    if parsed.hostname != "127.0.0.1" or parsed.port is None:
        raise ValueError("dedicated Redis listener probe requires an IPv4 loopback URL")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.25)
        return probe.connect_ex((parsed.hostname, parsed.port)) == 0


def _start_verified_dedicated_redis(
    redis_config: Path,
    redis_url: str,
    *,
    cwd: Path,
    listener_probe: Callable[[str], bool] = _redis_listener_present,
    popen_factory: Callable[..., subprocess.Popen[Any]] = subprocess.Popen,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    sleeper: Callable[[float], None] = time.sleep,
) -> subprocess.Popen[Any]:
    if listener_probe(redis_url):
        raise RuntimeError("pre-existing Redis listener occupies the dedicated port")
    redis = popen_factory(["redis-server", str(redis_config)], cwd=cwd)
    try:
        if type(getattr(redis, "pid", None)) is not int or redis.pid <= 0:
            raise RuntimeError("dedicated Redis spawned without a valid process ID")
        for _ in range(50):
            if redis.poll() is not None:
                raise RuntimeError("dedicated Redis exited during startup")
            identity = runner(
                ["redis-cli", "-u", redis_url, "INFO", "server"],
                capture_output=True,
                text=True,
                check=False,
            )
            if identity.returncode == 0:
                match = re.search(r"(?m)^process_id:([0-9]+)\r?$", identity.stdout)
                if match is None or int(match.group(1)) != redis.pid:
                    raise RuntimeError("dedicated Redis listener ownership mismatch")
                if redis.poll() is not None:
                    raise RuntimeError("dedicated Redis exited after ownership verification")
                ping = runner(
                    ["redis-cli", "-u", redis_url, "PING"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if (
                    redis.poll() is None
                    and ping.returncode == 0
                    and ping.stdout.strip() == "PONG"
                ):
                    return redis
            sleeper(0.1)
        raise RuntimeError("dedicated Redis did not become ready")
    except Exception:
        _stop_children([redis])
        raise


def _supervisor_uv_binary() -> str:
    value = str(os.environ.get("JOHN_LOMEIN_UV") or "")
    binary = Path(value).expanduser()
    if not value or not binary.is_absolute():
        raise FileNotFoundError("public Honcho supervisor uv is unavailable")
    binary = binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise FileNotFoundError("public Honcho supervisor uv is unavailable")
    return str(binary)


def supervise_public_service(manifest_path: Path) -> int:
    manifest_path = Path(manifest_path).expanduser().resolve()
    manifest, settings = _load_manifest(manifest_path)
    runtime_value = str((manifest.get("runtime") or {}).get("hermes_home") or "")
    if not runtime_value or not Path(runtime_value).expanduser().is_absolute():
        raise ValueError("instance runtime home is invalid")
    runtime = Path(runtime_value).expanduser().resolve()
    slug = str((manifest.get("instance") or {}).get("slug") or "")
    server_root = Path(str(settings["server_root"])).resolve()
    redis_config = server_root.parent / "redis" / "redis.conf"
    pause_path = runtime / "state" / "honcho" / "INGESTION_PAUSED.json"
    uv_binary = _supervisor_uv_binary()
    stopping = False

    def stop_signal(_signum: int, _frame: Any) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop_signal)
    signal.signal(signal.SIGINT, stop_signal)
    children: list[subprocess.Popen[Any]] = []
    try:
        if pause_path.exists() or pause_path.is_symlink():
            raise RuntimeError("public Honcho manual-clear pause is active")
        validate_pinned_checkout(
            server_root,
            expected_url=str(settings["checkout_url"]),
            expected_commit=str(settings["checkout_commit"]),
        )
        database_identity = assert_dedicated_database(
            str(settings["database"]), str(settings["workspace"])
        )
        redis = _start_verified_dedicated_redis(
            redis_config,
            str(settings["redis_url"]),
            cwd=server_root.parent,
        )
        children.append(redis)

        tombstone_dir = runtime / "private" / "honcho-deletion-tombstones"
        blockers = honcho_startup_blockers(
            tombstone_dir,
            database=str(settings["database"]),
            workspace=str(settings["workspace"]),
        )
        if blockers:
            raise RuntimeError("public Honcho startup blocked by deletion replay")
        flush_dedicated_honcho_cache(str(settings["redis_url"]))
        retention = run_public_retention_cycle(
            manifest_path,
            database_identity=database_identity,
        )
        _write_status(runtime, state="starting_children", retention=retention)

        while not stopping:
            api = subprocess.Popen(
                [
                    uv_binary,
                    "run",
                    "--frozen",
                    "fastapi",
                    "run",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(urlparse(str(settings["base_url"])).port),
                    "src/main.py",
                ],
                cwd=server_root,
            )
            deriver = subprocess.Popen(
                [uv_binary, "run", "--frozen", "python", "-m", "src.deriver"],
                cwd=server_root,
            )
            service_children = [api, deriver]
            children.extend(service_children)
            _write_status(runtime, state="running", child_pids=[api.pid, deriver.pid])
            deadline = time.monotonic() + RETENTION_INTERVAL_SECONDS
            while not stopping and time.monotonic() < deadline:
                if pause_path.exists() or pause_path.is_symlink():
                    raise RuntimeError("public Honcho pause requested")
                if any(child.poll() is not None for child in service_children):
                    raise RuntimeError("public Honcho child exited")
                time.sleep(1)
            if not stopping:
                _write_status(runtime, state="retention_running")
            _stop_children(service_children)
            children = [child for child in children if child not in service_children]
            if stopping:
                break
            assert_honcho_quiescent(str(settings["base_url"]), public_child_names(slug))
            database_identity = assert_dedicated_database(
                str(settings["database"]), str(settings["workspace"])
            )
            retention = run_public_retention_cycle(
                manifest_path,
                database_identity=database_identity,
            )
            _write_status(runtime, state="retention_complete", retention=retention)
        _write_status(runtime, state="stopped")
        return 0
    except Exception as exc:
        _stop_children(children)
        health = {
            "healthy": False,
            "reasons": ["public_honcho_supervisor_failure"],
            "error_class": type(exc).__name__,
        }
        write_pause_receipt(pause_path, health)
        try:
            _stop_guide(manifest_path, runtime, slug)
        except Exception:
            health["reasons"].append("guide_stop_failed")
        _write_status(runtime, state="paused", health=health)
        # Stay resident so launchd KeepAlive cannot turn a privacy failure into
        # a restart loop. Manual pause clearance and an explicit service reload
        # are required after repair/replay.
        next_backup_expiry = 0.0
        while not stopping:
            if time.monotonic() >= next_backup_expiry:
                try:
                    expire_public_backups(
                        runtime / "private" / "honcho-backups",
                        now=datetime.now(timezone.utc),
                    )
                except Exception as expiry_exc:
                    health["reasons"] = sorted(
                        {*(health.get("reasons") or []), "public_backup_expiry_failed"}
                    )
                    health["backup_expiry_error_class"] = type(expiry_exc).__name__
                    _write_status(runtime, state="paused", health=health)
                next_backup_expiry = time.monotonic() + RETENTION_INTERVAL_SECONDS
            time.sleep(5)
        return 2
    finally:
        _stop_children(children)


def parser() -> argparse.ArgumentParser:
    out = argparse.ArgumentParser(description=__doc__)
    sub = out.add_subparsers(dest="command", required=True)
    for name in ("public-service-provision", "public-service-install", "supervise"):
        command = sub.add_parser(name)
        command.add_argument("--manifest", required=True)
    return out


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "public-service-provision":
            result = provision_public_service(Path(args.manifest))
        elif args.command == "public-service-install":
            result = install_public_service(Path(args.manifest))
        else:
            return supervise_public_service(Path(args.manifest))
    except Exception as exc:
        print(f"public Honcho service error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
