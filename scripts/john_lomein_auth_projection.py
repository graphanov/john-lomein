#!/usr/bin/env python3
"""Broker OpenAI Codex access credentials into John Lomein runtimes.

The real user's Hermes auth store is the sole owner of the rotating OAuth
refresh-token chain.  John Lomein runtime roots and role profiles receive only
a short-lived access-token projection represented as a manual API-key pool
entry.  A model process can therefore read a usable bearer token without being
able to consume, replace, or copy the single-use refresh token.

This module deliberately has no dependency on Hermes at import time.  Refresh
work is delegated to Hermes' own isolated interpreter, where its credential
pool provides the lock-aware, single-use-token refresh implementation.
"""

from __future__ import annotations

import argparse
import base64
import copy
import datetime as dt
import json
import os
import pwd
import secrets
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - John Lomein supports POSIX hosts.
    fcntl = None  # type: ignore[assignment]

# ``_run_hermes_refresh`` intentionally invokes this file with Python ``-I``.
# Isolated mode omits the script directory from sys.path, so add only this
# exact, product-owned directory before importing the canonical profile map.
_SCRIPT_ROOT = Path(__file__).resolve().parent
if str(_SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_ROOT))

from john_lomein_profile_contract import CANONICAL_ROLE_PROFILES


PROVIDER = "openai-codex"
BASE_URL = "https://chatgpt.com/backend-api/codex"
PROJECTION_ID = "john-lomein-openai-codex"
PROJECTION_LABEL = "John Lomein OpenAI Codex access projection"
PROJECTION_SOURCE = "manual:api_key"
PROJECTION_KEYS = frozenset(
    {
        "id",
        "label",
        "auth_type",
        "priority",
        "source",
        "access_token",
        "base_url",
    }
)
CANONICAL_PROFILE_NAMES = tuple(CANONICAL_ROLE_PROFILES.values())
FILE_MODE = 0o600
PRIVATE_DIRECTORY_MODE = 0o700
MAX_AUTH_BYTES = 2 * 1024 * 1024
DEFAULT_REFRESH_HORIZON_SECONDS = 20 * 60
DEFAULT_LOCK_TIMEOUT_SECONDS = 30.0
DEFAULT_REFRESH_TIMEOUT_SECONDS = 90.0


class AuthProjectionError(RuntimeError):
    """A fail-closed credential projection contract violation."""


def _fail(code: str) -> AuthProjectionError:
    return AuthProjectionError(code)


def _normalized_absolute(path: os.PathLike[str] | str, *, label: str) -> Path:
    try:
        raw = os.fspath(path)
    except TypeError:
        raise _fail(f"{label}_invalid") from None
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise _fail(f"{label}_invalid")
    value = Path(raw).expanduser()
    if not value.is_absolute():
        raise _fail(f"{label}_not_absolute")
    normalized = Path(os.path.normpath(raw))
    if value != normalized or ".." in value.parts:
        raise _fail(f"{label}_not_normalized")
    return value


def _safe_shared_ancestor(info: os.stat_result, *, owner_uid: int) -> bool:
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, owner_uid}:
        return False
    mode = stat.S_IMODE(info.st_mode)
    if not mode & 0o022:
        return True
    # Root-owned sticky directories such as /tmp are safe shared ancestors:
    # another user cannot replace this user's child.  No credential leaf or
    # credential-owning directory is allowed to use this exception.
    return info.st_uid == 0 and bool(mode & stat.S_ISVTX)


def _canonical_no_untrusted_symlink(
    path: os.PathLike[str] | str,
    *,
    label: str,
    must_exist: bool = True,
) -> Path:
    """Return a canonical absolute path, rejecting user-controlled symlinks."""

    raw = _normalized_absolute(path, label=label)
    owner_uid = os.geteuid()
    current = Path(raw.anchor)
    for component in raw.parts[1:]:
        candidate = current / component
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            if must_exist:
                raise _fail(f"{label}_missing")
            current = candidate
            continue
        except OSError:
            raise _fail(f"{label}_stat_failed") from None
        if stat.S_ISLNK(info.st_mode):
            try:
                parent_info = current.stat()
            except OSError:
                raise _fail(f"{label}_symlink_component") from None
            immutable_platform_alias = (
                info.st_uid == 0
                and parent_info.st_uid == 0
                and not bool(parent_info.st_mode & 0o022)
            )
            if not immutable_platform_alias:
                raise _fail(f"{label}_symlink_component")
            try:
                current = candidate.resolve(strict=True)
            except (OSError, RuntimeError):
                raise _fail(f"{label}_symlink_component") from None
            continue
        if not stat.S_ISDIR(info.st_mode):
            if candidate != raw:
                raise _fail(f"{label}_ancestry_not_directory")
        elif candidate != raw and not _safe_shared_ancestor(
            info, owner_uid=owner_uid
        ):
            raise _fail(f"{label}_ancestry_unsafe")
        current = candidate
    canonical = current
    if must_exist and not canonical.exists():
        raise _fail(f"{label}_missing")
    return canonical


def _validate_private_directory(path: Path, *, label: str) -> Path:
    canonical = _canonical_no_untrusted_symlink(path, label=label)
    try:
        info = canonical.lstat()
    except OSError:
        raise _fail(f"{label}_stat_failed") from None
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != PRIVATE_DIRECTORY_MODE
    ):
        raise _fail(f"{label}_unsafe")
    return canonical


def _safe_file_info(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == FILE_MODE
    )


def _directory_fd(directory: Path, *, label: str) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory_flag:
        raise _fail("auth_projection_nofollow_unsupported")
    try:
        fd = os.open(
            str(directory),
            os.O_RDONLY | nofollow | directory_flag | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError:
        raise _fail(f"{label}_open_failed") from None
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != PRIVATE_DIRECTORY_MODE
        ):
            raise _fail(f"{label}_unsafe")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read_json_file(
    path: Path,
    *,
    label: str,
    missing_ok: bool = False,
) -> dict[str, Any]:
    parent = _validate_private_directory(path.parent, label=f"{label}_parent")
    if path.parent != parent:
        path = parent / path.name
    parent_fd = _directory_fd(parent, label=f"{label}_parent")
    fd: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(
            os, "O_CLOEXEC", 0
        )
        try:
            fd = os.open(path.name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            if missing_ok:
                return {}
            raise _fail(f"{label}_missing") from None
        except OSError:
            raise _fail(f"{label}_open_failed") from None
        before = os.fstat(fd)
        if not _safe_file_info(before):
            raise _fail(f"{label}_unsafe")
        if before.st_size > MAX_AUTH_BYTES:
            raise _fail(f"{label}_too_large")
        chunks: list[bytes] = []
        remaining = MAX_AUTH_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > MAX_AUTH_BYTES:
            raise _fail(f"{label}_too_large")
        after = os.fstat(fd)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or not _safe_file_info(after)
        ):
            raise _fail(f"{label}_changed")
        try:
            decoded = payload.decode("utf-8", errors="strict")
            value = json.loads(
                decoded,
                object_pairs_hook=_reject_duplicate_json_keys,
            )
        except (UnicodeError, json.JSONDecodeError, ValueError):
            raise _fail(f"{label}_malformed") from None
        if not isinstance(value, dict):
            raise _fail(f"{label}_invalid_shape")
        return value
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent_fd)


def _serialize_json(payload: Mapping[str, Any]) -> bytes:
    try:
        encoded = (
            json.dumps(
                payload,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise _fail("auth_projection_payload_not_json") from None
    if len(encoded) > MAX_AUTH_BYTES:
        raise _fail("auth_projection_payload_too_large")
    return encoded


def _atomic_json_write(path: Path, payload: Mapping[str, Any], *, label: str) -> None:
    parent = _validate_private_directory(path.parent, label=f"{label}_parent")
    if path.parent != parent:
        path = parent / path.name
    encoded = _serialize_json(payload)
    parent_fd = _directory_fd(parent, label=f"{label}_parent")
    temp_name = f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(12)}"
    temp_fd: int | None = None
    try:
        try:
            existing = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        except OSError:
            raise _fail(f"{label}_stat_failed") from None
        if existing is not None and not _safe_file_info(existing):
            raise _fail(f"{label}_unsafe")
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            temp_fd = os.open(
                temp_name,
                flags,
                FILE_MODE,
                dir_fd=parent_fd,
            )
        except OSError:
            raise _fail(f"{label}_temp_create_failed") from None
        info = os.fstat(temp_fd)
        if not _safe_file_info(info):
            raise _fail(f"{label}_temp_unsafe")
        view = memoryview(encoded)
        while view:
            written = os.write(temp_fd, view)
            if written <= 0:
                raise _fail(f"{label}_write_failed")
            view = view[written:]
        os.fsync(temp_fd)
        os.close(temp_fd)
        temp_fd = None
        try:
            os.replace(
                temp_name,
                path.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
        except OSError:
            raise _fail(f"{label}_replace_failed") from None
        os.fsync(parent_fd)
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        try:
            os.unlink(temp_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        except OSError:
            pass
        os.close(parent_fd)


@contextmanager
def _auth_lock(
    auth_path: Path,
    *,
    timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
) -> Iterator[None]:
    """Acquire Hermes' compatible ``auth.lock`` advisory flock."""

    if fcntl is None:
        raise _fail("auth_projection_fcntl_unavailable")
    parent = _validate_private_directory(
        auth_path.parent, label="auth_projection_lock_parent"
    )
    lock_name = auth_path.with_suffix(".lock").name
    parent_fd = _directory_fd(parent, label="auth_projection_lock_parent")
    fd: int | None = None
    try:
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            fd = os.open(lock_name, flags, FILE_MODE, dir_fd=parent_fd)
        except OSError:
            raise _fail("auth_projection_lock_open_failed") from None
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
        ):
            raise _fail("auth_projection_lock_unsafe")
        # Hermes historically creates this advisory lock through ``open(a+)``
        # and the process umask.  Tightening a proven owner-owned, single-link
        # regular lock is compatible with Hermes and removes local metadata
        # exposure without touching the lock contents.
        try:
            os.fchmod(fd, FILE_MODE)
        except OSError:
            raise _fail("auth_projection_lock_mode_failed") from None
        if stat.S_IMODE(os.fstat(fd).st_mode) != FILE_MODE:
            raise _fail("auth_projection_lock_unsafe_mode")
        deadline = time.monotonic() + max(1.0, float(timeout_seconds))
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except (BlockingIOError, OSError):
                if time.monotonic() >= deadline:
                    raise _fail("auth_projection_lock_timeout") from None
                time.sleep(0.05)
        yield
    finally:
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)
        os.close(parent_fd)


@contextmanager
def _auth_locks(paths: Sequence[Path]) -> Iterator[None]:
    """Acquire multiple auth locks in canonical lexical order."""

    ordered = sorted({str(path): path for path in paths}.values(), key=str)
    with ExitStack() as stack:
        for path in ordered:
            stack.enter_context(_auth_lock(path))
        yield


def _b64url_json(segment: str, *, label: str) -> dict[str, Any]:
    if not segment or len(segment) > MAX_AUTH_BYTES:
        raise _fail(f"{label}_invalid")
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (ValueError, UnicodeError, json.JSONDecodeError):
        raise _fail(f"{label}_invalid") from None
    if not isinstance(value, dict):
        raise _fail(f"{label}_invalid")
    return value


def _jwt_claims(token: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(token, str) or not token or len(token) > MAX_AUTH_BYTES:
        raise _fail(f"{label}_invalid")
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise _fail(f"{label}_invalid")
    header = _b64url_json(parts[0], label=f"{label}_header")
    claims = _b64url_json(parts[1], label=f"{label}_claims")
    if not isinstance(header.get("alg"), str) or not header["alg"].strip():
        raise _fail(f"{label}_header_invalid")
    exp = claims.get("exp")
    iat = claims.get("iat")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        raise _fail(f"{label}_missing_exp")
    if iat is not None and (
        isinstance(iat, bool) or not isinstance(iat, (int, float))
    ):
        raise _fail(f"{label}_invalid_iat")
    if iat is not None and float(iat) > time.time() + 300:
        raise _fail(f"{label}_future_iat")
    return claims


def _valid_access_token(
    token: Any,
    *,
    label: str,
    horizon_seconds: int = 0,
) -> str:
    claims = _jwt_claims(token, label=label)
    if float(claims["exp"]) <= time.time() + max(0, int(horizon_seconds)):
        raise _fail(f"{label}_expired_or_expiring")
    return str(token)


def _account_id(claims: Mapping[str, Any], *, label: str) -> str:
    auth = claims.get("https://api.openai.com/auth")
    if isinstance(auth, Mapping):
        for key in (
            "chatgpt_account_id",
            "chatgpt_account_user_id",
            "chatgpt_user_id",
            "user_id",
        ):
            value = auth.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    subject = claims.get("sub")
    if isinstance(subject, str) and subject.strip():
        return subject.strip()
    raise _fail(f"{label}_account_missing")


def _timestamp(value: Any, *, label: str) -> float:
    if isinstance(value, bool):
        raise _fail(f"{label}_invalid")
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 1_000_000_000_000:
            number /= 1000.0
        if number <= 0:
            raise _fail(f"{label}_invalid")
        return number
    if not isinstance(value, str) or not value.strip():
        raise _fail(f"{label}_missing")
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(raw)
    except ValueError:
        raise _fail(f"{label}_invalid") from None
    if parsed.tzinfo is None:
        raise _fail(f"{label}_timezone_missing")
    return parsed.timestamp()


def default_authority_home(
    env: Mapping[str, str] | None = None,
) -> Path:
    values = os.environ if env is None else env
    configured = str(values.get("HERMES_REAL_HOME") or "").strip()
    if configured:
        real_home = _normalized_absolute(
            configured, label="auth_projection_real_home"
        )
    else:
        try:
            real_home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        except (KeyError, OSError):
            raise _fail("auth_projection_real_home_unavailable") from None
        real_home = _normalized_absolute(
            real_home, label="auth_projection_real_home"
        )
    return real_home / ".hermes"


def _authority_home(path: Path | None) -> Path:
    selected = default_authority_home() if path is None else path
    return _validate_private_directory(
        _normalized_absolute(selected, label="auth_projection_authority_home"),
        label="auth_projection_authority_home",
    )


def _runtime_home(path: Path) -> Path:
    return _validate_private_directory(
        _normalized_absolute(path, label="auth_projection_runtime_home"),
        label="auth_projection_runtime_home",
    )


def _canonical_profile(
    runtime_home: Path,
    value: os.PathLike[str] | str,
) -> Path:
    raw = os.fspath(value)
    if raw in CANONICAL_PROFILE_NAMES:
        candidate = runtime_home / "profiles" / raw
    else:
        candidate = _normalized_absolute(
            raw, label="auth_projection_profile"
        )
    expected_root = runtime_home / "profiles"
    if (
        candidate.parent != expected_root
        or candidate.name not in CANONICAL_PROFILE_NAMES
    ):
        raise _fail("auth_projection_profile_not_canonical")
    return _validate_private_directory(
        candidate,
        label=f"auth_projection_profile_{candidate.name}",
    )


def _projection_homes(
    runtime_home: Path,
    profiles: Sequence[os.PathLike[str] | str],
) -> list[Path]:
    runtime = _runtime_home(runtime_home)
    selected: Sequence[os.PathLike[str] | str]
    selected = profiles or CANONICAL_PROFILE_NAMES
    resolved = [_canonical_profile(runtime, value) for value in selected]
    unique: list[Path] = []
    seen = {runtime}
    for profile in resolved:
        if profile not in seen:
            unique.append(profile)
            seen.add(profile)
    return [runtime, *unique]


def _provider_state(
    store: Mapping[str, Any],
    *,
    label: str,
    require_unexpired_access: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    providers = store.get("providers")
    if not isinstance(providers, Mapping):
        raise _fail(f"{label}_providers_invalid")
    state = providers.get(PROVIDER)
    if not isinstance(state, Mapping):
        raise _fail(f"{label}_provider_missing")
    tokens = state.get("tokens")
    if not isinstance(tokens, Mapping):
        raise _fail(f"{label}_tokens_missing")
    raw_access_token = tokens.get("access_token")
    if require_unexpired_access:
        access_token = _valid_access_token(
            raw_access_token,
            label=f"{label}_access_token",
        )
    else:
        _jwt_claims(raw_access_token, label=f"{label}_access_token")
        access_token = str(raw_access_token)
    refresh_token = tokens.get("refresh_token")
    if not isinstance(refresh_token, str) or not refresh_token.strip():
        raise _fail(f"{label}_refresh_token_missing")
    return dict(state), {
        **dict(tokens),
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


def _matching_pool_row(
    store: Mapping[str, Any],
    tokens: Mapping[str, Any],
    *,
    label: str,
) -> dict[str, Any]:
    pool = store.get("credential_pool")
    if not isinstance(pool, Mapping):
        raise _fail(f"{label}_pool_invalid")
    rows = pool.get(PROVIDER)
    if not isinstance(rows, list):
        raise _fail(f"{label}_pool_missing")
    matching = [
        row
        for row in rows
        if isinstance(row, Mapping)
        and row.get("access_token") == tokens.get("access_token")
        and row.get("refresh_token") == tokens.get("refresh_token")
    ]
    if len(matching) != 1:
        raise _fail(f"{label}_pool_chain_ambiguous")
    row = dict(matching[0])
    if row.get("auth_type") != "oauth":
        raise _fail(f"{label}_pool_auth_type_invalid")
    return row


def _projection_row(access_token: str) -> dict[str, Any]:
    return {
        "id": PROJECTION_ID,
        "label": PROJECTION_LABEL,
        "auth_type": "api_key",
        "priority": 0,
        "source": PROJECTION_SOURCE,
        "access_token": access_token,
        "base_url": BASE_URL,
    }


def _projection_payload(
    existing: Mapping[str, Any],
    *,
    access_token: str,
) -> dict[str, Any]:
    providers_raw = existing.get("providers", {})
    pool_raw = existing.get("credential_pool", {})
    if not isinstance(providers_raw, Mapping):
        raise _fail("auth_projection_existing_providers_invalid")
    if not isinstance(pool_raw, Mapping):
        raise _fail("auth_projection_existing_pool_invalid")

    providers = {
        str(key): copy.deepcopy(value)
        for key, value in providers_raw.items()
        if isinstance(key, str) and key != PROVIDER
    }
    pool = {
        str(key): copy.deepcopy(value)
        for key, value in pool_raw.items()
        if isinstance(key, str) and key != PROVIDER
    }
    pool[PROVIDER] = [_projection_row(access_token)]
    result: dict[str, Any] = {
        "version": existing.get("version", 1),
        "providers": providers,
        "credential_pool": pool,
        "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    active = existing.get("active_provider")
    if isinstance(active, str) and active and active != PROVIDER:
        result["active_provider"] = active
    suppressed = existing.get("suppressed_sources")
    if suppressed is not None:
        if not isinstance(suppressed, Mapping):
            raise _fail("auth_projection_existing_suppressed_invalid")
        filtered = {
            str(key): copy.deepcopy(value)
            for key, value in suppressed.items()
            if isinstance(key, str) and key != PROVIDER
        }
        if filtered:
            result["suppressed_sources"] = filtered
    return result


def _safe_executable(path: Path, *, label: str) -> Path:
    candidate = _normalized_absolute(path, label=label)
    try:
        resolved = candidate.resolve(strict=True)
        info = resolved.stat()
    except (OSError, RuntimeError):
        raise _fail(f"{label}_missing") from None
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid not in {0, os.geteuid()}
        or info.st_mode & 0o022
        or not os.access(candidate, os.X_OK)
    ):
        raise _fail(f"{label}_unsafe")
    return candidate


def _hermes_python(authority_home: Path) -> Path:
    configured = str(os.environ.get("HERMES_PYTHON") or "").strip()
    candidates = []
    if configured:
        candidates.append(Path(configured).expanduser())
    candidates.extend(
        (
            authority_home / "hermes-agent" / "venv" / "bin" / "python",
            authority_home / "hermes-agent" / ".venv" / "bin" / "python",
        )
    )
    for index, candidate in enumerate(candidates):
        if not candidate.is_absolute():
            continue
        try:
            return _safe_executable(
                candidate, label=f"auth_projection_hermes_python_{index}"
            )
        except AuthProjectionError:
            continue
    raise _fail("auth_projection_hermes_python_unavailable")


def _run_hermes_refresh(
    authority_home: Path,
    *,
    refresh_horizon_seconds: int,
) -> None:
    """Run the Hermes pool refresh worker without transporting token bytes."""

    interpreter = _hermes_python(authority_home)
    env = dict(os.environ)
    env["HERMES_HOME"] = str(authority_home)
    env.pop("PYTHONHOME", None)
    env.pop("PYTHONPATH", None)
    command = [
        str(interpreter),
        "-I",
        str(Path(__file__).resolve()),
        "_refresh-authority-worker",
        "--authority-home",
        str(authority_home),
        "--refresh-horizon-seconds",
        str(max(0, int(refresh_horizon_seconds))),
    ]
    try:
        completed = subprocess.run(
            command,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=DEFAULT_REFRESH_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise _fail("auth_projection_authority_refresh_failed") from None
    if completed.returncode != 0:
        raise _fail("auth_projection_authority_refresh_failed")


def _hermes_refresh_in_process(
    authority_home: Path,
    *,
    refresh_horizon_seconds: int,
) -> None:
    """Refresh through Hermes internals. Called only by the isolated worker."""

    os.environ["HERMES_HOME"] = str(authority_home)
    try:
        from agent.credential_pool import load_pool
        from hermes_cli.auth import _codex_access_token_is_expiring
    except Exception:
        raise _fail("auth_projection_hermes_import_failed") from None
    try:
        pool = load_pool(PROVIDER)
        entry = pool.select()
        if entry is None:
            raise _fail("auth_projection_authority_pool_empty")
        if (
            getattr(entry, "source", None) != "device_code"
            or getattr(entry, "auth_type", None) != "oauth"
            or not getattr(entry, "refresh_token", None)
        ):
            raise _fail("auth_projection_authority_pool_not_singleton")
        access_token = str(
            getattr(entry, "runtime_api_key", None)
            or getattr(entry, "access_token", "")
            or ""
        )
        if not access_token:
            raise _fail("auth_projection_authority_access_missing")
        if _codex_access_token_is_expiring(
            access_token, max(0, int(refresh_horizon_seconds))
        ):
            entry = pool.try_refresh_matching(access_token)
            if entry is None:
                raise _fail("auth_projection_authority_refresh_rejected")
            access_token = str(
                getattr(entry, "runtime_api_key", None)
                or getattr(entry, "access_token", "")
                or ""
            )
        if not access_token or _codex_access_token_is_expiring(
            access_token, max(0, int(refresh_horizon_seconds))
        ):
            raise _fail("auth_projection_authority_access_stale")
    except AuthProjectionError:
        raise
    except Exception:
        raise _fail("auth_projection_authority_refresh_failed") from None


def _authority_access_token(
    authority_home: Path,
    *,
    refresh_horizon_seconds: int,
) -> str:
    auth_path = authority_home / "auth.json"
    with _auth_lock(auth_path):
        # Validate the authority chain before allowing Hermes to act on it.
        initial = _read_json_file(auth_path, label="auth_projection_authority")
        _state, tokens = _provider_state(
            initial,
            label="auth_projection_authority",
            require_unexpired_access=False,
        )
        _matching_pool_row(
            initial, tokens, label="auth_projection_authority"
        )

    _run_hermes_refresh(
        authority_home,
        refresh_horizon_seconds=refresh_horizon_seconds,
    )

    with _auth_lock(auth_path):
        refreshed = _read_json_file(
            auth_path, label="auth_projection_authority"
        )
        _state, tokens = _provider_state(
            refreshed, label="auth_projection_authority"
        )
        _matching_pool_row(
            refreshed, tokens, label="auth_projection_authority"
        )
        return _valid_access_token(
            tokens["access_token"],
            label="auth_projection_authority_access_token",
            horizon_seconds=refresh_horizon_seconds,
        )


def sync_projection(
    runtime_home: Path,
    *,
    profiles: Sequence[os.PathLike[str] | str] = (),
    authority_home: Path | None = None,
    provider: str = PROVIDER,
    refresh_horizon_seconds: int = DEFAULT_REFRESH_HORIZON_SECONDS,
    _refresh: Callable[[Path], str] | None = None,
) -> dict[str, Any]:
    """Refresh the authority and atomically project one access-only row."""

    normalized_provider = str(provider or "").strip().lower()
    if normalized_provider != PROVIDER:
        return {
            "status": "not_applicable",
            "provider": normalized_provider,
            "targets": 0,
        }
    if isinstance(refresh_horizon_seconds, bool) or refresh_horizon_seconds < 0:
        raise _fail("auth_projection_refresh_horizon_invalid")
    authority = _authority_home(authority_home)
    homes = _projection_homes(runtime_home, profiles)
    if authority in homes:
        raise _fail("auth_projection_authority_is_projection")

    # Validate and load every destination before refresh. A malformed or
    # redirected destination therefore cannot cause a partial projection.
    existing: list[tuple[Path, dict[str, Any]]] = []
    for index, home in enumerate(homes):
        auth_path = home / "auth.json"
        with _auth_lock(auth_path):
            current = _read_json_file(
                auth_path,
                label=f"auth_projection_target_{index}",
                missing_ok=True,
            )
        existing.append((auth_path, current))

    # The common path is intentionally credential-authority free: a valid,
    # identical projection with enough task horizon needs no refresh-worker
    # process and no filesystem writes. The trusted authority is consulted
    # only when a destination is missing, divergent, malformed, or expiring.
    projected_token: str | None = None
    projections_current = True
    for index, (_auth_path, current) in enumerate(existing):
        try:
            token = _verify_store(
                current,
                label=f"auth_projection_target_{index}",
                horizon_seconds=refresh_horizon_seconds,
            )
        except AuthProjectionError:
            projections_current = False
            break
        if projected_token is None:
            projected_token = token
        elif token != projected_token:
            projections_current = False
            break
    if projections_current and projected_token is not None:
        return {
            "status": "current",
            "provider": PROVIDER,
            "targets": len(existing),
        }

    access_token = (
        _refresh(authority)
        if _refresh is not None
        else _authority_access_token(
            authority,
            refresh_horizon_seconds=refresh_horizon_seconds,
        )
    )
    access_token = _valid_access_token(
        access_token,
        label="auth_projection_refreshed_access_token",
        horizon_seconds=refresh_horizon_seconds,
    )

    written = 0
    for index, (auth_path, current) in enumerate(existing):
        payload = _projection_payload(current, access_token=access_token)
        with _auth_lock(auth_path):
            # Re-read after refresh so concurrent safe non-OpenAI updates are
            # merged instead of overwritten. Any unsafe change fails closed.
            latest = _read_json_file(
                auth_path,
                label=f"auth_projection_target_{index}",
                missing_ok=True,
            )
            payload = _projection_payload(latest, access_token=access_token)
            _atomic_json_write(
                auth_path,
                payload,
                label=f"auth_projection_target_{index}",
            )
        written += 1
    return {
        "status": "ok",
        "provider": PROVIDER,
        "targets": written,
    }


def _verify_store(
    store: Mapping[str, Any],
    *,
    label: str,
    horizon_seconds: int,
) -> str:
    providers = store.get("providers")
    pool = store.get("credential_pool")
    if not isinstance(providers, Mapping):
        raise _fail(f"{label}_providers_invalid")
    if PROVIDER in providers:
        raise _fail(f"{label}_provider_singleton_present")
    if not isinstance(pool, Mapping):
        raise _fail(f"{label}_pool_invalid")
    rows = pool.get(PROVIDER)
    if not isinstance(rows, list) or len(rows) != 1:
        raise _fail(f"{label}_pool_shape_invalid")
    row = rows[0]
    if not isinstance(row, Mapping) or set(row) != PROJECTION_KEYS:
        raise _fail(f"{label}_row_shape_invalid")
    expected = {
        "id": PROJECTION_ID,
        "label": PROJECTION_LABEL,
        "auth_type": "api_key",
        "priority": 0,
        "source": PROJECTION_SOURCE,
        "base_url": BASE_URL,
    }
    for key, value in expected.items():
        if row.get(key) != value:
            raise _fail(f"{label}_row_{key}_invalid")
    return _valid_access_token(
        row.get("access_token"),
        label=f"{label}_access_token",
        horizon_seconds=horizon_seconds,
    )


def verify_projection(
    runtime_home: Path,
    *,
    profiles: Sequence[os.PathLike[str] | str] = (),
    authority_home: Path | None = None,
    provider: str = PROVIDER,
    horizon_seconds: int = 0,
) -> dict[str, Any]:
    """Verify every runtime projection without refreshing or writing it."""

    normalized_provider = str(provider or "").strip().lower()
    if normalized_provider != PROVIDER:
        return {
            "status": "not_applicable",
            "provider": normalized_provider,
            "targets": 0,
        }
    if isinstance(horizon_seconds, bool) or horizon_seconds < 0:
        raise _fail("auth_projection_verify_horizon_invalid")
    authority = _authority_home(authority_home)
    homes = _projection_homes(runtime_home, profiles)
    if authority in homes:
        raise _fail("auth_projection_authority_is_projection")
    observed_token: str | None = None
    for index, home in enumerate(homes):
        auth_path = home / "auth.json"
        with _auth_lock(auth_path):
            store = _read_json_file(
                auth_path, label=f"auth_projection_verify_{index}"
            )
        token = _verify_store(
            store,
            label=f"auth_projection_verify_{index}",
            horizon_seconds=horizon_seconds,
        )
        if observed_token is None:
            observed_token = token
        elif token != observed_token:
            raise _fail("auth_projection_tokens_diverged")
    return {
        "status": "ok",
        "provider": PROVIDER,
        "targets": len(homes),
    }


def recover_authority(
    runtime_home: Path,
    *,
    from_profile: os.PathLike[str] | str,
    authority_home: Path | None = None,
    provider: str = PROVIDER,
) -> dict[str, Any]:
    """Explicitly promote a strictly newer same-account profile token chain."""

    normalized_provider = str(provider or "").strip().lower()
    if normalized_provider != PROVIDER:
        return {
            "status": "not_applicable",
            "provider": normalized_provider,
            "recovered": False,
        }
    runtime = _runtime_home(runtime_home)
    profile = _canonical_profile(runtime, from_profile)
    authority = _authority_home(authority_home)
    if authority in {runtime, profile}:
        raise _fail("auth_projection_authority_is_projection")
    source_path = profile / "auth.json"
    authority_path = authority / "auth.json"

    with _auth_locks((source_path, authority_path)):
        source = _read_json_file(
            source_path, label="auth_projection_recovery_source"
        )
        current = _read_json_file(
            authority_path, label="auth_projection_recovery_authority"
        )
        source_state, source_tokens = _provider_state(
            source,
            label="auth_projection_recovery_source",
            require_unexpired_access=False,
        )
        authority_state, authority_tokens = _provider_state(
            current,
            label="auth_projection_recovery_authority",
            require_unexpired_access=False,
        )
        source_row = _matching_pool_row(
            source,
            source_tokens,
            label="auth_projection_recovery_source",
        )
        _matching_pool_row(
            current,
            authority_tokens,
            label="auth_projection_recovery_authority",
        )

        source_claims = _jwt_claims(
            source_tokens["access_token"],
            label="auth_projection_recovery_source_access",
        )
        authority_claims = _jwt_claims(
            authority_tokens["access_token"],
            label="auth_projection_recovery_authority_access",
        )
        _valid_access_token(
            source_tokens["access_token"],
            label="auth_projection_recovery_source_access",
        )
        if _account_id(
            source_claims, label="auth_projection_recovery_source"
        ) != _account_id(
            authority_claims, label="auth_projection_recovery_authority"
        ):
            raise _fail("auth_projection_recovery_account_mismatch")

        source_refresh_at = _timestamp(
            source_state.get("last_refresh"),
            label="auth_projection_recovery_source_last_refresh",
        )
        authority_refresh_at = _timestamp(
            authority_state.get("last_refresh"),
            label="auth_projection_recovery_authority_last_refresh",
        )
        if source_refresh_at <= authority_refresh_at:
            raise _fail("auth_projection_recovery_not_newer")
        row_refresh_at = _timestamp(
            source_row.get("last_refresh"),
            label="auth_projection_recovery_source_pool_last_refresh",
        )
        if row_refresh_at != source_refresh_at:
            raise _fail("auth_projection_recovery_refresh_evidence_mismatch")

        providers = current.get("providers")
        pool = current.get("credential_pool")
        if not isinstance(providers, Mapping) or not isinstance(pool, Mapping):
            raise _fail("auth_projection_recovery_authority_shape_invalid")
        recovered = copy.deepcopy(current)
        recovered_providers = dict(copy.deepcopy(providers))
        recovered_pool = dict(copy.deepcopy(pool))
        promoted_state = copy.deepcopy(source_state)
        promoted_state.pop("last_auth_error", None)
        recovered_providers[PROVIDER] = promoted_state
        promoted_row = copy.deepcopy(source_row)
        promoted_row["source"] = "device_code"
        promoted_row["priority"] = 0
        for key in (
            "last_status",
            "last_status_at",
            "last_error_code",
            "last_error_reason",
            "last_error_message",
            "last_error_reset_at",
        ):
            if key in promoted_row:
                promoted_row[key] = None
        recovered_pool[PROVIDER] = [promoted_row]
        recovered["providers"] = recovered_providers
        recovered["credential_pool"] = recovered_pool
        recovered["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        _atomic_json_write(
            authority_path,
            recovered,
            label="auth_projection_recovery_authority",
        )
    return {
        "status": "ok",
        "provider": PROVIDER,
        "recovered": True,
        "source_profile": profile.name,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Broker John Lomein OpenAI Codex access projections."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    def common(command: argparse.ArgumentParser) -> None:
        command.add_argument("--runtime-home", type=Path, required=True)
        command.add_argument("--profile", action="append", default=[])
        command.add_argument("--authority-home", type=Path)
        command.add_argument("--provider", default=PROVIDER)
        command.add_argument("--quiet", action="store_true")

    sync = commands.add_parser("sync")
    common(sync)
    sync.add_argument(
        "--refresh-horizon-seconds",
        type=int,
        default=DEFAULT_REFRESH_HORIZON_SECONDS,
    )

    verify = commands.add_parser("verify")
    common(verify)
    verify.add_argument("--horizon-seconds", type=int, default=0)

    recover = commands.add_parser("recover-authority")
    recover.add_argument("--runtime-home", type=Path, required=True)
    recover.add_argument("--from-profile", required=True)
    recover.add_argument("--authority-home", type=Path)
    recover.add_argument("--provider", default=PROVIDER)
    recover.add_argument("--quiet", action="store_true")
    return parser


def _public_main(argv: Sequence[str]) -> int:
    args = _parser().parse_args(list(argv))
    if args.command == "sync":
        result = sync_projection(
            args.runtime_home,
            profiles=args.profile,
            authority_home=args.authority_home,
            provider=args.provider,
            refresh_horizon_seconds=args.refresh_horizon_seconds,
        )
    elif args.command == "verify":
        result = verify_projection(
            args.runtime_home,
            profiles=args.profile,
            authority_home=args.authority_home,
            provider=args.provider,
            horizon_seconds=args.horizon_seconds,
        )
    else:
        result = recover_authority(
            args.runtime_home,
            from_profile=args.from_profile,
            authority_home=args.authority_home,
            provider=args.provider,
        )
    if not args.quiet:
        print(json.dumps(result, sort_keys=True))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if values and values[0] == "_refresh-authority-worker":
        worker = argparse.ArgumentParser(add_help=False)
        worker.add_argument("--authority-home", type=Path, required=True)
        worker.add_argument(
            "--refresh-horizon-seconds", type=int, required=True
        )
        try:
            args = worker.parse_args(values[1:])
            authority = _authority_home(args.authority_home)
            _hermes_refresh_in_process(
                authority,
                refresh_horizon_seconds=args.refresh_horizon_seconds,
            )
            return 0
        except BaseException:
            # The parent intentionally discards worker output. Never serialize
            # an exception from Hermes: upstream messages may contain secrets.
            return 2
    try:
        return _public_main(values)
    except AuthProjectionError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
