#!/usr/bin/env python3
"""Capability-scoped local Honcho proxy for an isolated Hermes process.

The controller reads one protected profile configuration and exposes only its
fixed loopback Honcho origin and workspace over a private Unix socket.  The
sandbox receives a random per-process capability, never a Honcho credential or
a routable TCP endpoint.
"""

from __future__ import annotations

import hmac
import http.client
import http.server
import json
import os
import re
import socketserver
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit


HONCHO_SOCKET_NAME = "honcho.sock"
HONCHO_BASE_URL = "http://localhost"
MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_CHUNK = 64 * 1024
MAX_HEADER_BYTES = 32 * 1024
MAX_HEADER_COUNT = 64
MAX_CONFIG_BYTES = 1024 * 1024
UPSTREAM_TIMEOUT_SECONDS = 120.0
_ID = r"[A-Za-z0-9_.:-]{1,256}"
_WORKSPACE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_SAFE_CONTENT_TYPES = frozenset({"application/json", "application/problem+json"})
_SENSITIVE_QUERY = re.compile(
    r"(?:auth|authorization|credential|password|secret|token|api.?key)",
    re.IGNORECASE,
)
_SECRET_CONFIG_KEYS = frozenset(
    {
        "apikey",
        "api_key",
        "oauth",
        "accesstoken",
        "access_token",
        "refreshtoken",
        "refresh_token",
        "authorization",
        "credential",
        "credentials",
        "secret",
    }
)
_FORWARDED_RESPONSE_HEADERS = frozenset(
    {"content-type", "retry-after", "x-request-id"}
)


class HonchoBrokerError(RuntimeError):
    """A fail-closed Honcho broker contract violation."""


@dataclass(frozen=True)
class HonchoBinding:
    host: str
    port: int
    workspace: str
    save_messages: bool
    profile: str


def _absolute(path: Path, *, label: str) -> Path:
    raw = Path(os.path.abspath(path.expanduser()))
    if path != raw or "\x00" in str(path):
        raise HonchoBrokerError(f"{label}_not_absolute")
    return raw


def _safe_regular_file(path: Path) -> None:
    runtime = path.parents[2]
    for directory in (runtime, runtime / "profiles", path.parent):
        if directory.is_symlink():
            raise HonchoBrokerError("honcho_broker_config_unsafe")
        try:
            directory_info = directory.lstat()
        except OSError:
            raise HonchoBrokerError("honcho_broker_config_missing") from None
        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or directory_info.st_uid != os.geteuid()
            or directory_info.st_mode & 0o022
        ):
            raise HonchoBrokerError("honcho_broker_config_unsafe")
    if path.is_symlink():
        raise HonchoBrokerError("honcho_broker_config_unsafe")
    try:
        info = path.lstat()
    except OSError:
        raise HonchoBrokerError("honcho_broker_config_missing") from None
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_mode & 0o022
        or info.st_size > MAX_CONFIG_BYTES
    ):
        raise HonchoBrokerError("honcho_broker_config_unsafe")


def _contains_secret_config(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).casefold() in _SECRET_CONFIG_KEYS:
                return True
            if _contains_secret_config(child):
                return True
    elif isinstance(value, list):
        return any(_contains_secret_config(child) for child in value)
    return False


def load_binding(env: Mapping[str, str], profile: str) -> HonchoBinding:
    """Load the immutable origin/workspace/write policy for one profile."""

    from john_lomein_profile_contract import CANONICAL_ROLE_PROFILES

    roles = {
        configured: role for role, configured in CANONICAL_ROLE_PROFILES.items()
    }
    role = roles.get(profile)
    if role is None:
        raise HonchoBrokerError("honcho_broker_profile_invalid")
    controller_values = [
        str(env.get(name) or "").strip()
        for name in ("BOT_HERMES_HOME", "JOHN_LOMEIN_INSTANCE_HERMES_HOME")
        if str(env.get(name) or "").strip()
    ]
    if controller_values:
        roots = [
            _absolute(Path(value), label="honcho_broker_runtime")
            for value in controller_values
        ]
        if any(root != roots[0] for root in roots[1:]):
            raise HonchoBrokerError("honcho_broker_runtime_mismatch")
        runtime = roots[0]
    else:
        runtime_raw = str(env.get("HERMES_HOME") or "").strip()
        if not runtime_raw:
            raise HonchoBrokerError("honcho_broker_runtime_missing")
        runtime = _absolute(Path(runtime_raw), label="honcho_broker_runtime")
    config_path = runtime / "profiles" / profile / "honcho.json"
    _safe_regular_file(config_path)
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
        raise HonchoBrokerError("honcho_broker_config_invalid") from None
    try:
        contains_secret = _contains_secret_config(data)
    except RecursionError:
        raise HonchoBrokerError("honcho_broker_config_invalid") from None
    if not isinstance(data, Mapping) or contains_secret:
        raise HonchoBrokerError("honcho_broker_config_secret_denied")

    base_url = data.get("baseUrl")
    hosts = data.get("hosts")
    active = hosts.get("hermes") if isinstance(hosts, Mapping) else None
    if not isinstance(base_url, str) or not isinstance(active, Mapping):
        raise HonchoBrokerError("honcho_broker_config_binding_missing")
    parsed = urlsplit(base_url)
    try:
        port = parsed.port
    except ValueError:
        raise HonchoBrokerError("honcho_broker_origin_invalid") from None
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise HonchoBrokerError("honcho_broker_origin_invalid")
    port = 80 if port is None else port
    if port < 1 or port > 65535:
        raise HonchoBrokerError("honcho_broker_origin_invalid")

    workspace = active.get("workspace")
    save_messages = active.get("saveMessages")
    if not isinstance(workspace, str) or not _WORKSPACE.fullmatch(workspace):
        raise HonchoBrokerError("honcho_broker_workspace_invalid")
    if type(save_messages) is not bool:
        raise HonchoBrokerError("honcho_broker_write_policy_invalid")
    if role != "guide" and save_messages:
        raise HonchoBrokerError("honcho_broker_write_policy_invalid")
    return HonchoBinding(
        host=str(parsed.hostname),
        port=port,
        workspace=workspace,
        save_messages=save_messages,
        profile=profile,
    )


def _route_patterns(workspace: str, *, save_messages: bool) -> tuple[re.Pattern[str], ...]:
    root = re.escape(f"/v3/workspaces/{workspace}")
    patterns = [
        re.compile(rf"^POST {root}/peers$"),
        re.compile(rf"^POST {root}/peers/list$"),
        re.compile(rf"^POST {root}/sessions$"),
        re.compile(rf"^POST {root}/sessions/list$"),
        re.compile(rf"^POST {root}/search$"),
        re.compile(rf"^GET {root}/queue/status$"),
        re.compile(rf"^POST {root}/peers/{_ID}/(?:chat|context|search|sessions)$"),
        re.compile(rf"^GET {root}/peers/{_ID}/(?:representation|card)$"),
        re.compile(rf"^POST {root}/sessions/{_ID}/(?:context|search)$"),
        re.compile(rf"^GET {root}/sessions/{_ID}/(?:peers|summaries)$"),
        re.compile(rf"^POST {root}/sessions/{_ID}/peers$"),
        re.compile(rf"^GET {root}/sessions/{_ID}/peers/{_ID}/config$"),
        re.compile(rf"^POST {root}/sessions/{_ID}/messages/list$"),
        re.compile(rf"^GET {root}/sessions/{_ID}/messages/{_ID}$"),
    ]
    if save_messages:
        patterns.append(re.compile(rf"^POST {root}/sessions/{_ID}/messages$"))
    return tuple(patterns)


def _validated_target(
    method: str,
    raw_target: str,
    *,
    binding: HonchoBinding,
    capability: str,
) -> str:
    if len(raw_target) > 16 * 1024 or capability in raw_target:
        raise HonchoBrokerError("honcho_broker_target_invalid")
    parsed = urlsplit(raw_target)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise HonchoBrokerError("honcho_broker_absolute_target_denied")
    if "%" in parsed.path or "//" in parsed.path or ".." in parsed.path:
        raise HonchoBrokerError("honcho_broker_target_invalid")
    normalized_method = method.upper()
    route = f"{normalized_method} {parsed.path}"
    if normalized_method == "POST" and parsed.path == "/v3/workspaces":
        pass
    elif not any(
        pattern.fullmatch(route)
        for pattern in _route_patterns(
            binding.workspace,
            save_messages=binding.save_messages,
        )
    ):
        raise HonchoBrokerError("honcho_broker_route_denied")
    try:
        pairs = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=64,
        )
    except (ValueError, TypeError):
        raise HonchoBrokerError("honcho_broker_query_invalid") from None
    if any(
        _SENSITIVE_QUERY.search(key)
        or capability in key
        or capability in value
        or len(key) > 128
        or len(value) > 4096
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in key + value)
        for key, value in pairs
    ):
        raise HonchoBrokerError("honcho_broker_query_denied")
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")


def _validate_json_body(
    body: bytes,
    *,
    path: str,
    capability: str,
) -> None:
    if capability.encode("ascii") in body:
        raise HonchoBrokerError("honcho_broker_capability_leak_denied")
    if not body:
        if path == "/v3/workspaces":
            raise HonchoBrokerError("honcho_broker_workspace_body_invalid")
        return

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise HonchoBrokerError("honcho_broker_json_duplicate_key")
            result[key] = value
        return result

    def invalid_constant(_value: str) -> None:
        raise HonchoBrokerError("honcho_broker_json_constant_invalid")

    try:
        value = json.loads(
            body,
            object_pairs_hook=pairs,
            parse_constant=invalid_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise HonchoBrokerError("honcho_broker_json_invalid") from None
    if not isinstance(value, (dict, list)):
        raise HonchoBrokerError("honcho_broker_json_invalid")

    def contains_capability(item: Any) -> bool:
        if isinstance(item, str):
            return capability in item
        if isinstance(item, Mapping):
            return any(
                contains_capability(key) or contains_capability(child)
                for key, child in item.items()
            )
        if isinstance(item, list):
            return any(contains_capability(child) for child in item)
        return False

    if contains_capability(value):
        raise HonchoBrokerError("honcho_broker_capability_leak_denied")
    if path == "/v3/workspaces":
        # The exact ID value is checked by the handler against the binding.
        if not isinstance(value, dict) or set(value) != {"id"}:
            raise HonchoBrokerError("honcho_broker_workspace_body_invalid")


def _validated_binding(binding: HonchoBinding) -> HonchoBinding:
    from john_lomein_profile_contract import CANONICAL_ROLE_PROFILES

    valid_profiles = frozenset(CANONICAL_ROLE_PROFILES.values())
    guide_profile = CANONICAL_ROLE_PROFILES["guide"]
    if (
        not isinstance(binding, HonchoBinding)
        or binding.host not in {"127.0.0.1", "localhost", "::1"}
        or type(binding.port) is not int
        or not 1 <= binding.port <= 65535
        or not _WORKSPACE.fullmatch(binding.workspace)
        or type(binding.save_messages) is not bool
        or binding.profile not in valid_profiles
        or (binding.profile != guide_profile and binding.save_messages)
    ):
        raise HonchoBrokerError("honcho_broker_binding_invalid")
    return binding


def _upstream_headers(binding: HonchoBinding, *, has_body: bool) -> dict[str, str]:
    host = binding.host
    display_host = f"[{host}]" if ":" in host else host
    headers = {
        "Accept": "application/json, text/event-stream",
        "Accept-Encoding": "identity",
        "Connection": "close",
        "Host": f"{display_host}:{binding.port}",
        "User-Agent": "JohnLomeinHonchoBroker/1",
    }
    if has_body:
        headers["Content-Type"] = "application/json"
    return headers


class _ThreadingUnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False


class _BrokerHandler(http.server.BaseHTTPRequestHandler):
    server_version = "JohnLomeinHonchoBroker/1"
    protocol_version = "HTTP/1.0"

    def log_message(self, _format: str, *_args: Any) -> None:
        return None

    def _error(self, status: int, code: str) -> None:
        payload = json.dumps(
            {"error": {"code": code, "message": "Honcho broker request denied"}},
            separators=(",", ":"),
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def _authorized(self) -> bool:
        values = self.headers.get_all("Authorization", failobj=[])
        if len(values) != 1:
            return False
        expected = f"Bearer {self.server.capability}"
        return hmac.compare_digest(str(values[0]), expected)

    def _request_body(self, path: str) -> bytes:
        if len(self.headers) > MAX_HEADER_COUNT:
            raise HonchoBrokerError("honcho_broker_headers_too_large")
        header_bytes = sum(
            len(str(name)) + len(str(value)) + 4
            for name, value in self.headers.items()
        )
        if header_bytes > MAX_HEADER_BYTES:
            raise HonchoBrokerError("honcho_broker_headers_too_large")
        if self.headers.get_all("Transfer-Encoding", failobj=[]):
            raise HonchoBrokerError("honcho_broker_transfer_encoding_denied")
        lengths = self.headers.get_all("Content-Length", failobj=[])
        if len(lengths) > 1:
            raise HonchoBrokerError("honcho_broker_content_length_invalid")
        raw_length = lengths[0] if lengths else "0"
        try:
            length = int(raw_length)
        except (TypeError, ValueError):
            raise HonchoBrokerError("honcho_broker_content_length_invalid") from None
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise HonchoBrokerError("honcho_broker_request_too_large")
        if length:
            content_types = self.headers.get_all("Content-Type", failobj=[])
            if len(content_types) != 1:
                raise HonchoBrokerError("honcho_broker_content_type_invalid")
            media_type = str(content_types[0]).split(";", 1)[0].strip().casefold()
            if media_type not in _SAFE_CONTENT_TYPES:
                raise HonchoBrokerError("honcho_broker_content_type_invalid")
        body = self.rfile.read(length)
        if len(body) != length:
            raise HonchoBrokerError("honcho_broker_request_truncated")
        _validate_json_body(
            body,
            path=path,
            capability=self.server.capability,
        )
        return body

    def _forward(self) -> None:
        if not self._authorized():
            self._error(401, "honcho_broker_unauthorized")
            return
        try:
            target = _validated_target(
                self.command,
                self.path,
                binding=self.server.binding,
                capability=self.server.capability,
            )
            path = urlsplit(target).path
            body = self._request_body(path)
            if self.command == "GET" and body:
                raise HonchoBrokerError("honcho_broker_get_body_denied")
            if path == "/v3/workspaces":
                value = json.loads(body)
                if value != {"id": self.server.binding.workspace}:
                    raise HonchoBrokerError("honcho_broker_workspace_denied")
        except HonchoBrokerError as exc:
            self._error(403, str(exc))
            return

        upstream = None
        try:
            binding = self.server.binding
            upstream = self.server.upstream_factory(
                binding.host,
                binding.port,
                timeout=UPSTREAM_TIMEOUT_SECONDS,
            )
            upstream.request(
                self.command,
                target,
                body=body or None,
                headers=_upstream_headers(binding, has_body=bool(body)),
            )
            response = upstream.getresponse()
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(MAX_RESPONSE_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise HonchoBrokerError("honcho_broker_response_too_large")
                chunks.append(chunk)
            payload = b"".join(chunks)
            if self.server.capability.encode("ascii") in payload:
                raise HonchoBrokerError("honcho_broker_response_capability_denied")
            self.send_response(response.status, response.reason)
            for name, value in response.getheaders():
                if name.casefold() in _FORWARDED_RESPONSE_HEADERS:
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
        except Exception:
            if not self.wfile.closed:
                try:
                    self._error(502, "honcho_broker_upstream_failed")
                except OSError:
                    pass
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except Exception:
                    pass

    do_GET = _forward
    do_POST = _forward
    do_PUT = _forward
    do_PATCH = _forward

    def do_DELETE(self) -> None:
        self._error(403, "honcho_broker_delete_denied")

    def do_CONNECT(self) -> None:
        self._error(403, "honcho_broker_connect_denied")

    def do_TRACE(self) -> None:
        self._error(403, "honcho_broker_trace_denied")

    def do_OPTIONS(self) -> None:
        self._error(403, "honcho_broker_options_denied")


def create_server(
    socket_path: Path,
    *,
    binding: HonchoBinding,
    capability: str,
    upstream_factory: Callable[..., Any] = http.client.HTTPConnection,
) -> _ThreadingUnixHTTPServer:
    """Create a private, fixed-origin Honcho HTTP server on one Unix socket."""

    path = _absolute(socket_path, label="honcho_broker_socket")
    if (
        not 16 <= len(capability) <= 128
        or not capability.isascii()
        or any(
            char
            not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for char in capability
        )
    ):
        raise HonchoBrokerError("honcho_broker_capability_missing")
    if path.exists() or path.is_symlink():
        raise HonchoBrokerError("honcho_broker_socket_exists")
    safe_binding = _validated_binding(binding)
    server = _ThreadingUnixHTTPServer(str(path), _BrokerHandler)
    server.binding = safe_binding
    server.capability = capability
    server.upstream_factory = upstream_factory
    os.chmod(path, 0o600)
    return server
