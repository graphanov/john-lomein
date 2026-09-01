#!/usr/bin/env python3
"""Controller-owned OpenAI Codex provider broker for isolated model roles.

The controller resolves and refreshes the real OAuth credential, then exposes
only a short-lived Unix-domain HTTP endpoint to one sandboxed Hermes process.
The model namespace never receives a provider token or a routable provider
host.  The broker fixes the upstream origin and limits the HTTP surface to the
Codex endpoints required by Hermes.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import http.server
import json
import os
import secrets
import signal
import socketserver
import stat
import subprocess
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit


sys.dont_write_bytecode = True

_SCRIPT_ROOT = Path(__file__).resolve().parent
if str(_SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_ROOT))

from john_lomein_profile_contract import CANONICAL_ROLE_PROFILES
from john_lomein_honcho_broker import (
    HONCHO_SOCKET_NAME,
    HonchoBinding,
    create_server as create_honcho_server,
    load_binding,
)


UPSTREAM_HOST = "chatgpt.com"
UPSTREAM_PORT = 443
UPSTREAM_PREFIX = "/backend-api/codex"
BROKER_API_KEY = "john-lomein-provider-broker"
BROKER_SOCKET_NAME = "broker.sock"
BROKER_SESSION_LENGTH = 24
MAX_REQUEST_BYTES = 32 * 1024 * 1024
MAX_RESPONSE_CHUNK = 64 * 1024
UPSTREAM_TIMEOUT_SECONDS = 180.0
ALLOWED_ROUTES = frozenset(
    {
        ("GET", "/models"),
        ("GET", "/usage"),
        ("POST", "/responses"),
        ("POST", "/responses/compact"),
    }
)
ALLOWED_QUERY_KEYS = {
    "/models": frozenset({"client_version"}),
    "/usage": frozenset(),
    "/responses": frozenset(),
    "/responses/compact": frozenset(),
}
FORWARDED_RESPONSE_HEADERS = frozenset(
    {
        "content-type",
        "openai-processing-ms",
        "openai-version",
        "retry-after",
        "x-request-id",
    }
)


class ProviderBrokerError(RuntimeError):
    """A fail-closed provider broker contract violation."""


def _absolute_path(path: Path, *, label: str) -> Path:
    raw = Path(os.path.abspath(path.expanduser()))
    if path != raw or "\x00" in str(path):
        raise ProviderBrokerError(f"{label}_not_absolute")
    return raw


def _account_id(access_token: str) -> str | None:
    """Extract the optional ChatGPT account claim without retaining the JWT."""

    try:
        parts = access_token.split(".")
        if len(parts) < 2:
            return None
        encoded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(encoded))
        auth = claims.get("https://api.openai.com/auth", {})
        value = auth.get("chatgpt_account_id") if isinstance(auth, Mapping) else None
        return value if isinstance(value, str) and value else None
    except Exception:
        return None


def _upstream_target(method: str, raw_target: str) -> str:
    parsed = urlsplit(raw_target)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise ProviderBrokerError("provider_broker_absolute_target_denied")
    path = parsed.path
    normalized_method = method.upper()
    if (normalized_method, path) not in ALLOWED_ROUTES:
        raise ProviderBrokerError("provider_broker_route_denied")
    allowed_query = ALLOWED_QUERY_KEYS[path]
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if any(key not in allowed_query for key, _value in pairs):
        raise ProviderBrokerError("provider_broker_query_denied")
    suffix = f"?{parsed.query}" if parsed.query else ""
    return f"{UPSTREAM_PREFIX}{path}{suffix}"


def _upstream_headers(
    incoming: http.client.HTTPMessage,
    *,
    access_token: str,
) -> dict[str, str]:
    headers = {
        "Accept": "text/event-stream, application/json",
        "Accept-Encoding": "identity",
        "Authorization": f"Bearer {access_token}",
        "Connection": "close",
        "Content-Type": "application/json",
        "Host": UPSTREAM_HOST,
        "User-Agent": "JohnLomeinProviderBroker/1",
        "originator": "hermes-agent",
    }
    content_type = incoming.get("Content-Type")
    if content_type:
        headers["Content-Type"] = content_type
    beta = incoming.get("OpenAI-Beta")
    if beta:
        headers["OpenAI-Beta"] = beta
    account_id = _account_id(access_token)
    if account_id:
        headers["ChatGPT-Account-ID"] = account_id
    return headers


class _ThreadingUnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False


class _BrokerHandler(http.server.BaseHTTPRequestHandler):
    server_version = "JohnLomeinProviderBroker/1"
    protocol_version = "HTTP/1.0"

    def log_message(self, _format: str, *_args: Any) -> None:
        return None

    def _error(self, status: int, code: str) -> None:
        payload = json.dumps(
            {"error": {"code": code, "message": "provider broker request denied"}},
            separators=(",", ":"),
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def _authorized(self) -> bool:
        expected = f"Bearer {self.server.capability}"
        observed = str(self.headers.get("Authorization") or "")
        return hmac.compare_digest(observed, expected)

    def _request_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding"):
            raise ProviderBrokerError("provider_broker_transfer_encoding_denied")
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except (TypeError, ValueError):
            raise ProviderBrokerError("provider_broker_content_length_invalid") from None
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise ProviderBrokerError("provider_broker_request_too_large")
        body = self.rfile.read(length)
        if len(body) != length:
            raise ProviderBrokerError("provider_broker_request_truncated")
        return body

    def _forward(self) -> None:
        if not self._authorized():
            self._error(401, "provider_broker_unauthorized")
            return
        try:
            target = _upstream_target(self.command, self.path)
            body = self._request_body()
        except ProviderBrokerError as exc:
            self._error(403, str(exc))
            return

        upstream = None
        try:
            upstream = self.server.upstream_factory(
                UPSTREAM_HOST,
                UPSTREAM_PORT,
                timeout=UPSTREAM_TIMEOUT_SECONDS,
            )
            upstream.request(
                self.command,
                target,
                body=body or None,
                headers=_upstream_headers(
                    self.headers,
                    access_token=self.server.access_token,
                ),
            )
            response = upstream.getresponse()
            self.send_response(response.status, response.reason)
            for name, value in response.getheaders():
                if name.casefold() in FORWARDED_RESPONSE_HEADERS:
                    self.send_header(name, value)
            self.send_header("Connection", "close")
            self.end_headers()
            while True:
                chunk = response.read(MAX_RESPONSE_CHUNK)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except Exception:
            if not self.wfile.closed:
                try:
                    self._error(502, "provider_broker_upstream_failed")
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

    def do_CONNECT(self) -> None:
        self._error(403, "provider_broker_connect_denied")


def create_server(
    socket_path: Path,
    *,
    access_token: str,
    capability: str,
    upstream_factory: Callable[..., Any] = http.client.HTTPSConnection,
) -> _ThreadingUnixHTTPServer:
    """Create a private, fixed-origin HTTP server on one Unix socket."""

    path = _absolute_path(socket_path, label="provider_broker_socket")
    if not access_token or not capability:
        raise ProviderBrokerError("provider_broker_credential_missing")
    if path.exists() or path.is_symlink():
        raise ProviderBrokerError("provider_broker_socket_exists")
    server = _ThreadingUnixHTTPServer(str(path), _BrokerHandler)
    server.access_token = access_token
    server.capability = capability
    server.upstream_factory = upstream_factory
    os.chmod(path, 0o600)
    return server


def _runtime_home(env: Mapping[str, str]) -> Path:
    controller_values = [
        str(env.get(name) or "").strip()
        for name in (
            "BOT_HERMES_HOME",
            "JOHN_LOMEIN_INSTANCE_HERMES_HOME",
        )
        if str(env.get(name) or "").strip()
    ]
    if controller_values:
        homes = [
            _absolute_path(Path(value), label="provider_broker_runtime")
            for value in controller_values
        ]
        if any(home != homes[0] for home in homes[1:]):
            raise ProviderBrokerError("provider_broker_runtime_mismatch")
        home = homes[0]
    else:
        raw = str(env.get("HERMES_HOME") or "").strip()
        if not raw:
            raise ProviderBrokerError("provider_broker_runtime_missing")
        home = _absolute_path(Path(raw), label="provider_broker_runtime")
    info = home.lstat()
    if (
        home.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o022
    ):
        raise ProviderBrokerError("provider_broker_runtime_unsafe")
    return home


def _controller_root() -> Path:
    try:
        temporary = Path("/tmp").resolve(strict=True)
        info = temporary.stat()
    except OSError:
        raise ProviderBrokerError("provider_broker_tmp_unavailable") from None
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or not stat.S_IMODE(info.st_mode) & stat.S_ISVTX
    ):
        raise ProviderBrokerError("provider_broker_tmp_unsafe")
    return temporary / f"jl-pb-{os.geteuid()}"


def _validate_controller_socket(env: Mapping[str, str], socket_path: Path) -> Path:
    _runtime_home(env)
    root = _controller_root()
    root.mkdir(mode=0o700, exist_ok=True)
    if root.is_symlink():
        raise ProviderBrokerError("provider_broker_root_unsafe")
    info = root.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ProviderBrokerError("provider_broker_root_unsafe")
    path = _absolute_path(socket_path, label="provider_broker_socket")
    session = path.parent
    if (
        path.name != BROKER_SOCKET_NAME
        or session.parent != root
        or len(session.name) != BROKER_SESSION_LENGTH
        or any(char not in "0123456789abcdef" for char in session.name)
        or len(os.fsencode(path)) > 100
    ):
        raise ProviderBrokerError("provider_broker_socket_outside_runtime")
    try:
        session.mkdir(mode=0o700)
    except OSError:
        raise ProviderBrokerError("provider_broker_session_create_failed") from None
    session_info = session.lstat()
    if (
        session.is_symlink()
        or not stat.S_ISDIR(session_info.st_mode)
        or session_info.st_uid != os.geteuid()
        or stat.S_IMODE(session_info.st_mode) != 0o700
    ):
        raise ProviderBrokerError("provider_broker_session_unsafe")
    return path


def _validate_honcho_controller_socket(
    provider_path: Path,
    honcho_path: Path | None,
) -> Path:
    expected = provider_path.with_name(HONCHO_SOCKET_NAME)
    candidate = expected if honcho_path is None else _absolute_path(
        honcho_path,
        label="honcho_broker_socket",
    )
    if candidate != expected or len(os.fsencode(candidate)) > 100:
        raise ProviderBrokerError("honcho_broker_socket_outside_runtime")
    if candidate.exists() or candidate.is_symlink():
        raise ProviderBrokerError("honcho_broker_socket_exists")
    return candidate


def _controller_access_token(env: Mapping[str, str]) -> str:
    from john_lomein_auth_projection import (
        DEFAULT_REFRESH_HORIZON_SECONDS,
        _authority_access_token,
        _authority_home,
    )

    configured = str(env.get("JOHN_LOMEIN_AUTH_AUTHORITY_HOME") or "").strip()
    authority = _authority_home(Path(configured) if configured else None)
    return _authority_access_token(
        authority,
        refresh_horizon_seconds=DEFAULT_REFRESH_HORIZON_SECONDS,
    )


def run_controller(
    socket_path: Path,
    profile: str,
    command: Sequence[str],
    *,
    honcho_socket_path: Path | None = None,
    env: Mapping[str, str] | None = None,
    upstream_factory: Callable[..., Any] = http.client.HTTPSConnection,
    honcho_upstream_factory: Callable[..., Any] = http.client.HTTPConnection,
) -> int:
    """Run one sandbox command while both controller brokers are alive."""

    if profile not in CANONICAL_ROLE_PROFILES.values():
        raise ProviderBrokerError("provider_broker_profile_invalid")
    if not command:
        raise ProviderBrokerError("provider_broker_command_missing")
    controller_env = dict(os.environ if env is None else env)
    path = _validate_controller_socket(controller_env, socket_path)
    honcho_path = _validate_honcho_controller_socket(path, honcho_socket_path)
    child = None
    server = None
    honcho_server = None
    server_thread = None
    honcho_server_thread = None
    prior_handlers: dict[int, Any] = {}

    def forward(signum: int, _frame: Any) -> None:
        if child is not None and child.poll() is None:
            child.send_signal(signum)

    try:
        capability = secrets.token_urlsafe(32)
        honcho_capability = secrets.token_urlsafe(32)
        honcho_binding: HonchoBinding = load_binding(controller_env, profile)
        access_token = _controller_access_token(controller_env)
        server = create_server(
            path,
            access_token=access_token,
            capability=capability,
            upstream_factory=upstream_factory,
        )
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        honcho_server = create_honcho_server(
            honcho_path,
            binding=honcho_binding,
            capability=honcho_capability,
            upstream_factory=honcho_upstream_factory,
        )
        honcho_server_thread = threading.Thread(
            target=honcho_server.serve_forever,
            daemon=True,
        )
        honcho_server_thread.start()
        child_env = dict(controller_env)
        child_env["JOHN_LOMEIN_PROVIDER_BROKER_SOCKET"] = str(path)
        child_env["JOHN_LOMEIN_PROVIDER_BROKER_CAPABILITY"] = capability
        child_env["JOHN_LOMEIN_HONCHO_BROKER_SOCKET"] = str(honcho_path)
        child_env["JOHN_LOMEIN_HONCHO_BROKER_CAPABILITY"] = honcho_capability
        child_env["JOHN_LOMEIN_HONCHO_BROKER_WORKSPACE"] = (
            honcho_binding.workspace
        )
        child = subprocess.Popen(list(command), env=child_env)
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            prior_handlers[signum] = signal.signal(signum, forward)
        return child.wait()
    finally:
        for signum, handler in prior_handlers.items():
            signal.signal(signum, handler)
        if server is not None:
            server.shutdown()
            server.server_close()
        if honcho_server is not None:
            honcho_server.shutdown()
            honcho_server.server_close()
        if server_thread is not None:
            server_thread.join(timeout=3)
        if honcho_server_thread is not None:
            honcho_server_thread.join(timeout=3)
        path.unlink(missing_ok=True)
        honcho_path.unlink(missing_ok=True)
        try:
            path.parent.rmdir()
        except OSError:
            pass
        try:
            path.parent.parent.rmdir()
        except OSError:
            pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a sealed model provider broker")
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--honcho-socket", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    try:
        return run_controller(
            args.socket,
            args.profile,
            command,
            honcho_socket_path=args.honcho_socket,
        )
    except Exception as exc:
        digest = hashlib.sha256(type(exc).__name__.encode()).hexdigest()[:12]
        print(
            f"john-lomein provider broker refused execution: {type(exc).__name__}:{digest}",
            file=sys.stderr,
        )
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
