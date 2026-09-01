#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from john_lomein_honcho_broker import (  # noqa: E402
    MAX_REQUEST_BYTES,
    HonchoBinding,
    HonchoBrokerError,
    create_server,
    load_binding,
)


class FakeResponse:
    status = 200
    reason = "OK"

    def getheaders(self):
        return [
            ("Content-Type", "application/json"),
            ("Set-Cookie", "upstream-secret=forbidden"),
            ("Authorization", "Bearer upstream-secret"),
        ]

    def read(self, amount: int = -1):
        if getattr(self, "_read", False):
            return b""
        self._read = True
        return b'{"selected_workspace":true}'


class FakeUpstream:
    def __init__(self, host: str, port: int, *, timeout: float):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.requests = []

    def request(self, method, path, body=None, headers=None):
        self.requests.append((method, path, body, dict(headers or {})))

    def getresponse(self):
        return FakeResponse()

    def close(self):
        return None


def unix_http_request(path: Path, request: bytes) -> bytes:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(3)
    client.connect(str(path))
    try:
        client.sendall(request)
        try:
            client.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        chunks = []
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        client.close()


class RunningBroker:
    def __init__(self, root: Path, *, save_messages: bool = False):
        self.socket_path = root / "honcho.sock"
        self.capability = "ephemeral-honcho-capability"
        self.binding = HonchoBinding(
            host="127.0.0.1",
            port=8000,
            workspace="selected-workspace",
            save_messages=save_messages,
            profile="john-lomein-guide" if save_messages else "john-lomein-forge",
        )
        self.upstreams = []

        def factory(host, port, *, timeout):
            upstream = FakeUpstream(host, port, timeout=timeout)
            self.upstreams.append(upstream)
            return upstream

        self.server = create_server(
            self.socket_path,
            binding=self.binding,
            capability=self.capability,
            upstream_factory=factory,
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.socket_path.unlink(missing_ok=True)

    def request(self, target: str, *, method: str = "GET", body: bytes = b"") -> bytes:
        headers = (
            f"{method} {target} HTTP/1.1\r\n"
            "Host: attacker.invalid\r\n"
            f"Authorization: Bearer {self.capability}\r\n"
            "Cookie: private-cookie\r\n"
        ).encode()
        if body:
            headers += (
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
            )
        return unix_http_request(self.socket_path, headers + b"\r\n" + body)


class HonchoBrokerTest(unittest.TestCase):
    def test_selected_workspace_route_forwards_to_fixed_loopback_without_auth(self):
        with tempfile.TemporaryDirectory() as tmp:
            with RunningBroker(Path(tmp)) as running:
                response = running.request(
                    "/v3/workspaces/selected-workspace/queue/status"
                )

            self.assertIn(b" 200 ", response)
            self.assertIn(b'"selected_workspace":true', response)
            self.assertNotIn(b"Set-Cookie", response)
            self.assertNotIn(b"Authorization", response)
            self.assertNotIn(running.capability.encode(), response)
            self.assertEqual(len(running.upstreams), 1)
            upstream = running.upstreams[0]
            self.assertEqual((upstream.host, upstream.port), ("127.0.0.1", 8000))
            method, target, body, headers = upstream.requests[0]
            self.assertEqual(method, "GET")
            self.assertEqual(
                target,
                "/v3/workspaces/selected-workspace/queue/status",
            )
            self.assertIsNone(body)
            self.assertEqual(headers["Host"], "127.0.0.1:8000")
            self.assertNotIn("Authorization", headers)
            self.assertNotIn("Cookie", headers)
            self.assertNotIn(running.capability, repr(headers))

    def test_workspace_ensure_is_exact_and_message_writes_follow_policy(self):
        ensure = json.dumps({"id": "selected-workspace"}).encode()
        message = json.dumps({"messages": [{"content": "hello"}]}).encode()
        with tempfile.TemporaryDirectory() as tmp:
            with RunningBroker(Path(tmp), save_messages=True) as writable:
                ensured = writable.request(
                    "/v3/workspaces",
                    method="POST",
                    body=ensure,
                )
                written = writable.request(
                    "/v3/workspaces/selected-workspace/sessions/session-a/messages",
                    method="POST",
                    body=message,
                )
            with RunningBroker(Path(tmp), save_messages=False) as read_only:
                denied = read_only.request(
                    "/v3/workspaces/selected-workspace/sessions/session-a/messages",
                    method="POST",
                    body=message,
                )

        self.assertIn(b" 200 ", ensured)
        self.assertIn(b" 200 ", written)
        self.assertIn(b" 403 ", denied)
        self.assertEqual(len(read_only.upstreams), 0)

    def test_denies_cross_workspace_listing_destructive_admin_and_tunneling_routes(self):
        body = b'{"id":"other-workspace"}'
        with tempfile.TemporaryDirectory() as tmp:
            with RunningBroker(Path(tmp), save_messages=True) as running:
                requests = (
                    ("GET", "/v3/workspaces/list", b""),
                    ("POST", "/v3/workspaces/list", b"{}"),
                    ("GET", "/v3/workspaces/other-workspace/queue/status", b""),
                    ("POST", "/v3/workspaces", body),
                    ("DELETE", "/v3/workspaces/selected-workspace", b""),
                    ("POST", "/v3/workspaces/selected-workspace/schedule_dream", b"{}"),
                    ("POST", "/v3/workspaces/selected-workspace/sessions/a/clone", b"{}"),
                    ("POST", "/v3/workspaces/selected-workspace/sessions/a/messages/upload", b"{}"),
                    ("POST", "/v3/workspaces/selected-workspace/conclusions", b"{}"),
                    ("GET", "/admin", b""),
                    ("GET", "/openapi.json", b""),
                    ("GET", "/docs", b""),
                    ("GET", "https://example.invalid/v3/workspaces/selected-workspace", b""),
                    ("CONNECT", "example.invalid:443", b""),
                    ("TRACE", "/v3/workspaces/selected-workspace", b""),
                )
                responses = [
                    running.request(target, method=method, body=request_body)
                    for method, target, request_body in requests
                ]

        for response in responses:
            self.assertRegex(response.splitlines()[0], rb" 40[134] ")
        self.assertEqual(running.upstreams, [])

    def test_denies_oversized_malformed_smuggled_and_capability_leaking_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            with RunningBroker(Path(tmp), save_messages=True) as running:
                authorization = (
                    f"Authorization: Bearer {running.capability}\r\n"
                ).encode()
                escaped_capability = (
                    '"'
                    + "".join(f"\\u{ord(char):04x}" for char in running.capability)
                    + '"'
                ).encode()
                encoded_capability = "".join(
                    f"%{byte:02X}" for byte in running.capability.encode()
                )
                requests = (
                    b"POST /v3/workspaces HTTP/1.1\r\n"
                    + authorization
                    + b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                    b"POST /v3/workspaces HTTP/1.1\r\n"
                    + authorization
                    + b"Content-Length: 2\r\nContent-Length: 3\r\n\r\n{}",
                    b"POST /v3/workspaces HTTP/1.1\r\n"
                    + authorization
                    + f"Content-Length: {MAX_REQUEST_BYTES + 1}\r\n\r\n".encode(),
                    b"POST /v3/workspaces HTTP/1.1\r\n"
                    + authorization
                    + b"Content-Type: application/json\r\nContent-Length: 1\r\n\r\n{",
                    b"POST /v3/workspaces HTTP/1.1\r\n"
                    + authorization
                    + b"Content-Type: application/json\r\nContent-Length: 53\r\n\r\n"
                    + b'{"id":"selected-workspace","id":"selected-workspace"}',
                    b"POST /v3/workspaces/selected-workspace/search HTTP/1.1\r\n"
                    + authorization
                    + b"Content-Type: application/json\r\nContent-Length: 13\r\n\r\n"
                    + b'{"query":NaN}',
                    b"GET /v3/workspaces/selected-workspace/queue/status HTTP/1.1\r\n"
                    + authorization
                    + b"Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
                    b"POST /v3/workspaces/selected-workspace/sessions/a/messages HTTP/1.1\r\n"
                    + authorization
                    + b"Content-Type: application/json\r\n"
                    + f"Content-Length: {len(running.capability) + 2}\r\n\r\n".encode()
                    + json.dumps(running.capability).encode(),
                    b"POST /v3/workspaces/selected-workspace/sessions/a/messages HTTP/1.1\r\n"
                    + authorization
                    + b"Content-Type: application/json\r\n"
                    + f"Content-Length: {len(escaped_capability)}\r\n\r\n".encode()
                    + escaped_capability,
                    (
                        "GET /v3/workspaces/selected-workspace/queue/status?"
                        f"token={running.capability} HTTP/1.1\r\n"
                        f"Authorization: Bearer {running.capability}\r\n\r\n"
                    ).encode(),
                    (
                        "GET /v3/workspaces/selected-workspace/queue/status?"
                        f"q={encoded_capability} HTTP/1.1\r\n"
                        f"Authorization: Bearer {running.capability}\r\n\r\n"
                    ).encode(),
                )
                responses = [
                    unix_http_request(running.socket_path, request)
                    for request in requests
                ]

        for response in responses:
            self.assertIn(b" 403 ", response.split(b"\r\n", 1)[0])
            self.assertNotIn(running.capability.encode(), response)
        self.assertEqual(running.upstreams, [])

    def test_binding_is_loaded_only_from_exact_safe_profile_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = root / "runtime"
            profile = runtime / "profiles" / "john-lomein-guide"
            profile.mkdir(parents=True, mode=0o700)
            config = {
                "baseUrl": "http://127.0.0.1:8123",
                "hosts": {
                    "hermes": {
                        "workspace": "selected-workspace",
                        "saveMessages": True,
                    }
                },
            }
            path = profile / "honcho.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            os.chmod(path, 0o600)

            binding = load_binding(
                {"BOT_HERMES_HOME": str(runtime)},
                "john-lomein-guide",
            )
            self.assertEqual(
                binding,
                HonchoBinding(
                    host="127.0.0.1",
                    port=8123,
                    workspace="selected-workspace",
                    save_messages=True,
                    profile="john-lomein-guide",
                ),
            )

            bad_configs = (
                {**config, "baseUrl": "https://api.honcho.dev"},
                {**config, "apiKey": "real-auth-must-not-be-read"},
                {
                    **config,
                    "hosts": {
                        "hermes": {
                            "workspace": "../other",
                            "saveMessages": True,
                        }
                    },
                },
            )
            for bad in bad_configs:
                path.write_text(json.dumps(bad), encoding="utf-8")
                with self.assertRaises(HonchoBrokerError):
                    load_binding(
                        {"BOT_HERMES_HOME": str(runtime)},
                        "john-lomein-guide",
                    )

            private_profile = runtime / "profiles" / "john-lomein-forge"
            private_profile.mkdir(mode=0o700)
            private_config = private_profile / "honcho.json"
            private_config.write_text(json.dumps(config), encoding="utf-8")
            os.chmod(private_config, 0o600)
            with self.assertRaisesRegex(HonchoBrokerError, "write_policy"):
                load_binding(
                    {"BOT_HERMES_HOME": str(runtime)},
                    "john-lomein-forge",
                )
            config["hosts"]["hermes"]["saveMessages"] = False
            private_config.write_text(json.dumps(config), encoding="utf-8")
            private_binding = load_binding(
                {"BOT_HERMES_HOME": str(runtime)},
                "john-lomein-forge",
            )
            self.assertFalse(private_binding.save_messages)


if __name__ == "__main__":
    unittest.main()
