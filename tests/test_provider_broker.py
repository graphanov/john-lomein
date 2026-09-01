#!/usr/bin/env python3
from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import john_lomein_provider_broker as broker  # noqa: E402
from john_lomein_honcho_broker import HonchoBinding  # noqa: E402
from john_lomein_model_isolation import (  # noqa: E402
    honcho_broker_socket_path,
    provider_broker_socket_path,
)
from john_lomein_provider_broker import (  # noqa: E402
    BROKER_API_KEY,
    ProviderBrokerError,
    create_server,
)


class FakeResponse:
    status = 200
    reason = "OK"

    def getheaders(self):
        return [("Content-Type", "application/json"), ("Set-Cookie", "forbidden")]

    def read(self, amount: int = -1):
        if getattr(self, "_read", False):
            return b""
        self._read = True
        return b'{"trusted_provider":true}'


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


class ProviderBrokerTest(unittest.TestCase):
    def test_runtime_home_accepts_the_exported_instance_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            runtime.mkdir(mode=0o700)
            profile = runtime / "profiles" / "john-lomein-maintainer"
            profile.mkdir(parents=True, mode=0o700)
            selected = broker._runtime_home(
                {
                    "JOHN_LOMEIN_INSTANCE_HERMES_HOME": str(runtime),
                    "HERMES_HOME": str(profile),
                }
            )
            self.assertEqual(selected, runtime)

    def test_broker_forwards_only_codex_route_and_owns_real_authorization(self):
        with tempfile.TemporaryDirectory() as tmp:
            socket_path = Path(tmp) / "provider.sock"
            upstreams = []

            def factory(host, port, *, timeout):
                upstream = FakeUpstream(host, port, timeout=timeout)
                upstreams.append(upstream)
                return upstream

            real_credential = "authority-" + "credential"
            server = create_server(
                socket_path,
                access_token=real_credential,
                capability="session-capability",
                upstream_factory=factory,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                body = b'{"model":"gpt-test","stream":true}'
                response = unix_http_request(
                    socket_path,
                    b"POST /responses HTTP/1.1\r\n"
                    b"Host: attacker.invalid\r\n"
                    b"Authorization: Bearer session-capability\r\n"
                    b"Cookie: steal=this\r\n"
                    b"Content-Type: application/json\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode()
                    + body,
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

            self.assertIn(b" 200 ", response)
            self.assertIn(b'{"trusted_provider":true}', response)
            self.assertNotIn(b"Set-Cookie", response)
            self.assertEqual(len(upstreams), 1)
            upstream = upstreams[0]
            self.assertEqual((upstream.host, upstream.port), ("chatgpt.com", 443))
            self.assertEqual(len(upstream.requests), 1)
            method, path, forwarded_body, headers = upstream.requests[0]
            self.assertEqual(method, "POST")
            self.assertEqual(path, "/backend-api/codex/responses")
            self.assertEqual(forwarded_body, body)
            self.assertEqual(headers["Authorization"], f"Bearer {real_credential}")
            self.assertEqual(headers["Host"], "chatgpt.com")
            self.assertNotIn("Cookie", headers)
            self.assertNotIn("session-capability", repr(headers))

    def test_broker_rejects_connect_absolute_urls_and_unapproved_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            socket_path = Path(tmp) / "provider.sock"
            calls = []

            def factory(*args, **kwargs):
                calls.append((args, kwargs))
                return FakeUpstream(*args, **kwargs)

            server = create_server(
                socket_path,
                access_token="authority-" + "credential",
                capability="session-capability",
                upstream_factory=factory,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                requests = (
                    b"CONNECT example.invalid:443 HTTP/1.1\r\nAuthorization: Bearer session-capability\r\n\r\n",
                    b"GET https://example.invalid/ HTTP/1.1\r\nAuthorization: Bearer session-capability\r\n\r\n",
                    b"GET /api/workspaces HTTP/1.1\r\nAuthorization: Bearer session-capability\r\n\r\n",
                    b"GET /models HTTP/1.1\r\nAuthorization: Bearer wrong\r\n\r\n",
                )
                responses = [unix_http_request(socket_path, item) for item in requests]
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

            for response in responses:
                self.assertRegex(response.splitlines()[0], rb" 40[134] ")
            self.assertEqual(calls, [])

    def test_broker_constants_are_non_secret_local_capabilities(self):
        self.assertEqual(BROKER_API_KEY, "john-lomein-provider-broker")
        self.assertNotIn(".", BROKER_API_KEY)
        with self.assertRaises(ProviderBrokerError):
            create_server(
                Path("relative.sock"),
                access_token="credential",
                capability="capability",
            )

    def test_controller_owns_credential_and_broker_lifetime(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            runtime.mkdir(mode=0o700)
            socket_path = provider_broker_socket_path()
            honcho_socket = honcho_broker_socket_path(socket_path)
            upstreams = []
            honcho_upstreams = []

            def factory(host, port, *, timeout):
                upstream = FakeUpstream(host, port, timeout=timeout)
                upstreams.append(upstream)
                return upstream

            def honcho_factory(host, port, *, timeout):
                upstream = FakeUpstream(host, port, timeout=timeout)
                honcho_upstreams.append(upstream)
                return upstream

            child = (
                "import os,socket\n"
                "path=os.environ['JOHN_LOMEIN_PROVIDER_BROKER_SOCKET']\n"
                "cap=os.environ['JOHN_LOMEIN_PROVIDER_BROKER_CAPABILITY']\n"
                "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect(path)\n"
                "request=f'GET /models HTTP/1.1\\r\\nAuthorization: Bearer {cap}\\r\\n\\r\\n'.encode()\n"
                "s.sendall(request);response=b''\n"
                "while True:\n"
                " chunk=s.recv(65536)\n"
                " if not chunk: break\n"
                " response+=chunk\n"
                "hpath=os.environ['JOHN_LOMEIN_HONCHO_BROKER_SOCKET']\n"
                "hcap=os.environ['JOHN_LOMEIN_HONCHO_BROKER_CAPABILITY']\n"
                "h=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);h.connect(hpath)\n"
                "hrequest=f'GET /v3/workspaces/selected-workspace/queue/status HTTP/1.1\\r\\nAuthorization: Bearer {hcap}\\r\\n\\r\\n'.encode()\n"
                "h.sendall(hrequest);hresponse=b''\n"
                "while True:\n"
                " chunk=h.recv(65536)\n"
                " if not chunk: break\n"
                " hresponse+=chunk\n"
                "ok=b'trusted_provider' in response and b'trusted_provider' in hresponse\n"
                "raise SystemExit(0 if ok else 9)\n"
            )
            env = {
                "BOT_HERMES_HOME": str(runtime),
                "PATH": os.environ.get("PATH", ""),
            }
            with mock.patch.object(
                broker,
                "_controller_access_token",
                return_value="authority-" + "credential",
            ), mock.patch.object(
                broker,
                "load_binding",
                return_value=HonchoBinding(
                    host="127.0.0.1",
                    port=8000,
                    workspace="selected-workspace",
                    save_messages=True,
                    profile="john-lomein-guide",
                ),
            ):
                status = broker.run_controller(
                    socket_path,
                    "john-lomein-guide",
                    [sys.executable, "-I", "-c", child],
                    env=env,
                    upstream_factory=factory,
                    honcho_upstream_factory=honcho_factory,
                )

            self.assertEqual(status, 0)
            self.assertFalse(socket_path.exists())
            self.assertFalse(honcho_socket.exists())
            self.assertFalse(socket_path.parent.exists())
            self.assertEqual(len(upstreams), 1)
            self.assertEqual(len(honcho_upstreams), 1)
            self.assertEqual(
                honcho_upstreams[0].requests[0][1],
                "/v3/workspaces/selected-workspace/queue/status",
            )
            self.assertNotIn(
                "Authorization",
                honcho_upstreams[0].requests[0][3],
            )
            headers = upstreams[0].requests[0][3]
            self.assertEqual(
                headers["Authorization"],
                "Bearer authority-" + "credential",
            )

    def test_controller_cleans_session_when_authority_resolution_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            runtime.mkdir(mode=0o700)
            socket_path = provider_broker_socket_path()
            env = {"BOT_HERMES_HOME": str(runtime)}
            with mock.patch.object(
                broker,
                "_controller_access_token",
                side_effect=ProviderBrokerError("synthetic-authority-failure"),
            ), mock.patch.object(
                broker,
                "load_binding",
                return_value=HonchoBinding(
                    host="127.0.0.1",
                    port=8000,
                    workspace="selected-workspace",
                    save_messages=True,
                    profile="john-lomein-guide",
                ),
            ):
                with self.assertRaisesRegex(
                    ProviderBrokerError,
                    "synthetic-authority-failure",
                ):
                    broker.run_controller(
                        socket_path,
                        "john-lomein-guide",
                        [sys.executable, "-I", "-c", "pass"],
                        env=env,
                    )
            self.assertFalse(socket_path.parent.exists())

    def test_controller_rejects_honcho_binding_before_credential_resolution(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            runtime.mkdir(mode=0o700)
            socket_path = provider_broker_socket_path()
            env = {"BOT_HERMES_HOME": str(runtime)}
            with mock.patch.object(
                broker,
                "load_binding",
                side_effect=ProviderBrokerError("synthetic-honcho-binding-failure"),
            ), mock.patch.object(
                broker,
                "_controller_access_token",
            ) as credential:
                with self.assertRaisesRegex(
                    ProviderBrokerError,
                    "synthetic-honcho-binding-failure",
                ):
                    broker.run_controller(
                        socket_path,
                        "john-lomein-guide",
                        [sys.executable, "-I", "-c", "pass"],
                        env=env,
                    )
            credential.assert_not_called()
            self.assertFalse(socket_path.parent.exists())


if __name__ == "__main__":
    unittest.main()
