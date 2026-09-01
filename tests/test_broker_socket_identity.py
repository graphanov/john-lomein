from __future__ import annotations

import os
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from broker.john_lomein_broker_daemon import (
    BrokerDaemon,
    BrokerDaemonError,
    PeerCredentials,
    bind_server_socket,
    peer_credentials,
    read_frame,
    sanitize_process_environment,
    write_frame,
)


class BrokerSocketIdentityTest(unittest.TestCase):
    def test_unix_peer_credentials_come_from_kernel(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            credentials = peer_credentials(left)
        finally:
            left.close()
            right.close()
        self.assertEqual(credentials.uid, os.getuid())
        self.assertEqual(credentials.gid, os.getgid())
        if sys.platform.startswith("linux"):
            self.assertIsNotNone(credentials.pid)

    def test_length_prefixed_protocol_round_trips(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            write_frame(left, b'{"packet":"request"}')
            self.assertEqual(
                read_frame(right, maximum_bytes=1024),
                b'{"packet":"request"}',
            )
        finally:
            left.close()
            right.close()

    def test_oversized_length_is_rejected_before_body_read(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            left.sendall(struct.pack("!I", 4097))
            with self.assertRaisesRegex(
                BrokerDaemonError, "outside policy"
            ):
                read_frame(right, maximum_bytes=4096)
        finally:
            left.close()
            right.close()

    def test_frame_timeout_is_an_absolute_request_deadline(self):
        clock = [0.0]
        raw = bytearray(struct.pack("!I", 8) + b"12345678")

        class DripSocket:
            def settimeout(self, _value: float) -> None:
                pass

            def recv(self, _count: int) -> bytes:
                clock[0] += 0.4
                return bytes([raw.pop(0)]) if raw else b""

        with mock.patch(
            "broker.john_lomein_broker_daemon.time.monotonic",
            new=lambda: clock[0],
        ):
            with self.assertRaisesRegex(
                BrokerDaemonError, "timed out"
            ):
                read_frame(
                    DripSocket(),  # type: ignore[arg-type]
                    maximum_bytes=1024,
                    timeout_seconds=1.0,
                )

    def test_second_daemon_cannot_unlink_a_live_socket(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            path = root / "broker.sock"
            config: dict[str, Any] = {
                "broker_uid": os.getuid(),
                "transport": {
                    "socket_path": str(path),
                    "submit_gid": os.getgid(),
                },
            }
            first = bind_server_socket(config)
            try:
                with self.assertRaisesRegex(
                    BrokerDaemonError, "socket lock|already active"
                ):
                    bind_server_socket(config)
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    client.connect(str(path))
                finally:
                    client.close()
            finally:
                first.close()
                path.unlink(missing_ok=True)
                path.with_name(path.name + ".lock").unlink(missing_ok=True)

    def test_stale_owned_socket_is_reclaimed_under_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            path = root / "broker.sock"
            stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            stale.bind(str(path))
            stale.close()
            config: dict[str, Any] = {
                "broker_uid": os.getuid(),
                "transport": {
                    "socket_path": str(path),
                    "submit_gid": os.getgid(),
                },
            }
            server = bind_server_socket(config)
            try:
                self.assertTrue(path.exists())
            finally:
                server.close()
                path.unlink(missing_ok=True)
                path.with_name(path.name + ".lock").unlink(missing_ok=True)

    def test_rejected_client_cannot_crash_daemon_by_closing_early(self):
        daemon = BrokerDaemon(
            config={
                "transport": {
                    "request_timeout_seconds": 1,
                    "max_request_bytes": 1024,
                }
            },
            handler=lambda *_args: {
                "unexpected": "handler should not be called"
            },
        )
        connection = mock.Mock(spec=socket.socket)
        with (
            mock.patch(
                "broker.john_lomein_broker_daemon.peer_credentials",
                return_value=PeerCredentials(uid=123, gid=456, pid=789),
            ),
            mock.patch(
                "broker.john_lomein_broker_daemon."
                "validate_requester_uid",
            ),
            mock.patch(
                "broker.john_lomein_broker_daemon.read_frame",
                return_value=b"{invalid-json",
            ),
            mock.patch(
                "broker.john_lomein_broker_daemon.write_frame",
                side_effect=BrokerDaemonError("client disconnected"),
            ),
        ):
            daemon.handle_connection(connection)

    def test_sensitive_caller_environment_is_removed(self):
        previous = dict(os.environ)
        sensitive = (
            "GH_TOKEN",
            "HTTPS_PROXY",
            "GH_CONFIG_DIR",
            "OPENAI_API_KEY",
            "OPENSSL_CONF",
            "SSL_CERT_FILE",
            "SSLKEYLOGFILE",
        )
        try:
            os.environ["GH_TOKEN"] = "must-not-leak"
            os.environ["HTTPS_PROXY"] = "https://attacker.invalid"
            os.environ["GH_CONFIG_DIR"] = "/tmp/model-owned"
            os.environ["OPENAI_API_KEY"] = "must-not-leak"
            os.environ["OPENSSL_CONF"] = "/tmp/model-owned/openssl.cnf"
            os.environ["SSL_CERT_FILE"] = "/tmp/model-owned/ca.pem"
            os.environ["SSLKEYLOGFILE"] = "/tmp/model-owned/tls.keys"
            sanitize_process_environment()
            for name in sensitive:
                self.assertNotIn(name, os.environ)
        finally:
            os.environ.clear()
            os.environ.update(previous)


if __name__ == "__main__":
    unittest.main()
