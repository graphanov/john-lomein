#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import socket
import struct
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_broker.john_lomein_release_broker_daemon import (
    PeerCredentials,
    ReleaseBrokerDaemon,
    ReleaseBrokerDaemonError,
    bind_server_socket,
    peer_credentials,
    read_frame,
    read_single_frame,
    sanitize_process_environment,
    write_frame,
)


class ReleaseBrokerSocketIdentityTest(unittest.TestCase):
    def test_unix_peer_credentials_are_kernel_derived(self):
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

    def test_one_framed_request_requires_write_side_eof(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        payload = b'{"schema_version":"request"}'
        try:
            left.sendall(struct.pack("!I", len(payload)) + payload)
            left.shutdown(socket.SHUT_WR)
            self.assertEqual(
                read_single_frame(
                    right,
                    maximum_bytes=1024,
                    timeout_seconds=1,
                ),
                payload,
            )
        finally:
            left.close()
            right.close()

    def test_second_frame_or_trailing_byte_is_rejected(self):
        for trailing in (b"x", struct.pack("!I", 2) + b"{}"):
            with self.subTest(trailing=trailing):
                left, right = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_STREAM
                )
                payload = b"{}"
                try:
                    left.sendall(
                        struct.pack("!I", len(payload))
                        + payload
                        + trailing
                    )
                    left.shutdown(socket.SHUT_WR)
                    with self.assertRaisesRegex(
                        ReleaseBrokerDaemonError, "trailing"
                    ):
                        read_single_frame(
                            right,
                            maximum_bytes=1024,
                            timeout_seconds=1,
                        )
                finally:
                    left.close()
                    right.close()

    def test_request_without_write_side_eof_times_out(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        payload = b"{}"
        try:
            left.sendall(struct.pack("!I", len(payload)) + payload)
            with self.assertRaisesRegex(
                ReleaseBrokerDaemonError, "did not terminate"
            ):
                read_single_frame(
                    right,
                    maximum_bytes=1024,
                    timeout_seconds=0.01,
                )
        finally:
            left.close()
            right.close()

    def test_oversized_frame_is_rejected_before_body(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            left.sendall(struct.pack("!I", 4097))
            with self.assertRaisesRegex(
                ReleaseBrokerDaemonError, "outside policy"
            ):
                read_frame(right, maximum_bytes=4096)
        finally:
            left.close()
            right.close()

    def test_daemon_rejects_spoofed_body_identity_using_peer_uid(self):
        config = {
            "broker_uid": 500,
            "transport": {
                "requester_uid": 100,
                "request_timeout_seconds": 1,
                "max_request_bytes": 4096,
            },
        }
        handled: list[Any] = []
        daemon = ReleaseBrokerDaemon(
            config=config,
            handler=lambda value, peer: handled.append(
                (value, peer)
            )
            or {"signed": True},
        )
        connection = mock.Mock(spec=socket.socket)
        with (
            mock.patch(
                "release_broker.john_lomein_release_broker_daemon."
                "peer_credentials",
                return_value=PeerCredentials(
                    uid=999, gid=999, pid=123
                ),
            ),
            mock.patch(
                "release_broker.john_lomein_release_broker_daemon."
                "write_frame"
            ) as write,
        ):
            daemon.handle_connection(connection)
        self.assertEqual(handled, [])
        response = json.loads(write.call_args.args[1])
        self.assertFalse(response["ok"])
        self.assertEqual(
            response["error"]["code"], "request_rejected"
        )

    def test_wrong_uid_never_reaches_handler_even_with_claimed_uid(self):
        config = {
            "broker_uid": 500,
            "transport": {
                "requester_uid": 100,
                "request_timeout_seconds": 1,
                "max_request_bytes": 4096,
            },
        }
        daemon = ReleaseBrokerDaemon(
            config=config,
            handler=lambda *_args: self.fail(
                "unauthorized handler invocation"
            ),
        )
        body = json.dumps(
            {"claimed_uid": 100}, separators=(",", ":")
        ).encode()
        connection = mock.Mock(spec=socket.socket)
        with (
            mock.patch(
                "release_broker.john_lomein_release_broker_daemon."
                "peer_credentials",
                return_value=PeerCredentials(
                    uid=101, gid=101, pid=5
                ),
            ),
            mock.patch(
                "release_broker.john_lomein_release_broker_daemon."
                "read_single_frame",
                return_value=body,
            ),
            mock.patch(
                "release_broker.john_lomein_release_broker_daemon."
                "write_frame"
            ),
        ):
            daemon.handle_connection(connection)

    def test_internal_failure_response_does_not_expose_exception_text(self):
        config = {
            "broker_uid": 500,
            "transport": {
                "requester_uid": 100,
                "request_timeout_seconds": 1,
                "max_request_bytes": 4096,
            },
        }
        daemon = ReleaseBrokerDaemon(
            config=config,
            handler=lambda *_args: (_ for _ in ()).throw(
                RuntimeError("secret token material")
            ),
        )
        connection = mock.Mock(spec=socket.socket)
        with (
            mock.patch(
                "release_broker.john_lomein_release_broker_daemon."
                "peer_credentials",
                return_value=PeerCredentials(
                    uid=100, gid=200, pid=5
                ),
            ),
            mock.patch(
                "release_broker.john_lomein_release_broker_daemon."
                "validate_requester_uid",
                return_value=100,
            ),
            mock.patch(
                "release_broker.john_lomein_release_broker_daemon."
                "read_single_frame",
                return_value=b"{}",
            ),
            mock.patch(
                "release_broker.john_lomein_release_broker_daemon."
                "write_frame"
            ) as write,
        ):
            daemon.handle_connection(connection)
        raw = write.call_args.args[1]
        self.assertNotIn(b"secret", raw)
        response = json.loads(raw)
        self.assertEqual(
            response["error"]["code"], "broker_failure"
        )

    def test_success_response_is_single_frame_then_eof(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        request = b'{"schema_version":"test"}'
        config = {
            "broker_uid": os.getuid() + 1,
            "transport": {
                "requester_uid": os.getuid(),
                "request_timeout_seconds": 2,
                "max_request_bytes": 4096,
            },
        }
        daemon = ReleaseBrokerDaemon(
            config=config,
            handler=lambda *_args: {
                "schema_version": "test-receipt",
                "payload": {},
                "signature": "x",
            },
        )

        def serve() -> None:
            with right:
                daemon.handle_connection(right)

        with (
            mock.patch(
                "release_broker.john_lomein_release_broker_daemon."
                "peer_credentials",
                return_value=PeerCredentials(
                    uid=os.getuid(), gid=os.getgid(), pid=123
                ),
            ),
            mock.patch(
                "release_broker.john_lomein_release_broker_daemon."
                "validate_requester_uid",
                return_value=os.getuid(),
            ),
        ):
            thread = threading.Thread(target=serve)
            thread.start()
            left.sendall(
                struct.pack("!I", len(request)) + request
            )
            left.shutdown(socket.SHUT_WR)
            raw = read_frame(left, maximum_bytes=4096)
            self.assertEqual(left.recv(1), b"")
            thread.join(timeout=2)
        left.close()
        response = json.loads(raw)
        self.assertTrue(response["ok"])

    def test_second_daemon_cannot_unlink_live_release_socket(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            root.chmod(0o700)
            path = root / "release.sock"
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
                    ReleaseBrokerDaemonError,
                    "socket lock|already active",
                ):
                    bind_server_socket(config)
            finally:
                first.close()
                path.unlink(missing_ok=True)
                path.with_name(
                    path.name + ".lock"
                ).unlink(missing_ok=True)

    def test_socket_binding_refuses_wrong_private_key_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            root.chmod(0o700)
            config: dict[str, Any] = {
                "broker_uid": os.getuid(),
                "broker_private_gid": os.getgid() + 1,
                "transport": {
                    "socket_path": str(root / "release.sock"),
                    "submit_gid": os.getgid(),
                },
            }
            with self.assertRaisesRegex(
                ReleaseBrokerDaemonError, "private-key group"
            ):
                bind_server_socket(config)

    def test_sensitive_environment_is_cleared(self):
        previous = dict(os.environ)
        sensitive = (
            "GH_TOKEN",
            "HTTPS_PROXY",
            "OPENAI_API_KEY",
            "SSLKEYLOGFILE",
            "OPENSSL_CONF",
        )
        try:
            for name in sensitive:
                os.environ[name] = "must-not-leak"
            sanitize_process_environment()
            for name in sensitive:
                self.assertNotIn(name, os.environ)
        finally:
            os.environ.clear()
            os.environ.update(previous)


if __name__ == "__main__":
    unittest.main()
